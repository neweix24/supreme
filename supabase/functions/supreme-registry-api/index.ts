import postgres from "postgres";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_ANON_KEY =
  Deno.env.get("SUPABASE_ANON_KEY") ??
  Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ??
  "";
const DATABASE_URL = Deno.env.get("SUPABASE_DB_URL") ?? "";

const allowedOrigins = new Set([
  "https://neweix.com",
  "https://www.neweix.com",
  "http://localhost:3000",
]);

const db = DATABASE_URL
  ? postgres(DATABASE_URL, { max: 1, prepare: false, ssl: "require" })
  : null;

type JsonObject = Record<string, unknown>;

function json(
  body: unknown,
  status = 200,
  requestId = crypto.randomUUID(),
  extraHeaders: HeadersInit = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "private, no-store, max-age=0",
      pragma: "no-cache",
      "x-content-type-options": "nosniff",
      "x-request-id": requestId,
      ...extraHeaders,
    },
  });
}

function errorResponse(
  code: string,
  message: string,
  status: number,
  requestId: string,
): Response {
  return json({ error: { code, message, request_id: requestId } }, status, requestId);
}

function corsHeaders(origin: string | null): HeadersInit {
  const headers: Record<string, string> = {
    "access-control-allow-headers": "authorization, apikey, content-type, idempotency-key, if-match",
    "access-control-allow-methods": "GET, POST, PATCH, OPTIONS",
    "access-control-max-age": "600",
    vary: "Origin",
  };
  if (origin && allowedOrigins.has(origin)) headers["access-control-allow-origin"] = origin;
  return headers;
}

function decodeJwtClaims(token: string): JsonObject {
  const part = token.split(".")[1];
  if (!part) throw new Error("Invalid bearer token.");
  const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return JSON.parse(decoded) as JsonObject;
}

function isFreshAal2(claims: JsonObject): boolean {
  if (claims.aal !== "aal2") return false;
  const authTime = typeof claims.auth_time === "number" ? claims.auth_time : 0;
  if (!authTime || Date.now() / 1000 - authTime > 300 || authTime > Date.now() / 1000 + 30) {
    return false;
  }
  const amr = Array.isArray(claims.amr) ? claims.amr : [];
  return amr.some((entry) =>
    entry !== null &&
    typeof entry === "object" &&
    ["totp", "webauthn", "phone", "email"].includes(
      String((entry as JsonObject).method ?? ""),
    )
  );
}

async function readJson(request: Request, maxBytes = 64 * 1024): Promise<JsonObject> {
  const contentLength = request.headers.get("content-length");
  if (contentLength && (!/^\d+$/.test(contentLength) || Number(contentLength) > maxBytes)) {
    throw new RangeError("Request body is too large.");
  }
  const reader = request.body?.getReader();
  if (!reader) throw new TypeError("Request body is required.");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new RangeError("Request body is too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TypeError("Request body must be a JSON object.");
  }
  return parsed as JsonObject;
}

function requireString(value: unknown, name: string, max = 200): string {
  if (typeof value !== "string" || value.trim().length === 0 || value.length > max) {
    throw new TypeError(`Invalid ${name}.`);
  }
  return value.trim();
}

function serviceId(value: string): string {
  if (!/^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/.test(value) || value.length > 64) {
    throw new TypeError("Invalid service ID.");
  }
  return value;
}

function hasProductionImpact(value: JsonObject): boolean {
  if (value.risk_tier === "high" || value.risk_tier === "critical") return true;
  const environments = Array.isArray(value.environments) ? value.environments : [];
  return environments.some((item) =>
    item !== null &&
    typeof item === "object" &&
    (item as JsonObject).classification === "production"
  );
}

async function authenticate(request: Request): Promise<{
  userId: string;
  claims: JsonObject;
}> {
  if (!db || !SUPABASE_URL || !SUPABASE_ANON_KEY) {
    throw new Error("Supreme registry backend is not configured.");
  }
  const authorization = request.headers.get("authorization") ?? "";
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new Response("Unauthorized", { status: 401 });
  const token = match[1];
  const userResponse = await fetch(new URL("/auth/v1/user", SUPABASE_URL), {
    headers: { apikey: SUPABASE_ANON_KEY, authorization: `Bearer ${token}` },
    redirect: "error",
    signal: AbortSignal.timeout(5_000),
  });
  if (!userResponse.ok) throw new Response("Unauthorized", { status: 401 });
  const user = await userResponse.json() as { id?: string };
  if (typeof user.id !== "string" || !/^[0-9a-f-]{36}$/i.test(user.id)) {
    throw new Response("Unauthorized", { status: 401 });
  }

  const [ruler] = await db`
    select user_id::text
    from public.staff_profiles
    where user_id = ${user.id}::uuid
      and role = 'supreme'
      and is_active = true
      and public_id = 'supreme'
    limit 2
  `;
  const [count] = await db`
    select count(*)::integer as active_count
    from public.staff_profiles
    where role = 'supreme'
      and is_active = true
      and public_id = 'supreme'
  `;
  if (!ruler || ruler.user_id !== user.id || count?.active_count !== 1) {
    throw new Response("Forbidden", { status: 403 });
  }
  return { userId: user.id, claims: decodeJwtClaims(token) };
}

async function audit(input: {
  actor: string;
  action: string;
  serviceId?: string | null;
  environmentId?: string | null;
  outcome: "success" | "denied" | "failure" | "pending";
  requestId: string;
  details?: JsonObject;
}): Promise<void> {
  if (!db) throw new Error("Database is unavailable.");
  await db`
    insert into supreme.audit_events
      (request_id, actor_user_id, action, target_service_id, environment_id, outcome, policy_version, details)
    values
      (${input.requestId}::uuid, ${input.actor}::uuid, ${input.action},
       ${input.serviceId ?? null}, ${input.environmentId ?? null},
       ${input.outcome}, 'v1', ${db.json(input.details ?? {})})
  `;
}

async function serviceRows(cursor: string | null, limit: number, onlyId?: string) {
  if (!db) throw new Error("Database is unavailable.");
  return await db`
    select
      s.service_id, s.display_name, s.description,
      jsonb_build_object(
        'provider', s.repository_provider,
        'full_name', s.repository_full_name,
        'default_branch', s.repository_default_branch,
        'url', s.repository_url
      ) as repository,
      coalesce((
        select jsonb_agg(jsonb_build_object(
          'environment_id', e.environment_id,
          'classification', e.classification,
          'api_base_url', e.api_base_url,
          'contract_version', e.contract_version,
          'health_url', e.health_url,
          'enabled', e.enabled
        ) order by e.environment_id)
        from supreme.service_environments e
        where e.service_id = s.service_id
      ), '[]'::jsonb) as environments,
      coalesce((
        select jsonb_agg(c.capability order by c.capability)
        from supreme.service_capabilities c
        where c.service_id = s.service_id
      ), '[]'::jsonb) as capabilities,
      '[]'::jsonb as integration_secret_refs,
      jsonb_build_object('team', s.owner_team, 'contact_ref', s.owner_contact_ref) as owner,
      s.data_classification, s.risk_tier,
      jsonb_build_object(
        'kind', s.health_check_kind,
        'path', s.health_check_path,
        'timeout_seconds', s.health_check_timeout_seconds,
        'expected_status', to_jsonb(s.health_check_expected_status)
      ) as health_check,
      s.status, s.metadata_version, s.updated_at
    from supreme.services s
    where (${onlyId ?? null}::text is null or s.service_id = ${onlyId ?? null})
      and (${cursor ?? null}::text is null or s.service_id > ${cursor ?? null})
    order by s.service_id
    limit ${limit}
  `;
}

async function createControlRequest(
  actor: string,
  requestId: string,
  idempotencyKey: string,
  requestType: string,
  action: string,
  targetServiceId: string | null,
  environmentId: string | null,
  parameters: JsonObject,
) {
  if (!db) throw new Error("Database is unavailable.");
  const [created] = await db`
    insert into supreme.control_requests
      (request_type, service_id, environment_id, action, normalized_parameters,
       requester_user_id, idempotency_key, policy_version, approval_required)
    values
      (${requestType}, ${targetServiceId}, ${environmentId}, ${action},
       ${db.json(parameters)}, ${actor}::uuid, ${idempotencyKey}, 'v1', true)
    on conflict (requester_user_id, idempotency_key) do nothing
    returning id::text, status, created_at
  `;
  if (created) {
    await audit({
      actor,
      action,
      serviceId: targetServiceId,
      environmentId,
      outcome: "pending",
      requestId,
      details: { control_request_id: created.id, request_type: requestType },
    });
    return { ...created, duplicate: false };
  }
  const [existing] = await db`
    select id::text, status, created_at
    from supreme.control_requests
    where requester_user_id = ${actor}::uuid and idempotency_key = ${idempotencyKey}
    limit 1
  `;
  if (!existing) throw new Error("Idempotency lookup failed.");
  return { ...existing, duplicate: true };
}

async function handle(request: Request): Promise<Response> {
  const requestId = crypto.randomUUID();
  const origin = request.headers.get("origin");
  const cors = corsHeaders(origin);
  if (origin && !allowedOrigins.has(origin)) {
    return errorResponse("ORIGIN_NOT_ALLOWED", "This origin is not allowed.", 403, requestId);
  }
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  try {
    if (!db) return errorResponse("BACKEND_NOT_CONFIGURED", "Registry backend is not configured.", 503, requestId);
    const { userId, claims } = await authenticate(request);
    const url = new URL(request.url);
    const routeIndex = url.pathname.indexOf("/v1/");
    const path = routeIndex >= 0 ? url.pathname.slice(routeIndex) : url.pathname;
    const parts = path.split("/").filter(Boolean);

    if (request.method === "GET" && parts.length === 2 && parts[0] === "v1" && parts[1] === "services") {
      const limitRaw = Number(url.searchParams.get("limit") ?? "50");
      const limit = Number.isInteger(limitRaw) ? Math.min(Math.max(limitRaw, 1), 100) : 50;
      const cursor = url.searchParams.get("cursor");
      const rows = await serviceRows(cursor, limit + 1);
      const hasMore = rows.length > limit;
      const visible = hasMore ? rows.slice(0, limit) : rows;
      const nextCursor = hasMore ? visible[visible.length - 1].service_id : null;
      await audit({ actor: userId, action: "services.list", outcome: "success", requestId });
      return json({
        schema_version: 1,
        services: visible,
        next_cursor: nextCursor,
        request_id: requestId,
      }, 200, requestId, cors);
    }

    if (parts[0] === "v1" && parts[1] === "services" && parts.length === 3 && request.method === "GET") {
      const id = serviceId(parts[2]);
      const rows = await serviceRows(null, 1, id);
      const record = rows[0];
      if (!record) return errorResponse("SERVICE_NOT_FOUND", "Service not found.", 404, requestId);
      await audit({ actor: userId, action: "services.read", serviceId: id, outcome: "success", requestId });
      const etag = `"${id}:${record.metadata_version}"`;
      return json({ service: record, request_id: requestId }, 200, requestId, {
        ...cors,
        etag,
      });
    }

    if (request.method === "POST" && parts.length === 2 && parts[0] === "v1" && parts[1] === "services") {
      const idempotencyKey = requireString(request.headers.get("idempotency-key"), "Idempotency-Key", 128);
      if (idempotencyKey.length < 8) throw new TypeError("Idempotency-Key must contain at least 8 characters.");
      const body = await readJson(request);
      const id = serviceId(requireString(body.service_id, "service_id", 64));
      const displayName = requireString(body.display_name, "display_name", 120);
      const repository = body.repository;
      if (!repository || typeof repository !== "object" || Array.isArray(repository)) {
        throw new TypeError("repository is required.");
      }
      const repo = repository as JsonObject;
      requireString(repo.provider, "repository.provider", 20);
      requireString(repo.full_name, "repository.full_name", 200);
      requireString(repo.default_branch, "repository.default_branch", 100);
      if (!Array.isArray(body.environments) || body.environments.length < 1 || body.environments.length > 10) {
        throw new TypeError("At least one and at most ten environments are required.");
      }
      if (!Array.isArray(body.capabilities) || body.capabilities.length > 100) {
        throw new TypeError("capabilities must be an array.");
      }
      const highImpact = hasProductionImpact(body);
      if (highImpact && !isFreshAal2(claims)) {
        await audit({ actor: userId, action: "services.register.denied", serviceId: id, outcome: "denied", requestId, details: { reason: "fresh_aal2_required" } });
        return errorResponse("MFA_REQUIRED", "Fresh MFA (AAL2) is required for production-impacting registration.", 403, requestId);
      }
      const result = await createControlRequest(
        userId, requestId, idempotencyKey, "register_service", "services.register",
        id, null, body,
      );
      return json({ control_request: result, request_id: requestId }, result.duplicate ? 200 : 202, requestId, cors);
    }

    if (request.method === "PATCH" && parts.length === 3 && parts[0] === "v1" && parts[1] === "services") {
      const id = serviceId(parts[2]);
      const ifMatch = request.headers.get("if-match");
      if (!ifMatch) return errorResponse("PRECONDITION_REQUIRED", "If-Match is required.", 428, requestId);
      const [current] = await db`
        select metadata_version, risk_tier
        from supreme.services where service_id = ${id} limit 1
      `;
      if (!current) return errorResponse("SERVICE_NOT_FOUND", "Service not found.", 404, requestId);
      const expectedEtag = `"${id}:${current.metadata_version}"`;
      if (ifMatch !== expectedEtag) {
        return errorResponse("REGISTRY_VERSION_CONFLICT", "The service record has changed.", 412, requestId);
      }
      const idempotencyKey = requireString(request.headers.get("idempotency-key"), "Idempotency-Key", 128);
      if (idempotencyKey.length < 8) throw new TypeError("Idempotency-Key must contain at least 8 characters.");
      const body = await readJson(request);
      const envRows = await db`
        select classification from supreme.service_environments where service_id = ${id}
      `;
      const highImpact = current.risk_tier === "high" || current.risk_tier === "critical" ||
        envRows.some((row) => row.classification === "production");
      if (highImpact && !isFreshAal2(claims)) {
        await audit({ actor: userId, action: "services.update.denied", serviceId: id, outcome: "denied", requestId, details: { reason: "fresh_aal2_required" } });
        return errorResponse("MFA_REQUIRED", "Fresh MFA (AAL2) is required for production-impacting changes.", 403, requestId);
      }
      const result = await createControlRequest(
        userId, requestId, idempotencyKey, "update_service", "services.update",
        id, null, { if_match: expectedEtag, patch: body },
      );
      return json({ control_request: result, request_id: requestId }, result.duplicate ? 200 : 202, requestId, cors);
    }

    if (request.method === "GET" && parts.length === 4 && parts[0] === "v1" && parts[1] === "services" && parts[3] === "health") {
      const id = serviceId(parts[2]);
      const environmentId = requireString(url.searchParams.get("environment_id"), "environment_id", 32);
      const [target] = await db`
        select e.health_url, e.api_base_url, e.enabled, s.health_check_kind,
               s.health_check_timeout_seconds, s.health_check_expected_status
        from supreme.service_environments e
        join supreme.services s on s.service_id = e.service_id
        where e.service_id = ${id} and e.environment_id = ${environmentId}
        limit 1
      `;
      if (!target || !target.enabled) return errorResponse("ENVIRONMENT_DISABLED", "Environment is not available.", 404, requestId);
      if (target.health_check_kind !== "http" || !target.health_url || !target.api_base_url) {
        return errorResponse("HEALTH_CHECK_NOT_CONFIGURED", "Health check is not configured.", 409, requestId);
      }
      const healthUrl = new URL(target.health_url);
      const apiUrl = new URL(target.api_base_url);
      if (healthUrl.protocol !== "https:" || healthUrl.origin !== apiUrl.origin) {
        return errorResponse("HEALTH_TARGET_REJECTED", "Health target is outside the registered origin.", 400, requestId);
      }
      const started = performance.now();
      let status = 0;
      let outcome: "success" | "failure" = "failure";
      try {
        const response = await fetch(healthUrl, {
          method: "GET",
          redirect: "error",
          headers: { accept: "application/json, text/plain;q=0.8" },
          signal: AbortSignal.timeout(target.health_check_timeout_seconds * 1000),
        });
        status = response.status;
        await response.body?.cancel();
        if (target.health_check_expected_status.includes(status)) outcome = "success";
      } catch {
        status = 0;
      }
      const latencyMs = Math.round(performance.now() - started);
      await audit({
        actor: userId, action: "service.health.check", serviceId: id,
        environmentId, outcome, requestId, details: { status, latency_ms: latencyMs },
      });
      return json({
        service_id: id,
        environment_id: environmentId,
        healthy: outcome === "success",
        status: status || null,
        latency_ms: latencyMs,
        checked_at: new Date().toISOString(),
        request_id: requestId,
      }, 200, requestId, cors);
    }

    return errorResponse("ROUTE_NOT_FOUND", "Route not found.", 404, requestId);
  } catch (error) {
    if (error instanceof Response) {
      return errorResponse(
        error.status === 401 ? "UNAUTHORIZED" : "FORBIDDEN",
        error.status === 401 ? "A valid Supreme session is required." : "Supreme ruler access is required.",
        error.status,
        requestId,
      );
    }
    if (error instanceof TypeError || error instanceof RangeError || error instanceof SyntaxError) {
      return errorResponse("INVALID_REQUEST", error.message, 400, requestId);
    }
    console.error("Supreme registry request failed", { requestId, error: String(error) });
    return errorResponse("INTERNAL_ERROR", "The registry request could not be completed.", 500, requestId);
  }
}

Deno.serve(handle);
