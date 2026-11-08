import postgres from "npm:postgres@3.4.7";

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
  requestId: string = crypto.randomUUID(),
  extraHeaders: Record<string, string> = {},
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

function corsHeaders(origin: string | null): Record<string, string> {
  const headers: Record<string, string> = {
    "access-control-allow-headers": "authorization, apikey, content-type, idempotency-key, if-match",
    "access-control-allow-methods": "GET, POST, PATCH, OPTIONS",
    "access-control-max-age": "600",
    vary: "Origin",
  };
  if (origin && allowedOrigins.has(origin)) headers["access-control-allow-origin"] = origin;
  return headers;
}

function decodeClaimsAfterSupabaseUserVerification(token: string): JsonObject {
  const part = token.split(".")[1];
  if (!part) throw new Error("Invalid bearer token.");
  const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return JSON.parse(decoded) as JsonObject;
}

function hasVerifiedSupremeAppSession(claims: JsonObject): boolean {
  // This must be a server-signed custom access-token claim populated only by
  // the Supabase Auth hook after checking an active, attested device session.
  // User-editable metadata, request headers, User-Agent, and Origin are not proof.
  const binding = claims.supreme_app_session;
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) return false;
  const session = binding as JsonObject;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return session.status === "active" &&
    typeof session.session_id === "string" && uuid.test(session.session_id) &&
    typeof session.device_id === "string" && uuid.test(session.device_id) &&
    typeof session.attested_at === "number" && Number.isFinite(session.attested_at) &&
    session.attested_at > 0 && session.attested_at <= Date.now() / 1000 + 30;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
}

function decodeCanonicalBase64(value: unknown, maxBytes: number): Uint8Array {
  if (typeof value !== "string" || value.length === 0 || value.length > Math.ceil(maxBytes * 4 / 3) + 4 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new TypeError("Invalid base64 encoding.");
  }
  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.length > maxBytes || btoa(binary) !== value) throw new TypeError("Invalid base64 encoding.");
  return bytes;
}

function derEcdsaToP1363(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der[0] !== 0x30) throw new TypeError("Invalid ECDSA signature.");
  let offset = 1;
  let sequenceLength = der[offset++];
  if (sequenceLength & 0x80) {
    const count = sequenceLength & 0x7f;
    if (count !== 1 || offset >= der.length) throw new TypeError("Invalid ECDSA signature length.");
    sequenceLength = der[offset++];
  }
  if (sequenceLength !== der.length - offset || der[offset++] !== 0x02) {
    throw new TypeError("Invalid ECDSA signature sequence.");
  }
  const rLength = der[offset++];
  if (rLength < 1 || offset + rLength >= der.length) throw new TypeError("Invalid ECDSA signature R.");
  const r = der.slice(offset, offset + rLength);
  offset += rLength;
  if (der[offset++] !== 0x02) throw new TypeError("Invalid ECDSA signature S.");
  const sLength = der[offset++];
  if (sLength < 1 || offset + sLength !== der.length) throw new TypeError("Invalid ECDSA signature S.");
  const s = der.slice(offset, offset + sLength);
  const normalize = (value: Uint8Array): Uint8Array => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    const trimmed = value.slice(start);
    if (trimmed.length > 32) throw new TypeError("ECDSA integer exceeds P-256 size.");
    const out = new Uint8Array(32);
    out.set(trimmed, 32 - trimmed.length);
    return out;
  };
  const output = new Uint8Array(64);
  output.set(normalize(r), 0);
  output.set(normalize(s), 32);
  return output;
}

async function sha256Bytes(value: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(value.length);
  copy.set(value);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", copy.buffer));
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function verifyControlDecisionSignature(input: {
  spki: Uint8Array;
  signatureDer: Uint8Array;
  challengeId: string;
  nonce: Uint8Array;
  requestId: string;
  decision: string;
  reasonHash: Uint8Array;
}): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "spki",
    input.spki,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const payload = new TextEncoder().encode([
    "NEWEIX-SUPREME-CONTROL-DECISION-V1",
    input.challengeId,
    base64Url(input.nonce),
    input.requestId,
    input.decision,
    hex(input.reasonHash),
  ].join("\\n"));
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    derEcdsaToP1363(input.signatureDer),
    payload,
  );
}

function isFreshAal2(claims: JsonObject): boolean {
  if (claims.aal !== "aal2") return false;
  const authTime = typeof claims.auth_time === "number" ? claims.auth_time : 0;
  if (!authTime || Date.now() / 1000 - authTime > 300 || authTime > Date.now() / 1000 + 30) {
    return false;
  }
  // Supreme currently permits password + authenticator TOTP only.
  // Do not treat phone/email OTP as an equivalent second factor.
  const amr = Array.isArray(claims.amr) ? claims.amr : [];
  return amr.some((entry) =>
    entry !== null &&
    typeof entry === "object" &&
    (entry as JsonObject).method === "totp"
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

function assertOnlyKeys(value: JsonObject, allowed: string[], label: string): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new TypeError(`Unknown ${label} field.`);
}

function validateServicePayload(body: JsonObject): void {
  assertOnlyKeys(body, [
    "service_id", "display_name", "description", "repository", "environments",
    "capabilities", "integration_secret_refs", "owner", "data_classification",
    "risk_tier", "health_check", "status", "metadata_version", "updated_at"
  ], "service");
  requireString(body.service_id, "service_id", 64);
  requireString(body.display_name, "display_name", 120);
  if (body.description !== undefined && (typeof body.description !== "string" || body.description.length > 1000)) {
    throw new TypeError("Invalid description.");
  }
  if (body.status !== undefined && !["planned", "active", "suspended", "retired"].includes(String(body.status))) {
    throw new TypeError("Invalid service status.");
  }
  if (body.data_classification !== undefined && !["public", "internal", "confidential", "restricted"].includes(String(body.data_classification))) {
    throw new TypeError("Invalid data classification.");
  }
  if (body.risk_tier !== undefined && !["low", "moderate", "high", "critical"].includes(String(body.risk_tier))) {
    throw new TypeError("Invalid risk tier.");
  }
  if (body.repository === undefined) {
    if (body.status !== "planned") throw new TypeError("A service without a repository must remain planned.");
  } else {
    if (!body.repository || typeof body.repository !== "object" || Array.isArray(body.repository)) {
      throw new TypeError("Invalid repository.");
    }
    const repo = body.repository as JsonObject;
    assertOnlyKeys(repo, ["provider", "full_name", "default_branch", "url"], "repository");
    if (!["github", "gitlab", "bitbucket", "other"].includes(requireString(repo.provider, "repository.provider", 20))) {
      throw new TypeError("Unsupported repository provider.");
    }
    requireString(repo.full_name, "repository.full_name", 200);
    requireString(repo.default_branch, "repository.default_branch", 100);
    if (repo.url !== undefined && (typeof repo.url !== "string" || !repo.url.startsWith("https://"))) {
      throw new TypeError("Repository URL must use HTTPS.");
    }
  }
  if (!Array.isArray(body.environments) || body.environments.length < 1 || body.environments.length > 10) {
    throw new TypeError("At least one and at most ten environments are required.");
  }
  const environmentIds = new Set<string>();
  for (const item of body.environments) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new TypeError("Invalid environment.");
    const env = item as JsonObject;
    assertOnlyKeys(env, ["environment_id", "classification", "api_base_url", "contract_version", "health_url", "enabled"], "environment");
    const envId = requireString(env.environment_id, "environment_id", 32);
    if (environmentIds.has(envId)) throw new TypeError("Duplicate environment ID.");
    environmentIds.add(envId);
    if (!/^[a-z][a-z0-9-]{1,31}$/.test(envId)) throw new TypeError("Invalid environment ID.");
    if (!["development", "staging", "production"].includes(String(env.classification))) throw new TypeError("Invalid environment classification.");
    for (const key of ["api_base_url", "health_url"]) {
      if (env[key] !== undefined && env[key] !== null) {
        if (typeof env[key] !== "string") throw new TypeError(`Invalid ${key}.`);
        const parsed = new URL(env[key] as string);
        if (parsed.protocol !== "https:") throw new TypeError(`${key} must use HTTPS.`);
      }
    }
    if (env.health_url && env.api_base_url && new URL(env.health_url as string).origin !== new URL(env.api_base_url as string).origin) {
      throw new TypeError("Health URL must use the registered API origin.");
    }
    if (env.enabled !== undefined && typeof env.enabled !== "boolean") throw new TypeError("Invalid environment enabled flag.");
  }
  if (!Array.isArray(body.capabilities) || body.capabilities.length > 100) throw new TypeError("capabilities must be an array.");
  const capabilities = new Set<string>();
  for (const value of body.capabilities) {
    const capability = requireString(value, "capability", 100);
    if (!/^[a-z][a-z0-9-]*(?:\\.[a-z][a-z0-9-]*)+$/.test(capability) || ["*", "admin", "write.all"].includes(capability)) {
      throw new TypeError("Invalid or overly broad capability.");
    }
    if (capabilities.has(capability)) throw new TypeError("Duplicate capability.");
    capabilities.add(capability);
  }
  if (body.integration_secret_refs !== undefined) {
    if (!Array.isArray(body.integration_secret_refs) || body.integration_secret_refs.length > 50) throw new TypeError("Invalid secret reference list.");
    for (const ref of body.integration_secret_refs) {
      if (typeof ref !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9/_:.-]{2,180}$/.test(ref)) {
        throw new TypeError("Secret references must be opaque identifiers, never secret values.");
      }
    }
  }
  if (body.owner !== undefined) {
    if (!body.owner || typeof body.owner !== "object" || Array.isArray(body.owner)) throw new TypeError("Invalid owner.");
    const owner = body.owner as JsonObject;
    assertOnlyKeys(owner, ["team", "contact_ref"], "owner");
    requireString(owner.team, "owner.team", 100);
    if (owner.contact_ref !== undefined && (typeof owner.contact_ref !== "string" || owner.contact_ref.length > 160)) {
      throw new TypeError("Invalid owner contact reference.");
    }
  }
  if (body.health_check !== undefined) {
    if (!body.health_check || typeof body.health_check !== "object" || Array.isArray(body.health_check)) throw new TypeError("Invalid health check.");
    const health = body.health_check as JsonObject;
    assertOnlyKeys(health, ["kind", "path", "timeout_seconds", "expected_status"], "health check");
    if (!["http", "none"].includes(String(health.kind))) throw new TypeError("Invalid health check kind.");
    if (health.kind === "http" && (typeof health.path !== "string" || !health.path.startsWith("/"))) throw new TypeError("HTTP health check requires an absolute path.");
    if (health.timeout_seconds !== undefined && (!Number.isInteger(health.timeout_seconds) || Number(health.timeout_seconds) < 1 || Number(health.timeout_seconds) > 30)) throw new TypeError("Invalid health check timeout.");
    if (health.expected_status !== undefined && (!Array.isArray(health.expected_status) || health.expected_status.length === 0 || health.expected_status.some((n) => !Number.isInteger(n) || Number(n) < 100 || Number(n) > 599))) throw new TypeError("Invalid health check status list.");
  }
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

  // Supreme authorization is owned by supreme.identities. Supabase Auth
  // supplies credentials only; Neweix Account and staff_profiles are not used.
  const [principal] = await db`
    select user_id::text
    from supreme.identities
    where user_id = ${user.id}::uuid
      and role = 'ruler'
      and is_active = true
      and public_id = 'supreme'
    limit 2
  `;
  const [count] = await db`
    select count(*)::integer as active_count
    from supreme.identities
    where role = 'ruler'
      and is_active = true
      and public_id = 'supreme'
  `;
  if (!principal || principal.user_id !== user.id || count?.active_count !== 1) {
    throw new Response("Forbidden", { status: 403 });
  }
  const claims = decodeClaimsAfterSupabaseUserVerification(token);
  if (claims.sub !== user.id) {
    throw new Response("Unauthorized", { status: 401 });
  }
  if (claims.aal !== "aal2") {
    throw new Response("Supreme AAL2 authentication is required.", { status: 403 });
  }
  if (!hasVerifiedSupremeAppSession(claims)) {
    throw new Response("Supreme app attestation is required.", { status: 403 });
  }

  // The JWT session_id is the Supabase Auth session. The signed custom claim's
  // session_id is the separate supreme.app_sessions row ID. Bind both to the
  // same active device row on every API request so revocation is immediate.
  const binding = claims.supreme_app_session as JsonObject;
  const authSessionId = claims.session_id;
  const appSessionId = binding.session_id;
  const deviceId = binding.device_id;
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (
    typeof authSessionId !== "string" || !uuid.test(authSessionId) ||
    typeof appSessionId !== "string" || !uuid.test(appSessionId) ||
    typeof deviceId !== "string" || !uuid.test(deviceId)
  ) {
    throw new Response("Supreme device session is invalid.", { status: 403 });
  }
  const [activeSession] = await db`
    select s.id::text as session_id, s.device_id::text as device_id
    from supreme.app_sessions s
    join supreme.devices d on d.id = s.device_id
    where s.id = ${appSessionId}::uuid
      and s.auth_session_id = ${authSessionId}::uuid
      and s.user_id = ${user.id}::uuid
      and s.status = 'active'
      and s.expires_at > now()
      and d.id = ${deviceId}::uuid
      and d.user_id = ${user.id}::uuid
      and d.status = 'active'
      and d.app_package = 'com.neweix.supreme'
      and d.security_level in ('trusted_environment', 'strongbox')
      and d.attested_at > now() - interval '30 days'
      and d.attested_at <= now()
    limit 1
  `;
  if (!activeSession || activeSession.session_id !== appSessionId || activeSession.device_id !== deviceId) {
    throw new Response("Supreme device session is revoked or expired.", { status: 403 });
  }
  await db`
    update supreme.devices
    set last_seen_at = now(), updated_at = now()
    where id = ${deviceId}::uuid and status = 'active'
  `;
  return { userId: user.id, claims };
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
       ${input.outcome}, 'v1', ${db.json(JSON.parse(JSON.stringify(input.details ?? {})))})
  `;
}

async function serviceRows(cursor: string | null, limit: number, onlyId?: string) {
  if (!db) throw new Error("Database is unavailable.");
  return await db`
    select
      s.service_id, s.display_name, s.description,
      case when s.repository_provider is null then null else jsonb_build_object(
        'provider', s.repository_provider,
        'full_name', s.repository_full_name,
        'default_branch', s.repository_default_branch,
        'url', s.repository_url
      ) end as repository,
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
       ${db.json(JSON.parse(JSON.stringify(parameters)))}, ${actor}::uuid, ${idempotencyKey}, 'v1', true)
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
    select id::text, status, created_at,
      (
        request_type = ${requestType}
        and action = ${action}
        and service_id is not distinct from ${targetServiceId}
        and environment_id is not distinct from ${environmentId}
        and normalized_parameters = ${db.json(JSON.parse(JSON.stringify(parameters)))}
      ) as same_request
    from supreme.control_requests
    where requester_user_id = ${actor}::uuid and idempotency_key = ${idempotencyKey}
    limit 1
  `;
  if (!existing) throw new Error("Idempotency lookup failed.");
  if (!existing.same_request) throw new TypeError("IDEMPOTENCY_KEY_REUSED");
  return { id: existing.id, status: existing.status, created_at: existing.created_at, duplicate: true };
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
      validateServicePayload(body);
      const id = serviceId(requireString(body.service_id, "service_id", 64));
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
      ` as unknown as Array<{ classification: string }>;
      const highImpact = hasProductionImpact(body) ||
        current.risk_tier === "high" || current.risk_tier === "critical" ||
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


    if (request.method === "GET" && parts.length === 2 && parts[0] === "v1" && parts[1] === "control-requests") {
      const requestedStatus = url.searchParams.get("status") ?? "pending";
      const allowedStatuses = ["pending", "approved", "rejected", "cancelled", "expired", "executed", "failed"];
      if (requestedStatus !== "all" && !allowedStatuses.includes(requestedStatus)) {
        throw new TypeError("Invalid control request status.");
      }
      const limitRaw = Number(url.searchParams.get("limit") ?? "50");
      const limit = Number.isInteger(limitRaw) ? Math.min(Math.max(limitRaw, 1), 100) : 50;
      const rows = await db`
        select id::text, request_type, service_id, environment_id, action,
               normalized_parameters, requester_user_id::text, status,
               approval_required, approved_by::text, approved_at,
               expires_at, created_at, updated_at
        from supreme.control_requests
        where (${requestedStatus} = 'all' or status = ${requestedStatus})
        order by created_at desc, id desc
        limit ${limit}
      `;
      await audit({ actor: userId, action: "control_requests.list", outcome: "success", requestId,
        details: { status: requestedStatus, count: rows.length } });
      return json({ control_requests: rows, request_id: requestId }, 200, requestId, cors);
    }

    if (request.method === "POST" && parts.length === 4 &&
        parts[0] === "v1" && parts[1] === "control-requests" && parts[3] === "decision-challenge") {
      if (!isFreshAal2(claims)) {
        return errorResponse("MFA_REQUIRED", "Fresh MFA (AAL2) is required to request a decision challenge.", 403, requestId);
      }
      const id = parts[2];
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
        throw new TypeError("Invalid control request ID.");
      }
      const body = await readJson(request, 8 * 1024);
      assertOnlyKeys(body, ["decision", "reason"], "decision challenge");
      const decision = requireString(body.decision, "decision", 16);
      if (decision !== "approve" && decision !== "reject") throw new TypeError("Decision must be approve or reject.");
      const reason = body.reason === undefined ? null : requireString(body.reason, "reason", 500);
      if (decision === "reject" && (!reason || reason.length < 8)) {
        throw new TypeError("A rejection reason of at least 8 characters is required.");
      }
      const binding = claims.supreme_app_session as JsonObject;
      const deviceId = requireString(binding.device_id, "device_id", 36);
      const [pending] = await db`
        select id::text from supreme.control_requests
        where id = ${id}::uuid and status = 'pending' and approval_required = true and expires_at > now()
        limit 1
      `;
      if (!pending) return errorResponse("CONTROL_REQUEST_NOT_PENDING", "Only pending control requests can be decided.", 409, requestId);
      const [device] = await db`
        select device_public_key_spki from supreme.devices
        where id = ${deviceId}::uuid and status = 'active' and device_public_key_spki is not null
        limit 1
      `;
      if (!device?.device_public_key_spki) {
        return errorResponse("DEVICE_SIGNING_KEY_UNAVAILABLE", "This device must be re-registered before signing decisions.", 403, requestId);
      }
      const nonce = crypto.getRandomValues(new Uint8Array(32));
      const nonceHash = await sha256Bytes(nonce);
      const reasonHash = await sha256Bytes(new TextEncoder().encode(reason ?? ""));
      const challengeExpiresAt = new Date(Date.now() + 90_000).toISOString();
      const [challenge] = await db`
        insert into supreme.control_decision_challenges
          (control_request_id, user_id, device_id, decision, reason_sha256, nonce_sha256, expires_at)
        values
          (${id}::uuid, ${userId}::uuid, ${deviceId}::uuid, ${decision},
           decode(${hex(reasonHash)}, 'hex'), decode(${hex(nonceHash)}, 'hex'), ${challengeExpiresAt})
        returning id::text
      `;
      await audit({ actor: userId, action: "control_requests.decision_challenge", outcome: "pending",
        requestId, details: { control_request_id: id, decision, challenge_id: challenge.id } });
      return json({
        challenge_id: challenge.id,
        nonce: base64Url(nonce),
        expires_at: challengeExpiresAt,
        request_id: requestId,
      }, 200, requestId, cors);
    }

    if (request.method === "POST" && parts.length === 4 &&
        parts[0] === "v1" && parts[1] === "control-requests" && parts[3] === "decision") {
      if (!isFreshAal2(claims)) {
        await audit({ actor: userId, action: "control_requests.decision.denied", outcome: "denied",
          requestId, details: { reason: "fresh_aal2_required", control_request_id: parts[2] } });
        return errorResponse("MFA_REQUIRED", "Fresh MFA (AAL2) is required to approve or reject a request.", 403, requestId);
      }
      const id = parts[2];
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
        throw new TypeError("Invalid control request ID.");
      }
      const body = await readJson(request, 8 * 1024);
      assertOnlyKeys(body, ["decision", "reason", "challenge_id", "nonce", "signature"], "decision");
      const decision = requireString(body.decision, "decision", 16);
      if (decision !== "approve" && decision !== "reject") throw new TypeError("Decision must be approve or reject.");
      const reason = body.reason === undefined ? null : requireString(body.reason, "reason", 500);
      if (decision === "reject" && (!reason || reason.length < 8)) {
        throw new TypeError("A rejection reason of at least 8 characters is required.");
      }
      const challengeId = requireString(body.challenge_id, "challenge_id", 36);
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(challengeId)) {
        throw new TypeError("Invalid decision challenge ID.");
      }
      const nonce = decodeCanonicalBase64(body.nonce, 32);
      if (nonce.length !== 32) throw new TypeError("Invalid decision nonce.");
      const signatureDer = decodeCanonicalBase64(body.signature, 80);
      const binding = claims.supreme_app_session as JsonObject;
      const deviceId = requireString(binding.device_id, "device_id", 36);
      const reasonHash = await sha256Bytes(new TextEncoder().encode(reason ?? ""));
      const nonceHash = await sha256Bytes(nonce);
      const [challenge] = await db`
        select id::text, nonce_sha256, reason_sha256
        from supreme.control_decision_challenges
        where id = ${challengeId}::uuid
          and control_request_id = ${id}::uuid
          and user_id = ${userId}::uuid
          and device_id = ${deviceId}::uuid
          and decision = ${decision}
          and expires_at > now()
          and consumed_at is null
        limit 1
      `;
      if (!challenge || hex(new Uint8Array(challenge.nonce_sha256)) !== hex(nonceHash) ||
          hex(new Uint8Array(challenge.reason_sha256)) !== hex(reasonHash)) {
        return errorResponse("DECISION_CHALLENGE_INVALID", "The decision challenge is invalid, expired, or already used.", 409, requestId);
      }
      const [deviceKey] = await db`
        select device_public_key_spki from supreme.devices
        where id = ${deviceId}::uuid and user_id = ${userId}::uuid and status = 'active'
        limit 1
      `;
      if (!deviceKey?.device_public_key_spki) {
        return errorResponse("DEVICE_SIGNING_KEY_UNAVAILABLE", "The registered device signing key is unavailable.", 403, requestId);
      }
      const spki = new Uint8Array(deviceKey.device_public_key_spki);
      const signatureValid = await verifyControlDecisionSignature({
        spki, signatureDer, challengeId, nonce, requestId: id, decision, reasonHash,
      });
      if (!signatureValid) {
        await audit({ actor: userId, action: "control_requests.decision.denied", outcome: "denied",
          requestId, details: { reason: "invalid_device_signature", control_request_id: id } });
        return errorResponse("DEVICE_SIGNATURE_INVALID", "The device signature could not be verified.", 403, requestId);
      }
      const [consumed] = await db`
        update supreme.control_decision_challenges
        set consumed_at = now()
        where id = ${challengeId}::uuid and nonce_sha256 = ${nonceHash}
          and consumed_at is null and expires_at > now()
        returning id::text
      `;
      if (!consumed) {
        return errorResponse("DECISION_CHALLENGE_REPLAYED", "The decision challenge has already been used.", 409, requestId);
      }
      const nextStatus = decision === "approve" ? "approved" : "rejected";
      const [changed] = await db`
        update supreme.control_requests
        set status = ${nextStatus},
            approved_by = case when ${decision} = 'approve' then ${userId}::uuid else null end,
            approved_at = case when ${decision} = 'approve' then now() else null end,
            updated_at = now()
        where id = ${id}::uuid
          and status = 'pending'
          and approval_required = true
          and expires_at > now()
        returning id::text, request_type, service_id, environment_id, action,
                  status, approved_by::text, approved_at, expires_at, updated_at
      `;
      if (!changed) {
        const [existing] = await db`
          select id::text, status, requester_user_id::text, expires_at
          from supreme.control_requests where id = ${id}::uuid limit 1
        `;
        if (!existing) return errorResponse("CONTROL_REQUEST_NOT_FOUND", "Control request not found.", 404, requestId);
        if (new Date(existing.expires_at).getTime() <= Date.now() && existing.status === "pending") {
          await db`update supreme.control_requests set status = 'expired', updated_at = now()
            where id = ${id}::uuid and status = 'pending' and expires_at <= now()`;
          await audit({ actor: userId, action: "control_requests.expire", outcome: "success",
            requestId, details: { control_request_id: id } });
          return errorResponse("CONTROL_REQUEST_EXPIRED", "The control request has expired.", 410, requestId);
        }
        if (existing.status === nextStatus && existing.requester_user_id === userId) {
          return json({ control_request: { id, status: nextStatus, duplicate: true }, request_id: requestId }, 200, requestId, cors);
        }
        return errorResponse("CONTROL_REQUEST_NOT_PENDING", "Only pending control requests can be decided.", 409, requestId);
      }
      await audit({
        actor: userId,
        action: decision === "approve" ? "control_requests.approve" : "control_requests.reject",
        serviceId: changed.service_id,
        environmentId: changed.environment_id,
        outcome: "success",
        requestId,
        details: { control_request_id: id, decision, reason, approved_at: changed.approved_at },
      });
      return json({ control_request: { ...changed, decision, duplicate: false }, request_id: requestId }, 200, requestId, cors);
    }

    if (request.method === "GET" && parts.length === 4 && parts[0] === "v1" && parts[1] === "services" && parts[3] === "health") {
      const id = serviceId(parts[2]);
      const environmentId = requireString(url.searchParams.get("environment_id"), "environment_id", 32);
      const [target] = await db`
        select e.health_url, e.api_base_url, e.enabled, s.health_check_kind,
               s.health_check_path, s.health_check_timeout_seconds, s.health_check_expected_status
        from supreme.service_environments e
        join supreme.services s on s.service_id = e.service_id
        where e.service_id = ${id} and e.environment_id = ${environmentId}
        limit 1
      `;
      if (!target || !target.enabled) return errorResponse("ENVIRONMENT_DISABLED", "Environment is not available.", 404, requestId);
      if (target.health_check_kind !== "http" || !target.api_base_url || (!target.health_url && !target.health_check_path)) {
        return errorResponse("HEALTH_CHECK_NOT_CONFIGURED", "Health check is not configured.", 409, requestId);
      }
      const apiUrl = new URL(target.api_base_url);
      const healthUrl = target.health_url
        ? new URL(target.health_url)
        : new URL(target.health_check_path, apiUrl);
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
      if (error.message === "IDEMPOTENCY_KEY_REUSED") {
        return errorResponse("IDEMPOTENCY_KEY_REUSED", "The idempotency key was already used for a different request.", 409, requestId);
      }
      return errorResponse("INVALID_REQUEST", error.message, 400, requestId);
    }
    console.error("Supreme registry request failed", { requestId, error: String(error) });
    return errorResponse("INTERNAL_ERROR", "The registry request could not be completed.", 500, requestId);
  }
}

Deno.serve(handle);
