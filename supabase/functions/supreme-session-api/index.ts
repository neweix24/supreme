import postgres from "npm:postgres@3.4.7";

const SUPABASE_URL = (Deno.env.get("SUPABASE_URL") ?? "").replace(/\/$/, "");
const SUPABASE_ANON_KEY =
  Deno.env.get("SUPABASE_ANON_KEY") ??
  Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ??
  "";
const DATABASE_URL = Deno.env.get("SUPABASE_DB_URL") ?? "";
const db = DATABASE_URL
  ? postgres(DATABASE_URL, { max: 2, prepare: false, ssl: "require" })
  : null;

type Claims = Record<string, unknown>;

function response(body: unknown, status = 200, requestId = crypto.randomUUID()): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "private, no-store, max-age=0",
      pragma: "no-cache",
      "x-content-type-options": "nosniff",
      "x-request-id": requestId,
    },
  });
}

function bearer(request: Request): string | null {
  const value = request.headers.get("authorization") ?? "";
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(value);
  return match?.[1] ?? null;
}

function decodeVerifiedClaims(token: string): Claims {
  const part = token.split(".")[1];
  if (!part) throw new Error("Invalid access token.");
  const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  const claims: unknown = JSON.parse(decoded);
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) {
    throw new Error("Invalid access token claims.");
  }
  return claims as Claims;
}

function isUuid(value: unknown): value is string {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

async function authenticate(request: Request): Promise<{
  userId: string;
  authSessionId: string;
  claims: Claims;
} | null> {
  const token = bearer(request);
  if (!token || !SUPABASE_URL || !SUPABASE_ANON_KEY) return null;

  // Ask Auth to validate the bearer token. Decoding alone is never authentication.
  const userResponse = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
    method: "GET",
    headers: {
      apikey: SUPABASE_ANON_KEY,
      authorization: `Bearer ${token}`,
      accept: "application/json",
    },
    redirect: "error",
    signal: AbortSignal.timeout(8_000),
  });
  if (!userResponse.ok) {
    await userResponse.body?.cancel();
    return null;
  }

  const user: unknown = await userResponse.json();
  if (!user || typeof user !== "object" || Array.isArray(user) ||
      !isUuid((user as Record<string, unknown>).id)) return null;

  const claims = decodeVerifiedClaims(token);
  const userId = (user as Record<string, unknown>).id as string;
  const authSessionId = claims.session_id;
  if (claims.sub !== userId || !isUuid(authSessionId)) return null;
  return { userId, authSessionId, claims };
}

async function handle(request: Request): Promise<Response> {
  const requestId = crypto.randomUUID();
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-methods": "GET, DELETE, OPTIONS",
        "access-control-allow-headers": "authorization, apikey, content-type",
        "access-control-max-age": "600",
        "cache-control": "no-store",
      },
    });
  }
  if (request.method !== "GET" && request.method !== "DELETE") {
    return response({ error: { code: "METHOD_NOT_ALLOWED", request_id: requestId } }, 405, requestId);
  }
  if (!db || !SUPABASE_URL || !SUPABASE_ANON_KEY) {
    return response({ error: { code: "SERVICE_NOT_CONFIGURED", request_id: requestId } }, 503, requestId);
  }

  try {
    const auth = await authenticate(request);
    if (!auth) {
      return response({ error: { code: "UNAUTHENTICATED", request_id: requestId } }, 401, requestId);
    }

    if (auth.claims.aal !== "aal2") {
      return response({ error: { code: "MFA_REQUIRED", request_id: requestId } }, 403, requestId);
    }
    const signedSession = auth.claims.supreme_app_session;
    if (!signedSession || typeof signedSession !== "object" ||
        (signedSession as Record<string, unknown>).status !== "active") {
      return response({ error: { code: "DEVICE_SESSION_CLAIM_REQUIRED", request_id: requestId } }, 403, requestId);
    }

    const [identity] = await db`
      select id::text
      from supreme.identities
      where user_id = ${auth.userId}::uuid
        and public_id = 'supreme'
        and role = 'ruler'
        and is_active = true
      limit 1
    `;
    if (!identity) {
      return response({ error: { code: "SUPREME_IDENTITY_REQUIRED", request_id: requestId } }, 403, requestId);
    }

    const [session] = await db`
      select
        s.id::text as session_id,
        s.device_id::text as device_id,
        s.status,
        s.attested_at,
        s.expires_at,
        d.security_level,
        d.status as device_status,
        d.last_seen_at
      from supreme.app_sessions s
      join supreme.devices d on d.id = s.device_id
      where s.user_id = ${auth.userId}::uuid
        and s.auth_session_id = ${auth.authSessionId}::uuid
        and d.user_id = ${auth.userId}::uuid
      limit 1
    `;

    if (request.method === "GET") {
      const active = Boolean(
        session &&
        session.status === "active" &&
        session.device_status === "active" &&
        (signedSession as Record<string, unknown>).session_id === session.session_id &&
        (signedSession as Record<string, unknown>).device_id === session.device_id &&
        new Date(session.expires_at).getTime() > Date.now(),
      );
      if (active) {
        await db`
          update supreme.devices
          set last_seen_at = now(), updated_at = now()
          where id = ${session.device_id}::uuid and status = 'active'
        `;
      }
      return response({
        authenticated: true,
        device_session_active: active,
        session: active ? {
          session_id: session.session_id,
          device_id: session.device_id,
          security_level: session.security_level,
          attested_at: session.attested_at,
          expires_at: session.expires_at,
        } : null,
        request_id: requestId,
      }, 200, requestId);
    }

    if (!session || session.status !== "active") {
      return response({ error: { code: "SESSION_NOT_ACTIVE", request_id: requestId } }, 409, requestId);
    }

    const [revoked] = await db`
      update supreme.app_sessions
      set status = 'revoked', revoked_at = now(), updated_at = now()
      where id = ${session.session_id}::uuid and status = 'active'
      returning id::text
    `;
    if (!revoked) {
      return response({ error: { code: "SESSION_ALREADY_REVOKED", request_id: requestId } }, 409, requestId);
    }

    await db`
      insert into supreme.audit_events (
        actor_user_id, action, outcome, policy_version, details
      ) values (
        ${auth.userId}::uuid,
        'device_session.revoke_self',
        'success',
        'v1',
        jsonb_build_object(
          'session_id', ${session.session_id},
          'device_id', ${session.device_id},
          'request_id', ${requestId}
        )
      )
    `;

    return response({ revoked: true, request_id: requestId }, 200, requestId);
  } catch (error) {
    console.error("Supreme session API failed", { requestId, error: String(error) });
    return response({ error: { code: "INTERNAL_ERROR", request_id: requestId } }, 500, requestId);
  }
}

Deno.serve(handle);
