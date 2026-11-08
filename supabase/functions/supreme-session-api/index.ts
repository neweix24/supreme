import postgres from "npm:postgres@3.4.7";

const SUPABASE_URL = (Deno.env.get("SUPABASE_URL") ?? "").replace(/\/$/, "");
const SUPABASE_ANON_KEY =
  Deno.env.get("SUPABASE_ANON_KEY") ??
  Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ??
  "";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const DATABASE_URL = Deno.env.get("SUPABASE_DB_URL") ?? "";
const SIGNING_CERT_SHA256 = (Deno.env.get("SUPREME_ANDROID_SIGNING_CERT_SHA256") ?? "").toLowerCase();
const db = DATABASE_URL
  ? postgres(DATABASE_URL, { max: 2, prepare: false, ssl: "require" })
  : null;

type Claims = Record<string, unknown>;
type AuthContext = { userId: string; authSessionId: string; claims: Claims };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[a-f0-9]{64}$/;

function response(body: unknown, status = 200, requestId: string = crypto.randomUUID()): Response {
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

function decodeClaimsAfterSupabaseUserVerification(token: string): Claims {
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
  return typeof value === "string" && UUID.test(value);
}

function isFreshAal2(claims: Claims): boolean {
  if (claims.aal !== "aal2") return false;
  const authTime = typeof claims.auth_time === "number" ? claims.auth_time : 0;
  const now = Date.now() / 1000;
  if (!authTime || now - authTime > 300 || authTime > now + 30) return false;

  // Supreme currently permits password + authenticator TOTP only.
  // AAL2 alone is not sufficient if the AMR does not prove TOTP.
  const amr = Array.isArray(claims.amr) ? claims.amr : [];
  return amr.some((entry) =>
    entry !== null &&
    typeof entry === "object" &&
    (entry as Record<string, unknown>).method === "totp"
  );
}

async function authenticate(request: Request): Promise<AuthContext | null> {
  const token = bearer(request);
  if (!token || !SUPABASE_URL || !SUPABASE_ANON_KEY) return null;

  const userResponse = await fetch(SUPABASE_URL + "/auth/v1/user", {
    method: "GET",
    headers: {
      apikey: SUPABASE_ANON_KEY,
      authorization: "Bearer " + token,
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

  const claims = decodeClaimsAfterSupabaseUserVerification(token);
  const userId = (user as Record<string, unknown>).id as string;
  const authSessionId = claims.session_id;
  if (claims.sub !== userId || !isUuid(authSessionId)) return null;
  return { userId, authSessionId, claims };
}

async function assertSupremeIdentity(userId: string): Promise<boolean> {
  if (!db) return false;
  const principals = await db.unsafe(
    "select user_id::text from supreme.identities where user_id = $1::uuid and public_id = 'supreme' and role = 'ruler' and is_active = true limit 2",
    [userId],
  );
  const counts = await db.unsafe(
    "select count(*)::integer as active_count from supreme.identities where public_id = 'supreme' and role = 'ruler' and is_active = true",
  );
  return principals.length === 1 &&
    principals[0].user_id === userId &&
    Number(counts[0]?.active_count) === 1;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new TypeError("Invalid challenge encoding.");
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = Uint8Array.from(atob(base64 + "="), (c) => c.charCodeAt(0));
  if (decoded.length !== 32 || base64Url(decoded) !== value) {
    throw new TypeError("Challenge encoding is not canonical.");
  }
  return decoded;
}

async function sha256Hex(value: Uint8Array): Promise<string> {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", copy.buffer));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sessionBindingHash(auth: AuthContext): Promise<string> {
  // The legacy requester_ip_hash column is used as a non-reversible per-session
  // rate-limit binding. The endpoint does not trust client-supplied IP headers.
  return await sha256Hex(new TextEncoder().encode(auth.userId + ":" + auth.authSessionId));
}

async function postServiceRpc(name: string, payload: Record<string, unknown>): Promise<unknown> {
  if (!SUPABASE_URL || !SERVICE_ROLE_KEY) throw new Error("Supreme service credentials are unavailable.");
  const result = await fetch(SUPABASE_URL + "/rest/v1/rpc/" + name, {
    method: "POST",
    headers: {
      apikey: SERVICE_ROLE_KEY,
      authorization: "Bearer " + SERVICE_ROLE_KEY,
      "content-type": "application/json",
      accept: "application/json",
    },
    body: JSON.stringify(payload),
    redirect: "error",
    signal: AbortSignal.timeout(8_000),
  });
  const text = await result.text();
  if (!result.ok) throw new Error("Supreme database operation failed (" + result.status + ").");
  try {
    return JSON.parse(text);
  } catch {
    throw new Error("Supreme database returned an invalid response.");
  }
}

async function boundedJson(request: Request, limit = 96 * 1024): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) throw new TypeError("Expected JSON.");
  const declared = request.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > limit)) {
    throw new RangeError("Request too large.");
  }
  const reader = request.body?.getReader();
  if (!reader) throw new TypeError("Missing request body.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel();
        throw new RangeError("Request too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  const value: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("Invalid JSON object.");
  return value as Record<string, unknown>;
}

async function issueChallenge(auth: AuthContext, requestId: string): Promise<Response> {
  if (!db || !SERVICE_ROLE_KEY) {
    return response({ error: { code: "SERVICE_NOT_CONFIGURED", request_id: requestId } }, 503, requestId);
  }
  if (!isFreshAal2(auth.claims) || !(await assertSupremeIdentity(auth.userId))) {
    return response({ error: { code: "SUPREME_AAL2_REQUIRED", request_id: requestId } }, 403, requestId);
  }

  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const challengeHash = await sha256Hex(nonce);
  const bindingHash = await sessionBindingHash(auth);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  const challengeId = await postServiceRpc("issue_supreme_app_attestation_challenge", {
    p_challenge_hash: challengeHash,
    p_requester_ip_hash: bindingHash,
    p_expires_at: expiresAt,
  });

  if (typeof challengeId !== "string" || !UUID_V4.test(challengeId)) {
    return response({ error: { code: "RATE_LIMITED", request_id: requestId } }, 429, requestId);
  }
  return response({
    success: true,
    challenge_id: challengeId,
    challenge: base64Url(nonce),
    expires_at: expiresAt,
    request_id: requestId,
  }, 200, requestId);
}

async function issueDeviceSession(
  auth: AuthContext,
  request: Request,
  requestId: string,
): Promise<Response> {
  if (!db || !SERVICE_ROLE_KEY || !SUPABASE_URL) {
    return response({ error: { code: "SERVICE_NOT_CONFIGURED", request_id: requestId } }, 503, requestId);
  }
  if (!isFreshAal2(auth.claims) || !(await assertSupremeIdentity(auth.userId))) {
    return response({ error: { code: "SUPREME_AAL2_REQUIRED", request_id: requestId } }, 403, requestId);
  }
  if (!SHA256.test(SIGNING_CERT_SHA256)) {
    return response({ error: { code: "PRODUCTION_SIGNER_NOT_CONFIGURED", request_id: requestId } }, 503, requestId);
  }

  let payload: Record<string, unknown>;
  try {
    payload = await boundedJson(request);
  } catch (error) {
    return response({
      error: {
        code: error instanceof RangeError ? "REQUEST_TOO_LARGE" : "INVALID_REQUEST",
        request_id: requestId,
      },
    }, error instanceof RangeError ? 413 : 400, requestId);
  }

  const allowedKeys = new Set(["challenge_id", "challenge", "certificate_chain", "proof_signature"]);
  if (Object.keys(payload).length !== 4 ||
      Object.keys(payload).some((key) => !allowedKeys.has(key)) ||
      typeof payload.challenge_id !== "string" || !UUID_V4.test(payload.challenge_id) ||
      typeof payload.challenge !== "string" ||
      !Array.isArray(payload.certificate_chain) ||
      payload.certificate_chain.length < 3 ||
      payload.certificate_chain.length > 10 ||
      !payload.certificate_chain.every((item) => typeof item === "string" && item.length <= 24_000) ||
      typeof payload.proof_signature !== "string" || payload.proof_signature.length > 512) {
    return response({ error: { code: "INVALID_ATTESTATION_PAYLOAD", request_id: requestId } }, 400, requestId);
  }

  let challenge: Uint8Array;
  try {
    challenge = decodeBase64Url(payload.challenge);
  } catch {
    return response({ error: { code: "INVALID_CHALLENGE", request_id: requestId } }, 400, requestId);
  }

  const challengeHash = await sha256Hex(challenge);
  const bindingHash = await sessionBindingHash(auth);
  let verifierResponse: Response;
  try {
    verifierResponse = await fetch(SUPABASE_URL + "/functions/v1/supreme-attestation-verify", {
      method: "POST",
      headers: {
        authorization: "Bearer " + SERVICE_ROLE_KEY,
        apikey: SERVICE_ROLE_KEY,
        "content-type": "application/json",
        "x-neweix-attestation-ip-hash": bindingHash,
      },
      body: JSON.stringify({
        challenge_id: payload.challenge_id,
        challenge: payload.challenge,
        certificate_chain: payload.certificate_chain,
        proof_signature: payload.proof_signature,
      }),
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    return response({ error: { code: "ATTESTATION_SERVICE_UNAVAILABLE", request_id: requestId } }, 503, requestId);
  }

  const verifierText = await verifierResponse.text();
  if (verifierText.length > 8_192) {
    return response({ error: { code: "INVALID_VERIFIER_RESPONSE", request_id: requestId } }, 502, requestId);
  }
  let verified: Record<string, unknown>;
  try {
    const value: unknown = JSON.parse(verifierText);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid verifier JSON.");
    verified = value as Record<string, unknown>;
  } catch {
    return response({ error: { code: "INVALID_VERIFIER_RESPONSE", request_id: requestId } }, 502, requestId);
  }

  if (!verifierResponse.ok || verified.verified !== true ||
      verified.proof_of_possession_verified !== true ||
      typeof verified.device_key_sha256 !== "string" || !SHA256.test(verified.device_key_sha256) ||
      typeof verified.device_public_key_spki_base64 !== "string" ||
      verified.device_public_key_spki_base64.length > 1024 ||
      !["trusted_environment", "strongbox"].includes(String(verified.security_level))) {
    return response({
      error: { code: verifierResponse.status >= 500 ? "ATTESTATION_SERVICE_UNAVAILABLE" : "ATTESTATION_REJECTED", request_id: requestId },
    }, verifierResponse.status >= 500 ? 503 : 403, requestId);
  }

  const now = new Date();
  const expiresAt = new Date(now.getTime() + 4 * 60 * 60 * 1000).toISOString();
  const registered = await postServiceRpc("register_supreme_attested_device_session", {
    p_user_id: auth.userId,
    p_auth_session_id: auth.authSessionId,
    p_device_key_sha256: verified.device_key_sha256,
    p_signing_certificate_sha256: SIGNING_CERT_SHA256,
    p_security_level: verified.security_level,
    p_attested_at: now.toISOString(),
    p_expires_at: expiresAt,
  });

  if (!registered || typeof registered !== "object" ||
      (registered as Record<string, unknown>).registered !== true) {
    return response({ error: { code: "SESSION_REGISTRATION_FAILED", request_id: requestId } }, 503, requestId);
  }
  const value = registered as Record<string, unknown>;
  const deviceId = value.device_id;
  const publicKeyBase64 = verified.device_public_key_spki_base64 as string;
  let publicKeyDer: Uint8Array;
  try {
    if (!isUuid(deviceId)) throw new TypeError("Invalid registered device ID.");
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(publicKeyBase64)) {
      throw new TypeError("Invalid public key encoding.");
    }
    const binary = atob(publicKeyBase64);
    publicKeyDer = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    if (publicKeyDer.length < 64 || publicKeyDer.length > 256 || btoa(binary) !== publicKeyBase64) {
      throw new TypeError("Invalid public key length or encoding.");
    }
  } catch {
    return response({ error: { code: "INVALID_ATTESTED_PUBLIC_KEY", request_id: requestId } }, 502, requestId);
  }

  // Persist only the SPKI extracted from the certificate whose chain, Google
  // revocation state, Android KeyDescription and proof-of-possession passed.
  const storedKey = await db.unsafe(
    "update supreme.devices set device_public_key_spki = decode($1, 'base64'), updated_at = now() where id = $2::uuid and user_id = $3::uuid and device_key_sha256 = $4 and status = 'active' returning id::text",
    [publicKeyBase64, deviceId, auth.userId, verified.device_key_sha256],
  );
  if (storedKey.length !== 1) {
    return response({ error: { code: "DEVICE_PUBLIC_KEY_REGISTRATION_FAILED", request_id: requestId } }, 503, requestId);
  }

  return response({
    registered: true,
    session_id: value.session_id,
    device_id: value.device_id,
    expires_at: value.expires_at,
    security_level: verified.security_level,
    provisioning_method: verified.provisioning_method ?? "unknown",
    request_id: requestId,
  }, 200, requestId);
}

async function readOrRevokeSession(
  auth: AuthContext,
  request: Request,
  requestId: string,
): Promise<Response> {
  if (!db) {
    return response({ error: { code: "SERVICE_NOT_CONFIGURED", request_id: requestId } }, 503, requestId);
  }
  if (auth.claims.aal !== "aal2" || !(await assertSupremeIdentity(auth.userId))) {
    return response({ error: { code: "MFA_OR_IDENTITY_REQUIRED", request_id: requestId } }, 403, requestId);
  }
  const signedSession = auth.claims.supreme_app_session;
  if (!signedSession || typeof signedSession !== "object" || Array.isArray(signedSession) ||
      (signedSession as Record<string, unknown>).status !== "active") {
    return response({ error: { code: "DEVICE_SESSION_CLAIM_REQUIRED", request_id: requestId } }, 403, requestId);
  }

  const claim = signedSession as Record<string, unknown>;
  if (!isUuid(claim.session_id) || !isUuid(claim.device_id)) {
    return response({ error: { code: "INVALID_DEVICE_SESSION_CLAIM", request_id: requestId } }, 403, requestId);
  }
  const rows = await db.unsafe(
    "select s.id::text as session_id, s.device_id::text as device_id, s.status, s.attested_at, s.expires_at, d.security_level, d.status as device_status, d.last_seen_at from supreme.app_sessions s join supreme.devices d on d.id = s.device_id where s.id = $1::uuid and s.user_id = $2::uuid and s.auth_session_id = $3::uuid and d.id = $4::uuid and d.user_id = $2::uuid limit 1",
    [claim.session_id, auth.userId, auth.authSessionId, claim.device_id],
  );
  const session = rows[0];

  if (request.method === "GET") {
    const active = Boolean(
      session &&
      session.status === "active" &&
      session.device_status === "active" &&
      claim.session_id === session.session_id &&
      claim.device_id === session.device_id &&
      new Date(session.expires_at).getTime() > Date.now(),
    );
    if (active) {
      await db.unsafe(
        "update supreme.devices set last_seen_at = now(), updated_at = now() where id = $1::uuid and status = 'active'",
        [session.device_id],
      );
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
  const revoked = await db.unsafe(
    "update supreme.app_sessions set status = 'revoked', revoked_at = now(), updated_at = now() where id = $1::uuid and status = 'active' returning id::text",
    [session.session_id],
  );
  if (revoked.length !== 1) {
    return response({ error: { code: "SESSION_ALREADY_REVOKED", request_id: requestId } }, 409, requestId);
  }
  await db.unsafe(
    "insert into supreme.audit_events (actor_user_id, action, outcome, policy_version, details) values ($1::uuid, 'device_session.revoke_self', 'success', 'v1', jsonb_build_object('session_id', $2::uuid, 'device_id', $3::uuid, 'request_id', $4))",
    [auth.userId, session.session_id, session.device_id, requestId],
  );
  return response({ revoked: true, request_id: requestId }, 200, requestId);
}

async function handle(request: Request): Promise<Response> {
  const requestId = crypto.randomUUID();
  const pathname = new URL(request.url).pathname.replace(/\/+$/, "");
  const suffix = pathname.split("/").pop() ?? "";

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-methods": "GET, POST, DELETE, OPTIONS",
        "access-control-allow-headers": "authorization, apikey, content-type",
        "access-control-max-age": "600",
        "cache-control": "no-store",
      },
    });
  }

  const operation = request.method === "POST" ? suffix : "";
  if (request.method !== "GET" && request.method !== "DELETE" &&
      !(request.method === "POST" && (operation === "challenge" || operation === "issue"))) {
    return response({ error: { code: "METHOD_NOT_ALLOWED", request_id: requestId } }, 405, requestId);
  }
  if (!db || !SUPABASE_URL || !SUPABASE_ANON_KEY || !SERVICE_ROLE_KEY) {
    return response({ error: { code: "SERVICE_NOT_CONFIGURED", request_id: requestId } }, 503, requestId);
  }

  try {
    const auth = await authenticate(request);
    if (!auth) {
      return response({ error: { code: "UNAUTHENTICATED", request_id: requestId } }, 401, requestId);
    }
    if (request.method === "POST" && operation === "challenge") {
      return await issueChallenge(auth, requestId);
    }
    if (request.method === "POST" && operation === "issue") {
      return await issueDeviceSession(auth, request, requestId);
    }
    return await readOrRevokeSession(auth, request, requestId);
  } catch (error) {
    console.error("Supreme session API failed", { requestId, error: String(error) });
    return response({ error: { code: "INTERNAL_ERROR", request_id: requestId } }, 500, requestId);
  }
}

Deno.serve(handle);
