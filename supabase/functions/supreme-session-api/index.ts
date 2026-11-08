import postgres from "npm:postgres@3.4.7";

const SUPABASE_URL = (Deno.env.get("SUPABASE_URL") ?? "").replace(/\/$/, "");
const SUPABASE_ANON_KEY =
  Deno.env.get("SUPABASE_ANON_KEY") ??
  Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ??
  "";
const SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const RECOVERY_NOTIFICATION_URL = Deno.env.get("SUPREME_RECOVERY_NOTIFICATION_WEBHOOK_URL") ?? "";
const RECOVERY_NOTIFICATION_SECRET = Deno.env.get("SUPREME_RECOVERY_NOTIFICATION_WEBHOOK_SECRET") ?? "";
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

  const allowedKeys = new Set(["challenge_id", "challenge", "certificate_chain", "proof_signature", "bootstrap_authorization", "recovery_request_id", "recovery_material"]);
  if (Object.keys(payload).length < 4 || Object.keys(payload).length > 7 ||
      Object.keys(payload).some((key) => !allowedKeys.has(key)) ||
      typeof payload.challenge_id !== "string" || !UUID_V4.test(payload.challenge_id) ||
      typeof payload.challenge !== "string" ||
      !Array.isArray(payload.certificate_chain) ||
      payload.certificate_chain.length < 3 ||
      payload.certificate_chain.length > 10 ||
      !payload.certificate_chain.every((item) => typeof item === "string" && item.length <= 24_000) ||
      typeof payload.proof_signature !== "string" || payload.proof_signature.length > 512 ||
      (payload.bootstrap_authorization !== undefined &&
        (typeof payload.bootstrap_authorization !== "string" ||
          !/^[a-f0-9]{64}$/.test(payload.bootstrap_authorization))) ||
      ((payload.recovery_request_id === undefined) !== (payload.recovery_material === undefined)) ||
      (payload.recovery_request_id !== undefined &&
        (typeof payload.recovery_request_id !== "string" || !UUID_V4.test(payload.recovery_request_id) ||
         typeof payload.recovery_material !== "string" || !/^[a-f0-9]{64}$/.test(payload.recovery_material))) ||
      (payload.bootstrap_authorization !== undefined && payload.recovery_request_id !== undefined)) {
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
  const bootstrapTokenHash = typeof payload.bootstrap_authorization === "string"
    ? await sha256Hex(new TextEncoder().encode(payload.bootstrap_authorization))
    : null;
  const recoveryMode = typeof payload.recovery_request_id === "string";
  const recoveryMaterialHash = recoveryMode
    ? await sha256Hex(new TextEncoder().encode(payload.recovery_material as string))
    : null;
  let registered: unknown;
  try {
    registered = recoveryMode
      ? await postServiceRpc("complete_supreme_break_glass_recovery", {
          p_user_id: auth.userId,
          p_auth_session_id: auth.authSessionId,
          p_request_id: payload.recovery_request_id,
          p_token_sha256: recoveryMaterialHash,
          p_device_key_sha256: verified.device_key_sha256,
          p_signing_certificate_sha256: SIGNING_CERT_SHA256,
          p_security_level: verified.security_level,
          p_attested_at: now.toISOString(),
          p_expires_at: expiresAt,
        })
      : await postServiceRpc("register_supreme_attested_device_session", {
          p_user_id: auth.userId,
          p_auth_session_id: auth.authSessionId,
          p_device_key_sha256: verified.device_key_sha256,
          p_signing_certificate_sha256: SIGNING_CERT_SHA256,
          p_security_level: verified.security_level,
          p_attested_at: now.toISOString(),
          p_expires_at: expiresAt,
          p_bootstrap_token_sha256: bootstrapTokenHash,
        });
  } catch {
    if (recoveryMode) {
      await db.unsafe(
        "insert into supreme.audit_events(actor_user_id, action, outcome, policy_version, details) values ($1::uuid, 'recovery.complete', 'denied', 'v1', jsonb_build_object('recovery_request_id', $2::uuid, 'reason', 'recovery_precondition_failed', 'request_id', $3))",
        [auth.userId, payload.recovery_request_id, requestId],
      );
      return response({ error: { code: "RECOVERY_COMPLETION_DENIED", request_id: requestId } }, 409, requestId);
    }
    return response({ error: { code: "SESSION_REGISTRATION_FAILED", request_id: requestId } }, 503, requestId);
  }

  if (!registered || typeof registered !== "object") {
    return response({ error: { code: "SESSION_REGISTRATION_FAILED", request_id: requestId } }, 503, requestId);
  }
  const value = registered as Record<string, unknown>;
  if (value.bootstrap_required === true) {
    return response({
      error: { code: "SUPREME_BOOTSTRAP_AUTHORIZATION_REQUIRED", request_id: requestId },
      bootstrap_required: true,
    }, 409, requestId);
  }
  if (value.registered !== true) {
    return response({ error: { code: "SESSION_REGISTRATION_FAILED", request_id: requestId } }, 503, requestId);
  }
  const deviceId = value.device_id;
  const pendingApproval = value.pending_approval === true;
  if (recoveryMode && value.completed !== true) {
    return response({ error: { code: "RECOVERY_COMPLETION_FAILED", request_id: requestId } }, 409, requestId);
  }
  if (recoveryMode) {
    await dispatchRecoveryNotification(payload.recovery_request_id as string, "completed");
  }
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
    "update supreme.devices set device_public_key_spki = decode($1, 'base64'), device_key_biometric_auth_required = true, updated_at = now() where id = $2::uuid and user_id = $3::uuid and device_key_sha256 = $4 and status in ('active', 'pending_approval') returning id::text",
    [publicKeyBase64, deviceId, auth.userId, verified.device_key_sha256],
  );
  if (storedKey.length !== 1) {
    return response({ error: { code: "DEVICE_PUBLIC_KEY_REGISTRATION_FAILED", request_id: requestId } }, 503, requestId);
  }

  if (pendingApproval) {
    return response({
      registered: true,
      pending_approval: true,
      device_id: value.device_id,
      security_level: verified.security_level,
      provisioning_method: verified.provisioning_method ?? "unknown",
      request_id: requestId,
    }, 200, requestId);
  }

  return response({
    registered: true,
    pending_approval: false,
    session_id: value.session_id,
    device_id: value.device_id,
    expires_at: value.expires_at,
    security_level: verified.security_level,
    provisioning_method: verified.provisioning_method ?? "unknown",
    request_id: requestId,
  }, 200, requestId);
}


function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.length);
  copy.set(value);
  return copy.buffer;
}

function derEcdsaToP1363(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der[0] !== 0x30) throw new TypeError("Invalid ECDSA signature.");
  let offset = 1;
  let length = der[offset++];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count !== 1 || offset >= der.length) throw new TypeError("Invalid ECDSA signature length.");
    length = der[offset++];
  }
  if (length !== der.length - offset || der[offset++] !== 0x02) throw new TypeError("Invalid ECDSA signature sequence.");
  const rLength = der[offset++];
  if (rLength < 1 || offset + rLength >= der.length) throw new TypeError("Invalid ECDSA signature R.");
  const r = der.slice(offset, offset + rLength);
  offset += rLength;
  if (der[offset++] !== 0x02) throw new TypeError("Invalid ECDSA signature S.");
  const sLength = der[offset++];
  if (sLength < 1 || offset + sLength !== der.length) throw new TypeError("Invalid ECDSA signature S.");
  const scalar = (value: Uint8Array) => {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0) start++;
    const trimmed = value.slice(start);
    if (trimmed.length > 32) throw new TypeError("ECDSA scalar is too large.");
    const output = new Uint8Array(32);
    output.set(trimmed, 32 - trimmed.length);
    return output;
  };
  const output = new Uint8Array(64);
  output.set(scalar(r), 0);
  output.set(scalar(der.slice(offset)), 32);
  return output;
}

async function verifyEnrollmentApprovalSignature(
  spki: Uint8Array,
  challengeId: string,
  nonce: Uint8Array,
  requestId: string,
  targetDeviceId: string,
  signatureDer: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "spki", toArrayBuffer(spki), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"],
  );
  const payload = new TextEncoder().encode([
    "NEWEIX-SUPREME-DEVICE-ENROLLMENT-APPROVAL-V1",
    challengeId,
    base64Url(nonce),
    requestId,
    targetDeviceId,
  ].join("\n"));
  return await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    toArrayBuffer(derEcdsaToP1363(signatureDer)),
    toArrayBuffer(payload),
  );
}

async function trustedApprover(
  auth: AuthContext,
  requireFreshAal2: boolean,
): Promise<{ deviceId: string; spki: Uint8Array } | null> {
  if (!db || (requireFreshAal2 && !isFreshAal2(auth.claims)) ||
      !(await assertSupremeIdentity(auth.userId))) return null;
  const binding = auth.claims.supreme_app_session;
  if (!binding || typeof binding !== "object" || Array.isArray(binding)) return null;
  const claim = binding as Record<string, unknown>;
  if (!isUuid(claim.session_id) || !isUuid(claim.device_id)) return null;
  const rows = await db.unsafe(
    "select d.device_public_key_spki from supreme.app_sessions s join supreme.devices d on d.id = s.device_id where s.id = $1::uuid and s.auth_session_id = $2::uuid and s.user_id = $3::uuid and s.device_id = $4::uuid and s.status = 'active' and s.expires_at > now() and d.status = 'active' and d.device_key_biometric_auth_required = true and d.device_public_key_spki is not null limit 1",
    [claim.session_id, auth.authSessionId, auth.userId, claim.device_id],
  );
  if (rows.length !== 1) return null;
  return { deviceId: claim.device_id, spki: new Uint8Array(rows[0].device_public_key_spki) };
}

async function enrollmentRequests(auth: AuthContext, requestId: string): Promise<Response> {
  const approver = await trustedApprover(auth, false);
  if (!approver) return response({ error: { code: "TRUSTED_DEVICE_REQUIRED", request_id: requestId } }, 403, requestId);
  const rows = await db!.unsafe(
    "select r.id::text as request_id, r.device_id::text as device_id, d.security_level, r.requested_at, r.expires_at from supreme.device_enrollment_requests r join supreme.devices d on d.id = r.device_id where r.user_id = $1::uuid and r.status = 'pending' and r.expires_at > now() and d.status = 'pending_approval' order by r.requested_at asc limit 25",
    [auth.userId],
  );
  return response({ enrollment_requests: rows, request_id: requestId }, 200, requestId);
}

async function enrollmentApprovalChallenge(
  auth: AuthContext, requestId: string, enrollmentRequestId: string,
): Promise<Response> {
  const approver = await trustedApprover(auth, true);
  if (!approver) return response({ error: { code: "TRUSTED_DEVICE_REQUIRED", request_id: requestId } }, 403, requestId);
  if (!isUuid(enrollmentRequestId)) return response({ error: { code: "INVALID_ENROLLMENT_ID", request_id: requestId } }, 400, requestId);
  const target = await db!.unsafe(
    "select r.id::text as id, r.device_id::text as device_id from supreme.device_enrollment_requests r join supreme.devices d on d.id = r.device_id where r.id = $1::uuid and r.user_id = $2::uuid and r.status = 'pending' and r.expires_at > now() and d.status = 'pending_approval' and d.id <> $3::uuid limit 1",
    [enrollmentRequestId, auth.userId, approver.deviceId],
  );
  if (target.length !== 1) return response({ error: { code: "ENROLLMENT_NOT_PENDING", request_id: requestId } }, 409, requestId);

  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const digest = await sha256Hex(nonce);
  const challenges = await db!.unsafe(
    "with lock_row as materialized (select pg_advisory_xact_lock(hashtextextended($1 || ':' || $2, 0))), recent as materialized (select count(*)::integer as n from supreme.device_enrollment_approval_challenges c cross join lock_row where c.user_id = $1::uuid and c.approving_device_id = $2::uuid and c.created_at > now() - interval '10 minutes') insert into supreme.device_enrollment_approval_challenges (enrollment_request_id, user_id, approving_device_id, approving_auth_session_id, nonce_sha256, expires_at) select $3::uuid, $1::uuid, $2::uuid, $5::uuid, decode($4, 'hex'), now() + interval '90 seconds' from recent where recent.n < 10 returning id::text, expires_at",
    [auth.userId, approver.deviceId, enrollmentRequestId, digest, auth.authSessionId],
  );
  if (challenges.length !== 1) return response({ error: { code: "APPROVAL_RATE_LIMITED", request_id: requestId } }, 429, requestId);
  return response({
    challenge_id: challenges[0].id,
    nonce: base64Url(nonce),
    enrollment_request_id: enrollmentRequestId,
    device_id: target[0].device_id,
    expires_at: challenges[0].expires_at,
    request_id: requestId,
  }, 200, requestId);
}

async function approveEnrollment(
  auth: AuthContext, request: Request, requestId: string, enrollmentRequestId: string,
): Promise<Response> {
  const approver = await trustedApprover(auth, true);
  if (!approver) return response({ error: { code: "TRUSTED_DEVICE_REQUIRED", request_id: requestId } }, 403, requestId);
  if (!isUuid(enrollmentRequestId)) return response({ error: { code: "INVALID_ENROLLMENT_ID", request_id: requestId } }, 400, requestId);
  let body: Record<string, unknown>;
  try { body = await boundedJson(request, 8 * 1024); }
  catch { return response({ error: { code: "INVALID_REQUEST", request_id: requestId } }, 400, requestId); }
  const allowed = new Set(["challenge_id", "nonce", "device_id", "signature"]);
  if (Object.keys(body).length !== 4 || Object.keys(body).some((key) => !allowed.has(key)) ||
      !isUuid(body.challenge_id) || !isUuid(body.device_id) ||
      typeof body.nonce !== "string" || typeof body.signature !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(body.nonce) ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(body.signature) || body.signature.length < 80 || body.signature.length > 160) {
    return response({ error: { code: "INVALID_APPROVAL_PAYLOAD", request_id: requestId } }, 400, requestId);
  }
  const nonce = decodeBase64Url(body.nonce);
  const target = await db!.unsafe(
    "select d.id::text as device_id from supreme.device_enrollment_requests r join supreme.devices d on d.id = r.device_id where r.id = $1::uuid and r.user_id = $2::uuid and r.status = 'pending' and r.expires_at > now() and d.status = 'pending_approval' and d.id = $3::uuid limit 1",
    [enrollmentRequestId, auth.userId, body.device_id],
  );
  if (target.length !== 1) return response({ error: { code: "ENROLLMENT_NOT_PENDING", request_id: requestId } }, 409, requestId);
  let valid = false;
  try {
    const signature = Uint8Array.from(atob(body.signature), (character) => character.charCodeAt(0));
    valid = await verifyEnrollmentApprovalSignature(
      approver.spki, body.challenge_id, nonce, enrollmentRequestId, body.device_id, signature,
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    await db!.unsafe(
      "insert into supreme.audit_events (actor_user_id, action, outcome, policy_version, details) values ($1::uuid, 'device_enrollment.approve', 'denied', 'v1', jsonb_build_object('enrollment_request_id', $2::uuid, 'approving_device_id', $3::uuid, 'reason', 'invalid_device_signature', 'request_id', $4))",
      [auth.userId, enrollmentRequestId, approver.deviceId, requestId],
    );
    return response({ error: { code: "DEVICE_SIGNATURE_INVALID", request_id: requestId } }, 403, requestId);
  }

  const nonceHash = await sha256Hex(nonce);
  const result = await postServiceRpc("approve_supreme_device_enrollment", {
    p_enrollment_request_id: enrollmentRequestId,
    p_challenge_id: body.challenge_id,
    p_user_id: auth.userId,
    p_approving_device_id: approver.deviceId,
    p_approving_auth_session_id: auth.authSessionId,
    p_nonce_sha256: "\\x" + nonceHash,
  });
  if (!result || typeof result !== "object" || (result as Record<string, unknown>).approved !== true) {
    return response({ error: { code: "ENROLLMENT_APPROVAL_FAILED", request_id: requestId } }, 409, requestId);
  }
  return response({ approved: true, enrollment_request_id: enrollmentRequestId, device_id: body.device_id, request_id: requestId }, 200, requestId);
}


async function deviceInventory(auth: AuthContext, requestId: string): Promise<Response> {
  const approver = await trustedApprover(auth, false);
  if (!approver) return response({ error: { code: "TRUSTED_DEVICE_REQUIRED", request_id: requestId } }, 403, requestId);
  const rows = await db!.unsafe(
    "select d.id::text as device_id, d.status, d.security_level, d.attested_at, d.last_seen_at, d.created_at, (d.id = $2::uuid) as is_current_device, (select count(*)::integer from supreme.app_sessions s where s.device_id = d.id and s.user_id = d.user_id and s.status = 'active' and s.expires_at > now()) as active_sessions from supreme.devices d where d.user_id = $1::uuid order by case d.status when 'active' then 0 when 'pending_approval' then 1 when 'revoked' then 2 else 3 end, d.created_at desc limit 50",
    [auth.userId, approver.deviceId],
  );
  return response({ devices: rows, request_id: requestId }, 200, requestId);
}

async function deviceRevocationChallenge(auth: AuthContext, requestId: string, targetDeviceId: string): Promise<Response> {
  const approver = await trustedApprover(auth, true);
  if (!approver) return response({ error: { code: "TRUSTED_DEVICE_REQUIRED", request_id: requestId } }, 403, requestId);
  if (!isUuid(targetDeviceId) || targetDeviceId === approver.deviceId) return response({ error: { code: "INVALID_REVOCATION_TARGET", request_id: requestId } }, 400, requestId);
  const target = await db!.unsafe(
    "select id::text from supreme.devices where id = $1::uuid and user_id = $2::uuid and status = 'active' limit 1",
    [targetDeviceId, auth.userId],
  );
  if (target.length !== 1) return response({ error: { code: "DEVICE_NOT_ACTIVE", request_id: requestId } }, 409, requestId);
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const digest = await sha256Hex(nonce);
  const challenges = await db!.unsafe(
    "with lock_row as materialized (select pg_advisory_xact_lock(hashtextextended($1 || ':' || $2, 0))), recent as materialized (select count(*)::integer as n from supreme.device_management_challenges c cross join lock_row where c.user_id = $1::uuid and c.approving_device_id = $2::uuid and c.created_at > now() - interval '10 minutes') insert into supreme.device_management_challenges (user_id, action, target_device_id, approving_device_id, approving_auth_session_id, nonce_sha256, expires_at) select $1::uuid, 'revoke_device', $3::uuid, $2::uuid, $5::uuid, decode($4, 'hex'), now() + interval '90 seconds' from recent where recent.n < 10 returning id::text, expires_at",
    [auth.userId, approver.deviceId, targetDeviceId, digest, auth.authSessionId],
  );
  if (challenges.length !== 1) return response({ error: { code: "DEVICE_ACTION_RATE_LIMITED", request_id: requestId } }, 429, requestId);
  return response({ challenge_id: challenges[0].id, nonce: base64Url(nonce), device_id: targetDeviceId, expires_at: challenges[0].expires_at, request_id: requestId }, 200, requestId);
}

async function revokeRemoteDevice(auth: AuthContext, request: Request, requestId: string, targetDeviceId: string): Promise<Response> {
  const approver = await trustedApprover(auth, true);
  if (!approver) return response({ error: { code: "TRUSTED_DEVICE_REQUIRED", request_id: requestId } }, 403, requestId);
  if (!isUuid(targetDeviceId) || targetDeviceId === approver.deviceId) return response({ error: { code: "INVALID_REVOCATION_TARGET", request_id: requestId } }, 400, requestId);
  let body: Record<string, unknown>;
  try { body = await boundedJson(request, 8 * 1024); }
  catch { return response({ error: { code: "INVALID_REQUEST", request_id: requestId } }, 400, requestId); }
  const allowed = new Set(["challenge_id", "nonce", "signature"]);
  if (Object.keys(body).length !== 3 || Object.keys(body).some((key) => !allowed.has(key)) ||
      !isUuid(body.challenge_id) || typeof body.nonce !== "string" || typeof body.signature !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(body.nonce) || !/^[A-Za-z0-9+/]+={0,2}$/.test(body.signature) ||
      body.signature.length < 80 || body.signature.length > 160) {
    return response({ error: { code: "INVALID_DEVICE_REVOCATION_PAYLOAD", request_id: requestId } }, 400, requestId);
  }
  let valid = false;
  try {
    const signature = Uint8Array.from(atob(body.signature), (character) => character.charCodeAt(0));
    const payload = new TextEncoder().encode([
      "NEWEIX-SUPREME-DEVICE-REVOKE-V1", body.challenge_id, body.nonce, targetDeviceId,
    ].join("\n"));
    const key = await crypto.subtle.importKey("spki", toArrayBuffer(approver.spki), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key,
      toArrayBuffer(derEcdsaToP1363(signature)), toArrayBuffer(payload));
  } catch { valid = false; }
  if (!valid) {
    await db!.unsafe(
      "insert into supreme.audit_events (actor_user_id, action, outcome, policy_version, details) values ($1::uuid, 'device.revoke_remote', 'denied', 'v1', jsonb_build_object('target_device_id', $2::uuid, 'approving_device_id', $3::uuid, 'reason', 'invalid_device_signature', 'request_id', $4))",
      [auth.userId, targetDeviceId, approver.deviceId, requestId],
    );
    return response({ error: { code: "DEVICE_SIGNATURE_INVALID", request_id: requestId } }, 403, requestId);
  }
  const nonceHash = await sha256Hex(decodeBase64Url(body.nonce));
  const result = await postServiceRpc("revoke_supreme_device", {
    p_user_id: auth.userId, p_target_device_id: targetDeviceId, p_challenge_id: body.challenge_id,
    p_approving_device_id: approver.deviceId, p_approving_auth_session_id: auth.authSessionId,
    p_nonce_sha256: "\\x" + nonceHash,
  });
  if (!result || typeof result !== "object" || (result as Record<string, unknown>).revoked !== true) {
    return response({ error: { code: "DEVICE_REVOCATION_FAILED", request_id: requestId } }, 409, requestId);
  }
  return response({ revoked: true, device_id: targetDeviceId, revoked_sessions: (result as Record<string, unknown>).revoked_sessions ?? 0, request_id: requestId }, 200, requestId);
}


async function dispatchRecoveryNotification(requestId: string, eventType: "requested" | "completed"): Promise<boolean> {
  if (!db || !RECOVERY_NOTIFICATION_URL || !RECOVERY_NOTIFICATION_SECRET) return false;
  let url: URL;
  try {
    url = new URL(RECOVERY_NOTIFICATION_URL);
    if (url.protocol !== "https:") return false;
  } catch {
    return false;
  }
  const rows = await db.unsafe(
    "select id::text, payload, delivered_at from supreme.recovery_notification_outbox where recovery_request_id = $1::uuid and event_type = $2 limit 1",
    [requestId, eventType],
  );
  if (rows.length !== 1) return false;
  if (rows[0].delivered_at) return true;
  try {
    const result = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer " + RECOVERY_NOTIFICATION_SECRET,
        "x-neweix-supreme-event": eventType,
      },
      body: JSON.stringify(rows[0].payload),
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
    });
    if (!result.ok) {
      await db.unsafe(
        "update supreme.recovery_notification_outbox set attempts = attempts + 1, last_error_code = $2 where id = $1::uuid and delivered_at is null",
        [rows[0].id, "HTTP_" + result.status],
      );
      await result.body?.cancel();
      return false;
    }
    await result.body?.cancel();
    await postServiceRpc("mark_supreme_recovery_notification_delivered", {
      p_request_id: requestId,
      p_event_type: eventType,
    });
    return true;
  } catch {
    await db.unsafe(
      "update supreme.recovery_notification_outbox set attempts = attempts + 1, last_error_code = 'DELIVERY_FAILED' where id = $1::uuid and delivered_at is null",
      [rows[0].id],
    );
    return false;
  }
}

async function beginBreakGlassRecovery(auth: AuthContext, request: Request, requestId: string): Promise<Response> {
  if (!db || !SERVICE_ROLE_KEY) {
    return response({ error: { code: "SERVICE_NOT_CONFIGURED", request_id: requestId } }, 503, requestId);
  }
  if (!isFreshAal2(auth.claims) || !(await assertSupremeIdentity(auth.userId))) {
    return response({ error: { code: "SUPREME_AAL2_REQUIRED", request_id: requestId } }, 403, requestId);
  }
  let body: Record<string, unknown>;
  try { body = await boundedJson(request, 8 * 1024); }
  catch { return response({ error: { code: "INVALID_REQUEST", request_id: requestId } }, 400, requestId); }
  if (Object.keys(body).length !== 1 || typeof body.recovery_material !== "string" ||
      !/^[a-f0-9]{64}$/.test(body.recovery_material)) {
    return response({ error: { code: "INVALID_RECOVERY_MATERIAL", request_id: requestId } }, 400, requestId);
  }
  const tokenHash = await sha256Hex(new TextEncoder().encode(body.recovery_material));
  let result: unknown;
  try {
    result = await postServiceRpc("begin_supreme_break_glass_recovery", {
      p_user_id: auth.userId,
      p_auth_session_id: auth.authSessionId,
      p_token_sha256: tokenHash,
    });
  } catch {
    await db.unsafe(
      "insert into supreme.audit_events(actor_user_id, action, outcome, policy_version, details) values ($1::uuid, 'recovery.request', 'denied', 'v1', jsonb_build_object('reason', 'recovery_precondition_failed', 'request_id', $2))",
      [auth.userId, requestId],
    );
    return response({ error: { code: "RECOVERY_REQUEST_DENIED", request_id: requestId } }, 409, requestId);
  }
  if (!result || typeof result !== "object" || !isUuid((result as Record<string, unknown>).request_id)) {
    return response({ error: { code: "RECOVERY_REQUEST_FAILED", request_id: requestId } }, 409, requestId);
  }
  const recovery = result as Record<string, unknown>;
  const notificationDelivered = await dispatchRecoveryNotification(
    recovery.request_id as string, "requested",
  );
  return response({
    requested: true,
    request_id: recovery.request_id,
    available_at: recovery.available_at,
    expires_at: recovery.expires_at,
    notification_delivered: notificationDelivered,
    notification_retry_required: !notificationDelivered,
    request_id_trace: requestId,
  }, 202, requestId);
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
    "select s.id::text as session_id, s.device_id::text as device_id, s.status, s.attested_at, s.expires_at, d.security_level, d.status as device_status, d.device_key_biometric_auth_required, d.last_seen_at from supreme.app_sessions s join supreme.devices d on d.id = s.device_id where s.id = $1::uuid and s.user_id = $2::uuid and s.auth_session_id = $3::uuid and d.id = $4::uuid and d.user_id = $2::uuid limit 1",
    [claim.session_id, auth.userId, auth.authSessionId, claim.device_id],
  );
  const session = rows[0];

  if (request.method === "GET") {
    if (session && session.status === "active" && session.device_status === "active" &&
        session.device_key_biometric_auth_required !== true) {
      return response({
        error: { code: "BIOMETRIC_DEVICE_REENROLLMENT_REQUIRED", request_id: requestId },
      }, 403, requestId);
    }
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

  const parts = pathname.split("/").filter(Boolean);
  const isEnrollmentList = request.method === "GET" && suffix === "enrollments";
  const isEnrollmentChallenge = request.method === "POST" && parts.length >= 4 && parts[parts.length - 1] === "challenge" && parts[parts.length - 3] === "enrollments";
  const isEnrollmentApproval = request.method === "POST" && parts.length >= 4 && parts[parts.length - 3] === "enrollments" && parts[parts.length - 1] === "approve";
  const isDeviceInventory = request.method === "GET" && suffix === "devices";
  const isDeviceRevocationChallenge = request.method === "POST" && parts.length >= 5 && parts[parts.length - 4] === "devices" && parts[parts.length - 2] === "revoke" && suffix === "challenge";
  const isDeviceRevocation = request.method === "POST" && parts.length >= 4 && parts[parts.length - 3] === "devices" && suffix === "revoke";
  const isRecoveryRequest = request.method === "POST" && suffix === "request" && parts[parts.length - 2] === "recovery";
  const operation = request.method === "POST" ? suffix : "";
  if (request.method !== "GET" && request.method !== "DELETE" &&
      !(request.method === "POST" && (operation === "challenge" || operation === "issue" || isEnrollmentChallenge || isEnrollmentApproval || isDeviceRevocationChallenge || isDeviceRevocation || isRecoveryRequest))) {
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
    if (request.method === "POST" && operation === "challenge" && !isEnrollmentChallenge && !isDeviceRevocationChallenge) {
      return await issueChallenge(auth, requestId);
    }
    if (request.method === "POST" && operation === "issue") {
      return await issueDeviceSession(auth, request, requestId);
    }
    if (isEnrollmentList) return await enrollmentRequests(auth, requestId);
    if (isEnrollmentChallenge) return await enrollmentApprovalChallenge(auth, requestId, parts[parts.length - 2]);
    if (isEnrollmentApproval) return await approveEnrollment(auth, request, requestId, parts[parts.length - 2]);
    if (isDeviceInventory) return await deviceInventory(auth, requestId);
    if (isDeviceRevocationChallenge) return await deviceRevocationChallenge(auth, requestId, parts[parts.length - 3]);
    if (isDeviceRevocation) return await revokeRemoteDevice(auth, request, requestId, parts[parts.length - 2]);
    if (isRecoveryRequest) return await beginBreakGlassRecovery(auth, request, requestId);
    return await readOrRevokeSession(auth, request, requestId);
  } catch (error) {
    console.error("Supreme session API failed", { requestId, error: String(error) });
    return response({ error: { code: "INTERNAL_ERROR", request_id: requestId } }, 500, requestId);
  }
}

Deno.serve(handle);
