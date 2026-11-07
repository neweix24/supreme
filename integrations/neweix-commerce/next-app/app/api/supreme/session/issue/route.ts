import { createHash } from "node:crypto";
import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { getCloudflareContext } from "@opennextjs/cloudflare";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const NO_STORE = {
  "Cache-Control": "private, no-store, max-age=0",
  Pragma: "no-cache",
  "X-Content-Type-Options": "nosniff",
};
const MAX_BODY_BYTES = 96 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA256 = /^[a-f0-9]{64}$/i;

function fail(message: string, status: number) {
  return NextResponse.json({ error: message }, { status, headers: NO_STORE });
}

async function boundedJson(request: Request): Promise<Record<string, unknown>> {
  const declared = request.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > MAX_BODY_BYTES)) {
    throw new RangeError("Request too large.");
  }
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type") ?? "")) {
    throw new TypeError("Expected JSON.");
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
      if (size > MAX_BODY_BYTES) {
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

function bearer(request: Request): string | null {
  const value = request.headers.get("authorization") ?? "";
  const match = /^Bearer ([A-Za-z0-9._~-]+)$/.exec(value);
  return match?.[1] ?? null;
}

function jwtClaims(token: string): Record<string, unknown> {
  const part = token.split(".")[1];
  if (!part) throw new TypeError("Invalid token.");
  const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  const claims: unknown = JSON.parse(decoded);
  if (!claims || typeof claims !== "object" || Array.isArray(claims)) throw new TypeError("Invalid token.");
  return claims as Record<string, unknown>;
}

export async function POST(request: Request) {
  const sourceIp = request.headers.get("cf-connecting-ip")?.trim();
  if (!sourceIp || sourceIp.length > 64) return fail("Secure device registration is unavailable.", 503);

  const token = bearer(request);
  if (!token) return fail("Supreme sign-in is required.", 401);

  let payload: Record<string, unknown>;
  try {
    payload = await boundedJson(request);
  } catch (error) {
    return fail(error instanceof RangeError ? "Attestation request is too large." : "Invalid attestation request.", error instanceof RangeError ? 413 : 400);
  }

  const challengeId = payload.challenge_id;
  const challenge = payload.challenge;
  const certificateChain = payload.certificate_chain;
  const proofSignature = payload.proof_signature;
  if (!UUID.test(String(challengeId)) || typeof challenge !== "string" ||
      !/^[A-Za-z0-9_-]{43}$/.test(challenge) ||
      !Array.isArray(certificateChain) || certificateChain.length < 3 ||
      certificateChain.length > 10 ||
      !certificateChain.every((item) => typeof item === "string" && item.length <= 24_000) ||
      typeof proofSignature !== "string" || proofSignature.length > 512) {
    return fail("Attestation payload is invalid.", 400);
  }

  try {
    const { env } = await getCloudflareContext();
    const runtimeEnv = env as Record<string, unknown>;
    const supabaseUrl = runtimeEnv.NEXT_PUBLIC_SUPABASE_URL ?? process.env.NEXT_PUBLIC_SUPABASE_URL;
    const serviceRoleKey = runtimeEnv.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (typeof supabaseUrl !== "string" || !supabaseUrl.startsWith("https://") ||
        typeof serviceRoleKey !== "string" || !serviceRoleKey) {
      return fail("Supreme registration service is not configured.", 503);
    }

    const authResponse = await fetch(supabaseUrl.replace(/\/$/, "") + "/auth/v1/user", {
      headers: { apikey: serviceRoleKey, authorization: "Bearer " + token, accept: "application/json" },
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(8_000),
    });
    if (!authResponse.ok) {
      await authResponse.body?.cancel();
      return fail("Supreme sign-in has expired.", 401);
    }
    const authUser: unknown = await authResponse.json();
    if (!authUser || typeof authUser !== "object" || Array.isArray(authUser) ||
        !UUID.test(String((authUser as Record<string, unknown>).id))) {
      return fail("Supreme sign-in could not be verified.", 401);
    }

    const claims = jwtClaims(token);
    const userId = String((authUser as Record<string, unknown>).id);
    const authSessionId = claims.session_id;
    if (claims.sub !== userId || !UUID.test(String(authSessionId)) || claims.aal !== "aal2") {
      return fail("Verified Supreme MFA (AAL2) is required.", 403);
    }

    const productionSigner = runtimeEnv.SUPREME_ANDROID_SIGNING_CERT_SHA256 ?? process.env.SUPREME_ANDROID_SIGNING_CERT_SHA256;
    if (typeof productionSigner !== "string" || !SHA256.test(productionSigner)) {
      return fail("Supreme production app signer is not configured.", 503);
    }

    const signerDigest = productionSigner.toLowerCase();
    const db = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const requesterIpHash = createHash("sha256").update(sourceIp).digest("hex");
    const verifier = await fetch(supabaseUrl.replace(/\/$/, "") + "/functions/v1/supreme-attestation-verify", {
      method: "POST",
      headers: {
        authorization: "Bearer " + serviceRoleKey,
        apikey: serviceRoleKey,
        "content-type": "application/json",
        "x-neweix-attestation-ip-hash": requesterIpHash,
      },
      body: JSON.stringify({
        challenge_id: challengeId,
        challenge,
        certificate_chain: certificateChain,
        proof_signature: proofSignature,
      }),
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
    const verifierText = await verifier.text();
    if (verifierText.length > 8_192) return fail("Device verifier returned an invalid response.", 502);
    let verified: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(verifierText);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid response");
      verified = parsed as Record<string, unknown>;
    } catch {
      return fail("Device verifier returned an invalid response.", 502);
    }
    if (!verifier.ok || verified.verified !== true || verified.proof_of_possession_verified !== true ||
        typeof verified.device_key_sha256 !== "string" || !SHA256.test(verified.device_key_sha256) ||
        !["trusted_environment", "strongbox"].includes(String(verified.security_level))) {
      return fail("Android hardware attestation was rejected.", verifier.status >= 500 ? 503 : 403);
    }

    const now = new Date();
    const expiresAt = new Date(now.getTime() + 12 * 60 * 60 * 1000).toISOString();
    const { data: registered, error: registrationError } = await db.rpc(
      "register_supreme_attested_device_session",
      {
        p_user_id: userId,
        p_auth_session_id: authSessionId,
        p_device_key_sha256: verified.device_key_sha256,
        p_signing_certificate_sha256: signerDigest,
        p_security_level: verified.security_level,
        p_attested_at: now.toISOString(),
        p_expires_at: expiresAt,
      },
    );
    if (registrationError || !registered || registered.registered !== true) {
      console.error("Supreme device session registration failed", registrationError?.message);
      return fail("Supreme device session could not be created.", 503);
    }

    return NextResponse.json({
      registered: true,
      session_id: registered.session_id,
      device_id: registered.device_id,
      expires_at: registered.expires_at,
      security_level: verified.security_level,
    }, { headers: NO_STORE });
  } catch (error) {
    console.error("Supreme device registration error", String(error));
    return fail("Supreme device registration is temporarily unavailable.", 503);
  }
}
