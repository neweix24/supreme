import * as Sentry from "npm:@sentry/deno@11.9.0";

const SENTRY_DSN = Deno.env.get("SENTRY_DSN") ?? "https://4a80e5b20d5f93801845e87071a1e612@o4512412827058176.ingest.us.sentry.io/4512412888530944";
Sentry.init({
  dsn: SENTRY_DSN,
  defaultIntegrations: false,
  sendDefaultPii: false,
  tracesSampleRate: 0,
  environment: Deno.env.get("SENTRY_ENVIRONMENT") ?? "production",
});

async function reportSentryError(error: unknown, functionName: string, requestId?: string | null): Promise<void> {
  Sentry.withScope((scope) => {
    scope.setTag("service", "neweix");
    scope.setTag("supabase_function", functionName);
    const region = Deno.env.get("SB_REGION");
    const executionId = Deno.env.get("SB_EXECUTION_ID");
    if (region) scope.setTag("region", region);
    if (executionId) scope.setExtra("execution_id", executionId);
    if (requestId) scope.setTag("request_id", requestId);
    Sentry.captureException(error);
  });
  await Sentry.flush(2000);
}

function withSentry(functionName: string, handler: (request: Request) => Response | Promise<Response>): (request: Request) => Promise<Response> {
  return async (request: Request): Promise<Response> => {
    try {
      const result = await handler(request);
      if (result.status >= 500) {
        await reportSentryError(new Error(`${functionName} returned HTTP ${result.status}`), functionName, result.headers.get("x-request-id"));
      }
      return result;
    } catch (error) {
      await reportSentryError(error, functionName, request.headers.get("x-request-id"));
      return new Response(JSON.stringify({ error: { code: "INTERNAL_ERROR" } }), {
        status: 500,
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
      });
    }
  };
}

import { fetchGoogleAttestationMetadata } from "../_shared/supreme-google-attestation-metadata.ts";
import { parseX509Certificate } from "../_shared/supreme-x509-certificate.ts";
import { verifySupremeAndroidAttestation } from "../_shared/supreme-attestation-verifier.ts";
import { handleSupremeAttestationVerify } from "./handler.ts";

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

function restHeaders(): HeadersInit {
  return {
    apikey: serviceRoleKey,
    authorization: `Bearer ${serviceRoleKey}`,
    "content-type": "application/json",
  };
}

async function assertChallengeAvailable(
  challengeId: string,
  challengeHash: string,
  requesterIpHash: string,
): Promise<boolean> {
  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error("Supabase server credentials are unavailable.");
  }

  // This is an atomic reservation, not a read-only lookup. The database
  // permits at most three concurrent/repeated verification attempts per
  // challenge and enforces the original requester IP binding.
  const response = await fetch(
    new URL("/rest/v1/rpc/reserve_supreme_app_attestation_verification_attempt", supabaseUrl),
    {
      method: "POST",
      headers: restHeaders(),
      body: JSON.stringify({
        p_challenge_id: challengeId,
        p_challenge_hash: challengeHash,
        p_requester_ip_hash: requesterIpHash,
      }),
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    },
  );
  if (!response.ok) throw new Error("Challenge attempt reservation failed.");
  return await response.json() === true;
}

async function consumeChallenge(
  challengeId: string,
  challengeHash: string,
): Promise<boolean> {
  if (!supabaseUrl || !serviceRoleKey) {
    throw new Error("Supabase server credentials are unavailable.");
  }

  const response = await fetch(
    new URL("/rest/v1/rpc/consume_supreme_app_attestation_challenge", supabaseUrl),
    {
      method: "POST",
      headers: restHeaders(),
      body: JSON.stringify({
        p_challenge_id: challengeId,
        p_challenge_hash: challengeHash,
      }),
      redirect: "error",
      signal: AbortSignal.timeout(5_000),
    },
  );
  if (!response.ok) throw new Error("Challenge consumption failed.");
  return await response.json() === true;
}

Deno.serve(withSentry("supreme-attestation-verify", (request) =>
  handleSupremeAttestationVerify(request, {
    serviceRoleKey: serviceRoleKey || null,
    signingCertificateSha256: Deno.env.get("SUPREME_ANDROID_SIGNING_CERT_SHA256") ?? null,
    minimumPackageVersion: Deno.env.get("SUPREME_ANDROID_MIN_VERSION_CODE") ?? null,
    fetchMetadata: fetchGoogleAttestationMetadata,
    parseCertificate: parseX509Certificate,
    verifyAttestation: verifySupremeAndroidAttestation,
    assertChallengeAvailable,
    consumeChallenge,
  })
));
