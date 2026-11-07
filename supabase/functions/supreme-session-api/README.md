# Supreme session API

Deploy as the Supabase Edge Function `supreme-session-api` with JWT verification enabled.

## Required server configuration

- Supabase project defaults: `SUPABASE_URL`, `SUPABASE_ANON_KEY` or `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SERVICE_ROLE_KEY`.
- `SUPABASE_DB_URL`: server-side database connection string if it is not already present in the Edge Function runtime.
- `SUPREME_ANDROID_SIGNING_CERT_SHA256`: the permanent production APK signer SHA-256 digest. Never set this to the debug signer.

Never place service-role credentials, database URLs or signing configuration in the APK.

## Endpoints

All endpoints require a valid Supabase bearer access token. Challenge creation and registration additionally require the one active Supreme identity, AAL2 and a recent authentication time.

- `POST /functions/v1/supreme-session-api/challenge`: creates a five-minute server nonce. Its rate-limit binding is derived from the authenticated user and exact Supabase Auth session; client-provided IP headers are not trusted.
- `POST /functions/v1/supreme-session-api/issue`: calls the deployed Android verifier, then registers the verifier-returned hardware key against the exact AAL2 Auth session using the service-role-only registration RPC.
- `GET /functions/v1/supreme-session-api`: returns the current Auth session's device-bound status. It does not treat a valid Supabase user session as sufficient Supreme authorization.
- `DELETE /functions/v1/supreme-session-api`: revokes only the current Auth session's Supreme device-session record and appends an audit event.

All responses are private/no-store. The API does not accept a user ID or Auth session ID from the request body.

## Required deployment and activation order

1. Apply the Supreme identity, device-bound session, and atomic registration migrations.
2. Configure the Supabase Custom Access Token Hook exactly as documented in `docs/security/supreme-device-session-hook.md`.
3. Set the production signer digest and minimum version secrets on both the attestation verifier and session API functions.
4. Deploy `supreme-attestation-verify` and `supreme-session-api`.
5. Test a production-signed APK on a physical Android device, including AAL1, wrong account, replay, expired challenge, revoked device, wrong signer, and verifier outage cases.

The native app calls only this Supreme-owned Supabase Edge Function. It does not depend on a Neweix website API route or Neweix Account login.

Do not insert device/session rows manually for production users or treat a debug APK as trusted.
