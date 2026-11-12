# Supreme app-bound API request signatures

Status: implementation in branch PR #58; a versioned Supabase migration candidate is now included, but it has not been applied. Production enforcement is not enabled.

## Goal

A copied Supabase access token must not be sufficient to call a privileged Supreme API from a browser, script, or unrelated client. Every Registry API request must prove possession of the private key registered to the active, attested Android device.

This is a second factor at the API transport boundary. It does not replace password sign-in, TOTP/AAL2, the signed `supreme_app_session` claim, live session/device checks, or server-side authorization.

## Existing implementation facts

- Android attestation creates a P-256 Android Keystore key and the server stores the verifier-derived SPKI in `supreme.devices.device_public_key_spki`.
- That key is configured for per-use strong biometric authentication.
- The native app already uses a one-time nonce and that key to sign control-decision approvals/rejections.
- The Registry API currently validates the Supabase bearer token, the signed `supreme_app_session` claim, AAL2, the active Supreme identity, and the live device/session rows.
- Ordinary Registry reads and writes do not currently require a device-key signature. CORS and User-Agent/Origin checks cannot close this gap.

## Implementation status in this branch

- Android now has a distinct non-exportable P-256 request-signing key and a central Registry transport that obtains a one-time challenge and signs each privileged request.
- The session API accepts the explicit `request_signing` attestation purpose and stores the verified public key separately on the already active device.
- The attestation verifier enforces hardware `NO_AUTH_REQUIRED` for this transport key, while retaining per-operation biometric authentication for approval keys.
- The Registry API verifies the request signature and atomically consumes the challenge before dispatching the route. Browser-origin requests are denied.
- The required database changes are in `supabase/migrations/20261112170000_supreme_app_bound_request_signatures.sql`; this is a reviewed migration candidate, not an applied migration. The older `docs/security/supreme-api-request-signatures-schema.sql` remains a reference copy.

## Required design

### 1. Separate transport proof from human approval

Do not silently reuse the existing biometric-per-use decision key for every background API request. That would cause a biometric prompt for every dashboard read and break normal app operation.

Register a second P-256 hardware-backed Android Keystore key for request proof. Its private key must be non-exportable and its attestation chain must be verified by the existing server verifier against the exact package, production signer digest, hardware security level, verified boot state, and a fresh one-time server challenge. This transport key is not configured for per-operation biometric authentication; access to it is gated by the authenticated app process and the existing app lock. Keep the current biometric-per-use key exclusively for human approval/rejection signatures.

The server must store the request-proof public key separately from the approval key. Do not overwrite the existing approval key field until a migration and a re-enrollment plan are reviewed.

### 2. Issue one-time request challenges

Add a private challenge table in the `supreme` schema. Store only a SHA-256 hash of a cryptographically random 32-byte nonce, plus user ID, app-session ID, device ID, expiry, and consumed timestamp. Revoke direct access to all client roles. Only the server runtime may insert/read/consume challenges.

The challenge endpoint must:
- authenticate the bearer token with Supabase Auth;
- verify the single active Supreme ruler identity;
- validate the signed app-session claim and live device/session binding;
- enforce a short expiry (maximum 60 seconds) and per-device rate limit;
- return the challenge ID, raw nonce, and expiry with `Cache-Control: no-store`.

### 3. Canonical signed request

The Android client signs this UTF-8 payload using SHA256withECDSA:

```text
NEWEIX-SUPREME-API-REQUEST-V1
<challenge_id>
<base64url-no-padding nonce>
<uppercase HTTP method>
<canonical path and query>
<lowercase hex SHA-256 of exact request body bytes>
<unix timestamp in seconds>
```

Rules:
- Sign the exact method, path/query, and body bytes that will be sent. Do not parse and reserialize JSON between hashing and sending.
- Reject fragments, absolute URLs, encoded path separators, dot segments, duplicate security-sensitive query parameters, and non-canonical base64url.
- Use a bounded clock-skew window (60 seconds maximum).
- Never include the bearer token in the signed payload or expose it to page JavaScript.
- Send the challenge ID, canonical base64url nonce, timestamp, and DER signature in dedicated headers. The server hashes the supplied nonce and compares it with the challenge row before signature verification. Storing only the nonce hash means the server cannot reconstruct the raw nonce from the row.

### 4. Verify and consume before routing

For every non-OPTIONS Registry API request:
1. Validate the Supabase bearer token using `/auth/v1/user`; never authorize from an unverified JWT decode.
2. Validate the server-signed app-session claim, AAL2, active identity, active device, and unexpired session.
3. Load the unconsumed, unexpired challenge bound to this exact user, app session, and device.
4. Load the request-proof SPKI from the matching active device row.
5. Reconstruct the canonical payload from the actual received method, path/query, raw body bytes, challenge row nonce, and timestamp.
6. Verify ECDSA signature with the stored SPKI.
7. Atomically consume the challenge with a conditional UPDATE that includes `consumed_at IS NULL` and `expires_at > now()`. Exactly one request may succeed.
8. Only then dispatch to route handlers.

Missing, invalid, expired, mismatched, or replayed proof must fail closed with a generic 403/409 response and an audit event that does not contain tokens, raw nonces, or signatures.

### 5. Android client requirements

- Keep auth endpoints (password, TOTP, attestation challenge/issue, refresh, logout) on their existing narrow contracts; do not apply Registry request signing before the request-proof key is enrolled.
- After a successful request-proof key enrollment, all Registry API calls must go through one central signed-request transport. No direct unwrapped Registry fetch is allowed.
- Generate a fresh challenge for each request; do not reuse a challenge after network failure. Retry by obtaining a new challenge and signing the exact retry payload.
- Keep the raw access token and request signatures out of logs, analytics, crash reports, intents, clipboard, WebView JavaScript, and persistent plaintext storage.
- If the request-proof key is missing, invalidated, or no longer matches the active device row, lock privileged features and require device re-enrollment. Never fall back to bearer-only access.

### 6. Rollout and acceptance gates

Do not deploy server enforcement until the Android signed-request client and server verifier are merged and tested together. Because the current Registry Function will reject unsigned privileged requests, the production rollout must be coordinated and the older APK must not be treated as compatible. Proposed order:
1. Review and apply the versioned schema migration during an approved maintenance window; verify the new columns, private challenge table, constraints, indexes, RLS, and service-role-only grants.
2. Deploy the updated attestation verifier and session API so the second hardware-backed key can be enrolled without replacing the biometric approval key.
3. Deploy the updated Registry API that issues one-time challenges and requires request signatures for every privileged route.
4. Release the matching Android APK only after positive and negative physical-device tests pass: wrong key, wrong path, changed body, expired challenge, replay, revoked device, expired app session, and copied bearer token from a browser/script.
5. Verify no client-role grants or RLS policies expose the private challenge table, and confirm browser-origin requests are denied.

Do not use an audit-only compatibility mode that permits bearer-only privileged requests; it would defeat the app-bound access requirement.

No production database migration, Edge Function deployment, Auth Hook change, or signing-secret change is authorized by this design document alone.
