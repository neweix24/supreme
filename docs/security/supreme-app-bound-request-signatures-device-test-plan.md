# Supreme app-bound request-signature device acceptance plan

Status: manual physical-device verification is pending. This plan is not evidence that any device test has passed.

## Test build requirements
- Install only the Debug/preview APK built from the exact PR head under test.
- Record the APK SHA-256, Git commit SHA, Android version, device model, and whether the key is reported as StrongBox or TEE.
- Use a disposable test Supreme account/device registration where available. Do not use a production owner session for destructive tests.
- Keep Supabase production schema and Edge Functions unchanged during this test plan.
- Never collect or paste access tokens, refresh tokens, raw private key material, raw challenge nonces, or signatures into logs or issue comments.

## Positive path
1. Install the preview APK on a supported physical Android device.
2. Sign in with the Supreme account password and complete TOTP MFA.
3. Confirm the existing biometric approval key attestation succeeds.
4. Confirm the separate request-signing key enrollment succeeds and the server reports hardware-backed security.
5. Open the dashboard and list services and pending control requests.
6. Repeat dashboard reads after background/foreground transitions and verify that each Registry request obtains a fresh challenge and succeeds without a biometric prompt for ordinary reads.
7. Submit a harmless control-request action in a test environment and verify the approval/rejection flow still prompts for strong biometrics using the original approval key.

## Negative and replay paths
For each case, use a fresh test challenge and capture only the request ID, HTTP status, and sanitized server audit reason.

| Case | Action | Expected result |
|---|---|---|
| Missing proof | Call a privileged Registry route without signature headers | 403 APP_REQUEST_PROOF_REQUIRED |
| Wrong key | Sign with a different P-256 key | 403 APP_REQUEST_SIGNATURE_INVALID |
| Changed path | Sign one route and send another | 403 APP_REQUEST_SIGNATURE_INVALID |
| Changed body | Sign one body and send modified bytes | 403 APP_REQUEST_SIGNATURE_INVALID |
| Expired timestamp | Send a timestamp outside the 60-second window | 403 APP_REQUEST_PROOF_EXPIRED |
| Expired challenge | Wait until the one-time challenge expires | 409 APP_REQUEST_CHALLENGE_INVALID |
| Replayed challenge | Send the exact signed request twice | First request may succeed; second must fail with 409 |
| Revoked device | Revoke the test device, then request a fresh challenge | 403 REQUEST_SIGNING_KEY_REQUIRED or the session's revocation denial |
| Expired/revoked session | Use a revoked or expired Supreme app session | Authentication/session denial; no Registry route executes |
| Copied bearer token | Attempt a privileged Registry request from browser/curl with the test bearer token but no valid device proof | 403; no privileged data returned |
| Browser CORS | Send browser-origin/OPTIONS request | Denied; no browser-origin Registry access |
| Key unavailable | Remove the app's request-signing key in a test device state | App fails closed and requires re-enrollment; no bearer-only fallback |

## Evidence and acceptance
- Record each case as pass/fail with timestamp, commit SHA, device model, Android version, status code, and sanitized audit event ID.
- Confirm challenge rows are bound to the same user, app session, and active device.
- Confirm the same challenge can be consumed only once under concurrent requests.
- Confirm the biometric approval key remains separate from the request-signing key.
- Confirm no secrets or raw cryptographic material appear in Android logs, Sentry, analytics, or crash reports.
- All positive and negative cases must pass before merging the PR or enabling production enforcement.

## Rollback
If any test fails, stop the rollout. Do not disable signature enforcement or add a bearer-only fallback. Revoke the test device/session, preserve sanitized diagnostic evidence, fix the implementation, and repeat the full matrix with a new build.