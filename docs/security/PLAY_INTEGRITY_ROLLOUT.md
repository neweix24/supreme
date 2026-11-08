# Supreme Play Integrity Rollout

## Status

Planning only. No Play Integrity client, verifier, Google Cloud credentials, or Play Console linkage has been added or enabled.

## Existing device guarantees

Supreme already performs server-side Android Key Attestation before issuing a device-bound session. Its Android KeyDescription policy requires:

- The exact `com.neweix.supreme` package and configured production signing-certificate digest.
- A hardware-backed P-256 signing key in TEE or StrongBox.
- A hardware-enforced per-operation biometric authenticator policy.
- A hardware-enforced RootOfTrust with `deviceLocked = true` and `verifiedBootState = VERIFIED`.
- Proof of possession, a server-issued one-time challenge, and challenge consumption.

Play Integrity is an additional signal. It must not be described as the mechanism that currently enforces the locked bootloader or verified boot state; those checks already exist in the Android Key Attestation verifier.

## Proposed protocol

Use the Play Integrity **Standard API**, not Classic requests.

1. Link the Android app's Google Cloud project to the app in Play Console and enable the Play Integrity API.
2. Add the official Play Integrity Android dependency and configure the public Cloud project number in Android BuildConfig. The project number is public configuration, not a credential.
3. The authenticated Supreme backend issues a short-lived, one-use challenge bound to the authenticated Supreme user, active device, and intended operation.
4. The Android app computes a SHA-256 request hash over a canonical representation of the challenge and operation context, requests a Standard Integrity token using that `requestHash`, and sends the opaque token to the Supreme backend.
5. The backend authenticates the caller, checks challenge ownership/expiry/replay state, obtains a Google OAuth access token using a server-only service account credential, and calls Google's `decodeIntegrityToken` endpoint.
6. The backend validates the decoded `requestDetails` (package name, request hash, timestamp), `appIntegrity.appRecognitionVerdict`, and `deviceIntegrity.deviceRecognitionVerdict`. It must never trust a client-supplied decoded verdict.
7. The backend records a minimal audit result and consumes the challenge atomically. Tokens/verdicts must not be cached for later privileged operations.

## Initial policy

Start with **observe-only telemetry**. Do not block login or device enrollment solely on Play Integrity until a production-signed app is distributed through a linked Google Play track and real-device verdicts have been observed.

After rollout evidence is available, the intended strict policy is:

- `appRecognitionVerdict == PLAY_RECOGNIZED`.
- `deviceRecognitionVerdict` contains `MEETS_DEVICE_INTEGRITY`.
- `requestDetails.requestPackageName` equals `com.neweix.supreme`.
- `requestDetails.requestHash` exactly matches the server-computed digest.
- `requestDetails.timestampMillis` is within a short server-defined freshness window.
- Missing, malformed, unevaluated, stale, or mismatched fields fail closed for the protected operation.

Do not require `MEETS_STRONG_INTEGRITY` by default. It is a stricter OS-security-update signal and could unnecessarily exclude legitimate devices. Do not treat `LICENSED` as equivalent to app integrity; evaluate licensing separately if Play distribution policy requires it.

## Secrets and configuration

Required before implementation can be end-to-end tested:

- Google Cloud project number linked to the Play Console app.
- Play Integrity API enabled for that project.
- A dedicated least-privilege Google service account authorized to decode integrity tokens.
- Service-account credential stored only as a Supabase Edge Function secret (or another server-side secret manager); never in Git, Android resources, BuildConfig, APK, or client responses.
- Production package/signing identity and a Play-distributed test track.

The service account must not be granted unrelated project or Play Console permissions. Prefer short-lived OAuth access tokens generated server-side from the service-account credential.

## Rollout and acceptance criteria

- Unit tests cover missing/invalid verdict fields, package mismatch, request-hash mismatch, stale timestamp, empty device verdict, missing app recognition, and malformed Google responses.
- Integration tests verify that an invalid or replayed challenge cannot create or upgrade a device session.
- CI runs Android compilation and Deno verifier tests without requiring production secrets.
- Observe-only results are reviewed on the actual production-signed Play-distributed build.
- Enforcement is enabled only after the owner approves the measured policy and a rollback path is documented.

## References

- https://developer.android.com/google/play/integrity/standard
- https://developer.android.com/google/play/integrity/setup
- https://developer.android.com/google/play/integrity/verdicts
