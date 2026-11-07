# Supreme device-bound session hook

## What this migration adds

`20261107200000_supreme_device_bound_auth_sessions.sql` creates the private device and app-session registries and a Supabase Custom Access Token Hook.

The hook adds a server-signed `supreme_app_session` claim only when all of these are true:

- The incoming Auth token has `aal2`.
- The Auth user maps to the single active `supreme.identities` principal (`public_id=supreme`, `role=ruler`).
- The current Supabase Auth `session_id` has an active, unexpired row in `supreme.app_sessions`.
- That session belongs to an active row in `supreme.devices` owned by the same Auth user.
- The device package is exactly `com.neweix.supreme`.
- The device security level is `trusted_environment` or `strongbox`.
- The attestation timestamp is no older than 30 days and is not in the future.

All client roles are denied direct access to the device/session tables. Only the service role can manage them; `supabase_auth_admin` receives read-only access for the token hook.

## Required Supabase configuration

After applying the migration to the intended Supabase project:

1. Open **Authentication → Hooks**.
2. Enable **Custom Access Token** and select `public.supreme_custom_access_token_hook`.
3. Save the hook configuration.
4. Confirm the hook runs on both initial token issuance and refresh.
5. Keep `service_role` credentials exclusively in trusted server-side functions.
6. Verify the hook does not add `supreme_app_session` for an ordinary Auth user or for the Supreme user without an active registered device session.

The migration does not enable the Auth Hook automatically. This is an explicit project-level Auth configuration step.

## Session lifecycle contract

A trusted server-side session issuer must do the following, in order:

1. Validate the Supabase bearer token with Supabase Auth (do not trust decoded JWT claims alone).
2. Confirm the caller is the active Supreme ruler in `supreme.identities`.
3. Require a successful, unconsumed Android Key Attestation verification for this exact login attempt.
4. Derive the device-key fingerprint from the public key that was actually verified by the attestation verifier. Never accept a client-supplied fingerprint as proof.
5. Upsert the device record using the verified package, production signing-certificate digest, security level, and attested timestamp.
6. Bind the new app session to the Auth JWT's `session_id`; do not accept a caller-selected session UUID.
7. Set a bounded expiry and revoke the previous app session(s) according to the device/session policy.
8. Return success only after the database transaction commits. The client must refresh its Auth token so the Auth Hook can issue the signed `supreme_app_session` claim.

Logout, lost-device handling, and administrative revocation must mark the relevant session/device as revoked. The next access-token refresh must omit the claim. Sensitive APIs must continue to check the session row or short token lifetime where immediate revocation is required.

## Important non-goals

- This hook is not a login endpoint and does not authenticate passwords or MFA.
- A successful attestation response alone is not a Supabase session or an authorization grant.
- Local Android biometric unlock is not server authentication.
- No customer account or workforce/staff profile is used.
- No session may be created from a preview/debug APK. The verifier must enforce the production package and production signing-certificate digest.

## Current implementation boundary

The native password + TOTP AAL2 flow, challenge endpoint, verifier call, atomic attestation-to-device registration RPC, session status/revocation API, and live Registry API checks are implemented in the Supreme repository and deployed as Supabase Edge Functions.

The database migrations are applied. The Supabase Custom Access Token Hook itself still requires the explicit project-level activation described above. The production APK signing certificate digest must be configured as the server-side `SUPREME_ANDROID_SIGNING_CERT_SHA256` secret. A physical-device positive/negative test and confirmation that the deployed website does not expose browser Supreme access are still required before production release.
