# Supreme security baseline

## Identity
- Exactly one Supreme principal is provisioned for the ruler role.
- The principal identifier is `supreme`; it is neither a Neweix Account customer nor an employee identity.
- Reuse the existing shared Supabase Auth project for credentials and sessions, but keep Supreme authorization identities in the Supreme-owned `supreme.identities` table (`role = 'ruler'`, `public_id = 'supreme'`, `is_active = true`).
- The unique index `supreme_identities_single_principal_uidx` guarantees one Supreme principal. Do not create a second Supreme identity source or Supabase project; use only `supreme.identities`.
- Do not require a `public.neweix_accounts` customer row for Supreme authorization. Future Neweix Employees remain a separate identity/workforce domain. The Supreme principal is provisioned independently in `supreme.identities`; no legacy workforce-profile table is read or recreated.
- Do not hard-code the identity or credentials into the Android binary.
- Enforce MFA server-side for privileged sessions.
- Require a server-signed `supreme_app_session` JWT claim containing an active session ID, registered device ID, and attestation timestamp. The claim may be minted only by a trusted Supabase Auth hook after checking server-side device/session records; never accept user metadata or client headers as proof.
- Until the device-session registry and Auth hook are deployed, privileged registry API access remains fail-closed.
- Require re-authentication for sensitive actions and after configurable inactivity.

## Device verification
- Use Android BiometricPrompt for supported biometrics and device credential fallback where appropriate.
- Treat biometrics as local device-user verification, not as proof of server identity.
- Keep server authentication and MFA independent from the local app lock.
- Provide session revocation and lost-device recovery procedures.

## Secrets
- Never ship GitHub, Cloudflare, Supabase service-role, or other privileged tokens in the APK.
- Store integration secrets only in backend secret storage.
- Use separate credentials per environment and integration.
- Rotate and revoke credentials; document ownership and expiry.
- Do not commit `.env`, signing keys, recovery codes, or real credentials.

## Authorization
- Enforce authorization in the backend for every operation.
- Deny by default; grant only the minimum required capability.
- Separate read, configuration, deployment, access-management, and destructive capabilities.
- Production deployment, permission escalation, credential changes, and destructive actions require explicit approval and strong re-authentication.
- UI hiding is not an authorization control.

## Audit
Record at minimum:
- Event ID and timestamp.
- Authenticated actor and assurance level.
- Target service, repository, environment, and resource.
- Requested operation and approved parameters.
- Approval references, executor identity, result, and error category.
- Request/correlation ID and relevant client/device metadata.

Audit records must not contain secrets or unnecessary personal data. Restrict modification and deletion.

## Operational safeguards
- Rate-limit privileged endpoints.
- Use idempotency keys for retried operations.
- Validate webhook signatures and reject replayed events.
- Use short-lived credentials where supported.
- Keep development, staging, and production isolated.
- Provide emergency disable/revoke controls.
- Log and alert on unusual access and failed privileged operations.

## Security review gate
No production write integration should be enabled until its scopes, approval path, rollback behavior, audit events, and failure modes are documented and tested.
