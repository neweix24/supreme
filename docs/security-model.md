# Supreme security baseline

## Identity
- Exactly one Supreme principal is provisioned for the ruler role.
- The principal identifier is `supreme`; it is not a normal employee or customer account.
- Do not hard-code the identity or credentials into the Android binary.
- Enforce MFA server-side for privileged sessions.
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
