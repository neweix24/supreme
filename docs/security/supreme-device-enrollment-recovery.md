# Supreme Device Enrollment, Approval, Revocation, and Recovery

Status: design contract for implementation; not enabled in production.

## Scope and invariants

- There is exactly one Supreme identity: `public_id = 'supreme'`, `role = 'ruler'`, and it belongs to one Auth user.
- Supreme remains independent of NEWEIX customer and employee identities.
- The Android app is distributed directly as an APK. Google Play and Play Integrity are not dependencies.
- No CAPTCHA is added.
- Password + TOTP and fresh AAL2 remain mandatory for privileged enrollment and recovery operations.
- Device enrollment must not grant a new device access merely because the user knows the password and TOTP.
- All device lifecycle changes must be auditable and fail closed.

## Existing behavior found during review

The current `register_supreme_attested_device_session` RPC inserts a newly attested device with `status = 'active'`. On a conflict for the same user/key it also sets the device back to active, even if its previous status was revoked or blocked. That means the current enrollment path does not yet implement approval by an already trusted device, and a revoked key could be reactivated by repeating enrollment. This must be corrected before enabling multi-device enrollment or recovery.

The current device table only permits `active`, `revoked`, and `blocked`. The current session API creates an active app session immediately after attestation. The app has a self-session revoke endpoint, but there is no complete trusted-device inventory, remote revocation flow, pending enrollment approval flow, or break-glass recovery workflow.

## Target lifecycle

### Device states

- `pending_approval`: attestation passed, but the device has no access to privileged Supreme APIs.
- `active`: explicitly approved and currently eligible for sessions.
- `revoked`: permanently denied; never auto-reactivated by re-attestation.
- `blocked`: security hold; only a separately authenticated recovery procedure may resolve it.

State transitions:
- First-device bootstrap: no device rows exist; one device can be enrolled through a one-time bootstrap ceremony.
- New device: attestation creates a pending enrollment request only.
- Approval: an already active device signs a short-lived, one-time approval challenge using its hardware-backed biometric-per-operation key.
- Revocation: an active device can revoke another device after fresh AAL2 and biometric signature; the current device may revoke itself only through explicit sign-out.
- Re-enrollment: a revoked or blocked key remains denied. A replacement device must use the recovery process; the old key is not silently reactivated.

### Session rules

- Pending devices receive no `supreme_app_session` JWT claim and cannot access the registry or control APIs.
- Approval binds the pending device key hash, pending request ID, user ID, decision, expiry, and approving device ID.
- Approval challenges are cryptographically random, expire quickly, are single-use, and are consumed atomically with the state transition.
- All approvals and revocations append audit events.
- A device's app session is capped at four hours and remains subject to fresh AAL2, device attestation age, and biometric signing policy.
- Revocation invalidates all app sessions for that device immediately; token refresh must not restore the claim.

## Enrollment protocol

1. New app performs password + TOTP and obtains a fresh AAL2 session.
2. Server verifies Android hardware attestation, verified boot, expected package/signing certificate, biometric-per-operation key policy, and proof of possession.
3. Server creates a `pending_approval` device enrollment record. It does not create an active app session or issue an active Supreme device claim.
4. If another active trusted device exists, it receives a pending request in its device-management screen.
5. The trusted device fetches an approval challenge bound to the exact pending enrollment and signs the canonical payload after BIOMETRIC_STRONG.
6. Server verifies the signature against the already registered public key of the approving device, consumes the challenge once, records the approver, and activates the new device atomically.
7. The new device must refresh its Supabase token after approval; only then may it receive the active device-session claim.

## First-device bootstrap

If no active or historical device exists, the first device requires a bootstrap ceremony. This is a special case and must not be inferred merely from an empty active-device query if revoked/blocked records exist.

The bootstrap ceremony must require:
- fresh password + TOTP AAL2;
- successful production-signer Android hardware attestation;
- a single-use bootstrap authorization generated during initial Supreme provisioning, stored offline by the owner, and verified server-side;
- atomic consumption and immutable audit event.

The bootstrap authorization must never be embedded in the APK, repository, QR code shown to an untrusted browser, or a client-side constant. If no bootstrap authorization was provisioned, initial enrollment remains disabled until a safe operator-assisted setup is performed.

## Break-glass recovery

Recovery is only for loss of every active trusted device. It must not be a password/TOTP-only bypass.

Required controls:
- offline recovery material generated during secure provisioning and stored outside the phone;
- fresh password + TOTP AAL2;
- a strong delay/cooling-off period (initial proposal: 24 hours) before a replacement device becomes active;
- notify the owner through an independently controlled channel when recovery is requested and again when it completes;
- recovery immediately revokes all previous device sessions and marks lost devices revoked;
- single-use recovery material is atomically consumed and cannot be regenerated by an unauthenticated client;
- audit every attempt, including denied and expired requests.

If offline recovery material is lost, recovery requires a separately documented, manually verified operator procedure. Do not add a hidden bypass or support override endpoint.

## Implementation progress

- [x] Add `pending_approval` device state and a private, service-role-only enrollment-request table.
- [x] New attested device keys are inserted as pending and do not receive an app session.
- [x] Existing active devices may renew; revoked and blocked keys are rejected without changing their state.
- [x] A previously revoked Auth session cannot be reactivated by the registration RPC.
- [x] Session API and Android registration flow report pending approval without persisting an app session.
- [x] NEWEIX integration endpoint propagates the pending state instead of returning an empty session identifier.
- [ ] First-device bootstrap authorization and secure provisioning.
- [x] Trusted-device approval challenge/signature verification and atomic activation API.
- [x] Android biometric approval flow and pending-enrollment list.
- [ ] Device inventory and remote revocation APIs/UI.
- [ ] Break-glass recovery implementation.
- [ ] Database regression tests and CI verification for enrollment approval.
- [ ] Physical-device validation of biometric approval and target-device re-attestation.

This is an intentionally incomplete hardening stage. Trusted-device approval is now implemented as an API ceremony, but first-device bootstrap, remote revocation, recovery, automated regression coverage, and physical-device verification remain outstanding. Do not deploy this migration as a complete enrollment solution.

## Database/API implementation sequence

1. Add a migration for `pending_approval`, enrollment requests, approval challenges, recovery requests, and consumed recovery credentials. Keep all tables in the private `supreme` schema with RLS enabled and service-role-only access.
2. Replace the current registration RPC so attestation creates pending enrollment unless the one-time first-device bootstrap rule is satisfied. Never change `revoked` or `blocked` back to `active` on conflict.
3. Add server-issued approval challenge and approval endpoints. Verify ECDSA signatures with the registered public key of the currently active approving device; do not accept a public key supplied by the client.
4. Add device inventory, approve, revoke, and recovery APIs with fresh AAL2 checks, CSRF/origin protections where applicable, strict request schemas, rate limits, and audit events.
5. Update the Supabase custom access-token hook and every privileged API session check to reject pending, revoked, blocked, expired, or biometric-unverified devices.
6. Add PostgreSQL regression tests for concurrent enrollment, replay, expired challenge, wrong approver, key substitution, revoked-key re-enrollment, recovery replay, cooling-off, and session invalidation.
7. Add Android UI for pending status, trusted-device approval, device inventory, revocation, and recovery. Never show approval controls on an untrusted pending device.
8. Complete physical-device tests before merge or production rollout.

## Explicit non-goals

- No Google Play Store release.
- No Play Integrity API.
- No CAPTCHA.
- No NEWEIX account integration.
- No password-only or TOTP-only recovery bypass.
- No automatic reactivation of revoked devices.
- No production migration or Edge Function deployment as part of this design document.
