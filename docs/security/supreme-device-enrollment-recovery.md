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

The bootstrap authorization must never be embedded in the APK, repository, QR code shown to an untrusted browser, or a client-side constant. The server stores only its SHA-256 digest. If no bootstrap authorization was provisioned, the registration RPC returns a bootstrap-required result without inserting a device row.

### Offline provisioning procedure (operator only)

Run this only after the migration has been reviewed and applied to the intended Supreme Supabase project.

1. On the owner's trusted computer, generate a one-time 256-bit code locally. Do not send it through chat, email, issue trackers, or commit it:
   `TOKEN="$(openssl rand -hex 32)"`
2. Calculate the digest:
   `printf '%s' "$TOKEN" | sha256sum`
3. In the Supabase SQL Editor, insert **only the 64-character digest** (never the raw token):
   ```sql
   insert into supreme.device_bootstrap_authorizations (user_id, token_sha256, expires_at)
   select i.user_id, '<SHA256_DIGEST>', now() + interval '7 days'
   from supreme.identities i
   where i.public_id = 'supreme'
     and i.role = 'ruler'
     and i.is_active = true
     and (
       select count(*) from supreme.identities
       where public_id = 'supreme' and role = 'ruler' and is_active = true
     ) = 1
     and not exists (
       select 1 from supreme.devices d where d.user_id = i.user_id
     )
     and not exists (
       select 1 from supreme.device_bootstrap_authorizations b
       where b.user_id = i.user_id
         and b.consumed_at is null
         and b.expires_at > now()
     )
   returning id, expires_at;
   ```
4. Keep `$TOKEN` offline. Enter it only into the Android app's first-device bootstrap field after password + TOTP. The app sends it over HTTPS; the API hashes it immediately. The raw code is never stored in the database or Android session storage.
5. Clear the shell variable after securely recording the code offline: `unset TOKEN`.

The SQL insert must return exactly one row. Zero rows means the identity/device/pre-existing authorization preconditions were not met; stop and investigate rather than weakening the checks. The code expires after seven days and is consumed atomically only when the first attested device and its four-hour app session are registered successfully. Any pre-existing device history, including revoked or blocked devices, permanently disqualifies this bootstrap path; use the separate recovery procedure instead.

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

### Break-glass recovery implementation

The recovery path is implemented as a separate flow; it does not reuse first-device bootstrap.

1. During secure owner provisioning, generate a 256-bit random recovery code locally and insert only its SHA-256 digest into `supreme.recovery_authorizations`. Keep the raw code offline and outside the phone.
2. Configure the Edge Function secrets `SUPREME_RECOVERY_NOTIFICATION_WEBHOOK_URL` and `SUPREME_RECOVERY_NOTIFICATION_WEBHOOK_SECRET`. The URL must be HTTPS. The receiver must verify the bearer secret and independently notify the owner; return 2xx only after accepting the notification.
3. When all trusted devices are lost, sign in with password + TOTP. Enter the offline recovery code and leave the recovery request ID empty. The API creates a pending request with a 24-hour cooling-off period and queues an independent notification.
4. If notification delivery fails or is not configured, the request remains blocked. Re-enter the same offline code after configuring the notifier to retry delivery; completion remains impossible until delivery is acknowledged.
5. After the cooling-off period, sign in again with password + TOTP, enter the same offline code and the recovery request UUID, and complete fresh Android hardware attestation with biometric proof-of-possession.
6. The database atomically consumes the recovery authorization, activates the newly attested device, creates its four-hour app session, and leaves all prior devices revoked. A replay cannot create another session.

Example operator provisioning (run locally; never paste the raw code into chat, a repository, or a ticket):

```sh
RECOVERY_CODE="$(openssl rand -hex 32)"
RECOVERY_SHA256="$(printf '%s' "$RECOVERY_CODE" | sha256sum | cut -d' ' -f1)"
printf 'Store this code offline now: %s\n' "$RECOVERY_CODE"
printf 'Insert only this digest in the intended Supreme Supabase project: %s\n' "$RECOVERY_SHA256"
unset RECOVERY_CODE
```

In the intended project's SQL Editor, insert the digest returned above:

```sql
insert into supreme.recovery_authorizations(user_id, token_sha256, expires_at)
select i.user_id, '<64_CHARACTER_SHA256_DIGEST>', now() + interval '365 days'
from supreme.identities i
where i.public_id = 'supreme' and i.role = 'ruler' and i.is_active = true
  and (select count(*) from supreme.identities
       where public_id = 'supreme' and role = 'ruler' and is_active = true) = 1
  and not exists (
    select 1 from supreme.recovery_authorizations a
    where a.user_id = i.user_id and a.consumed_at is null and a.expires_at > now()
  )
returning id, expires_at;
```

The insert must return exactly one row. The webhook is an external operator-controlled dependency and is intentionally not hard-coded or pointed at an unverified personal address. The application fails closed when the independent notification is unavailable.

## Implementation progress

- [x] Add `pending_approval` device state and a private, service-role-only enrollment-request table.
- [x] New attested device keys are inserted as pending and do not receive an app session.
- [x] Existing active devices may renew; revoked and blocked keys are rejected without changing their state.
- [x] A previously revoked Auth session cannot be reactivated by the registration RPC.
- [x] Session API and Android registration flow report pending approval without persisting an app session.
- [x] NEWEIX integration endpoint propagates the pending state instead of returning an empty session identifier.
- [x] First-device bootstrap authorization: 256-bit offline code, server-side SHA-256 digest, single-use atomic consumption, fresh AAL2 + verified Android attestation, and no historical device rows.
- [x] Android first-device bootstrap code entry is ephemeral and never persisted.
- [ ] Operator provisioning and migration application in the intended Supabase project.
- [x] Trusted-device approval challenge/signature verification and atomic activation API.
- [x] Android biometric-per-operation approval flow and pending-enrollment list.
- [x] Recheck the approver's active app session atomically when consuming an approval challenge.
- [x] Audit rejected enrollment signatures.
- [x] Trusted-device inventory API and Android dashboard listing with status, security level, last-seen time, and active-session count.
- [x] Remote revocation requires fresh AAL2, a 90-second one-time challenge, and a hardware-backed biometric signature from a different active trusted device.
- [x] Remote revocation atomically marks the target device revoked and invalidates every active app session on it; current device cannot be remotely revoked through this flow.
- [x] Audit successful and invalid-signature remote revocation attempts.
- [ ] Operator provisioning and migration application in the intended Supabase project.
- [x] Break-glass recovery request, 24-hour cooling-off, offline single-use authorization, fresh-AAL2 + hardware-attested completion, atomic old-session revocation, and independent notification outbox/webhook delivery.
- [x] PostgreSQL regression tests and CI for bootstrap, pending-device isolation, revoked/blocked key non-reactivation, and remote device revocation/replay/self-revocation.
- [ ] Configure and verify the independent recovery notification webhook in the intended Supabase project.
- [ ] Provision the offline recovery digest in the intended Supreme Supabase project.
- [ ] Physical-device validation of biometric approval, break-glass request/completion, and target-device re-attestation.

This is an intentionally incomplete hardening stage. Trusted-device approval, first-device bootstrap, device inventory, and biometric remote revocation are implemented in code. Operator provisioning, migration/Edge Function deployment, break-glass recovery, full approval/recovery regression coverage, and physical-device verification remain outstanding. Do not deploy these migrations as a complete enrollment/recovery solution.

## Database/API implementation sequence

1. Add a migration for `pending_approval`, enrollment requests, approval challenges, recovery requests, and consumed recovery credentials. Keep all tables in the private `supreme` schema with RLS enabled and service-role-only access.
2. Replace the current registration RPC so attestation creates pending enrollment unless the one-time first-device bootstrap rule is satisfied. Never change `revoked` or `blocked` back to `active` on conflict.
3. Add server-issued approval challenge and approval endpoints. Verify ECDSA signatures with the registered public key of the currently active approving device; do not accept a public key supplied by the client.
4. Add device inventory, approve, revoke, and recovery APIs with fresh AAL2 checks, strict request schemas, rate limits, biometric signatures for destructive actions, and audit events. The device inventory and remote-revocation API are implemented in the follow-up migration and session function.
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
