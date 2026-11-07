# Supreme security and integration audit — 2026-11-08

## Scope

Reviewed the Supreme repository's Android login/MFA flow, session and registry Edge Functions, Android attestation verifier, Neweix server integration routes, and connected Supabase project. This is a code/configuration audit, not a penetration test or physical-device certification.

## Confirmed findings and fixes in this change

### 1. Supreme identity authorization still depended on the deleted staff table

The live database no longer contains `public.staff_profiles`, but `private.has_staff_role(text[])` still queried it. Supreme EixPay/Eixverse control RPCs use this helper, so those operations could fail at runtime. Two product-review moderation RPCs also queried the removed table directly.

**Fix:** the helper now authorizes only the active `supreme.identities` row with `public_id='supreme'` and `role='ruler'`. The two review RPCs now perform the same direct Supreme identity check and retain AAL2 enforcement. Non-Supreme employee roles are not inferred from a Supreme identity.

### 2. Server routes queried a schema the authenticated role cannot read

The live database reports no `USAGE` privilege on schema `supreme` and no `SELECT` privilege on `supreme.identities` for `authenticated` (or `anon`). Twelve Next.js integration call sites queried that table directly, which fails closed even for the actual Supreme account.

**Fix:** added `public.is_current_supreme_ruler()`, a narrowly scoped SECURITY DEFINER RPC that returns only a boolean for the current JWT subject. Integration middleware, server helpers and API routes now use this RPC; the private identity table remains inaccessible to client roles.

### 3. A deployed control-plane function was missing from source control

The live `supreme-neweix-api` Edge Function was active (version 2), but no matching source file existed in this repository.

**Fix:** the deployed function source is now checked into `supabase/functions/supreme-neweix-api/index.ts` and included in the Deno type-check workflow.

## Supabase security review

- All nine tables in the `supreme` schema have RLS enabled. They have no client-role table grants; `service_role` is the only role found with table access. This is consistent with the server-only data-access model.
- Security Advisor now reports 34 authenticated-callable SECURITY DEFINER functions: 33 pre-existing functions plus the new boolean-only `public.is_current_supreme_ruler()` RPC. The inspected functions bind data to `auth.uid()`; Supreme control functions additionally enforce AAL2 and the Supreme role check. These warnings are not 34 confirmed vulnerabilities.
- One anonymous-callable SECURITY DEFINER function, `public.eixpay_list_product_reviews(uuid)`, displays approved product reviews without login. Its query returns only approved reviews and is intentionally public; retain that narrow result set.
- Security Advisor reports leaked-password protection disabled. Enabling Supabase's HaveIBeenPwned-backed password protection requires an eligible Supabase plan and the Auth password settings in the Dashboard.
- The database contains `public.supreme_custom_access_token_hook(event jsonb)`, and `supabase_auth_admin` has EXECUTE permission. The hook verifies the active `supreme.identities` row, AAL2, an active device-bound session, app package, security level, and 30-day attestation freshness. The connected project tools do not expose the Auth Hooks activation setting, so activation itself remains unverified.

## Authentication and Android release status

- Supabase Auth logs recorded password-grant failures with `captcha_failed: no captcha_token found` before the Turnstile fix. No successful physical-device login after the fix has been observed yet.
- The identity authorization migration is applied to the connected Supabase project as `20261107185618_supreme_identity_authorization_hardening`; the SQL regression test passed after application.
- Both Android debug build workflows passed for commit `9cdd3e4`. Those artifacts are debug-signed preview APKs, not production releases.
- The production release workflow requires the production keystore, store password, key alias, key password, and a signer SHA-256 fingerprint matching the server-side attestation configuration. Until those production signing values are configured and a release workflow succeeds, a debug APK must not be treated as a production-authenticated app.
- CAPTCHA, TOTP, Google Android Key Attestation, proof-of-possession, device registration, refresh-token rotation, and server-side revocation still require a physical Android device test.

## Remaining cross-repository work

Several legacy commerce/warehouse RPCs still contain direct references to the removed `public.staff_profiles` table (order status, returns, Pathao booking, warehouse allocation, and product submission review). Their authorization must be migrated to the separate employee identity system in the appropriate Neweix/Employees repository. Do not recreate `public.staff_profiles` as a workaround.

## Deployment order

1. Merge this change after all CI checks pass.
2. The identity authorization migration is already applied and the live `supreme-neweix-api` version 2 source matches the newly versioned repository source.
3. Configure the production Android signing secrets and matching attestation fingerprint.
4. Install the production-signed APK on a physical Android device and verify Turnstile → password → TOTP → hardware attestation → device-bound session → registry access.
5. Confirm the Supabase Custom Access Token Hook is enabled in Auth Hooks settings.
6. Re-run Supabase Security Advisor and verify that Supreme-specific identity/access failures are resolved.
