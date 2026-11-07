# NEWEIX → Supreme consolidation inventory

**Source:** `neweix24/neweix` (branch `main`)  
**Destination:** `neweix24/supreme`  
**Migration branch:** `migration/neweix-supreme-consolidation`

## Migration rule

Supreme-specific work is migrated into this repository without modifying the NEWEIX repository. Existing destination files are compared by Git blob SHA before copying. Identical files are retained rather than duplicated. Where the source and destination differ, the destination version is reviewed before replacement; a newer source revision is not automatically assumed to be safer.

## Scope checked

The source tree was scanned for 112 Supreme-owned or explicitly Supreme-scoped files across:

- Supreme Android app and native security helpers.
- Supreme dashboard routes, API routes, and feature components.
- Supreme Android attestation verifier, helper modules, tests, and reference fixtures.
- Supreme database migrations and security tests.
- Supreme-specific GitHub Actions workflows and security documentation.
- Supreme PWA/service-worker and icon assets.

Of these, 99 mapped files had identical Git blob SHAs in the destination. The remaining 13 differences were reviewed individually.

## Consolidation performed

- Updated the Android `MainActivity.kt` from the source revision after comparing the existing native shell.
- Added `SupremeAttestationClient.kt` as a native transport reference. It is not wired into login and must not be treated as authentication.
- Updated the attestation endpoint documentation with the latest challenge-attempt budget and production migration history.
- Added the Supreme web icon to the preserved commerce integration snapshot.
- Added the latest five timestamp-aligned Supreme SQL migration references and the missing attestation-attempt-budget SQL test.
- Kept the destination's three Android/attestation workflows because they already use the new Supreme repository paths. The source workflows still reference NEWEIX paths/branch names and were not copied over the adapted versions.

## Preserved source areas

- `apps/android/` — native Android app.
- `services/android-attestation/` — verifier source, helper modules, tests, and scripts.
- `integrations/neweix-commerce/next-app/app/supreme/` — existing dashboard routes.
- `integrations/neweix-commerce/next-app/app/api/supreme/` — existing Supreme API route snapshots.
- `integrations/neweix-commerce/next-app/features/supreme/` — dashboard feature components.
- `integrations/neweix-commerce/supabase/migrations-reference/` and `tests-reference/` — source database history and tests.
- `docs/imported-from-neweix/security/` — historical security and verifier decisions.

## Explicitly not done

- No changes were pushed to `neweix24/neweix`.
- No production database migrations were applied.
- No secrets, signing keys, API tokens, or environment files were copied.
- No production deployment or APK release was performed.
- No claim is made that the imported Next.js modules build independently.

## Known architecture boundary

The dashboard/API source was originally part of the NEWEIX Commerce Next.js application. Its shared imports, Supabase schema, RLS, and commerce-owned data dependencies must be mapped before it can be detached into Supreme Core. The Android shell and attestation client still point to `neweix.com`; these are preserved source dependencies, not the final independent Supreme hosting configuration.

## Next steps

1. Inventory imports and runtime dependencies of the preserved dashboard/API modules.
2. Define Supreme-owned identity, session, MFA, device-attestation, service registry, approvals, remote configuration, and audit contracts.
3. Separate Supreme-owned data from NEWEIX commerce data; keep migrations in reference-only status until a clean schema plan exists.
4. Build and test the Android app in this repository; fix any CI/path or signing configuration issues.
5. Move runtime control to a Supreme-owned API/domain and add integration tests before production enablement.
