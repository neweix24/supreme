# Supreme source extraction from NEWEIX

**Source repository:** `neweix24/neweix`  
**Destination repository:** `neweix24/supreme`

## What was imported

- Native Android project source, launcher resources, and app configuration under `apps/android/`.
- Supreme Android build, preview, and attestation reference workflows under `.github/workflows/`.
- Supreme dashboard pages, login page, UI features, and API route source under `integrations/neweix-commerce/next-app/`.
- Android Key Attestation verifier, Edge Function, tests, and helper scripts under `services/android-attestation/`.
- Supreme-related NEWEIX SQL migrations and database tests under `integrations/neweix-commerce/supabase/*-reference/`.
- Attestation security design documents under `docs/imported-from-neweix/security/`.
- Existing Supreme icon artwork.

## What this does not mean

- The original NEWEIX repository was not modified or deleted.
- The imported Next.js routes are not yet standalone; their dependencies on the old app must be untangled.
- The SQL migration files are references, not approved migrations for a fresh Supreme database.
- No production deployment, Supabase schema change, or credential transfer was performed.
- CI workflows were imported as a starting point; they still require execution and review in this repository.

## Next engineering steps

1. Run Android compilation in this repository and fix any missing Gradle wrapper/configuration issues.
2. Inspect Android package ID, private route configuration, signing, and attestation challenge lifecycle.
3. Map shared NEWEIX imports used by imported API/UI source.
4. Define Supreme-owned database schema independently; preserve commerce-owned data behind integration APIs.
5. Implement Supreme Core authentication, MFA, authorization, service registry, approvals, and audit events.
6. Add CI checks and require successful builds/tests before merge or release.
