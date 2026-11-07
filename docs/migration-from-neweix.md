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

## Known coupling that still needs removal

The imported Android shell currently loads the private workspace from `https://neweix.com` and uses the former NEWEIX private-path configuration. This is preserved as historical implementation, not accepted as the final independent Supreme app architecture. Before a separate Supreme release, move the shell to a Supreme-owned domain/API origin, replace the private-path discovery mechanism with authenticated backend sessions, and verify that no production secret is embedded in the APK. The old README explicitly documents that the private path is extractable and is not an authentication factor.

The imported Next.js API routes and dashboard are also commerce-app-bound. They must not be treated as the new Supreme Core API until their imports, data ownership, and authorization boundaries are refactored.
