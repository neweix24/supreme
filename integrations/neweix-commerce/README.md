# NEWEIX Commerce integration — imported Supreme modules

This directory contains a source snapshot of Supreme-related dashboard pages, API routes, UI features, and database artifacts that previously lived inside the `neweix24/neweix` repository.

## Important boundary

These files were extracted from the NEWEIX Commerce Next.js application. They are **not yet a standalone Supreme backend or deployable application**. Some modules import shared authentication, authorization, Supabase, UI, and domain helpers from the original NEWEIX application. Those dependencies must be identified and replaced with explicit versioned integration contracts before these files can be built independently.

## Contents

- `next-app/app/api/supreme/` — Supreme-related API route source snapshot.
- `next-app/app/supreme/` — Supreme web dashboard and route source snapshot.
- `next-app/app/auth/supreme-login/` — existing Supreme login page source.
- `next-app/features/supreme/` — dashboard feature components.
- `next-app/public/supreme-worker.js` — existing service worker source.
- `supabase/migrations-reference/` — NEWEIX database migration history used by the old implementation.
- `supabase/tests-reference/` — related database security and behavior tests.

## Database migration safety

Files in `migrations-reference` are preserved for traceability and design reuse only. **Do not apply them to a new Supreme Supabase project as-is.** They may depend on NEWEIX Commerce tables, functions, roles, RLS policies, and existing migration order. Extract Supreme-owned schema into new migrations only after dependencies are mapped and reviewed.

## Extraction plan

1. Map all imports from the original NEWEIX app to explicit shared contracts.
2. Separate Supreme-owned data from commerce-owned data.
3. Move Supreme-owned API operations into the independent Supreme Core API.
4. Keep commerce actions behind narrow, server-to-server integration APIs.
5. Add integration tests and verify authorization before enabling write operations.
