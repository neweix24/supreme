# Supreme registry database

The Supreme registry is stored in the existing Neweix Supabase project, but in a dedicated PostgreSQL schema named `supreme`.

## Isolation and security

- No new Supabase project is created.
- Existing Neweix commerce tables, Eixon financial tables, and Neweix Account tables are not reused or modified by this registry.
- The `supreme` schema is not exposed through the Supabase Data API and grants no access to `anon` or `authenticated`.
- Only server-side `service_role` operations may access registry tables. Never put the service-role key in Android or browser code.
- RLS is enabled on every table as defense in depth.
- `service_secret_refs` stores opaque references only, never secret values.
- `audit_events` is append-only for ordinary database operations.

## Tables

- `services`: canonical service/repository metadata and risk classification.
- `service_environments`: development, staging, and production endpoints and enablement.
- `service_capabilities`: explicit allow-listed capabilities; no wildcards.
- `service_secret_refs`: opaque secret-manager reference identifiers.
- `control_requests`: idempotent, approval-gated control requests.
- `audit_events`: immutable audit history.

## Identity

The registry does not create another Supreme account. The API must validate the signed-in Neweix Supabase Auth user server-side and confirm that the account is the single active `supreme` ruler identity before privileged access. Android PIN/biometric unlock is not server authorization or MFA.

## Migration

Applied to the existing Neweix Supabase project as migration `supreme_service_registry_v1` (database version `20261107141546`). The authenticated registry Edge Function is maintained at `supabase/functions/supreme-registry-api`.
