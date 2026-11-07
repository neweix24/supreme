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

## Registered services\n\nThe initial registry bootstrap includes:\n\n| Service | Repository | State | Notes |\n|---|---|---|---|\n| Neweix | `neweix24/neweix` | active | Existing production website; read-only observation only until adapters exist. |\n| Neweix Shop | `neweix24/shop` | planned | Standalone Shop extraction and migration are in progress. |\n| Eixon | `neweix24/eixon` | planned | Source extraction only; not yet a standalone deployable application. |\n| Neweix Account | `neweix24/account` | planned | Central identity system; uses the existing Neweix Supabase Auth project. |\n| Neweix Message | Not registered yet | planned | Repository and adapter have not been identified. |\n| Supreme | `neweix24/supreme` | planned | Central control plane is still being built. |\n\nNo service capabilities or provider secret references are enabled in the initial seed. This prevents the registry from implying that an adapter can already execute operations.\n\n## Tables

- `services`: canonical service/repository metadata and risk classification.
- `service_environments`: development, staging, and production endpoints and enablement.
- `service_capabilities`: explicit allow-listed capabilities; no wildcards.
- `service_secret_refs`: opaque secret-manager reference identifiers.
- `control_requests`: idempotent, approval-gated control requests.
- `audit_events`: immutable audit history.

## Identity

The registry does not create another Supreme account or identity table. The API validates the signed-in user in the existing shared Supabase Auth project and confirms the single active `public.staff_profiles` row (`role = 'supreme'`, `public_id = 'supreme'`, `is_active = true`). It does not require a Neweix Account customer row. Future Neweix Employees remain a separate identity/workforce domain. Android PIN/biometric unlock is not server authorization. Android PIN/biometric unlock is not server authorization or MFA.

## Migration

Applied to the existing Neweix Supabase project as migration `supreme_service_registry_v1` (database version `20261107141546`). The authenticated registry Edge Function is maintained at `supabase/functions/supreme-registry-api`.
