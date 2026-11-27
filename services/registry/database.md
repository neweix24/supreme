# Supreme registry database

The Supreme registry is stored in the existing Neweix Supabase project in the isolated PostgreSQL schema `supreme`.

## Isolation and authority

- No second Supabase project or second Supreme identity source is created.
- Neweix commerce, Eixon, Account, Employees, Connect, Neweix+, and Eixora data remain owned by their respective services.
- The `supreme` schema is not exposed through the Supabase Data API and grants no access to `anon` or `authenticated` browser roles.
- Only server-side service-role operations may access registry tables. Never put service-role keys in Android or browser code.
- RLS is enabled as defense in depth.
- `service_secret_refs` stores opaque references only, never secret values.
- Audit events are append-only for ordinary application operations.

## Canonical service inventory

| Service ID | Repository | Responsibility | Current state |
|---|---|---|---|
| `supreme` | `neweix24/supreme` | Highest authority, governance, reserved approvals, oversight | Active foundation |
| `neweix` | `neweix24/neweix` | Public hub, service directory, Admin entry point | Deployed; integrations incomplete |
| `neweix-account` | `neweix24/account` | Customer identity and sessions | Worker deployed; deployment/E2E/OIDC gates remain |
| `employees` | `neweix24/employees` | Admin and workforce identity/grants | Placeholder |
| `eixon` | `neweix24/eixon` | EIX token, wallet and unit ledger | Policy realignment required |
| `neweix-shop` | `neweix24/shop` | Single-vendor commerce | Storefront deployed; API/checkout disabled |
| `neweix-connect` | `neweix24/connect` | Messaging and communication | Foundation only |
| `neweix-plus` | `neweix24/neweix-plus` | Subscription and entitlements | Placeholder |
| `eixora` | `neweix24/eixora` | Social platform | Placeholder |

The old `neweix-message` registry ID is a legacy alias and is retired by the forward migration. It is not a separate tenth service.

## Tables

- `services`: canonical service/repository metadata and risk classification.
- `service_environments`: environment declarations and endpoint metadata.
- `service_capabilities`: explicit allow-listed operations; no wildcards.
- `service_secret_refs`: opaque secret-manager reference identifiers.
- `control_requests`: idempotent, approval-gated control requests.
- `audit_events`: privileged audit history.

## Migration history and safety

The initial registry schema/seed is recorded in migrations `20261107141546` and `20261107141942`. Migration `20261127180000_supreme_ecosystem_registry_alignment.sql` reconciles repository metadata and registers the nine current services while retiring the obsolete `neweix-message` alias. It is a source migration only and has **not** been applied to the production database by this work.

Review the migration against live registry rows and migration history before applying it. Do not directly edit production registry rows or skip Supreme's protected approval/audit process.

## Identity

The registry does not create another Supreme account or identity table. Supreme authorization is based on the single active `supreme.identities` principal (`role = ruler`, `public_id = supreme`, `is_active = true`). Customer Account identities and Admin/employee workforce identities remain separate. Android PIN/biometric unlock is not server authorization or MFA.
