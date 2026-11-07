# Ecosystem feature consolidation inventory

This inventory records features that already exist in the ecosystem so Supreme can control them without reimplementing their business logic.

## Operating rule

- Keep each service's business logic and authoritative data in its owning repository/service.
- Supreme owns the central control plane: service discovery, service-scoped authorization, approval, audit, remote configuration, and orchestration.
- A capability listed here is **implemented in its source service**, not automatically callable from Supreme.
- A capability becomes controllable from Supreme only after its service adapter is implemented, narrowly authorized, and integration-tested.
- Never copy production secrets or apply another service's migrations into Supreme.

## Existing implementation inventory

| Service | Already implemented source areas | Current Supreme status |
|---|---|---|
| **Neweix** | Storefront/catalog, cart/checkout, orders/payments, Pathao delivery, inventory/warehouses, customer account, staff/workforce, search/reviews, transactional SMS, social publishing | Source is preserved in `neweix24/neweix`; Supreme-specific dashboard/API source was imported as a reference snapshot. Service execution adapter is not enabled. |
| **Eixon** | EixPay wallet/ledger, transfer requests, referral rewards, integrity chain/watchdog, EixVerse missions/campaigns, Neweix+ membership UI/status | Extracted to `neweix24/eixon`; source extraction is not yet a standalone deployable service. Supreme adapter is not enabled. |
| **Neweix Account** | Email/password signup, username-or-email login, TOTP MFA, password recovery, live session validation/revocation, central account/service-access foundation | Uses the existing Neweix Supabase project. Supreme validates the central identity for its registry API; full OAuth/OIDC SSO integration is not yet ready. |
| **Supreme** | Service registry, control-request approval queue, audit foundation, Android attestation verifier source/tests, imported Supreme dashboard panels | Registry and approval API are deployed. Provider execution adapters and a standalone dashboard runtime remain unfinished. |

## Feature ownership and source paths

The machine-readable source map is [`config/ecosystem-capabilities.json`](../config/ecosystem-capabilities.json). It records repository-relative source paths and explicitly separates source implementation from Supreme integration readiness.

## Already imported into this repository

- Android app and security source: `apps/android/`, `services/android-attestation/`.
- Supreme dashboard, API routes and feature panels extracted from Neweix: `integrations/neweix-commerce/next-app/`.
- Historical SQL and tests retained for reference only: `integrations/neweix-commerce/supabase/migrations-reference/` and `tests-reference/`.
- Registry and approval foundation: `services/registry/` and `supabase/functions/supreme-registry-api/`.

These imported files are not all standalone or production-ready. The dashboard snapshot still has Neweix application imports and commerce data dependencies. The reference SQL must not be applied as-is.

## Migration order

1. Bind each existing source capability to its owning service and stable capability ID.
2. Implement read-only service adapters first; do not copy the service's business logic into Supreme.
3. Add service-scoped permissions and auditable control requests.
4. Add write operations only when the owning service exposes a safe API and Supreme approval policy is tested.
5. Surface the existing controls in the Supreme Android/web dashboard using server-delivered capability metadata.

## Verification boundary

This document is a repository-source inventory. It does not claim that live provider credentials, production service APIs, deployment adapters, or all user-facing flows have been tested.
