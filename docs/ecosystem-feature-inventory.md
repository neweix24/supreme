# Ecosystem implementation inventory

**Audit date:** 2026-11-27  
**Authority:** Supreme  
**Canonical governance:** [Ecosystem Governance and Operating Charter](./ecosystem-governance-charter.md)  
**Machine-readable inventory:** [`config/ecosystem-registry.json`](../config/ecosystem-registry.json)

This document records repository-level implementation evidence. A planned service, DNS record, branch, draft PR, or source snapshot is not a production capability.

## Authority and operating rule

- Supreme is the highest and final authority for policy, reserved approvals, Admin delegation, suspension/revocation, and oversight.
- Admin conducts normal day-to-day operations across services within its approved service-scoped grant.
- Each service owns its data and business logic. Supreme and Neweix do not duplicate or directly mutate another service's private data.
- A feature is operational only when its owning service implementation, API, authorization, database, tests, and deployment are verified.
- Registry membership does not grant execution permission.

## Repository inventory

| Repository | Responsibility | Verified source state on 2026-11-27 | Operational position |
|---|---|---|---|
| `neweix24/supreme` | Supreme authority, governance, approval, registry, privileged audit, protected Android app | Android app, session/device security, registry, attestation verifier/tests, and governance docs. Latest Android production workflow and CodeQL succeeded 25 Nov; APK artifact exists. | Active authority foundation. Provider execution adapters and some registry/session acceptance remain gated. |
| `neweix24/neweix` | Public ecosystem hub, directory, Admin entry point | Next.js public site, homepage, service directory, search/health APIs. CI and Cloudflare Worker deploy succeeded 27 Nov. | Public hub deployed; full Admin operations workspace and service integrations are not complete. |
| `neweix24/account` | Customer identity, Account ID, profiles, sessions and verification | Signup/login, username login, recovery, MFA, phone verification API, account security and migrations. | Production Worker/custom domain documented. Latest production deploy failed on 14 Nov because `CLOUDFLARE_API_TOKEN` was unavailable; OIDC service-client contract and full E2E acceptance remain open. |
| `neweix24/employees` | Workforce and Admin identity/grants | DOMAIN, README, ARCHITECTURE, ECOSYSTEM_ALIGNMENT and TODO now define workforce ownership, Admin grant lifecycle and delivery gates. | Documentation foundation only. No application, database, grant issuer, Admin principal, CI or verified runtime. Do not fabricate Admin/staff records. |
| `neweix24/eixon` | EIX token, wallet, unit ledger, approved loading/gift/purchase lifecycle | Current main has an EIX policy README/entry screen and routes disabling legacy wallet, P2P, referral, EixVerse, and Neweix+ surfaces. Historical SQL/functions remain. Draft PR #1 proposes a broader financial platform and is unmerged. | Policy realignment source work started. No standalone production runtime verified. API retirement responses return 410; database-level historical functions/privileges still require review. PR #1 must not merge as-is. |
| `neweix24/shop` | Single-vendor Neweix commerce | Main contains only three documentation entries. Application is on `feat/shop-ecosystem-remediation` with Next.js Storefront, NestJS API, Worker, tests and readiness docs. Draft PR #2 targets `neweix24-patch-1`, not `main`. | Storefront deployed; `/api` returns 503; catalogue/inventory are empty; checkout is disabled. CI passed 27 Nov. PR base/merge strategy and release blockers remain. |
| `neweix24/connect` | Messaging, conversations, notifications and attachments | Worker/API shell, initial migration, atomic conversation RPC/RLS hardening source, production API guard, Account table/status check, and CI workflow exist. GitHub Actions attempted two runs on 27 Nov, but both jobs failed before a runner was allocated; no CI steps executed. | Foundation only. Account service contract, isolated migration/RLS acceptance, complete messaging/realtime, and production deployment remain incomplete. |
| `neweix24/neweix-plus` | Subscription plans, memberships and entitlements | Domain declaration, README, ECOSYSTEM_ALIGNMENT and canonical Supreme charter pointer. | Documentation-only placeholder; no subscription application, database, API, CI, or verified runtime. Must not be implemented inside Eixon. |
| `neweix24/eixora` | Social platform and moderation | Domain declaration, README and ECOSYSTEM_ALIGNMENT. | Documentation-only placeholder; no social application, database, API, CI, or verified runtime. |

## Confirmed cross-repository corrections

1. Replace copied master blueprints in Neweix, Shop, and Neweix+ with links to the single Supreme charter.
2. Retire the obsolete Supreme registry alias `neweix-message`; register `neweix-connect` as the communication service.
3. Keep workforce/Admin identity in Employees; customer identity in Account; Supreme identity separate.
4. Remove Eixon's legacy person-to-person transfer and reward/membership surfaces from active routes. EIX is for Neweix purchases and the designated gift policy only.
5. Keep Neweix+ subscription/entitlement logic separate from Eixon.
6. Keep Shop on its reviewed remediation branch until its base-branch strategy and API runtime, Account SSO, Eixon contract, Admin grant, fulfilment, and schema gates are resolved.
7. Validate Connect membership/RLS and atomic-creation migrations in an isolated database; the source fix is not yet applied or production-tested. The new CI workflow failed before a GitHub runner was allocated, so no validation steps executed.
8. Implement the Employees Admin grant issuer and service-side validation against [Admin Grant Contract v1](./contracts/admin-grant-v1.md). The contract is currently design-only; no Admin principal or grant is active.

## Verification boundaries

- This is a GitHub source/metadata audit; not every source file has undergone line-by-line review.
- CI success proves only the jobs in that workflow. It does not prove every production integration or user journey works.
- Cloudflare deployment metadata, DNS presence, and Worker custom-domain bindings do not replace a controlled live HTTP/authentication test.
- Production database migrations, secret changes, DNS changes, deployments, merges, and destructive operations require their own review/approval gates.
