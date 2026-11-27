# Neweix Ecosystem Governance and Operating Charter

**Status:** Canonical and controlling ecosystem charter  
**Authority:** Supreme  
**Effective date:** 2026-11-27  
**Scope:** All repositories, services, environments, identities, data, and operational workflows owned by Neweix

This document is the single authoritative governance and ownership reference for the Neweix ecosystem. Older copies of `ECOSYSTEM_MASTER_BLUEPRINT.md` in service repositories are historical pointers only. Where local documentation conflicts with this charter, this charter takes precedence until Supreme approves a replacement.

## 1. Authority and operating model

The authority model is deliberately simple:

1. **Supreme is the highest and final authority.** Supreme owns ecosystem policy, authority delegation, reserved approvals, emergency suspension/revocation, and oversight. No Admin, employee, service, customer, or automation may override Supreme.
2. **Admin is the single day-to-day operational authority.** Admin conducts and coordinates ordinary business and service operations across the ecosystem within the permissions delegated by Supreme. Admin is responsible for getting the work done; Supreme is not the routine order, catalogue, support, or workforce operator.
3. **Employees and service operators work under Admin's delegated direction.** They receive only the service-scoped permissions required for their assigned duties.
4. **Customers and service identities are not authority roles.** A customer Account, an employee record, an Admin grant, a Supreme identity, and a machine/service identity must never be treated as interchangeable.

Supreme's authority is not reduced by delegating daily operations. Admin's operational responsibility does not grant Admin the power to change Supreme policy or self-elevate privileges.

### Supreme responsibilities

- Set and amend ecosystem-wide policy and ownership boundaries.
- Appoint, approve, scope, suspend, and revoke the Admin authority grant.
- Approve reserved/high-impact actions, including new services, repository ownership changes, production security/secret changes, destructive operations, migrations with material risk, payment/provider activation, EIX issuance/limits/gift policy changes, and production deployment authority.
- Freeze a service or capability when security, legal, integrity, or operational risk requires it.
- Review cross-service risk, audit records, exceptional incidents, and Admin performance.
- Resolve conflicts between service policies and this charter.

### Admin responsibilities

Admin runs normal day-to-day operations across the ecosystem, including:

- Shop catalogue, product publication within approved policy, pricing operations, inventory, orders, fulfilment, returns, and customer support.
- Eixon operational review, customer support, approved EIX load/gift workflows, and reconciliation visibility. Admin cannot create EIX or change monetary/token limits outside Supreme-approved policy.
- Neweix+ subscription support, entitlement operations, collection/benefit fulfilment, and customer assistance.
- Connect service operations, support conversations, abuse queues, and routine moderation.
- Eixora content/community operations and routine moderation.
- Employee onboarding/offboarding requests, duty allocation, and routine workforce administration within Supreme-approved authority.
- Service health review, incident triage, routine content/configuration updates, and operational reporting.
- Cross-service coordination and customer service.

Admin must use the service's approved interface/API. Admin does not receive direct unrestricted database access, provider root credentials, or the ability to bypass a service's authorization checks. Sensitive customer credentials, passwords, MFA seeds, and private message contents are not exposed merely because someone is Admin.

### Reserved actions

Admin may prepare and request a reserved action, and may execute it after the required approval. Supreme approval is required before:

- Changing this charter, the authority hierarchy, or service ownership.
- Creating or removing a service/repository or changing a canonical service identity.
- Granting or escalating Admin/Supreme/workforce privileges.
- Enabling a production payment, payout, deposit/withdrawal, external provider, or other regulated financial function.
- Changing EIX issuance, loading constraints, gift limits, or financial/token policy.
- Running destructive production migrations, deleting production data/resources, changing production DNS/custom domains, or rotating high-impact secrets.
- Enabling production write adapters or executing an irreversible/high-impact operation.

Routine operational work does not require Supreme approval each time, provided it is within a documented and tested Admin grant.

## 2. Identity boundaries

| Identity | Authority and ownership | Must not be used as |
|---|---|---|
| Supreme | One protected ruler identity, owned by Supreme and its isolated authorization records | Customer Account or employee/Admin identity |
| Admin | A workforce principal with an explicit Supreme-approved operational grant; workforce record owned by Employees | Supreme identity or customer Account |
| Employee | Workforce identity and assigned duties, owned by Employees | Customer identity or Supreme authority |
| Customer | Central identity, credentials, sessions, account ID and customer profiles, owned by Neweix Account | Admin, employee, or Supreme authority |
| Service identity | Narrow server-to-server principal for one integration and environment | Human login or universal administrator |

Neweix Account is the sole customer identity authority. A person may have multiple customer profiles/business identities beneath one Account, but that does not create workforce or Supreme authority. Supreme authentication remains separate from customer login. Admin and employee access must use the workforce/privileged authorization model, not a customer-supplied role, username, profile field, or browser flag.

The canonical [Admin Grant Contract v1](./contracts/admin-grant-v1.md) defines the required identity, token, approval, scope, revocation and service-side validation boundaries. It is design-only until implemented and tested. Until the Employees service and Admin grant issuer are implemented and tested, no new Admin identity, staff identity, or privileged access path may be fabricated. Existing operational access must remain explicitly provisioned and audited.

## 3. Repository and service ownership

Each repository below owns its domain code and data. Supreme owns governance and the registry; Neweix provides the central public hub and Admin entry point. Neweix is not the owner of every service's private database.

| Repository | Service | Source-of-truth responsibility |
|---|---|---|
| `neweix24/supreme` | Supreme | Highest authority, governance policy, approvals, registry, privileged audit, and protected Supreme Android/control-plane security |
| `neweix24/neweix` | Neweix | Public website, central service directory, ecosystem navigation, Admin workspace entry point, and cross-service operational overview |
| `neweix24/account` | Neweix Account | Customer credentials, signup/login, central Account ID, customer profiles, recovery, customer sessions, and customer verification |
| `neweix24/employees` | Employees | Admin/workforce identity records, employee records, job roles, and delegated workforce permissions |
| `neweix24/eixon` | Eixon | EIX policy implementation, EIX wallet records, EIX unit ledger, approved loading/gift/purchase lifecycle, and EIX audit/reconciliation |
| `neweix24/shop` | Neweix Shop | Neweix's single-vendor catalogue, cart, orders, inventory, fulfilment, returns, and shop support |
| `neweix24/connect` | Neweix Connect | Conversations, memberships, messages, attachments, notifications, privacy, and communication abuse controls |
| `neweix24/neweix-plus` | Neweix+ | Subscription plans, billing periods, membership state, entitlements, and member benefits |
| `neweix24/eixora` | Eixora | Social profiles, posts, feeds, comments, reactions, follows, discovery, and moderation data |

The current branch/implementation status is recorded in [the machine-readable ecosystem registry](../config/ecosystem-registry.json) and [the implementation inventory](./ecosystem-feature-inventory.md). A repository name, DNS record, Worker name, feature branch, or draft PR does not by itself prove that a service is deployed or production-ready.

## 4. Service interaction rules

- Neweix is the ecosystem's main public entry point and service directory. It must not silently become the source of truth for Account, Eixon, Shop, workforce, messaging, subscription, or social data.
- Admin uses the Neweix Admin workspace as the operational entry point where available, then works through the owning service's authenticated API/UI.
- Supreme uses its own protected app/backend and versioned, allow-listed integrations. A registry entry is not permission to execute an operation.
- Account authenticates customers. Participating services must use an approved first-party service-client/OIDC contract; they must not create competing customer passwords or trust client-provided Account IDs.
- Employees owns workforce records. Supreme approves the Admin authority grant; each service validates the grant and its scopes server-side.
- Eixon owns EIX records and the authoritative ledger. Shop and Neweix+ may request payment through an approved Eixon contract but must never write Eixon balances or ledger entries.
- Connect, Shop, Eixon, Neweix+, and Eixora keep their own domain records. Cross-service reads/writes must use versioned API contracts and narrow service identities.
- A shared Supabase project is not permission to share tables. Use service-owned schemas/tables, explicit grants, RLS, and tested RPC/API boundaries.
- No secrets, service-role keys, signing keys, provider credentials, or customer tokens belong in source code, frontend bundles, or the registry.

## 5. Eixon product policy

EIX is a Neweix ecosystem utility token intended to make purchases of Neweix products and services easier. It is not to be presented or implemented as a virtual currency, virtual asset, cryptocurrency, investment, cash balance, external payment instrument, or general-purpose external transaction medium.

Binding product boundaries:

- EIX is usable only for eligible Neweix-owned products and services.
- EIX acquisition/loading uses an approved direct online payment method inside the Eixon flow. Eixon is responsible for the load/payment record and EIX ledger. Provider activation requires separate verification and Supreme approval.
- Do not create third-party EIX merchants or an EIX marketplace for buying/loading EIX.
- No ordinary person-to-person transfer, wallet-to-wallet transfer, Account ID transfer, username transfer, or QR-based transfer.
- Only a separately designed, designated gift workflow may be offered. The current maximum gift limit is **BDT 1,000 per gift**. Admin cannot change this limit. Supreme alone may amend it.
- No cash-out, withdrawal, external remittance, or general deposit/withdraw dashboard function. Any future legally approved function requires explicit Supreme approval and a separate policy/release gate.
- Each customer Account has exactly one Eixon wallet. Personal and Business Profiles under the same Account use that same wallet and do not create separate wallets.
- Eixon owns the EIX unit ledger. Shop and Neweix+ consume approved Eixon payment contracts; neither creates a shadow balance or ledger.

The current Eixon repository contains legacy reward, transfer, EixVerse, and Neweix+ source. Those legacy flows are not authority to enable features. They must remain unavailable until replaced by code matching this policy. The current standalone-ledger Draft PR is not approved for merge as-is.

## 6. Commerce, subscriptions, and customer services

- Shop is a Neweix-owned single-vendor store, not a multi-vendor marketplace.
- Shop checkout must use Eixon only. COD, direct MFS/card gateways, and other alternate checkout methods are not allowed under the current policy.
- Shop checkout remains disabled until Account customer access, Supreme-approved Admin authorization, Eixon payment intent/confirmation/refund/reconciliation contracts, order lifecycle, delivery, and database policy gates are verified.
- Neweix+ is a separate subscription/entitlement service. Its provisional tiers are Free, Plus, Premium, and Elite. It must not be implemented as an Eixon membership module.
- Paid Neweix+ subscription payments use Eixon only. Neweix+ owns plan/membership/entitlement state; Eixon owns the payment and EIX ledger record.
- Connect is a communication product, not a generic integration bus. Do not claim end-to-end encryption until the complete protocol and key lifecycle are designed, reviewed, and tested.
- Eixora is a separate social platform. It uses Account for customer identity but owns social profile and content data.

## 7. Canonical documentation and change control

- This charter is the only master governance/ownership document.
- `config/ecosystem-registry.json` is the canonical repository/service inventory for planning and review.
- `config/service-registry.example.json` is the schema-valid example for Supreme's runtime registry. It lists metadata only; it grants no operation or capability.
- Local repositories may document their own implementation and runbooks, but their master-blueprint copies must link here rather than reproduce this architecture.
- A change that affects more than one service must update the contract and affected service documentation together. Do not copy or edit another service's private schema as a shortcut.
- Main/default branch is authoritative only for merged source. Draft PRs and feature branches are work in progress; they do not replace main until reviewed and merged.
- Production deployment, DNS, database migrations, credentials, destructive actions, and external provider activation require the applicable approval and release gates.
- Every privileged action must be authenticated, authorized server-side, least-privileged, idempotent where relevant, and auditable.

## 8. Current delivery order

1. Align every repository's local charter and remove stale copied master blueprints.
2. Reconcile Supreme's service registry with all nine repositories and retire the obsolete `neweix-message` registry alias in favor of `neweix-connect`.
3. Complete Account's production deployment and publish a tested customer service-client/OIDC contract.
4. Rebuild Eixon's active product surface to implement this EIX policy; keep the standalone-ledger draft unmerged until aligned.
5. Complete Shop's working branch release gates and resolve its PR/base-branch strategy before merge.
6. Fix Connect conversation membership, RLS, and atomic creation before enabling messaging.
7. Implement Employees/Admin grant foundation, then Neweix+ and Eixora as separate services.
8. Add service-scoped Admin operations in Neweix and Supreme oversight only after each owning service API is tested.

No repository is to be merged, deleted, or deployed merely to make the status table look complete.
