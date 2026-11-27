# Neweix Ecosystem Governance

**Status:** Canonical governance baseline  
**Authority:** Supreme  
**Applies to:** Every repository, service, environment, operator, integration and data store owned by Neweix.

## 1. Constitutional hierarchy

1. **Supreme is the highest authority of the Neweix ecosystem.** Supreme owns the ecosystem constitution, global policies, service registry, security baseline, privileged approvals, root governance and audit requirements.
2. **Admin is the central operational authority.** Admin operates and coordinates day-to-day activities across all Neweix services using explicitly granted, scoped and auditable permissions.
3. **Service owners are technical custodians.** Each service owns its implementation, domain data, APIs, reliability and service-specific controls. Service owners do not create competing ecosystem-wide identity, payment, policy or authority systems.
4. **Users and business profiles act only within their own permissions.**

Admin is responsible for operating the ecosystem, but is not above Supreme and does not inherit Supreme-only powers. No Admin role, service account, automation or repository maintainer may override Supreme policy.

## 2. Reserved Supreme powers

Only Supreme-approved, authenticated and auditable authority may:
- amend this governance baseline or the canonical service registry;
- appoint, suspend, scope or revoke top-level Admin grants;
- change global security, identity, financial or data-governance policy;
- approve production activation of a service or high-risk capability;
- authorize exceptional access, break-glass operations or cross-service data access;
- approve EIX issuance/adjustments, exceptional ledger corrections, refunds outside policy, or changes to Eixon financial invariants;
- approve destructive production changes, migrations with material data risk, domain/ownership transfers, or root credential rotation;
- resolve conflicts between services or policies.

Supreme authority itself must use strong authentication, device-bound authorization where supported, explicit intent, short-lived grants and immutable audit evidence. A code repository or GitHub administrator is not automatically Supreme.

## 3. Admin operating mandate

Admin coordinates and performs routine operations across all services, within assigned scopes:
- customer support, account review and policy-compliant moderation;
- catalog, product, inventory, order and fulfilment operations in Shop;
- content, community and safety operations in Connect and Eixora;
- subscription support and benefit administration in Neweix+;
- employee onboarding, roles, schedules and operational administration;
- service status, operational configuration, incident handling and reporting;
- routine refunds/cancellations or account restrictions only where a documented policy and permission explicitly allow them.

Every privileged action must record actor, role/grant, target, action, reason, timestamp, request/correlation ID and outcome. High-risk actions require dual control or a Supreme approval according to the service policy.

Admin must not:
- grant itself Supreme authority or expand its own permissions;
- change the global constitution, service ownership or reserved limits;
- access raw credentials, secrets or private data without a documented operational need and approved scope;
- write directly to another service's database or financial ledger;
- bypass service APIs, RLS, audit controls, approval workflows or release gates;
- activate a disabled financial, identity or production capability by changing an environment variable alone.

## 4. Single ownership rules

| Concern | Sole authoritative owner | Other services may |
|---|---|---|
| Supreme authority, global policy, Admin grants, service registry | Supreme | Request/consume approved grants and registry data |
| Public ecosystem entry point and service directory | Neweix | Link to canonical service destinations |
| Person identity, Account ID, username, authentication and profile identity | Account | Consume verified identity/claims; never create a competing customer identity |
| EIX, Wallet, balance, journal and financial ledger | Eixon | Request payment operations and consume signed results |
| Products, variants, stock, carts, orders and fulfilment | Shop | Request Eixon payment; consume Account identity |
| Conversations, messages and communication data | Connect | Consume Account identity and approved moderation grants |
| Subscription plans, entitlements and membership lifecycle | Neweix+ | Request Eixon payment and verify Account identity |
| Social profiles, posts, feeds and social interactions | Eixora | Consume Account identity and approved moderation grants |
| Workforce records and operational role assignment | Employees | Request/verify Admin grants; cannot grant Supreme authority |

No service may maintain a shadow copy that becomes authoritative for another service's domain. Read-only projections and caches are allowed if their source, freshness and invalidation rules are explicit.

## 5. Identity and authorization

- Account is the only customer identity provider. Account ID is permanent; profile/business identities belong to the Account.
- Service-to-service authentication uses registered clients, least-privilege scopes, audience-bound tokens, short expiry and key rotation.
- Admin access is a separate workforce/privileged identity and grant model. A customer Account is not automatically an Admin.
- Supreme approval is a distinct authority and must never be inferred from an Admin role, email address, repository access or a client-side flag.
- Every service authorizes on the server. UI hiding is not authorization.
- All cross-service calls verify issuer, audience, signature, expiry, scope, tenant/resource ownership and replay/idempotency controls.

## 6. Financial and commerce invariants

- Eixon alone owns EIX issuance, balance, wallet and ledger.
- EIX is a Neweix ecosystem token used to make purchases of Neweix products/services easier. It is not a virtual currency, virtual asset or external transaction medium under the approved product policy.
- EIX may be loaded through approved direct online payment methods. No Eixon merchant network is used to acquire EIX.
- No ordinary P2P transfer, wallet-to-wallet transfer, or Account ID/username/QR transfer.
- Only the designated gift flow is allowed; the current maximum gift limit is BDT 1,000 and is controlled by Supreme.
- Shop and Neweix+ must use Eixon payment contracts. They must never maintain EIX balances or ledger entries locally.
- Shop checkout, refunds, subscription renewals and payment confirmation remain disabled until signed payment-intent, confirmation, idempotency, refund, webhook and reconciliation contracts are implemented and tested.
- Deposit/withdrawal features remain disabled pending explicit legal and Supreme approval.

## 7. Data, API and deployment boundaries

- Each service owns its database schema and private data.
- Cross-service access occurs only through versioned, authenticated APIs or explicitly approved events.
- No shared database credentials, direct cross-service table writes, duplicated ledger, or implicit trust based on network location.
- Use idempotency keys for commands that can create financial, order or subscription effects.
- Use an outbox/inbox or equivalent reliable event pattern for cross-service state changes.
- Secrets remain in the owning platform's secret manager; never commit secrets.
- Production migrations are forward-only, reviewed, backed up and reconciled against migration history before application.
- Disabled capabilities fail closed. A missing integration is a blocker, not permission to use a mock or fallback payment method.
- Production activation requires security review, tests, observability, rollback plan, data migration review and Supreme-approved release authorization for high-risk capabilities.

## 8. Repository and documentation rules

- This file and `config/ecosystem-service-registry.json` are the canonical governance references in the Supreme repository.
- Other repositories keep only service-specific documentation and a short pointer to these canonical references. They must not fork or silently redefine global policy.
- The Neweix public service directory is a presentation of the registry, not an independent authority. Until automated registry consumption is implemented, any copied status must be marked as a synchronized projection with a recorded source revision.
- One service, one repository owner, one authoritative database, one contract per integration.
- Do not merge stale branches or old architecture proposals solely to make branches look unified.
- All changes go through reviewable branches and pull requests. Keep risky migrations and production activation separate from documentation alignment.

## 9. Conflict resolution

When sources disagree, apply this order:
1. Latest explicit Supreme-approved policy recorded in the canonical governance repository.
2. This governance baseline and canonical registry.
3. Approved service contracts and security policies.
4. Current implementation, only where it does not violate the above.
5. Older README files, copied blueprints, stale branches and unapproved proposals.

A conflict must be recorded and resolved in the owning service. Do not silently pick whichever implementation is easiest.

## 10. Current rollout status

The registry records observed implementation status, not desired maturity. "Deployed" does not mean all features are enabled. "Foundation" and "Planned" must not be presented as production-ready. Checkout, financial operations, privileged Admin actions and unfinished integrations remain fail-closed until their release gates pass.
