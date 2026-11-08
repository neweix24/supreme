# Supreme governance and authority model

**Version:** 1.0  
**Status:** Design baseline; enforcement must be implemented and tested  
**Owner:** Supreme  
**Applies to:** All Neweix ecosystem services

## 1. Purpose

This document defines the authority boundary between Supreme, Neweix, and the daily Admin. It complements the existing Supreme identity, session, service-registry, approval, and audit systems.

This is a policy specification. It does not by itself grant or enforce permissions. Runtime authorization must be implemented in server-side code and verified by tests before any capability is treated as active.

## 2. Authority hierarchy

### Supreme — highest authority

Supreme is the single highest authority for the ecosystem. The existing Supreme principal remains the only Supreme identity: `supreme.identities(public_id = 'supreme', role = 'ruler')`.

Supreme owns:
- Reserved governance decisions and ecosystem-wide policy.
- Appointment, suspension, and removal of the Admin role.
- Delegation and revocation of Admin permissions.
- Approval of high-impact, production, financial, access-control, and destructive actions.
- Emergency suspension of a service or privileged capability.
- Final review of security incidents and exceptional actions.

Supreme is not intended to perform every routine order, customer-support, or catalog task.

### Neweix — central headquarters and control plane

Neweix provides the central portal, service directory, operational overview, and administration workspace. It coordinates services through explicit APIs and does not become the owner of their private business data.

Neweix must:
- Display only the controls allowed by the authenticated actor's server-issued permissions.
- Send privileged requests to the owning service or Supreme control API.
- Preserve the approval reference and audit correlation ID across service calls.
- Never infer Supreme authority from a Neweix customer or employee account.

### Admin — daily administrator

Admin is the operational administrator responsible for routine daily activity across Neweix services, within a permission set delegated by Supreme.

Admin may perform routine, reversible business operations such as:
- Review and respond to customer support requests.
- Manage ordinary product listings and inventory within approved limits.
- Process routine orders, returns, and delivery workflows.
- Review service health and operational reports.
- Manage ordinary content moderation within published policy.
- Maintain routine settings that do not alter security, authority, financial rules, or production infrastructure.

Admin may not:
- Create another Supreme identity or claim the Supreme role.
- Change Supreme policies, reserved capabilities, or Supreme authentication.
- Grant or expand their own permissions.
- appoint or remove the Supreme ruler.
- Change financial issuance, currency rules, reserves, ledger controls, or transaction limits.
- Execute production infrastructure changes, credential rotations, or destructive actions without the required Supreme approval.
- Disable audit, security, MFA, device attestation, or approval requirements.

## 3. Identity separation

The following identities are distinct and must not be interchangeable:

| Identity | Source of truth | Purpose |
|---|---|---|
| Supreme ruler | `supreme.identities` plus Supabase Auth and attested Supreme session | Highest authority |
| Admin | Employees/workforce identity plus delegated Admin grants | Daily administration |
| Employee | Employees/workforce identity | Assigned operational work |
| Customer | Account identity | Customer access to services |
| Service principal | Service-specific machine identity | Narrow service-to-service calls |

A customer Account ID or Employee ID must never be accepted as proof of Supreme authority. The Supreme Android session must continue to require the server-signed, device-bound `supreme_app_session` claim and fresh AAL2 for protected operations.

## 4. Permission model

Use explicit, service-scoped capabilities. Deny by default. No wildcard grants.

Suggested permission namespaces:

- `admin.customers.read`
- `admin.support.manage`
- `shop.products.manage`
- `shop.inventory.manage`
- `shop.orders.process`
- `shop.returns.process`
- `connect.support.respond`
- `eixora.content.moderate`
- `reports.operations.read`
- `services.health.read`

Reserved Supreme-only capability namespaces include:

- `supreme.policy.manage`
- `supreme.admin.delegate`
- `supreme.authority.manage`
- `supreme.security.manage`
- `supreme.approvals.decide`
- `supreme.service.suspend`
- `supreme.integration.credentials.manage`
- `supreme.production.execute`
- `supreme.financial.policy.manage`
- `supreme.audit.retention.manage`

These names are design identifiers until their server-side policies and tests exist. A capability name in this document is not a live permission.

## 5. Risk and approval classes

| Class | Example | Required control |
|---|---|---|
| Routine | Read reports, answer support, process an ordinary order | Admin grant, service-side authorization, audit |
| Guarded | Bulk catalog changes, high-value refund, account restriction | Explicit capability, limits, fresh re-authentication where configured, audit |
| High impact | Production deployment, permission change, secret rotation, financial-rule change | Supreme approval, fresh AAL2, exact target/parameters binding, idempotency, execution verification |
| Critical | Delete production data, disable root security, revoke Supreme access | Disabled by default; separately designed break-glass procedure and out-of-band review |

Approval is not execution. An approval record only authorizes the exact action, target, environment, normalized parameters, expiry, and policy version. A separate executor must revalidate all bindings before acting.

## 6. Delegation lifecycle

1. Supreme creates or changes a named Admin grant.
2. The grant specifies exact capabilities, service scope, environment, limits, start time, and expiry/review date.
3. The system records the delegating Supreme principal, policy version, and audit event.
4. Admin receives only the resulting delegated permissions.
5. Supreme may revoke or suspend the grant immediately.
6. Expired or revoked grants must fail closed on the next server-side authorization check.

Admin must never be able to edit the grant that authorizes their own access.

## 7. Audit requirements

Record:
- Actor identity class and stable actor ID.
- Delegating authority, if the actor is operating under a grant.
- Capability and policy version evaluated.
- Service, environment, resource, and operation.
- Request and correlation IDs.
- Approval reference and exact action digest when applicable.
- Outcome, timestamp, and failure category.

Never record passwords, tokens, private keys, raw recovery codes, or unnecessary personal data. Audit storage must remain append-only or tamper-evident, with access restricted and integrity checks monitored.

## 8. Required enforcement tests

Before Admin operations are enabled, tests must prove:

1. A customer cannot call Admin or Supreme endpoints.
2. An employee without a matching grant is denied.
3. Admin can perform only explicitly delegated routine operations.
4. Admin cannot grant or expand their own access.
5. Admin cannot invoke any Supreme-only capability.
6. Expired and revoked grants are denied immediately.
7. A non-Supreme identity cannot approve a Supreme control request.
8. A Supreme approval cannot be replayed against a different target or parameter set.
9. Every allow and deny decision for privileged operations creates the required audit event.
10. Missing policy, unavailable authorization service, or malformed claims fail closed.

## 9. Implementation boundary and next steps

The repository already contains Supreme identity, MFA/AAL2, device-attested sessions, service registry, control-request foundations, and audit-chain work. This policy document does not claim that Admin delegation or all approval execution paths are implemented.

Implementation should proceed in this order:

1. Define the Admin identity and grant tables in the Employees/Neweix-owned identity domain; do not add Admin to `supreme.identities`.
2. Define a signed, short-lived delegated-authorization contract that Supreme can verify.
3. Add service-side authorization middleware and explicit capability checks.
4. Add tests for the ten enforcement requirements above.
5. Connect Neweix Admin UI only after server enforcement is deployed.
6. Keep all high-impact and reserved actions disabled until end-to-end approval and audit tests pass.

Never weaken the existing Supreme authentication, AAL2, device-attestation, or audit protections to make Admin workflows easier.
