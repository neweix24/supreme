# Supreme architecture

## 1. Purpose and authority

Supreme is the **highest and final authority** for the Neweix ecosystem. It owns governance policy, authority delegation, reserved approvals, emergency suspension/revocation, and privileged audit.

Admin is the single day-to-day operational authority. Admin conducts normal business and service operations across the ecosystem within Supreme-approved, service-scoped permissions. Supreme is not the routine order desk, catalogue operator, customer support team, or workforce scheduler. Supreme governs and oversees; Admin coordinates and performs ordinary operations through the owning service.

See [the canonical Ecosystem Governance and Operating Charter](./ecosystem-governance-charter.md) for the binding authority hierarchy, identity rules, service ownership, EIX policy, and release boundaries.

## 2. Identity separation

- **Supreme:** one protected ruler principal, authorized by Supreme-owned identity/session policy.
- **Admin:** workforce principal with an explicit Supreme-approved operational grant; workforce record belongs to Employees.
- **Employee:** workforce identity and least-privilege duties, owned by Employees.
- **Customer:** Account identity, credentials, sessions, and customer profiles, owned by Neweix Account.
- **Service identity:** a narrow server-to-server principal for one integration/environment.

Customer Account rows, user metadata, browser roles, usernames, and client headers never grant Admin or Supreme authority. Supreme authentication is separate from customer login.

## 3. Logical components

### Supreme Android client
- Presents Supreme's protected authority, governance, approvals, audit, and ecosystem oversight workflows.
- Authenticates to the Supreme backend over HTTPS with MFA and a verified app/device-bound session.
- Requests local PIN/biometric re-verification for protected app access.
- Stores only short-lived, revocable session material using platform-secure storage.
- Contains no provider administrator tokens or privileged backend credentials.

### Supreme core backend
- Validates the single Supreme identity, MFA state, session risk, device binding, and authorization on every privileged request.
- Owns ecosystem policy, registry metadata, reserved approval records, and privileged audit events.
- Approves/rejects reserved requests and may suspend/revoke service access or delegated authority.
- Does not absorb Shop, Eixon, Account, Connect, Neweix+, Eixora, or workforce business logic.

### Admin operations
- Until the unified Neweix Admin workspace is implemented, Admin enters each available service's authenticated Admin interface directly. Neweix remains the public service directory.
- Admin performs daily business operations through each owning service's API/UI.
- Supreme issues or approves the Admin grant. Employees owns workforce records. Each service independently validates the grant and requested scope.
- Routine operations proceed within the grant. Reserved actions pause for Supreme approval; Admin or a narrow executor performs the approved action.

### Service registry
Each service declares a stable service ID, display name, repository, environments, explicit capabilities, owning service, data classification, and risk tier. Credentials are opaque server-side references only.

Registry membership is not execution permission. An operation requires an implemented adapter, an allow-listed capability, service-side authorization, applicable Admin grant, and any required Supreme approval.

### Integrations
Provider integrations are backend-only adapters. Start with narrow read-only scopes. Add write access only for a specific reviewed workflow. No service may write another service's private tables directly.

## 4. Request and approval flow

1. Admin authenticates through the approved workforce/privileged path, or a customer authenticates through Account. These are distinct paths.
2. The owning service validates the principal, account/service status, grant, scope, resource ownership, and request parameters on the server.
3. Routine Admin operations execute within the approved grant and are audited by the owning service.
4. A reserved/high-impact action creates a Supreme control request with normalized parameters, requester, target service/environment, idempotency key, policy version, and expiry.
5. Supreme reviews the request using a fresh AAL2/device-bound authority session and approves or rejects it with an audit event.
6. After approval, Admin or an isolated least-privilege executor performs the approved action through the owning service's API.
7. The owning service records the result; Supreme records the approval/execution reference and oversight event.

Approval is not execution. A client-side hidden button is not authorization. Approval must not silently broaden the original request parameters.

## 5. Service data and integration boundaries

- **Neweix:** public hub and service directory. The unified Admin workspace and cross-service operational overview are planned capabilities, not verified live features.
- **Account:** customer identity and sessions.
- **Employees:** Admin/workforce identity records and delegated workforce permissions.
- **Eixon:** EIX wallet/unit ledger and approved EIX lifecycle.
- **Shop:** catalogue, inventory, orders, fulfilment, returns, and shop support.
- **Connect:** conversations, messages, memberships, attachments, notifications, and communication policies.
- **Neweix+:** subscriptions, tiers, memberships, and entitlements.
- **Eixora:** social profiles and social content.

Services use versioned APIs and narrow service identities. A shared Supabase project does not imply shared table ownership. Secrets are never stored in registry records, application bundles, or Git.

## 6. Remote configuration

Backend-delivered configuration may control safe UI content, feature visibility, thresholds, and supported workflow definitions. Configuration must be schema-versioned, validated, integrity-protected, and rolled out with versioning and rollback.

Remote configuration must not download and execute arbitrary code, bypass app-store policies, weaken authentication, or change authorization rules on the client. Authorization always remains server-side.

## 7. Deployment model

- Android client: signed application releases.
- Supreme core APIs/workers: independently deployed backend services.
- Registry and audit storage: Supreme-isolated schema in the existing shared Supabase project, with server-only access.
- Integrations: backend-only secrets and scoped provider credentials.
- Environments: development, staging, production, with production actions gated.

## 8. Delivery sequence

1. Maintain this charter and the canonical nine-repository registry.
2. Complete Supreme identity/device-session and registry authorization acceptance.
3. Complete Account customer service-client/OIDC contract and the separate Employees/Admin grant foundation.
4. Implement narrow read-only service adapters first.
5. Add Admin operational APIs per owning service.
6. Add reserved write operations only with Supreme approval, service-side authorization, idempotency, and audit tests.
7. Build Supreme oversight screens against stable API contracts.

A source snapshot, draft PR, CI success, DNS record, or Worker name is not production acceptance evidence.
