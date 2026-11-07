# Supreme architecture

## 1. Purpose

Supreme is the central administrative control plane for independently deployed ecosystem services. It is not intended to absorb every service into one application or repository. Each service keeps ownership of its runtime, data, and release lifecycle; Supreme coordinates authorized administration through versioned APIs and integrations.

## 2. Logical components

### Android client
- Presents the control dashboard and operational workflows.
- Authenticates to the Supreme backend over HTTPS.
- Requests local PIN/biometric re-verification for protected app access.
- Stores only short-lived, revocable session material using platform-secure storage.
- Contains no provider administrator tokens or privileged backend credentials.

### Core backend
- Validates identity, MFA state, session risk, and authorization on every privileged request.
- Applies role and policy checks independently of the UI.
- Orchestrates integrations using server-side credentials.
- Requires approvals for high-impact operations.
- Emits immutable or append-only audit events.

### Service registry
Each registered service should declare:
- Stable service ID and display name.
- Repository URL and default branch.
- Environment identifiers (development/staging/production).
- API base URL and contract version, where applicable.
- Supported capabilities and permitted operations.
- Health-check configuration.
- Owning team or accountable operator.
- Data classification and operational risk tier.

Do not store credentials in registry records.

### Integrations
Provider integrations are backend-only adapters. Start with narrow scopes and read-only access where possible. Add write permissions only for a specific reviewed workflow.

## 3. Request flow

1. User opens the Android app and completes local device verification.
2. Client establishes or refreshes an authenticated backend session.
3. Backend validates the existing shared Supabase Auth session, the one active `staff_profiles` Supreme principal (`role = supreme`, `public_id = supreme`), MFA/session assurance, and verified Android app/device binding. Neweix Account customer records are not part of Supreme authorization.
4. Backend loads the requested resource and evaluates server-side policy.
5. For sensitive operations, backend creates an approval request rather than executing immediately.
6. After approval, an isolated worker executes the operation with a narrowly scoped credential.
7. Backend records the result and audit event; client receives the operation status.

## 4. Remote configuration

Backend-delivered configuration may control feature visibility, safe UI content, operational thresholds, and supported workflow definitions. Configuration must be schema-versioned, validated, signed or integrity-protected in transit, and rolled out with versioning and rollback.

Remote configuration must not be used to download and execute arbitrary code, bypass app-store policies, weaken authentication, or change authorization rules on the client. Authorization always remains server-side.

## 5. Deployment model

- Android client: signed application releases.
- Core API and workers: independently deployed backend services.
- Registry and audit storage: managed server-side data stores.
- Integrations: server-side secrets and scoped provider credentials.
- Environments: development, staging, production, with production actions gated.

## 6. Initial implementation sequence

1. Establish contracts, threat model, and repository governance.
2. Implement identity/session and server-side authorization.
3. Implement service registry read APIs.
4. Implement audit event pipeline.
5. Add read-only GitHub repository/CI visibility.
6. Add approval-gated operations and deployment workflows.
7. Build Android dashboard against stable API contracts.
