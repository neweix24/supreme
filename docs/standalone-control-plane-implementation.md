# Supreme standalone control plane — implementation and migration plan

## Objective

Make `neweix24/supreme` the sole source repository for Supreme-owned application code, backend code, security controls, configuration, and release workflows. The Supreme Android application must be the operational interface for managing the registered Neweix ecosystem.

Supreme is a control plane, not a replacement for the business applications it manages. Business data and business logic remain in their owning services; Supreme creates and manages service registrations, capabilities, permissions, approved configuration, and auditable operations through explicit APIs.

## Source-of-truth rules

1. Supreme-owned application, backend, schema, policies, and release workflows live in this repository.
2. Neweix-owned storefront, checkout, orders, delivery, workforce, and commerce logic remain in `neweix24/neweix`.
3. Eixon-owned wallet, ledger, transfer, rewards, and campaign logic remain in `neweix24/eixon`.
4. Supreme has one independent principal (`public_id = 'supreme'`) in the existing shared Supabase Auth project. Reuse the existing `public.staff_profiles` row and unique index; never require a Neweix Account customer row or create duplicate identity tables. Future Neweix Employees remain separate from Supreme.
5. Supreme never copies service business logic or service-owned production tables into its own database.
6. Production secrets are stored only in backend secret storage. The Android binary, repository, and client configuration contain references, never secret values.
7. Every write operation is service-scoped, least-privilege, approval-gated according to risk, idempotent where appropriate, and audited.
8. A feature is not marked complete merely because its UI or source snapshot exists. It requires backend authorization, tests, and a verified end-to-end integration.

## Required Supreme application capabilities

### A. Home and system overview
- System health and service availability.
- Pending approvals and failed operations.
- Recent audit events and security alerts.
- Service, repository, environment, and integration summaries.

### B. Ecosystem and service management
- Create, view, update, suspend, resume, and archive service registrations.
- Maintain stable service IDs, repository ownership, deployment environments, endpoints, health checks, and service metadata.
- Discover and register additional services without hard-coded UI changes.
- Show the owner repository and source-of-truth for each capability.

### C. Repository management
- Register and inspect repositories and branches.
- View commits, pull requests, checks, releases, and deployment status.
- Create branches and pull requests through explicitly scoped GitHub permissions.
- Support reviewed code/configuration changes; never silently overwrite protected production branches.
- Keep GitHub credentials server-side and scoped to the required repositories/actions.

### D. Capability and feature management
- Maintain a versioned capability catalog for every registered service.
- Enable/disable a capability only when the owning service exposes a supported API.
- Configure safe feature flags and remote settings.
- Display capability state as one of: inventoried, adapter pending, read-only, write-enabled, suspended, or unavailable.
- Never present a catalog entry as executable before adapter verification.

### E. Integration management
- GitHub adapter: repository metadata, branches, pull requests, checks, and approved workflow actions.
- Cloudflare adapter: zones/workers/deployments/settings limited to explicitly granted scopes.
- Supabase adapter: project metadata, migrations, functions, and health operations with strict environment separation.
- Service adapters: versioned HTTPS contracts for Neweix, Eixon, Neweix Account, Neweix Message, and future services.
- Each adapter must have credential references, scope declarations, timeouts, retries, rate limits, health checks, and contract tests.

### F. Operations and deployment
- Create operation requests from the app.
- Preview exact target, environment, changed resources, and impact before approval.
- Separate read, configuration, deployment, access-management, and destructive operations.
- Require fresh MFA and explicit approval for production writes, permission escalation, secret rotation, and destructive actions.
- Execute approved requests asynchronously with idempotency keys and safe retry behavior.
- Provide operation status, logs, result, rollback guidance, and emergency disable/revoke controls.

### G. Access, identity, and device security
- Preserve exactly one Supreme ruler identity: `public.staff_profiles.role = 'supreme'`, `public_id = 'supreme'`, active.
- Reuse the existing Supabase Auth session and NEWEIX Supreme identity row; do not require a `neweix_accounts` customer record.
- Keep future Neweix Employees identity and workforce permissions separate from the Supreme ruler principal.
- Enforce MFA/AAL2 on privileged server operations.
- Require a server-signed, device-bound `supreme_app_session` claim on every registry request. The Auth hook and session/device registry must be implemented before enabling the app flow.
- Use Android biometric/device credential only as local app unlock, never as server authorization.
- Add device registration, attestation verification, session revocation, inactivity lock, and lost-device recovery.
- Never trust hidden UI controls as authorization.

### H. Approvals and audit
- Pending/approved/rejected/expired operation queue.
- Risk classification and approval policy per capability and environment.
- Append-only audit trail containing actor, assurance level, service, repository, environment, operation, approval, result, and correlation ID.
- No secrets or unnecessary personal data in audit records.

### I. Configuration and notifications
- Manage remote app configuration, navigation, capability availability, and safe service settings.
- Deliver actionable alerts for health failures, denied actions, pending approvals, and completed deployments.
- Keep native security changes and Android platform capabilities in versioned app releases.

## Current repository baseline

Already present in `main`:
- Android application shell and launcher resources under `apps/android/`.
- Android Key Attestation verifier source and tests under `services/android-attestation/`.
- Service registry contracts and deployed-source implementation under `services/registry/` and `supabase/functions/supreme-registry-api/`.
- Supreme-related dashboard/API source snapshots under `integrations/neweix-commerce/next-app/`.
- Historical NEWEIX SQL migrations/tests under `integrations/neweix-commerce/supabase/*-reference/`.
- Ecosystem capability catalog and source inventory under `config/` and `docs/`.

## Verified gaps before source deletion

1. **Standalone dashboard runtime:** imported pages still depend on NEWEIX-specific auth, staff roles, Supabase helpers, middleware, UI, and commerce schema.
2. **Supreme hosting boundary:** Android shell still targets the old `neweix.com` private route. A Supreme-owned runtime/API origin and session flow must replace it.
3. **Authentication and sessions:** central Account integration, MFA lifecycle, Android device registration/attestation, refresh, revocation, and recovery need complete end-to-end tests.
4. **GitHub adapter:** no production-ready Supreme-owned adapter and scoped credential lifecycle.
5. **Cloudflare adapter:** no production-ready zone/Worker/deployment adapter and scoped credential lifecycle.
6. **Supabase adapter:** no production-ready project/function/migration management adapter; no service-role secret may reach the app.
7. **Service adapters:** Neweix, Eixon, Account, Message, and future service adapters are not all implemented or contract-tested.
8. **Operations engine:** approval currently changes request state; it does not execute provider operations. A safe executor, queue, idempotency, status, rollback, and audit integration are required.
9. **App feature coverage:** imported dashboard panels are not yet connected to the central registry/capability API and are not proven standalone.
10. **Build and release:** Android and backend CI, signing, artifact verification, and production release must be verified from this repository.

## Migration and deletion gates

The source `neweix24/neweix` must not be cleaned by deleting files based only on their names. First:

1. Map every Supreme-owned source file and all imports/references from non-Supreme Neweix code.
2. Compare source and destination blobs; preserve the newest reviewed implementation in this repository.
3. Replace NEWEIX-specific runtime dependencies with Supreme-owned contracts.
4. Build and test the standalone Supreme web/API runtime and Android app.
5. Verify login, MFA, route privacy, device attestation, session refresh/revocation, registry, approvals, audit, and all enabled adapters.
6. Verify that NEWEIX production routes, middleware, CI, and deployment no longer require Supreme-owned files.
7. Prepare a dedicated NEWEIX cleanup branch and pull request. Remove only Supreme-owned files and references; preserve Neweix business features and shared dependencies.
8. Merge cleanup only after both repositories pass their required checks and the Supreme replacement is deployed and smoke-tested.

Until all gates pass, keep the original NEWEIX source intact as a rollback source. Do not delete or apply reference SQL migrations against production as part of source cleanup.

## Completion criteria

Supreme is complete only when the app can discover and manage all registered services, create and review capability/operation requests, invoke each enabled integration through a tested adapter, enforce server-side permissions and MFA, show reliable execution status, and produce immutable audit records. All production writes must have tested approval and rollback behavior.
