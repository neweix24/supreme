# Supreme

Supreme is the private, central control platform for the Neweix ecosystem. It is designed as a separate Android application and backend control plane that can securely manage registered services and repositories.

## Project principles

- **Separate control plane:** Supreme has its own repository, application, backend, and deployment lifecycle.
- **API-first integrations:** ecosystem services remain independently deployable and expose explicitly scoped integration APIs.
- **Least privilege:** the Android app never contains GitHub, Cloudflare, Supabase, or production administrator secrets.
- **Human approval:** sensitive operations such as production deployments, permission changes, and destructive actions require explicit authorization.
- **Auditable operations:** privileged actions must record actor, target, action, timestamp, result, and correlation ID.
- **Remote configuration:** supported screens, feature availability, and safe operational settings can be changed server-side without an app release. Native capability and security changes still require an app update.
- **Secure access:** the single Supreme principal reuses the existing Supabase Auth identity with Supreme-specific server-side authorization, MFA, and verified Android app/device attestation.

## Initial architecture

```text
Supreme Android App
        |
        | authenticated HTTPS API
        v
Supreme Core Backend
        |
        +-- Existing Supabase Auth + Supreme principal/session policy
        +-- Service registry
        +-- Authorization / approvals
        +-- Remote configuration
        +-- Audit events
        +-- Operations orchestration
        |
        +---- GitHub integration
        +---- Cloudflare integration
        +---- Supabase integration
        +---- Registered ecosystem services
```

## Repository layout

- `apps/android/` — existing native Android shell and device-security foundation
- `services/android-attestation/` — Android Key Attestation verifier source and tests
- `services/registry/` — versioned service registry contracts
- `integrations/neweix-commerce/` — preserved source snapshot of Supreme features previously embedded in Neweix; not a standalone backend
- `config/` — safe, non-secret configuration and ecosystem capability catalog
- `docs/` — architecture, security, operations, and development notes

## Existing ecosystem features

The already implemented features in Neweix, Eixon, Neweix Account and Supreme have been inventoried with their source ownership and migration readiness. See [Ecosystem feature inventory](docs/ecosystem-feature-inventory.md) and the machine-readable [capability catalog](config/ecosystem-capabilities.json).

**Important:** a feature listed in the catalog is not automatically executable from Supreme. The owning service remains the source of truth; Supreme must use a tested, service-scoped adapter rather than duplicate that service's business logic.

## Status

- The Supreme registry database is deployed in the existing Neweix Supabase project under the isolated `supreme` schema. No separate Supabase project was created.
- The `supreme-registry-api` Edge Function is deployed with JWT verification enabled. The current PR branch changes its authorization lookup to the Supreme-owned `supreme.identities` table (`role = ruler`, `public_id = supreme`) while retaining the existing shared Supabase Auth credentials/session. A new migration copies the existing Supreme Auth user UUID into that table; it has not been applied to production. The registry function change is also not yet deployed.
- The registry currently contains six known services: Neweix, Neweix Shop, Eixon, Neweix Account, Neweix Message, and Supreme. Only the existing Neweix website is marked active; the others remain planned until their deployment and integration boundaries are verified.
- No provider capabilities are enabled yet. GitHub, Cloudflare, Supabase administration, and service-specific execution adapters still require implementation, scoped credentials, and end-to-end tests.
- The Android shell, imported Supreme feature source, and Android attestation verifier are present. Imported Supreme routes now authorize through `supreme.identities`; legacy workforce-profile authorization is not part of the Supreme runtime.

## Standalone control-plane completion plan

See [Standalone control-plane implementation and migration gates](docs/standalone-control-plane-implementation.md) for the required app capabilities, current gaps, safe Neweix source cleanup gates, and completion criteria.

## Getting started

Read:
1. [Architecture](docs/architecture.md)
2. [Security model](docs/security-model.md)
3. [Service registry](services/registry/README.md)
4. [Ecosystem feature inventory](docs/ecosystem-feature-inventory.md)

## Security

Never commit credentials, access tokens, private keys, recovery codes, production environment files, or personal authentication data. Use server-side secret storage and least-privilege integration credentials.

## License

All rights reserved. This is a private project.

## Imported Supreme work

Existing Supreme implementation work from `neweix24/neweix` has been copied into this repository for separation and continued development.

- Android app: `apps/android/`
- Commerce-coupled dashboard and API source: `integrations/neweix-commerce/`
- Android Key Attestation service source: `services/android-attestation/`
- Extraction notes: [docs/migration-from-neweix.md](docs/migration-from-neweix.md)

**Important:** imported commerce API/UI modules still depend on the original Neweix application and are preserved as a source snapshot. SQL files under `migrations-reference` are not safe to apply directly to a fresh database. The original `neweix` repository remains unchanged.
