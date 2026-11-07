# Supreme

Supreme is the private, central control platform for the Neweix ecosystem. It is designed as a separate Android application and backend control plane that can securely manage registered services and repositories.

## Project principles

- **Separate control plane:** Supreme has its own repository, application, backend, and deployment lifecycle.
- **API-first integrations:** ecosystem services remain independently deployable and expose explicitly scoped integration APIs.
- **Least privilege:** the Android app never contains GitHub, Cloudflare, Supabase, or production administrator secrets.
- **Human approval:** sensitive operations such as production deployments, permission changes, and destructive actions require explicit authorization.
- **Auditable operations:** privileged actions must record actor, target, action, timestamp, result, and correlation ID.
- **Remote configuration:** supported screens, feature availability, and safe operational settings can be changed server-side without an app release. Native capability and security changes still require an app update.
- **Secure access:** the single Supreme identity uses strong server-side authentication, MFA, and device-level PIN/biometric re-verification.

## Initial architecture

```text
Supreme Android App
        |
        | authenticated HTTPS API
        v
Supreme Core Backend
        |
        +-- Identity & session policy
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
- `config/` — safe, non-secret example configuration
- `docs/` — architecture, security, operations, and development notes

## Status

- The Supreme registry database is deployed in the existing Neweix Supabase project under the isolated `supreme` schema. No separate Supabase project was created.
- The authenticated `supreme-registry-api` Edge Function is deployed with JWT verification enabled. It validates the existing Neweix Auth session, central Neweix Account row, and the single active `supreme` ruler identity.
- The registry currently contains six known services: Neweix, Neweix Shop, Eixon, Neweix Account, Neweix Message, and Supreme. Only the existing Neweix website is marked active; the others remain planned until their deployment and integration boundaries are verified.
- No provider capabilities are enabled yet. GitHub, Cloudflare, Supabase administration, and service-specific execution adapters still require implementation, scoped credentials, and end-to-end tests.
- The Android shell, imported Supreme feature source, and Android attestation verifier are present. Imported Neweix Commerce routes remain a reference snapshot and must not be treated as a production-ready standalone backend.

## Getting started

Read:
1. [Architecture](docs/architecture.md)
2. [Security model](docs/security-model.md)
3. [Service registry](services/registry/README.md)

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
