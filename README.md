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

- `apps/android/` — native Android shell and device-security foundation
- `services/android-attestation/` — Android Key Attestation verifier source and tests
- `services/registry/` — versioned service registry contracts
- `integrations/neweix-commerce/` — preserved source snapshot of Supreme features previously embedded in Neweix; not a standalone backend
- `config/` — safe, non-secret configuration and ecosystem capability catalog
- `docs/` — architecture, security, operations, and development notes

## Existing ecosystem features

The already implemented features in Neweix, Eixon, Neweix Account and Supreme have been inventoried with their source ownership and migration readiness. See [Ecosystem feature inventory](docs/ecosystem-feature-inventory.md) and the machine-readable [capability catalog](config/ecosystem-capabilities.json).

**Important:** a feature listed in the catalog is not automatically executable from Supreme. The owning service remains the source of truth; Supreme must use a tested, service-scoped adapter rather than duplicate that service's business logic.

## Verified status

- The Supreme registry database is deployed in the existing Neweix Supabase project under the isolated `supreme` schema.
- The live database has exactly one active `supreme.identities` ruler. Supreme does not use a Neweix Account customer identity or employee profile.
- The Supreme session and attestation Edge Functions are deployed. The Auth hook function exists with least-privilege grants, but the Custom Access Token Hook still requires activation in Supabase Authentication → Hooks.
- Supreme's Android debug build passes GitHub Actions and is installable on Android 8.0+; it is not a production release.
- A protected production release workflow is available. It requires the owner's permanent signing keystore and certificate fingerprint to be configured in the GitHub `production` environment and Supabase Edge Function secrets.
- The native app includes password/TOTP MFA, hardware-backed attestation client, encrypted refresh-token storage, and device-session verification. End-to-end operation remains fail-closed until production configuration and physical-device tests pass.
- The standalone web dashboard and production GitHub, Cloudflare, Supabase, and service-specific execution adapters are not complete. Service registrations are inventory until an adapter is implemented and tested.

## Documentation

- [Standalone control-plane implementation and migration gates](docs/standalone-control-plane-implementation.md)
- [Security model](docs/security-model.md)
- [Production Android release and signing](docs/production-android-release.md)
- [Architecture](docs/architecture.md)
- [Service registry](services/registry/README.md)
- [Ecosystem feature inventory](docs/ecosystem-feature-inventory.md)

## Security

Never commit credentials, access tokens, private keys, recovery codes, production environment files, or personal authentication data. Use server-side secret storage and least-privilege integration credentials.

## License

All rights reserved. This is a private project.

## Imported Supreme work

Existing Supreme implementation work from `neweix24/neweix` has been copied into this repository for separation and continued development.

- Android app: `apps/android/`
- Commerce-coupled dashboard and API source: `integrations/neweix-commerce/`
- Android Key Attestation service source: `services/android-attestation/`
- Extraction notes: [Migration from Neweix](docs/migration-from-neweix.md)

**Important:** imported commerce API/UI modules still depend on the original Neweix application and are preserved as a source snapshot. SQL files under `migrations-reference` are not safe to apply directly to production. The original `neweix` repository remains unchanged.
