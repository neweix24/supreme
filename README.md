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
- Live Supabase checks on 2026-11-07 confirm exactly one active `supreme.identities` ruler and that `public.staff_profiles` no longer exists. The single Supreme principal is linked to its own Supabase Auth user; no Neweix Account or customer profile is used. The deployed Registry API v7 and Session API v5 sources match this repository and require a server-signed `supreme_app_session` claim bound to the exact JWT session ID.
- The registry currently contains six known services: Neweix, Neweix Shop, Eixon, Neweix Account, Neweix Message, and Supreme. Only the existing Neweix website is marked active; the others remain planned until their deployment and integration boundaries are verified.
- No provider capabilities are enabled yet. GitHub, Cloudflare, Supabase administration, and service-specific execution adapters still require implementation, scoped credentials, and end-to-end tests.
- The native Android app has Supreme-only password + TOTP AAL2 sign-in, a server-issued challenge, hardware-backed Android attestation, device/session registration, encrypted Keystore refresh-token storage, biometric/PIN lock, and screenshot protection. Main-branch Android CI passed. The standalone Supreme web dashboard remains a source snapshot, not a deployed web runtime.

## Supreme app release status

- Supreme has exactly one principal: `supreme.identities(public_id='supreme', role='ruler')`, linked to its own Supabase Auth credential. The user does not have or use a Neweix Account for Supreme.
- The latest Android debug assemble and internal preview APK workflows passed. The artifact is debug-signed, for testing only, and is not a production release.
- The app's attestation result is bound by the deployed Supreme session API to a persisted device and the exact Supabase Auth `session_id`; the app refreshes its token and asks the live registry to revalidate that session/device.
- The Supabase Custom Access Token Hook function is installed, requires AAL2, and is executable by `supabase_auth_admin`. The connected project tools cannot verify whether the project-level Authentication → Hooks setting is active; confirm that setting before treating a physical-device login as complete.
- No production-signed APK has been built or verified. The available APK artifacts are debug-signed for UI/testing only; production release requires the protected keystore, alias/passwords, and a SHA-256 signer fingerprint matching the server verifier. Whether those secrets are already configured could not be verified through the available repository connector.
- Native challenge issuance and device-session registration run through the Supreme-owned `supreme-session-api` Supabase Edge Function. The Android app no longer depends on a Neweix website API route or Neweix Account identity.
- Live registry currently contains six service entries but zero capabilities and zero secret references. GitHub, Cloudflare, Supabase administration and each service's operations still need scoped adapters and approval/execution tests. The standalone web dashboard is not deployed.
## Production Android release

The protected [production APK release workflow](.github/workflows/supreme-android-production-release.yml) builds only after the permanent keystore and server-approved signer fingerprint are configured. Follow [Production Android release setup](docs/production-android-release.md); never commit or share the keystore.

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
