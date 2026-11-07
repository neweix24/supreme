# Service registry

The registry is the authoritative catalogue of ecosystem services Supreme is permitted to observe or operate.

## Registry rules
- Every service receives a stable, immutable `service_id`.
- Repository identity and deployment environments are explicit.
- Capabilities are allow-listed; no wildcard administrative permission.
- Credentials are referenced by server-side secret identifiers only. Secret values never belong in registry data.
- Production write capabilities remain disabled until separately reviewed and approved.
- Registry changes are versioned and audited.
- Supreme has one ruler identity: the `supreme` account. Registry records do not create user identities or roles.

## Contract files
- [Service Registry v1 JSON Schema](../../docs/contracts/service-registry-v1.schema.json)
- [Service Registry API v1 contract](../../docs/contracts/service-registry-api-v1.md)
- [Example registry](../../config/service-registry.example.json)

## Planned API surface
- `GET /v1/services` — list services visible to the authenticated principal.
- `GET /v1/services/{service_id}` — retrieve service metadata.
- `POST /v1/services` — submit a service registration request (approval-gated).
- `PATCH /v1/services/{service_id}` — submit a metadata update (audited and approval-gated).
- `GET /v1/services/{service_id}/health` — retrieve a bounded health summary.

## Implementation boundary

These files define contracts only. They do not represent deployed endpoints, a live registry database, or active provider credentials. The backend runtime and database choice remain intentionally uncommitted until the security and operational requirements are reviewed. Never copy the Neweix application's staff authentication model into Supreme; Supreme authorization must be based on its own ruler identity and server-side policy.
