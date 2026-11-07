# Service registry

The registry is the authoritative catalogue of ecosystem services that Supreme is permitted to observe or operate.

## Registry rules
- Every service receives a stable, immutable `service_id`.
- Repository identity and deployment environments are explicit.
- Capabilities are allow-listed; no wildcard administrative permission.
- Credentials are referenced by server-side secret identifiers only. Secret values never belong in registry data.
- Production write capabilities remain disabled until separately reviewed and approved.
- Registry changes are versioned and audited.

## Example

See [service-registry.example.json](../../config/service-registry.example.json).

## Planned API surface
- `GET /v1/services` — list services visible to the authenticated principal.
- `GET /v1/services/{service_id}` — retrieve service metadata.
- `POST /v1/services` — register a service (approval-gated).
- `PATCH /v1/services/{service_id}` — update metadata (audited).
- `GET /v1/services/{service_id}/health` — retrieve health summary.

These are design contracts, not implemented endpoints yet.
