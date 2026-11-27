# Supreme service registry

The registry is Supreme's authoritative catalogue of the nine ecosystem services. Supreme is the highest authority; Admin performs day-to-day operations through scoped service interfaces. Registry membership is not an execution permission.

## Registry rules

- Every service has one stable `service_id` and one canonical repository.
- Registry status describes service registration state; implementation/runtime evidence is tracked in [`config/ecosystem-registry.json`](../../config/ecosystem-registry.json).
- Capabilities are allow-listed. No wildcard or blanket administrator permission is permitted.
- Credentials are referenced by opaque server-side secret identifiers only. Secret values never belong in registry data.
- Production write capabilities remain disabled until reviewed, authorized, implemented, and integration-tested.
- Admin is the day-to-day operational actor, but every service validates a signed, scoped Admin grant on its own server boundary.
- Supreme approval is required for reserved actions. Approval changes request state; it does not itself execute the operation.
- Registry changes are versioned and audited.
- Supreme, customer Account, and workforce/Admin identities remain separate.

## Canonical references

- [Ecosystem Governance and Operating Charter](../../docs/ecosystem-governance-charter.md)
- [Nine-repository inventory](../../config/ecosystem-registry.json)
- [Service Registry v1 JSON Schema](../../docs/contracts/service-registry-v1.schema.json)
- [Service Registry API v1 contract](../../docs/contracts/service-registry-api-v1.md)
- [Schema-valid registry example](../../config/service-registry.example.json)
- [Database and isolation notes](./database.md)
- Runtime: `supabase/functions/supreme-registry-api`

## Deployed API surface

- `GET /v1/services` — list registered service metadata.
- `GET /v1/services/{service_id}` — retrieve one service record and ETag.
- `POST /v1/services` — submit a service registration request; it remains pending.
- `PATCH /v1/services/{service_id}` — submit a versioned metadata update request.
- `GET /v1/services/{service_id}/health?environment_id={id}` — bounded same-origin HTTPS health check.
- `GET /v1/control-requests?status=pending` — list pending or filtered approval requests.
- `POST /v1/control-requests/{request_id}/decision` — decide a pending request; fresh AAL2 is required.

## Runtime integration boundary

The registry database and API are in the existing Neweix Supabase project under the isolated `supreme` schema. Supreme authorization uses the single active `supreme.identities` ruler principal; it does not require an Account customer row. The deployed API/session integration has outstanding release gates documented in the repository.

Provider-specific GitHub, Cloudflare, Supabase administration, and service execution adapters are not generally enabled. A service is not controllable until its adapter is deployed, capability explicitly allow-listed, authorization tested, and the required Admin/Supreme approvals are in force.
