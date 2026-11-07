# Service registry

The registry is the authoritative catalogue of ecosystem services Supreme is permitted to observe or operate.

## Registry rules
- Every service receives a stable, immutable `service_id`.
- Repository identity and deployment environments are explicit when a repository exists.
- Capabilities are allow-listed; no wildcard administrative permission.
- Credentials are referenced by server-side secret identifiers only. Secret values never belong in registry data.
- Production write capabilities remain disabled until separately reviewed and approved.
- Registry changes are versioned and audited.
- Supreme has one ruler identity: the `supreme` account. Registry records do not create user identities or roles.

## Contract and implementation files
- [Service Registry v1 JSON Schema](../../docs/contracts/service-registry-v1.schema.json)
- [Service Registry API v1 contract](../../docs/contracts/service-registry-api-v1.md)
- [Example registry](../../config/service-registry.example.json)
- [Database and isolation notes](./database.md)
- Runtime: `supabase/functions/supreme-registry-api`

## Deployed API surface
- `GET /v1/services` — list registered service metadata.
- `GET /v1/services/{service_id}` — retrieve one service record and ETag.
- `POST /v1/services` — submit a service registration request; it remains pending.
- `PATCH /v1/services/{service_id}` — submit a versioned metadata update request.
- `GET /v1/services/{service_id}/health?environment_id={id}` — run a bounded HTTPS health check against a registered same-origin target.
- `GET /v1/control-requests?status=pending` — list pending or filtered approval requests.
- `POST /v1/control-requests/{request_id}/decision` — approve or reject a pending request; fresh AAL2 is required and rejection requires a reason.

The repository implementation requires a valid JWT from the existing shared Supabase Auth project and confirms the user is the single active `staff_profiles` row with `role = supreme` and `public_id = supreme`. It does not require a Neweix Account customer row. This corrected code is on the current PR branch and is not deployed yet; the deployed Edge Function must be updated before relying on the new check. The function uses server-side database access; the Android app never receives database credentials.

## Current implementation boundary

The registry database and API are deployed in the existing Neweix Supabase project, under the isolated `supreme` schema. Supreme authorization reuses the existing public Supreme identity row; it does not create a second identity table. The current repository change to remove the Neweix Account customer-row dependency still requires deployment. The schema is not exposed to `anon` or `authenticated` roles. The initial registry contains Neweix, Neweix Shop, Eixon, Neweix Account, Neweix Message, and Supreme. No service capabilities or provider secret references are enabled yet.

Provider-specific GitHub, Cloudflare, Supabase administration, and service execution adapters are not deployed. Registration/update requests can be queued and decided through the MFA-protected approval endpoint. Approval only changes the request state; it does not execute the requested operation. Provider-specific execution endpoints remain future implementation work. Do not treat a listed service as controllable until its adapter is implemented, authorized, and tested.
