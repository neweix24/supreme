# Supreme Service Registry API — v1

**Status:** v1 database and authenticated Edge Function implementation are being brought online. Provider-specific execution adapters and approval decisions remain separate implementation work.

## Purpose and boundary

The registry is Supreme's authoritative, non-secret catalogue of ecosystem services. It describes what exists and which capabilities have been explicitly allow-listed. It does not itself grant a user permission, hold provider credentials, or execute an operation.

A service remains responsible for its own runtime, data, authentication boundary, and release lifecycle. Supreme accesses it through a separately reviewed integration adapter.

## Identity and authorization

- The only Supreme ruler identity is the dedicated `supreme` account.
- A request must carry a valid Supreme session. The backend—not the Android client—resolves the principal and evaluates authorization.
- Local PIN/biometric verification is a device-unlock step; it is not a substitute for server authentication or MFA.
- Registry read operations require `services.read`.
- Register/update/suspend operations require `services.manage` and a recorded approval. Production-impacting changes require fresh MFA.
- A service capability is an upper bound on what Supreme may request. It never overrides the caller's own authorization.
- Unknown capabilities, unknown service IDs, and disabled environments fail closed.

## Routes

| Method | Route | Contract |
|---|---|---|
| GET | `/v1/services` | List services visible to the caller. |
| GET | `/v1/services/{service_id}` | Read one service's metadata. |
| POST | `/v1/services` | Submit a registration request; approval required before activation. |
| PATCH | `/v1/services/{service_id}` | Submit a versioned metadata change; audited and approval-gated. |
| GET | `/v1/services/{service_id}/health` | Read a bounded health summary for an enabled environment. |

All routes are HTTPS-only and versioned. List responses use cursor pagination and return only metadata safe for the caller's scope. Secrets and secret-manager values are never returned.

## Request conventions

- JSON request and response bodies use UTF-8.
- Mutating requests require an `Idempotency-Key` with a bounded length.
- Updates require the current `If-Match` ETag to prevent lost updates.
- The API returns an opaque request ID for support and audit correlation.
- Timestamps use RFC 3339 UTC.
- Health checks have strict timeouts and response-size limits; they must not become arbitrary URL fetches or SSRF primitives. Only registered, server-controlled targets are eligible.

## Response envelope

Successful responses contain the resource or result plus a request ID. Errors use:

```json
{
  "error": {
    "code": "REGISTRY_VERSION_CONFLICT",
    "message": "The service record has changed.",
    "request_id": "opaque-correlation-id"
  }
}
```

Do not expose stack traces, provider tokens, secret references, or internal policy details in client-facing errors.

## Capability naming

Capabilities use namespaced, explicit strings such as:

- `repository.read`
- `repository.workflow.read`
- `deployment.status.read`
- `service.health.read`

Write capabilities must identify a specific operation, for example `repository.workflow.dispatch`; broad wildcards such as `*`, `admin`, or `write.all` are prohibited.

## Risk and approval policy

| Risk | Examples | Execution rule |
|---|---|---|
| Read-only | Repository metadata, CI status, health summary | May execute after ordinary authorization. |
| Low-impact write | Non-production configuration change | Explicit capability, audit, and idempotency required. |
| High-impact | Production deployment, secret rotation, access changes | Separate approval, fresh MFA, scoped credential, and post-action verification required. |
| Critical | Delete production data/service, revoke root access | Disabled by default; require a separately designed break-glass procedure. |

Approvals are bound to the exact action, target service, environment, normalized parameters, requester, expiry, and policy version. Any change to those fields invalidates the approval.

## Audit requirements

Append an audit event for every registration request, metadata change, health check failure, approval decision, and attempted privileged operation. Events include actor, action, target, environment, request ID, outcome, timestamp, and policy version. Never record credentials or secret values.

## Compatibility

The initial JSON Schema is `service-registry-v1.schema.json`. Additive optional fields may be introduced only when consumers safely ignore unknown fields; breaking changes require a new schema/API major version. Registry records are validated before persistence and again when loaded by an executor.

## Explicitly not implemented by this contract

This document does not claim that the routes, identity provider, database, worker, approval engine, or provider integrations are deployed. Those are implementation milestones and must have independent tests and deployment evidence.
