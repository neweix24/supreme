# Supreme-approved Admin Grant Contract v1

**Status:** Canonical design contract; not yet implemented as a production token issuer  
**Authority:** Supreme  
**Workforce record owner:** Employees  
**Day-to-day operator:** Admin  
**Applies to:** All nine Neweix ecosystem services

## 1. Purpose

This contract defines how the single Admin conducts normal day-to-day operations across Neweix services without becoming equal to Supreme or receiving unsafe universal database/provider access.

Supreme is the highest and final authority. Admin is the operational authority for routine work within delegated scope. Employees owns the workforce/Admin identity record. Each target service validates the grant on its own server boundary.

This contract is design-only until the Employees issuer, Supreme approval binding, signing-key publication, service-side validation libraries, revocation and audit paths are implemented and tested. No Admin account or grant is created by adding this document.

## 2. Identity and grant lifecycle

1. Employees creates or maintains the workforce principal and its employment/operational status.
2. Supreme approves the Admin appointment and the maximum scope that may be delegated.
3. Employees issues a short-lived, signed, service-specific Admin grant only after checking a valid Supreme approval reference.
4. The Admin presents the grant to the target service over HTTPS.
5. The target service validates issuer, signature, audience, expiry, grant status, Supreme approval reference, scope, environment and current service state.
6. The service enforces the requested operation and records an audit event.
7. Supreme or an authorized issuer can suspend/revoke the grant. Services must check revocation/current grant state for protected mutations; offline JWT signature verification alone is not sufficient for revocable Admin write access.

A workforce record does not itself confer Admin authority. A customer Account, username, profile, browser flag, email address, or user-editable metadata never confers Admin or Supreme authority.

## 3. Required token claims

A future signed JWT/opaque grant must carry the following minimum claims. Exact issuer URL and signing-key discovery location are registered only after Employees is deployed and approved.

```json
{
  "iss": "registered-employees-issuer",
  "sub": "stable-workforce-principal-id",
  "aud": "exact-target-service-id",
  "jti": "unique-grant-token-id",
  "iat": 0,
  "nbf": 0,
  "exp": 0,
  "actor_type": "admin",
  "grant_id": "stable-admin-grant-id",
  "supreme_approval_ref": "approved-supreme-control-request-id",
  "policy_version": "v1",
  "environment": "production",
  "scope": [
    "shop.catalog.read",
    "shop.orders.review"
  ]
}
```

Rules:

- `iss` must match the Employees issuer registered by Supreme.
- `sub` identifies a workforce principal, never a customer Account ID.
- `aud` is exactly one service ID. Wildcard/multi-service audiences are prohibited.
- `scope` is an explicit allow-list of operations for that one service. No `*`, `admin`, or unrestricted `write.all` scopes.
- `exp` must be short-lived; target maximum is 10 minutes for routine operational grants. Sensitive write operations additionally check current grant/revocation status and may require step-up authentication.
- `supreme_approval_ref` must resolve to an approved, unexpired Supreme approval covering the same principal, target service, scope and environment.
- Tokens must be audience-bound, signed with a protected private key, rotated, and verified against pinned/registered public keys. Secrets never enter browser bundles or mobile clients.
- A grant is not transferable and cannot be delegated by Admin.

## 4. Operational scope

Admin is responsible for ordinary work in every service, with service-specific scopes such as:

| Service | Routine Admin operations (examples only) |
|---|---|
| Neweix | Public content, service directory metadata, support triage, operational overview |
| Account | Customer support actions specifically approved for workforce use; never read passwords, MFA secrets, or private tokens |
| Employees | Workforce record administration and duty assignment within approved scope |
| Eixon | Customer support, approved load/gift review, reconciliation visibility; no EIX issuance or policy/limit changes |
| Shop | Catalogue, pricing, inventory, order review, fulfilment, return and customer support |
| Connect | Support conversation handling, abuse queue review and routine moderation; no blanket access to private conversations |
| Neweix+ | Subscription support, benefit fulfilment, entitlement correction within approved policy |
| Eixora | Routine community/content moderation and support |

These are scope examples, not live permissions. Each operation must be separately enumerated by the owning service and approved before activation.

## 5. Supreme-reserved actions

Admin may prepare a request, but cannot self-approve or override Supreme for:

- Changing the ecosystem charter or service ownership.
- Appointing another Admin, changing the Admin's maximum authority, or granting Supreme/workforce privileges.
- Changing EIX product policy, issuance/load rules, gift limits (currently BDT 1,000 per gift), or enabling cash-out/external financial functions.
- Enabling payment providers, Shop checkout/write integrations, payout/deposit/withdrawal, or other regulated operations.
- Production database migrations with material/destructive effects, production secrets, DNS/custom-domain changes, irreversible data deletion, or security-policy weakening.
- Adding a service, enabling a new privileged capability, or changing an approved scope.

Reserved actions require a Supreme control request and fresh Supreme authentication/step-up verification as prescribed by the owning policy. Approval is not execution. The operation must still execute through the owning service's API with exact approved parameters.

## 6. Service-side enforcement

Every service must:

- Validate the Admin grant server-side on each privileged request.
- Verify signature, issuer, audience, expiry, not-before, token ID, scope, target service, environment and current grant status.
- Confirm the Supreme approval reference is valid for reserved scopes.
- Deny by default when issuer/registry/revocation services are unavailable for operations requiring online checks.
- Enforce resource-level checks and least-privilege data exposure.
- Prevent Admin from obtaining raw customer credentials, service-role keys, provider secrets, or unrestricted direct database access.
- Log actor, workforce principal, grant ID, Supreme approval reference, target service/environment, operation, result, timestamp and correlation ID. Do not log tokens/secrets or unnecessary private customer content.

The Admin UI must not be treated as an authorization boundary. Hiding a button is not enforcement.

## 7. Current implementation boundary

As of 2026-11-27, Employees is a documentation-only placeholder. No Admin workforce principal, grant issuer, signing key, JWKS endpoint, grant database, or service-side verification adapter is verified as deployed. No Admin is provisioned or activated by this contract.

The next implementation must start with Employees' workforce record and grant lifecycle, Supreme's approval binding, and a shared server-side validation contract. Do not create or enable a universal Admin role in the customer Account service.
