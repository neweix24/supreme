# Developer Program and Developer-Facing Features: Cancelled

**Decision status:** Approved cancellation  
**Effective date:** 2026-11-17  
**Authority:** Supreme governance policy  
**Scope:** All Neweix ecosystem services, repositories, product plans, documentation, APIs, dashboards, and future capability proposals.

## Decision

All previously proposed or approved developer-facing products, programs, and platform capabilities are cancelled. They must not be designed, implemented, exposed, marketed, or treated as active roadmap items unless a new explicit Supreme-level decision reverses this cancellation.

## Cancelled scope

- Developer Marketplace and developer service directory.
- Developer registration, onboarding, verification, approval, profiles, and developer-specific account tiers.
- Developer Mode, developer portal, developer dashboard, and developer management console.
- Developer API platform, API keys or credentials issued for third-party developers, API plans, quotas, and developer-specific access controls.
- Developer app, integration, extension, plugin, or service submission and publication workflows.
- Developer subscriptions, billing, invoices, commissions, revenue sharing, and payment records.
- Developer status pages, service publishing, developer incident feeds, and developer-facing monitoring products.
- Developer-specific repository, SDK, documentation portal, sandbox, testing environment, and integration program planning.
- Developer-specific governance, review, approval, reporting, analytics, and support workflows.

## Repository and implementation rules

1. Do not create new developer-facing repositories, services, routes, pages, tables, API endpoints, permissions, navigation items, or database migrations.
2. Do not expose developer-facing features from existing services or imported source snapshots.
3. Remove or disable any confirmed developer-only feature that is found in source code, after checking callers, data dependencies, tests, and migration safety.
4. Do not delete an entire repository, shared infrastructure, general-purpose engineering tools, or unrelated service functionality as part of this policy.
5. Do not close or merge unrelated pull requests. Open work is cancelled only when its actual scope is developer-facing.
6. Existing source code that cannot be safely removed immediately must remain inaccessible and clearly marked as deprecated/cancelled until a reviewed removal is completed.
7. Any future exception requires a new explicit Supreme approval and a documented scope change.

## What this decision does not cancel

- Ordinary software engineering and maintenance required to build and operate Neweix services.
- Internal engineering tools, CI/CD, security testing, source control, repository administration, and technical documentation needed by the Neweix team.
- Employees, warehouse staff, Admin, service operators, or other internal workforce roles.
- Existing customer-facing Neweix services and their ordinary APIs. These are not a third-party developer platform.

## Current repository audit note

The GitHub audit performed on 2026-11-17 found no open pull requests explicitly scoped to a Developer Marketplace, Developer Dashboard, or Developer API product. Existing open pull requests in Supreme, Account, and Eixon were unrelated to the cancelled developer-facing scope and were therefore left unchanged. The Supreme capability inventory did not list a separate developer platform capability.

The audit did not establish that every file in every repository is free of dormant developer-related code. Repositories without an available code-search index require a source-level review before claiming complete code removal.

## Enforcement status

This document records the binding product/governance cancellation. It does not claim that dormant code, branches, database objects, deployed routes, or third-party integrations have all been physically deleted. Those require repository-specific discovery and safe removal reviews.
