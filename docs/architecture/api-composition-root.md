# API Composition Root

## Purpose

`api.py` is intentionally small. It is the FastAPI composition root, not a
feature module. Its job is to assemble the application, configure global
middleware and register routers while keeping endpoint behavior in focused
modules.

This guardrail protects the public API surface from accidental monolith
regression and makes route inventory/OpenAPI changes easier to review.

## Current `api.py` Responsibilities

`api.py` may:

- create the `FastAPI` application;
- set application metadata such as title and version;
- configure global middleware such as CORS;
- call `include_app_routers(app)`;
- attach global request middleware such as authentication enforcement.

## Forbidden `api.py` Responsibilities

`api.py` must not contain:

- endpoint decorators such as `@app.get`, `@app.post`, `@app.patch` or
  `@app.delete`;
- request/response models;
- incident, case, detection, remediation or reporting business logic;
- database query helpers;
- RBAC policy implementations;
- Security Audit event construction;
- AI provider, Qdrant or report-generation logic.

## Router Registration Model

Routers are registered through `routers/include_app_routers(app)`. New endpoint
groups should be added to the appropriate router module, then included through
the existing router registration pattern.

Public API behavior should remain stable unless the task explicitly changes the
contract. Route inventory and OpenAPI baseline export are the review points for
that contract.

## Directory Responsibilities

| Area | Responsibility |
|---|---|
| `routers/` | FastAPI routers, dependency wiring and HTTP-level request handling. |
| `schemas/` | Pydantic request/response models and API payload contracts. |
| `services/` | Reusable business helpers shared across routers. |
| `security/` | Authentication, RBAC, authorization and audit helpers. |
| Focused root modules | Existing domain logic that has not yet moved into a package, kept focused and imported by routers/services. |
| `api.py` | App creation, global middleware and router registration only. |

## Adding a New API Route Safely

1. Add the route to an existing router or create a focused router module.
2. Put request/response schemas in `schemas/` when the payload is reusable or
   part of the public contract.
3. Put shared business logic in `services/` or a focused domain module.
4. Reuse existing RBAC and Security Audit helpers from `security/`.
5. Register the router through `include_app_routers(app)`.
6. Add or update focused tests for behavior, RBAC and payload shape.
7. Export route inventory and OpenAPI baseline when the public surface changes.

Do not add endpoint logic directly to `api.py`.

## Validation Commands

Run these from the repository root for API architecture changes:

```bash
.venv/bin/python scripts/check_api_composition_root.py
.venv/bin/python scripts/export_api_route_inventory.py
.venv/bin/python scripts/export_openapi_baseline.py
./ai-soc validate
.venv/bin/python -m pytest -q
```

For documentation changes related to API architecture, also run:

```bash
git diff --check
./ai-soc docs-validate
.venv/bin/python scripts/validate_docs_structure.py
```

## Pull Request Checklist

- `api.py` remains a composition root.
- No route decorators were added to `api.py`.
- Route inventory changes are intentional and explained.
- OpenAPI changes are intentional and explained.
- RBAC behavior is preserved or explicitly changed.
- Security Audit behavior is preserved where privileged actions are involved.
- Request and response payload changes are documented and tested.
- Documentation/indexes are updated when architecture or public API behavior
  changes.
