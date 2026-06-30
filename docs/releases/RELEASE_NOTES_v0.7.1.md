# v0.7.1 — Llama.cpp Runtime, Operational Memory, HTTPS Hardening and API Refactor

v0.7.1 is a hardening and architecture release for Sovereign AI SOC.

This release strengthens the local-first AI SOC platform with llama.cpp runtime support, operational Qdrant semantic memory, HTTPS-first access alignment for internal platform surfaces, and a major backend API refactor that turns `api.py` into a small FastAPI composition root.

## Highlights

### Llama.cpp runtime foundation

Sovereign AI SOC now includes the foundation for a llama.cpp-based local AI provider path.

This improves support for local GGUF models and gives operators more control over local runtime profiles, model routing and fallback behavior.

The local AI workflow remains governed and analyst-led. The LLM supports triage, incident analysis, case intelligence, recommended actions and decision support without becoming an autonomous response engine.

### Operational Qdrant semantic memory

Qdrant is now part of the operational platform foundation.

Semantic memory supports:

- historical incident memory;
- similar incident search;
- security knowledge retrieval;
- detection quality enrichment;
- AI context enrichment.

Qdrant remains intentionally bounded. It does not replace deterministic correlation, final severity decisions, analyst validation, suppression policy or case closure logic.

### HTTPS-first platform access

v0.7.1 aligns internal platform and observability access with the HTTPS-first deployment model.

Grafana, Qdrant and other internal operational surfaces are no longer treated as plain HTTP shortcuts from the application UI. The platform now expects these consoles and internal links to be accessed through the configured HTTPS path.

This is especially important for Qdrant, which is part of the core semantic memory workflow and must be handled as an internal platform component rather than an optional unsecured side console.

### Major `api.py` refactor

The backend API has been significantly refactored.

`api.py` has been reduced from a large monolithic FastAPI file into a small application composition root. Endpoint logic has been moved into dedicated routers, schemas, services and security modules.

The refactor preserves the existing API surface:

- route inventory unchanged;
- OpenAPI baseline unchanged;
- authentication behavior preserved;
- RBAC behavior preserved;
- security audit behavior preserved;
- request and response payloads preserved.

A permanent composition-root guard was added to prevent `api.py` from growing back into a monolith.

## Backend architecture improvements

The API is now organized around clearer module boundaries:

- `routers/` for endpoint registration;
- `schemas/` for Pydantic request and response models;
- `services/` for reusable business helpers;
- `security/` for authentication, RBAC and audit helpers;
- `api.py` for FastAPI app creation, middleware and router registration only.

## Validation

Validated areas include:

- API route inventory stability;
- OpenAPI stability;
- authentication and RBAC behavior;
- security audit behavior;
- incident core workflow;
- case core workflow;
- case intelligence routes;
- synthetic test routes;
- executive and metrics routes;
- platform ingest route;
- API composition-root guard;
- local validation through `./ai-soc validate`.

## Upgrade notes

Recommended after upgrade:

```bash
./ai-soc validate
./ai-soc validate-runtime
./ai-soc demo-validate
```

If using semantic memory, verify Qdrant health and collection status.

If using local AI runtime profiles, verify the active provider, loaded model and fallback behavior from the AI Providers and Health views.

## Compatibility

No intentional breaking API changes were introduced.

Existing frontend routes, backend API paths and OpenAPI behavior are expected to remain compatible with v0.7.0.
