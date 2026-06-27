# API Composition Root

`api.py` is intentionally small. It creates the FastAPI application, configures CORS and middleware, and includes application routers through `include_app_routers(app)`.

Endpoint routes belong in `routers/`. Request and response schemas belong in `schemas/`. Business and domain helpers belong in `services/` or focused domain modules. Auth, RBAC, and audit helpers belong in `security/`.

New routes must not be added directly to `api.py`. During API refactors, route inventory and the OpenAPI baseline must remain stable unless a task explicitly changes the public API.
