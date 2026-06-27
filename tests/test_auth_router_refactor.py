from __future__ import annotations

from scripts.export_api_route_inventory import iter_api_routes
from routers import auth as auth_router


def _auth_routes():
    return [
        route
        for route in iter_api_routes()
        if route.path in {"/auth/login", "/auth/me"}
    ]


def test_auth_routes_are_registered_once_from_auth_router() -> None:
    routes_by_path_method = {
        (route.path, method): route
        for route in _auth_routes()
        for method in route.methods or set()
    }

    assert set(routes_by_path_method) == {
        ("/auth/login", "POST"),
        ("/auth/me", "GET"),
    }
    assert routes_by_path_method[("/auth/login", "POST")].endpoint is auth_router.login
    assert routes_by_path_method[("/auth/me", "GET")].endpoint is auth_router.auth_me


def test_auth_route_inventory_has_no_duplicate_auth_paths() -> None:
    path_counts: dict[str, int] = {}

    for route in _auth_routes():
        path_counts[route.path] = path_counts.get(route.path, 0) + 1

    assert path_counts == {
        "/auth/login": 1,
        "/auth/me": 1,
    }
