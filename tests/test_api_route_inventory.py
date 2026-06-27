from __future__ import annotations

from fastapi.routing import APIRoute

from api import app


CRITICAL_ROUTE_METHODS = {
    "/auth/login": {"POST"},
    "/auth/me": {"GET"},
    "/users": {"GET", "POST"},
    "/security-audit/events": {"GET"},
    "/incidents": {"GET"},
    "/incidents/{incident_id}": {"GET"},
    "/cases": {"GET"},
    "/cases/{case_id}": {"GET"},
    "/platform/health": {"GET"},
    "/metrics": {"GET"},
    "/reports/incidents/{incident_id}": {"GET"},
    "/reports/cases/{case_id}": {"GET"},
    "/semantic-memory/capabilities": {"GET"},
    "/semantic-memory/search": {"GET"},
    "/ai-providers": {"GET"},
    "/remediation/proposals": {"GET", "POST"},
    "/network-events": {"GET"},
    "/dns-events": {"GET"},
}


def get_route_methods() -> dict[str, set[str]]:
    route_methods: dict[str, set[str]] = {}
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        route_methods.setdefault(route.path, set()).update(route.methods or set())
    return route_methods


def test_critical_api_routes_are_registered() -> None:
    route_methods = get_route_methods()

    for path, methods in CRITICAL_ROUTE_METHODS.items():
        assert path in route_methods
        assert methods <= route_methods[path]

    detection_control_paths = [
        path for path in route_methods if path.startswith("/detection-control/")
    ]
    assert detection_control_paths


def test_api_has_non_trivial_route_inventory() -> None:
    route_paths = set(get_route_methods())

    assert len(route_paths) > 100
