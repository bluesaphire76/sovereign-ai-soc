from __future__ import annotations

import api
from routers import security_audit
from scripts.export_api_route_inventory import iter_api_routes
from security.rbac import is_request_authorized


def _security_audit_routes():
    return [
        route
        for route in iter_api_routes()
        if route.path == "/security-audit/events"
    ]


def test_security_audit_route_is_registered_once_from_router() -> None:
    routes = _security_audit_routes()

    assert len(routes) == 1
    route = routes[0]
    assert route.methods == {"GET"}
    assert route.endpoint is security_audit.list_security_audit_events


def test_security_audit_endpoint_no_longer_lives_in_api_module() -> None:
    assert not hasattr(api, "list_security_audit_events")
    assert not hasattr(api, "serialize_security_audit_event")
    assert not hasattr(api, "parse_security_audit_datetime")


def test_security_audit_route_inventory_includes_expected_method() -> None:
    methods_by_path: dict[str, set[str]] = {}

    for route in iter_api_routes():
        methods_by_path.setdefault(route.path, set()).update(route.methods or set())

    assert methods_by_path["/security-audit/events"] == {"GET"}


def test_security_audit_rbac_remains_admin_only() -> None:
    assert is_request_authorized(
        "GET",
        "/security-audit/events",
        {"role": "ADMIN"},
    )
    assert not is_request_authorized(
        "GET",
        "/security-audit/events",
        {"role": "ANALYST"},
    )
    assert not is_request_authorized(
        "GET",
        "/security-audit/events",
        {"role": "VIEWER"},
    )
