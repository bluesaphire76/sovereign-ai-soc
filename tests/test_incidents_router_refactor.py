from __future__ import annotations

import api
from routers import incidents as incidents_router
from scripts.export_api_route_inventory import iter_api_routes


CORE_INCIDENT_ROUTE_METHODS = {
    "/incidents": {"GET"},
    "/incidents/{incident_id}": {"GET"},
    "/incidents/{incident_id}/status": {"PATCH"},
    "/incidents/{incident_id}/audit": {"GET"},
    "/incidents/{incident_id}/notes": {"GET", "POST"},
    "/incidents/{incident_id}/case": {"POST"},
}


NON_CORE_INCIDENT_PATHS = {
    "/incidents/{incident_id}/ai-brief",
    "/incidents/{incident_id}/timeline",
    "/incidents/{incident_id}/timeline/summary",
    "/incidents/{incident_id}/timeline/capabilities",
    "/incidents/{incident_id}/similar-incidents",
    "/incidents/{incident_id}/recommended-playbooks",
    "/incidents/{incident_id}/network-evidence",
    "/incidents/{incident_id}/dns-evidence",
    "/incidents/{incident_id}/remediation-plan",
    "/incidents/{incident_id}/remediation-dry-run",
    "/incidents/{incident_id}/remediation-rollback-readiness",
    "/incidents/{incident_id}/remediation-audit-trail",
    "/incidents/{incident_id}/remediation-replay",
    "/incidents/{incident_id}/remediation-actions/{action_id}/execute-approved",
}


def _routes_by_path_method():
    return {
        (route.path, method): route
        for route in iter_api_routes()
        for method in route.methods or set()
    }


def test_core_incident_routes_are_registered_once_from_incidents_router() -> None:
    routes_by_path_method = _routes_by_path_method()
    expected_path_methods = {
        (path, method)
        for path, methods in CORE_INCIDENT_ROUTE_METHODS.items()
        for method in methods
    }

    assert expected_path_methods <= set(routes_by_path_method)
    assert routes_by_path_method[("/incidents", "GET")].endpoint is incidents_router.list_incidents
    assert routes_by_path_method[("/incidents/{incident_id}", "GET")].endpoint is incidents_router.get_incident
    assert routes_by_path_method[("/incidents/{incident_id}/status", "PATCH")].endpoint is incidents_router.update_incident_status
    assert routes_by_path_method[("/incidents/{incident_id}/audit", "GET")].endpoint is incidents_router.get_incident_audit
    assert routes_by_path_method[("/incidents/{incident_id}/notes", "GET")].endpoint is incidents_router.get_incident_notes
    assert routes_by_path_method[("/incidents/{incident_id}/notes", "POST")].endpoint is incidents_router.create_incident_note
    assert routes_by_path_method[("/incidents/{incident_id}/case", "POST")].endpoint is incidents_router.create_case_from_incident


def test_core_incident_routes_no_longer_live_in_api_module() -> None:
    moved_names = {
        "list_incidents",
        "get_incident",
        "update_incident_status",
        "get_incident_audit",
        "get_incident_notes",
        "create_incident_note",
        "create_case_from_incident",
    }

    for name in moved_names:
        assert not hasattr(api, name)


def test_core_incident_routes_are_not_duplicated() -> None:
    counts: dict[tuple[str, str], int] = {}

    for route in iter_api_routes():
        if route.path in CORE_INCIDENT_ROUTE_METHODS:
            for method in route.methods or set():
                counts[(route.path, method)] = counts.get((route.path, method), 0) + 1

    assert counts == {
        (path, method): 1
        for path, methods in CORE_INCIDENT_ROUTE_METHODS.items()
        for method in methods
    }


def test_non_core_incident_routes_remain_registered_elsewhere() -> None:
    routes_by_path_method = _routes_by_path_method()
    registered_paths = {path for path, _method in routes_by_path_method}

    for path in NON_CORE_INCIDENT_PATHS:
        assert path in registered_paths

    for (path, _method), route in routes_by_path_method.items():
        if path in NON_CORE_INCIDENT_PATHS:
            assert route.endpoint.__module__ != incidents_router.__name__
