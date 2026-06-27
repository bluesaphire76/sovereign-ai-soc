from __future__ import annotations

import api
from routers import cases as cases_router
from routers import incidents as incidents_router
from scripts.export_api_route_inventory import iter_api_routes
from services import cases as cases_service


CORE_CASE_ROUTE_METHODS = {
    "/cases": {"GET"},
    "/cases/{case_id}": {"GET"},
    "/cases/{case_id}/workflow": {"PATCH"},
    "/cases/{case_id}/audit": {"GET"},
    "/cases/{case_id}/closure": {"GET", "PATCH"},
    "/cases/{case_id}/actions": {"GET", "POST"},
    "/cases/{case_id}/actions/{action_id}": {"PATCH"},
    "/cases/{case_id}/incidents": {"GET"},
}


NON_CORE_CASE_PATHS = {
    "/cases/{case_id}/actions/suggestions",
    "/cases/{case_id}/ai-generation/{job_type}",
    "/cases/{case_id}/ai-generation/{job_type}/latest",
    "/cases/{case_id}/ai-generation/jobs/{job_id}",
    "/cases/{case_id}/analysis",
    "/cases/{case_id}/timeline",
    "/cases/{case_id}/recommended-playbooks",
    "/cases/{case_id}/closure/semantic-context",
}


def _routes_by_path_method():
    return {
        (route.path, method): route
        for route in iter_api_routes()
        for method in route.methods or set()
    }


def test_core_case_routes_are_registered_once_from_cases_router() -> None:
    routes_by_path_method = _routes_by_path_method()
    expected_path_methods = {
        (path, method)
        for path, methods in CORE_CASE_ROUTE_METHODS.items()
        for method in methods
    }

    assert expected_path_methods <= set(routes_by_path_method)
    assert routes_by_path_method[("/cases", "GET")].endpoint is cases_router.list_cases
    assert routes_by_path_method[("/cases/{case_id}", "GET")].endpoint is cases_router.get_case
    assert routes_by_path_method[("/cases/{case_id}/workflow", "PATCH")].endpoint is cases_router.update_case_workflow
    assert routes_by_path_method[("/cases/{case_id}/audit", "GET")].endpoint is cases_router.get_case_audit
    assert routes_by_path_method[("/cases/{case_id}/closure", "GET")].endpoint is cases_router.get_case_closure
    assert routes_by_path_method[("/cases/{case_id}/closure", "PATCH")].endpoint is cases_router.update_case_closure
    assert routes_by_path_method[("/cases/{case_id}/actions", "GET")].endpoint is cases_router.list_case_actions
    assert routes_by_path_method[("/cases/{case_id}/actions", "POST")].endpoint is cases_router.create_case_action
    assert routes_by_path_method[("/cases/{case_id}/actions/{action_id}", "PATCH")].endpoint is cases_router.update_case_action
    assert routes_by_path_method[("/cases/{case_id}/incidents", "GET")].endpoint is cases_router.get_case_incidents


def test_core_case_routes_no_longer_live_in_api_module() -> None:
    moved_names = {
        "list_cases",
        "get_case",
        "update_case_workflow",
        "get_case_audit",
        "get_case_closure",
        "update_case_closure",
        "list_case_actions",
        "create_case_action",
        "update_case_action",
        "get_case_incidents",
    }

    for name in moved_names:
        assert not hasattr(api, name)


def test_core_case_routes_are_not_duplicated() -> None:
    counts: dict[tuple[str, str], int] = {}

    for route in iter_api_routes():
        if route.path in CORE_CASE_ROUTE_METHODS:
            for method in route.methods or set():
                counts[(route.path, method)] = counts.get((route.path, method), 0) + 1

    assert counts == {
        (path, method): 1
        for path, methods in CORE_CASE_ROUTE_METHODS.items()
        for method in methods
    }


def test_non_core_case_routes_remain_registered_elsewhere() -> None:
    routes_by_path_method = _routes_by_path_method()
    registered_paths = {path for path, _method in routes_by_path_method}

    for path in NON_CORE_CASE_PATHS:
        assert path in registered_paths

    for (path, _method), route in routes_by_path_method.items():
        if path in NON_CORE_CASE_PATHS:
            assert route.endpoint.__module__ != cases_router.__name__


def test_case_serialization_is_shared_with_incidents_router() -> None:
    assert cases_service.serialize_case.__module__ == "services.cases"
    assert cases_router.serialize_case is cases_service.serialize_case
    assert incidents_router.serialize_case is cases_service.serialize_case
    assert not hasattr(incidents_router, "_serialize_case_for_incident")
    assert not hasattr(incidents_router, "_calculate_case_sla_status")
    assert not hasattr(incidents_router, "_calculate_case_sla_breach_risk")
