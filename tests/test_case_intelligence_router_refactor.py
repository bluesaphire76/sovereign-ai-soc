from __future__ import annotations

import api
from routers import case_intelligence as case_intelligence_router
from scripts.export_api_route_inventory import build_route_inventory, iter_api_routes


CASE_INTELLIGENCE_ROUTE_METHODS = {
    "/cases/{case_id}/actions/suggestions": {"POST"},
    "/cases/{case_id}/ai-generation/{job_type}": {"POST"},
    "/cases/{case_id}/ai-generation/{job_type}/latest": {"GET"},
    "/cases/{case_id}/ai-generation/jobs/{job_id}": {"GET"},
    "/cases/{case_id}/timeline": {"GET"},
    "/cases/{case_id}/analysis": {"GET", "POST"},
}


def _routes_by_path_method():
    return {
        (route.path, method): route
        for route in iter_api_routes()
        for method in route.methods or set()
    }


def test_case_intelligence_routes_are_registered_once_from_router() -> None:
    routes_by_path_method = _routes_by_path_method()
    expected_path_methods = {
        (path, method)
        for path, methods in CASE_INTELLIGENCE_ROUTE_METHODS.items()
        for method in methods
    }

    assert expected_path_methods <= set(routes_by_path_method)
    assert (
        routes_by_path_method[("/cases/{case_id}/actions/suggestions", "POST")].endpoint
        is case_intelligence_router.suggest_case_action_plan
    )
    assert (
        routes_by_path_method[("/cases/{case_id}/ai-generation/{job_type}", "POST")].endpoint
        is case_intelligence_router.start_case_ai_generation_job
    )
    assert (
        routes_by_path_method[("/cases/{case_id}/ai-generation/{job_type}/latest", "GET")].endpoint
        is case_intelligence_router.get_latest_case_ai_generation_job
    )
    assert (
        routes_by_path_method[("/cases/{case_id}/ai-generation/jobs/{job_id}", "GET")].endpoint
        is case_intelligence_router.get_case_ai_generation_job
    )
    assert (
        routes_by_path_method[("/cases/{case_id}/timeline", "GET")].endpoint
        is case_intelligence_router.get_case_timeline
    )
    assert (
        routes_by_path_method[("/cases/{case_id}/analysis", "GET")].endpoint
        is case_intelligence_router.get_case_analysis
    )
    assert (
        routes_by_path_method[("/cases/{case_id}/analysis", "POST")].endpoint
        is case_intelligence_router.create_case_analysis
    )

    counts: dict[tuple[str, str], int] = {}
    for route in iter_api_routes():
        if route.path in CASE_INTELLIGENCE_ROUTE_METHODS:
            for method in route.methods or set():
                counts[(route.path, method)] = counts.get((route.path, method), 0) + 1

    assert counts == {
        (path, method): 1
        for path, methods in CASE_INTELLIGENCE_ROUTE_METHODS.items()
        for method in methods
    }


def test_case_intelligence_routes_no_longer_live_in_api_module() -> None:
    moved_names = {
        "suggest_case_action_plan",
        "run_case_generation_job_with_audit",
        "start_case_ai_generation_job",
        "get_latest_case_ai_generation_job",
        "get_case_ai_generation_job",
        "get_case_timeline",
        "get_case_analysis",
        "create_case_analysis",
    }

    for name in moved_names:
        assert not hasattr(api, name)


def test_case_intelligence_route_inventory_remains_stable() -> None:
    inventory = build_route_inventory()
    route_methods: dict[str, set[str]] = {}

    for item in inventory:
        if item["path"] in CASE_INTELLIGENCE_ROUTE_METHODS:
            route_methods.setdefault(str(item["path"]), set()).update(item["methods"])

    assert len(inventory) == 171
    assert route_methods == CASE_INTELLIGENCE_ROUTE_METHODS


def test_wazuh_ingest_route_remains_in_api_module() -> None:
    routes_by_path_method = _routes_by_path_method()

    assert routes_by_path_method[("/platform/ingest/wazuh", "GET")].endpoint is api.wazuh_ingest_watermark
