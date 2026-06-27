from __future__ import annotations

import api
from routers import executive as executive_router
from routers import metrics_summary as metrics_summary_router
from scripts.export_api_route_inventory import build_route_inventory, iter_api_routes


EXECUTIVE_METRICS_ROUTE_METHODS = {
    "/executive/summary": {"GET"},
    "/metrics/status-distribution": {"GET"},
    "/metrics/summary": {"GET"},
    "/metrics/top-hosts": {"GET"},
    "/metrics/risk-distribution": {"GET"},
}


def _routes_by_path_method():
    return {
        (route.path, method): route
        for route in iter_api_routes()
        for method in route.methods or set()
    }


def test_executive_and_metrics_routes_are_registered_once_from_routers() -> None:
    routes_by_path_method = _routes_by_path_method()
    expected_path_methods = {
        (path, method)
        for path, methods in EXECUTIVE_METRICS_ROUTE_METHODS.items()
        for method in methods
    }

    assert expected_path_methods <= set(routes_by_path_method)
    assert (
        routes_by_path_method[("/executive/summary", "GET")].endpoint
        is executive_router.executive_summary
    )
    assert (
        routes_by_path_method[("/metrics/status-distribution", "GET")].endpoint
        is metrics_summary_router.metrics_status_distribution
    )
    assert (
        routes_by_path_method[("/metrics/summary", "GET")].endpoint
        is metrics_summary_router.metrics_summary
    )
    assert (
        routes_by_path_method[("/metrics/top-hosts", "GET")].endpoint
        is metrics_summary_router.metrics_top_hosts
    )
    assert (
        routes_by_path_method[("/metrics/risk-distribution", "GET")].endpoint
        is metrics_summary_router.metrics_risk_distribution
    )

    counts: dict[tuple[str, str], int] = {}
    for route in iter_api_routes():
        if route.path in EXECUTIVE_METRICS_ROUTE_METHODS:
            for method in route.methods or set():
                counts[(route.path, method)] = counts.get((route.path, method), 0) + 1

    assert counts == {
        (path, method): 1
        for path, methods in EXECUTIVE_METRICS_ROUTE_METHODS.items()
        for method in methods
    }


def test_executive_and_metrics_routes_no_longer_live_in_api_module() -> None:
    moved_names = {
        "executive_summary",
        "metrics_status_distribution",
        "metrics_summary",
        "metrics_top_hosts",
        "metrics_risk_distribution",
    }

    for name in moved_names:
        assert not hasattr(api, name)


def test_executive_and_metrics_route_inventory_remains_stable() -> None:
    inventory = build_route_inventory()
    route_methods = {
        item["path"]: set(item["methods"])
        for item in inventory
        if item["path"] in EXECUTIVE_METRICS_ROUTE_METHODS
    }

    assert len(inventory) == 171
    assert route_methods == EXECUTIVE_METRICS_ROUTE_METHODS
