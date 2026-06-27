from __future__ import annotations

import re
from pathlib import Path

import api
from routers import platform_ingest as platform_ingest_router
from scripts.export_api_route_inventory import build_route_inventory, iter_api_routes


PLATFORM_INGEST_ROUTE_METHODS = {
    "/platform/ingest/wazuh": {"GET"},
}


def _routes_by_path_method():
    return {
        (route.path, method): route
        for route in iter_api_routes()
        for method in route.methods or set()
    }


def test_platform_ingest_route_is_registered_once_from_router() -> None:
    routes_by_path_method = _routes_by_path_method()

    assert ("/platform/ingest/wazuh", "GET") in routes_by_path_method
    assert (
        routes_by_path_method[("/platform/ingest/wazuh", "GET")].endpoint
        is platform_ingest_router.wazuh_ingest_watermark
    )

    counts: dict[tuple[str, str], int] = {}
    for route in iter_api_routes():
        if route.path in PLATFORM_INGEST_ROUTE_METHODS:
            for method in route.methods or set():
                counts[(route.path, method)] = counts.get((route.path, method), 0) + 1

    assert counts == {
        (path, method): 1
        for path, methods in PLATFORM_INGEST_ROUTE_METHODS.items()
        for method in methods
    }


def test_platform_ingest_route_no_longer_lives_in_api_module() -> None:
    assert not hasattr(api, "wazuh_ingest_watermark")


def test_no_route_decorators_remain_in_api_module() -> None:
    api_source = Path(api.__file__).read_text(encoding="utf-8")

    assert not re.search(r"^[ \t]*@app\.(get|post|patch|delete|put)\(", api_source, re.MULTILINE)


def test_platform_ingest_route_inventory_remains_stable() -> None:
    inventory = build_route_inventory()
    route_methods = {
        item["path"]: set(item["methods"])
        for item in inventory
        if item["path"] in PLATFORM_INGEST_ROUTE_METHODS
    }

    assert len(inventory) == 171
    assert route_methods == PLATFORM_INGEST_ROUTE_METHODS
