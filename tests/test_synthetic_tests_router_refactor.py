from __future__ import annotations

import api
from routers import synthetic_tests as synthetic_tests_router
from schemas.synthetic_tests import SyntheticTestRunCreate
from scripts.export_api_route_inventory import build_route_inventory, iter_api_routes


SYNTHETIC_TEST_ROUTE_METHODS = {
    "/synthetic-tests/scenarios": {"GET"},
    "/synthetic-tests/run": {"POST"},
}


def _routes_by_path_method():
    return {
        (route.path, method): route
        for route in iter_api_routes()
        for method in route.methods or set()
    }


def _model_default(model_cls, field_name: str):
    fields = getattr(model_cls, "model_fields", None)

    if fields is not None:
        return fields[field_name].default

    return model_cls.__fields__[field_name].default


def test_synthetic_test_routes_are_registered_once_from_router() -> None:
    routes_by_path_method = _routes_by_path_method()
    expected_path_methods = {
        (path, method)
        for path, methods in SYNTHETIC_TEST_ROUTE_METHODS.items()
        for method in methods
    }

    assert expected_path_methods <= set(routes_by_path_method)
    assert (
        routes_by_path_method[("/synthetic-tests/scenarios", "GET")].endpoint
        is synthetic_tests_router.list_synthetic_test_scenarios
    )
    assert (
        routes_by_path_method[("/synthetic-tests/run", "POST")].endpoint
        is synthetic_tests_router.run_synthetic_tests
    )

    counts: dict[tuple[str, str], int] = {}
    for route in iter_api_routes():
        if route.path in SYNTHETIC_TEST_ROUTE_METHODS:
            for method in route.methods or set():
                counts[(route.path, method)] = counts.get((route.path, method), 0) + 1

    assert counts == {
        (path, method): 1
        for path, methods in SYNTHETIC_TEST_ROUTE_METHODS.items()
        for method in methods
    }


def test_synthetic_test_routes_no_longer_live_in_api_module() -> None:
    moved_names = {
        "list_synthetic_test_scenarios",
        "run_synthetic_tests",
        "build_synthetic_incident",
    }

    for name in moved_names:
        assert not hasattr(api, name)


def test_synthetic_test_route_inventory_remains_non_trivial() -> None:
    inventory = build_route_inventory()
    route_methods = {
        item["path"]: set(item["methods"])
        for item in inventory
        if item["path"] in SYNTHETIC_TEST_ROUTE_METHODS
    }

    assert len(inventory) == 171
    assert route_methods == SYNTHETIC_TEST_ROUTE_METHODS


def test_synthetic_test_run_schema_defaults_are_unchanged() -> None:
    assert _model_default(SyntheticTestRunCreate, "scenario") == "all"
    assert _model_default(SyntheticTestRunCreate, "count") == 1
    assert _model_default(SyntheticTestRunCreate, "host") is None
    assert _model_default(SyntheticTestRunCreate, "created_by") is None

    payload = SyntheticTestRunCreate()
    assert payload.scenario == "all"
    assert payload.count == 1
    assert payload.host is None
    assert payload.created_by is None
