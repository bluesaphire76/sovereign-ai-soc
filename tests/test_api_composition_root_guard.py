from __future__ import annotations

from fastapi import FastAPI

from api import app
from scripts.check_api_composition_root import (
    MAX_API_LINES,
    api_line_count,
    find_route_decorators,
    read_api_source,
)
from scripts.export_api_route_inventory import build_route_inventory


def test_api_py_has_no_route_decorators() -> None:
    assert find_route_decorators(read_api_source()) == []


def test_api_py_size_guard() -> None:
    assert api_line_count(read_api_source()) <= MAX_API_LINES


def test_api_py_still_includes_routers() -> None:
    assert "include_app_routers(app)" in read_api_source()


def test_api_app_still_registers_routes() -> None:
    assert isinstance(app, FastAPI)
    assert len(build_route_inventory()) == 171
