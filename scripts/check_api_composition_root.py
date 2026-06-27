#!/usr/bin/env python3
"""Guard that keeps api.py as the FastAPI composition root."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
API_PATH = REPOSITORY_ROOT / "api.py"
MAX_API_LINES = 150
ROUTE_DECORATOR_RE = re.compile(
    r"^[ \t]*@app\.(get|post|patch|delete|put|options|head)\(",
    re.MULTILINE,
)


def fail(message: str) -> int:
    print(f"[FAIL] {message}")
    return 1


def read_api_source() -> str:
    return API_PATH.read_text(encoding="utf-8")


def api_line_count(source: str) -> int:
    return len(source.splitlines())


def find_route_decorators(source: str) -> list[str]:
    return [
        line.strip()
        for line in source.splitlines()
        if ROUTE_DECORATOR_RE.match(line)
    ]


def main() -> int:
    if not API_PATH.exists():
        return fail("api.py is missing.")

    source = read_api_source()
    line_count = api_line_count(source)
    route_decorators = find_route_decorators(source)

    if line_count > MAX_API_LINES:
        return fail(
            f"api.py is {line_count} lines; keep it at or below {MAX_API_LINES} lines."
        )

    if route_decorators:
        return fail(
            "api.py contains route decorators. Move endpoint routes into routers/: "
            + ", ".join(route_decorators)
        )

    if "FastAPI(" not in source:
        return fail("api.py does not appear to create the FastAPI app.")

    if "include_app_routers(app)" not in source:
        return fail("api.py must call include_app_routers(app).")

    print(
        "[OK] api.py composition root guard passed: "
        f"{line_count} lines, {len(route_decorators)} route decorators"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
