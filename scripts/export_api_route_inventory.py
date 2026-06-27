#!/usr/bin/env python3
"""Export the registered FastAPI route inventory for refactor baselining."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.routing import APIRoute


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = REPO_ROOT / "reports" / "validation" / "api-route-inventory.json"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from api import app  # noqa: E402


def build_route_inventory() -> list[dict[str, object]]:
    inventory: list[dict[str, object]] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        inventory.append(
            {
                "path": route.path,
                "methods": sorted(route.methods or []),
                "endpoint_name": route.endpoint.__name__,
                "route_name": route.name,
                "tags": [str(tag) for tag in route.tags],
            }
        )

    return sorted(
        inventory,
        key=lambda item: (
            str(item["path"]),
            ",".join(item["methods"]),
            str(item["route_name"]),
            str(item["endpoint_name"]),
        ),
    )


def main() -> int:
    inventory = build_route_inventory()
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"Exported {len(inventory)} API routes to "
        f"{REPORT_PATH.relative_to(REPO_ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
