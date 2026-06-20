#!/usr/bin/env python3
"""Report the current synthetic demo boundary without modifying state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts import demo_seed


SYNTHETIC_BOUNDARY = (
    "Demo records are synthetic, marker-owned data and must not be used as "
    "real security evidence."
)
StatusProvider = Callable[[], tuple[dict[str, Any], int]]


def build_report(
    seed_report: dict[str, Any],
    provider_exit_code: int,
) -> dict[str, Any]:
    seed_result = str(
        seed_report.get("seed_result")
        or seed_report.get("result")
        or "UNKNOWN"
    )
    counts = seed_report.get("counts")
    if not isinstance(counts, dict):
        counts = {}
    normalized_counts = {
        "incidents": int(counts.get("incidents") or 0),
        "cases": int(counts.get("cases") or 0),
        "case_links": int(counts.get("case_links") or 0),
        "case_actions": int(counts.get("case_actions") or 0),
        "case_ai_analyses": int(counts.get("case_ai_analyses") or 0),
    }
    marker = str(seed_report.get("marker") or demo_seed.DEMO_ACTOR)
    unavailable = (
        provider_exit_code != 0
        or seed_result in {"UNAVAILABLE", "NOT_READY", "FAILED", "UNKNOWN"}
    )
    if unavailable:
        result = "DEMO_INFO_NOT_READY"
        exit_code = 1
    elif seed_result in {"SEEDED", "PRESENT"}:
        result = "DEMO_INFO_READY"
        exit_code = 0
    else:
        result = "DEMO_INFO_READY_WITH_WARNINGS"
        exit_code = 0
    report: dict[str, Any] = {
        "result": result,
        "exit_code": exit_code,
        "marker": marker,
        "seed_status": seed_result,
        "counts": normalized_counts,
        "synthetic_boundary": SYNTHETIC_BOUNDARY,
        "next_steps": [
            "./ai-soc demo-reset --dry-run",
            "./ai-soc demo-seed --apply",
            "./ai-soc demo-validate --no-runtime",
        ],
    }
    message = seed_report.get("message")
    if isinstance(message, str) and message.strip():
        report["message"] = " ".join(message.split())
    return report


def default_status_provider() -> tuple[dict[str, Any], int]:
    return demo_seed.database_operation("status")


def print_human(report: dict[str, Any]) -> None:
    print("Sovereign AI SOC Demo Info")
    print()
    print(f"[INFO] Demo marker: {report['marker']}")
    status = "FAIL" if report["exit_code"] else (
        "OK" if report["seed_status"] in {"SEEDED", "PRESENT"} else "WARN"
    )
    print(f"[{status}] Demo seed status: {report['seed_status']}")
    counts = report["counts"]
    print(
        f"[{'OK' if counts['incidents'] else 'INFO'}] "
        f"Demo incidents: {counts['incidents']}"
    )
    print(
        f"[{'OK' if counts['cases'] else 'INFO'}] "
        f"Demo cases: {counts['cases']}"
    )
    print(f"[INFO] Linked demo records: {counts['case_links']}")
    print(f"[INFO] Demo actions: {counts['case_actions']}")
    print(f"[INFO] Demo analyses: {counts['case_ai_analyses']}")
    if report.get("message"):
        print(f"[WARN] {report['message']}")
    print(f"[INFO] {report['synthetic_boundary']}")
    print("[INFO] Reset demo records only: ./ai-soc demo-reset --dry-run")
    print()
    print(f"Result: {report['result']}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Show read-only synthetic demo status and ownership boundary.",
    )
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    *,
    status_provider: StatusProvider = default_status_provider,
) -> int:
    args = parse_args(argv)
    try:
        seed_report, provider_exit_code = status_provider()
        report = build_report(seed_report, provider_exit_code)
    except Exception as exc:
        report = build_report(
            {
                "result": "FAILED",
                "message": (
                    "Demo status could not be read: "
                    f"{exc.__class__.__name__}"
                ),
            },
            1,
        )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
