#!/usr/bin/env python3
"""Read-only validation for a local Sovereign AI SOC product demo."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT = 15


@dataclass(frozen=True)
class Check:
    check_id: str
    category: str
    status: str
    message: str


CommandResult = tuple[dict[str, Any] | None, str | None]
CommandRunner = Callable[[Path, list[str]], CommandResult]


def resolve_python(repository_root: Path = REPOSITORY_ROOT) -> str:
    virtualenv_python = repository_root / ".venv" / "bin" / "python"
    if virtualenv_python.is_file() and os.access(virtualenv_python, os.X_OK):
        return str(virtualenv_python)
    return sys.executable


def run_json_script(
    script: Path,
    arguments: list[str],
) -> tuple[dict[str, Any] | None, str | None]:
    command = [resolve_python(script.parent.parent), str(script), *arguments]
    try:
        completed = subprocess.run(
            command,
            cwd=script.parent.parent,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"{script.name} could not run: {exc.__class__.__name__}"

    try:
        payload = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        detail = (completed.stderr or completed.stdout).strip()
        return None, (
            f"{script.name} did not return valid JSON"
            + (f": {detail.splitlines()[0]}" if detail else "")
        )

    if not isinstance(payload, dict):
        return None, f"{script.name} returned an unexpected JSON payload"

    if completed.returncode != 0:
        message = payload.get("message") or f"exit code {completed.returncode}"
        return payload, f"{script.name} failed: {message}"

    return payload, None


def report_filename() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"demo-validation-{timestamp}.json"


def write_json_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            json.dump(report, temporary, indent=2, sort_keys=True)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
    finally:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()


class DemoValidator:
    def __init__(
        self,
        *,
        strict: bool,
        no_runtime: bool,
        write_report: bool,
        repository_root: Path = REPOSITORY_ROOT,
        command_runner: CommandRunner = run_json_script,
    ) -> None:
        self.strict = strict
        self.no_runtime = no_runtime
        self.write_report = write_report
        self.repository_root = repository_root
        self.command_runner = command_runner
        self.checks: list[Check] = []
        self.runtime_result: str | None = None
        self.demo_counts: dict[str, int] = {}
        self.demo_marker: str | None = None

    def add(
        self,
        check_id: str,
        category: str,
        status: str,
        message: str,
    ) -> None:
        self.checks.append(Check(check_id, category, status, message))

    def required_file(
        self,
        check_id: str,
        relative_path: str,
        label: str,
    ) -> None:
        exists = (self.repository_root / relative_path).is_file()
        self.add(
            check_id,
            "structure",
            "OK" if exists else "FAIL",
            f"{label} {'exists' if exists else 'is missing'}",
        )

    def collect_structure(self) -> None:
        repository_detected = (
            (self.repository_root / ".git").exists()
            and (self.repository_root / "README.md").is_file()
        )
        self.add(
            "repository_root",
            "structure",
            "OK" if repository_detected else "FAIL",
            (
                f"Repository root detected at {self.repository_root}"
                if repository_detected
                else f"Repository root not detected at {self.repository_root}"
            ),
        )
        self.required_file("wrapper", "ai-soc", "ai-soc wrapper")
        self.required_file(
            "demo_seed_script",
            "scripts/demo_seed.py",
            "demo seed script",
        )
        self.required_file(
            "runtime_validator",
            "scripts/validate_runtime.py",
            "runtime validation script",
        )

        report_dependencies = (
            "report_builder.py",
            "enterprise_report_templates.py",
            "evidence_pack_builder.py",
        )
        missing = [
            path
            for path in report_dependencies
            if not (self.repository_root / path).is_file()
        ]
        self.add(
            "report_dependencies",
            "report",
            "OK" if not missing else "FAIL",
            (
                "Report and evidence builder modules are available"
                if not missing
                else "Missing report dependencies: " + ", ".join(missing)
            ),
        )

    def collect_runtime(self) -> None:
        if self.no_runtime:
            self.add(
                "runtime",
                "runtime",
                "INFO",
                "Runtime validation skipped by --no-runtime",
            )
            return

        arguments = ["--json"]
        if self.strict:
            arguments.append("--strict")
        payload, error = self.command_runner(
            self.repository_root / "scripts" / "validate_runtime.py",
            arguments,
        )
        if payload:
            self.runtime_result = str(payload.get("result") or "UNKNOWN")

        if error or not payload:
            self.add(
                "runtime",
                "runtime",
                "FAIL",
                f"Runtime validation unavailable: {error or 'unknown error'}",
            )
            return

        if self.runtime_result == "READY":
            status = "OK"
        elif self.runtime_result == "READY_WITH_WARNINGS" and not self.strict:
            status = "WARN"
        else:
            status = "FAIL"
        self.add(
            "runtime",
            "runtime",
            status,
            f"Runtime validation completed: {self.runtime_result}",
        )

    def collect_demo_status(self) -> None:
        payload, error = self.command_runner(
            self.repository_root / "scripts" / "demo_seed.py",
            ["--status", "--json"],
        )
        if error or not payload:
            self.add(
                "demo_status",
                "demo",
                "FAIL",
                f"Demo seed status unavailable: {error or 'unknown error'}",
            )
            return

        result = str(
            payload.get("seed_result")
            or payload.get("result")
            or "UNKNOWN"
        )
        unavailable = result in {"UNAVAILABLE", "NOT_READY", "FAILED", "UNKNOWN"}
        status_message = str(payload.get("message") or "").strip()
        self.add(
            "demo_status",
            "demo",
            (
                "OK"
                if result in {"SEEDED", "PRESENT"}
                else "FAIL"
                if unavailable or self.strict
                else "WARN"
            ),
            (
                f"Demo seed status unavailable: {status_message or result}"
                if unavailable
                else f"Demo seed status available: {result}"
            ),
        )

        self.demo_marker = str(
            payload.get("demo_marker") or payload.get("marker") or ""
        ).strip()
        marker_valid = self.demo_marker.startswith("AI_SOC_DEMO_SEED")
        self.add(
            "demo_marker",
            "demo",
            "OK" if marker_valid else "FAIL",
            (
                f"Demo marker: {self.demo_marker}"
                if marker_valid
                else "Stable AI_SOC_DEMO_SEED marker is missing"
            ),
        )

        counts = payload.get("counts")
        if not isinstance(counts, dict):
            status = payload.get("status")
            counts = {
                "incidents": (
                    status.get("incident_count", 0)
                    if isinstance(status, dict)
                    else 0
                ),
                "cases": (
                    1
                    if isinstance(status, dict) and status.get("case_present")
                    else 0
                ),
            }
        self.demo_counts = {
            str(name): int(value)
            for name, value in counts.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }

        incident_count = self.demo_counts.get("incidents", 0)
        case_count = self.demo_counts.get("cases", 0)
        missing_status = "FAIL" if self.strict else "WARN"
        self.add(
            "demo_incidents",
            "demo",
            "OK" if incident_count > 0 else missing_status,
            f"Demo incidents present: {incident_count}",
        )
        self.add(
            "demo_cases",
            "demo",
            "OK" if case_count > 0 else missing_status,
            f"Demo cases present: {case_count}",
        )

        expected_incidents = 0
        status_payload = payload.get("status")
        if isinstance(status_payload, dict):
            expected_incidents = int(
                status_payload.get("expected_incident_count") or 0
            )
        inflated = bool(expected_incidents and incident_count > expected_incidents)
        idempotent = payload.get("idempotent") is True
        unsafe_collisions = (
            status_payload.get("unsafe_collisions", [])
            if isinstance(status_payload, dict)
            else []
        )
        self.add(
            "demo_idempotency",
            "demo",
            "FAIL" if inflated or unsafe_collisions or not idempotent else "OK",
            (
                "Demo status confirms idempotent seed and stable counts"
                if idempotent and not inflated and not unsafe_collisions
                else "Idempotency, duplicate inflation, or marker safety check failed"
            ),
        )

        synthetic = payload.get("synthetic") is True
        self.add(
            "demo_synthetic",
            "demo",
            "OK" if synthetic else "FAIL",
            (
                "Demo data is explicitly marked synthetic"
                if synthetic
                else "Demo status does not confirm synthetic data"
            ),
        )

        report_ready = (
            incident_count > 0
            and case_count > 0
            and self.demo_counts.get("case_links", 0) > 0
            and self.demo_counts.get("case_actions", 0) > 0
            and self.demo_counts.get("case_ai_analyses", 0) > 0
        )
        self.add(
            "report_data",
            "report",
            "OK" if report_ready else missing_status,
            (
                "Demo records contain linked incidents, an action, and analysis"
                if report_ready
                else "Demo records may be incomplete for case/report flows"
            ),
        )

    def summarize(self, report_path: str | None) -> tuple[dict[str, Any], int]:
        summary = {
            status.lower(): sum(check.status == status for check in self.checks)
            for status in ("OK", "WARN", "FAIL", "INFO")
        }
        summary["total"] = len(self.checks)
        exit_code = 1 if summary["fail"] else 0
        if exit_code:
            result = "DEMO_NOT_READY"
        elif summary["warn"]:
            result = "DEMO_READY_WITH_WARNINGS"
        else:
            result = "DEMO_READY"
        return (
            {
                "validator": "Sovereign AI SOC demo",
                "strict": self.strict,
                "runtime_skipped": self.no_runtime,
                "repository_root": str(self.repository_root),
                "result": result,
                "exit_code": exit_code,
                "summary": summary,
                "checks": [asdict(check) for check in self.checks],
                "demo_marker": self.demo_marker,
                "demo_counts": self.demo_counts,
                "runtime_result": self.runtime_result,
                "report_path": report_path,
            },
            exit_code,
        )

    def report(self) -> tuple[dict[str, Any], int]:
        self.collect_structure()
        self.collect_runtime()
        self.collect_demo_status()

        report_path: str | None = None
        if self.write_report:
            target = (
                self.repository_root
                / "reports"
                / "validation"
                / report_filename()
            )
            report_path = str(target)
            self.add(
                "validation_report",
                "report",
                "OK",
                f"Validation report written to {target}",
            )
            report, exit_code = self.summarize(report_path)
            try:
                write_json_report(target, report)
            except OSError as exc:
                self.checks[-1] = Check(
                    "validation_report",
                    "report",
                    "FAIL",
                    f"Could not write validation report: {exc.__class__.__name__}",
                )
                return self.summarize(None)
            return report, exit_code

        self.add(
            "validation_report",
            "report",
            "WARN",
            "Report export not executed by default",
        )
        return self.summarize(None)


def print_human(report: dict[str, Any]) -> None:
    print("Sovereign AI SOC Demo Validator")
    print(f"[INFO] Repository: {report['repository_root']}")
    print(f"[INFO] Mode: {'strict' if report['strict'] else 'standard'}")
    print("[INFO] Read-only validation; demo data is never seeded")
    print()
    for check in report["checks"]:
        print(f"[{check['status']}] {check['message']}")
    if not report["report_path"]:
        print(
            "[INFO] Run ./ai-soc demo-validate --write-report "
            "to create a local validation artifact"
        )
    print()
    print(f"Result: {report['result']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate local Sovereign AI SOC demo readiness.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable JSON report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat runtime and missing demo data warnings as failures.",
    )
    parser.add_argument(
        "--no-runtime",
        action="store_true",
        help="Skip runtime endpoint validation.",
    )
    parser.add_argument(
        "--write-report",
        action="store_true",
        help="Write a timestamped JSON report under reports/validation/.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report, exit_code = DemoValidator(
        strict=args.strict,
        no_runtime=args.no_runtime,
        write_report=args.write_report,
    ).report()
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print_human(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
