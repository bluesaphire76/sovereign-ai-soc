#!/usr/bin/env python3
"""Run safe, offline smoke checks for the root Sovereign AI SOC CLI."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT_SECONDS = 30.0

UNHANDLED_ERROR_MARKERS = (
    "Traceback (most recent call last):",
    "During handling of the above exception",
    "The above exception was the direct cause",
    "ModuleNotFoundError:",
    "ImportError:",
    "SyntaxError:",
    "NameError:",
    "Segmentation fault",
    "core dumped",
)
SECRET_PATTERNS = (
    ("GitHub personal access token", r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    ("GitHub classic token", r"\bghp_[A-Za-z0-9]{20,}"),
    ("private key", r"\bPRIVATE KEY\b"),
    (
        "bearer token",
        r"\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{20,}",
    ),
    ("password value", r"\bpassword\s*=\s*(?![<\"'$])\S{8,}"),
    ("API key value", r"\bapi[_-]?key\s*=\s*(?![<\"'$])\S{12,}"),
)


@dataclass(frozen=True)
class CommandSpec:
    arguments: tuple[str, ...]
    markers: tuple[str, ...] = ()
    any_markers: tuple[str, ...] = ()
    json_results: frozenset[str] = frozenset()
    json_identity: tuple[str, str] | None = None
    nonzero_results: frozenset[str] = frozenset()
    nonzero_markers: tuple[str, ...] = ()

    @property
    def display(self) -> str:
        return " ".join(("./ai-soc", *self.arguments))


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    execution_error: str | None = None


@dataclass(frozen=True)
class CheckResult:
    command: str
    status: str
    exit_code: int
    timed_out: bool
    message: str
    result: str | None = None


CommandRunner = Callable[[Path, Sequence[str], float], ProcessResult]

REQUIRED_COMMANDS = (
    CommandSpec(
        ("help",),
        markers=("Sovereign AI SOC local CLI", "Usage:"),
    ),
    CommandSpec(
        ("version",),
        markers=("Sovereign AI SOC local CLI", "Git commit:"),
    ),
    CommandSpec(
        ("validate",),
        markers=("Public CI baseline validation completed",),
    ),
    CommandSpec(
        ("docs-validate", "--json"),
        json_results=frozenset({"EXTERNAL_DOCS_READY"}),
        json_identity=("validator", "Sovereign AI SOC external documentation"),
    ),
    CommandSpec(
        ("doctor", "--json"),
        json_results=frozenset({"READY", "READY_WITH_WARNINGS"}),
        json_identity=("doctor", "Sovereign AI SOC"),
    ),
    CommandSpec(
        ("init", "--profile", "demo", "--dry-run"),
        markers=(
            "Sovereign AI SOC environment initializer",
            "[INFO] Profile: demo",
        ),
        any_markers=(
            "[OK] Dry run completed; no files written",
            "[OK] .env already exists; no changes made",
        ),
    ),
    CommandSpec(
        ("demo-seed", "--dry-run"),
        markers=(
            "[INFO] Mode: dry-run",
            "no database writes were performed",
            "Existing non-demo records would not be changed",
        ),
    ),
)

GRACEFUL_COMMANDS = (
    CommandSpec(
        ("validate-runtime", "--json"),
        json_results=frozenset({"READY", "READY_WITH_WARNINGS", "NOT_READY"}),
        json_identity=("validator", "Sovereign AI SOC runtime"),
        nonzero_results=frozenset({"NOT_READY"}),
    ),
    CommandSpec(
        ("demo-seed", "--status"),
        markers=("Sovereign AI SOC Demo Seed", "[INFO] Mode: status"),
        nonzero_markers=(
            "Could not inspect the application database",
            "dependencies/configuration are unavailable",
            "Application database is unavailable",
        ),
    ),
    CommandSpec(
        ("demo-info", "--json"),
        json_results=frozenset(
            {
                "DEMO_INFO_READY",
                "DEMO_INFO_READY_WITH_WARNINGS",
                "DEMO_INFO_NOT_READY",
            }
        ),
        nonzero_results=frozenset({"DEMO_INFO_NOT_READY"}),
    ),
    CommandSpec(
        ("demo-reset", "--dry-run", "--json"),
        json_results=frozenset(
            {
                "DEMO_RESET_DRY_RUN_READY",
                "DEMO_RESET_READY_WITH_WARNINGS",
                "DEMO_RESET_NOT_READY",
            }
        ),
        nonzero_results=frozenset({"DEMO_RESET_NOT_READY"}),
    ),
    CommandSpec(
        ("demo-validate", "--no-runtime", "--json"),
        json_results=frozenset(
            {"DEMO_READY", "DEMO_READY_WITH_WARNINGS", "DEMO_NOT_READY"}
        ),
        json_identity=("validator", "Sovereign AI SOC demo"),
        nonzero_results=frozenset({"DEMO_NOT_READY"}),
    ),
    CommandSpec(
        ("demo-status", "--json"),
        json_results=frozenset(
            {
                "DEMO_RUNTIME_READY",
                "DEMO_RUNTIME_READY_WITH_WARNINGS",
                "DEMO_RUNTIME_NOT_READY",
            }
        ),
        json_identity=("action", "status"),
        nonzero_results=frozenset({"DEMO_RUNTIME_NOT_READY"}),
    ),
    CommandSpec(
        ("demo-up", "--dry-run"),
        markers=("[DRY-RUN] No service changes were made.", "Result:"),
        nonzero_markers=("systemctl was not found",),
    ),
    CommandSpec(
        ("demo-down", "--dry-run"),
        markers=("[DRY-RUN] No service changes were made.", "Result:"),
        nonzero_markers=("systemctl was not found",),
    ),
)


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_command(
    repository_root: Path,
    arguments: Sequence[str],
    timeout_seconds: float,
) -> ProcessResult:
    try:
        completed = subprocess.run(
            list(arguments),
            cwd=repository_root,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return ProcessResult(
            124,
            _text(exc.stdout),
            _text(exc.stderr),
            timed_out=True,
        )
    except OSError as exc:
        return ProcessResult(
            127,
            execution_error=exc.__class__.__name__,
        )
    return ProcessResult(
        completed.returncode,
        completed.stdout,
        completed.stderr,
    )


def path_signature(path: Path) -> tuple[object, ...]:
    if not path.exists():
        return ("missing",)
    try:
        stat_result = path.stat()
    except OSError as exc:
        return ("unreadable", exc.__class__.__name__)
    if not path.is_dir():
        return (
            "file",
            stat_result.st_mode,
            stat_result.st_size,
            stat_result.st_mtime_ns,
        )

    entries: list[tuple[object, ...]] = []
    try:
        children = sorted(path.rglob("*"))
    except OSError as exc:
        return ("unreadable-directory", exc.__class__.__name__)
    for child in children:
        try:
            child_stat = child.stat()
            entries.append(
                (
                    str(child.relative_to(path)),
                    child.is_dir(),
                    child_stat.st_mode,
                    child_stat.st_size,
                    child_stat.st_mtime_ns,
                )
            )
        except OSError as exc:
            entries.append((str(child), exc.__class__.__name__))
    return ("directory", *entries)


def protected_state(repository_root: Path) -> dict[str, tuple[object, ...]]:
    return {
        name: path_signature(repository_root / name)
        for name in (".env", ".runtime", "reports/validation")
    }


def output_failures(output: str) -> list[str]:
    failures = [
        "unhandled Python error output: " + marker
        for marker in UNHANDLED_ERROR_MARKERS
        if marker.lower() in output.lower()
    ]
    for label, expression in SECRET_PATTERNS:
        if re.search(expression, output, re.IGNORECASE):
            failures.append("possible secret output: " + label)
    return failures


def parse_json_result(
    spec: CommandSpec,
    process: ProcessResult,
    failures: list[str],
) -> str | None:
    if not spec.json_results:
        return None
    try:
        payload = json.loads(process.stdout)
    except (json.JSONDecodeError, TypeError):
        failures.append("stdout is not valid JSON")
        return None
    if not isinstance(payload, dict):
        failures.append("JSON payload is not an object")
        return None

    result = str(payload.get("result")) if "result" in payload else None
    if result not in spec.json_results:
        failures.append(f"unexpected JSON result {result!r}")
    if payload.get("exit_code") != process.returncode:
        failures.append("JSON exit_code does not match process exit code")
    if spec.json_identity:
        key, expected = spec.json_identity
        if payload.get(key) != expected:
            failures.append(f"unexpected JSON identity field {key!r}")
    return result


def evaluate_command(
    spec: CommandSpec,
    process: ProcessResult,
    *,
    required: bool,
    protected_paths_changed: tuple[str, ...] = (),
) -> CheckResult:
    output = "\n".join(
        part for part in (process.stdout, process.stderr) if part
    )
    failures = output_failures(output)
    if process.timed_out:
        failures.append("command timed out")
    if process.execution_error:
        failures.append(f"could not execute command: {process.execution_error}")
    if not output.strip():
        failures.append("command returned no output")
    failures.extend(
        f"missing expected output marker {marker!r}"
        for marker in spec.markers
        if marker not in output
    )
    if spec.any_markers and not any(
        marker in output for marker in spec.any_markers
    ):
        failures.append("missing expected safe/no-op output")

    result = parse_json_result(spec, process, failures)
    if required and process.returncode != 0:
        failures.append(
            f"required command returned {process.returncode}, expected 0"
        )
    elif not required:
        if process.returncode not in {0, 1}:
            failures.append(
                f"graceful command returned unexpected exit code "
                f"{process.returncode}"
            )
        elif process.returncode == 1:
            expected = (
                result in spec.nonzero_results
                if spec.json_results
                else any(marker in output for marker in spec.nonzero_markers)
            )
            if not expected:
                failures.append(
                    "exit 1 did not report an expected unavailable-runtime "
                    "condition"
                )
    if protected_paths_changed:
        failures.append(
            "modified protected local path(s): "
            + ", ".join(protected_paths_changed)
        )

    if failures:
        return CheckResult(
            spec.display,
            "FAIL",
            process.returncode,
            process.timed_out,
            "; ".join(failures),
            result,
        )

    message = (
        "completed successfully"
        if required
        else f"returned {process.returncode}"
    )
    if process.returncode == 1:
        message += " with expected graceful degradation"
    if result:
        message += f" ({result})"
    return CheckResult(
        spec.display,
        "OK",
        process.returncode,
        False,
        message,
        result,
    )


class CliSmokeValidator:
    def __init__(
        self,
        *,
        repository_root: Path = REPOSITORY_ROOT,
        runner: CommandRunner = run_command,
        timeout_seconds: float = COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        self.repository_root = repository_root
        self.runner = runner
        self.timeout_seconds = timeout_seconds

    def run_spec(self, spec: CommandSpec, *, required: bool) -> CheckResult:
        before = protected_state(self.repository_root)
        process = self.runner(
            self.repository_root,
            ("./ai-soc", *spec.arguments),
            self.timeout_seconds,
        )
        after = protected_state(self.repository_root)
        changed = tuple(
            name for name, signature in before.items()
            if after.get(name) != signature
        )
        return evaluate_command(
            spec,
            process,
            required=required,
            protected_paths_changed=changed,
        )

    def report(self) -> tuple[dict[str, object], int]:
        required_checks = [
            self.run_spec(spec, required=True)
            for spec in REQUIRED_COMMANDS
        ]
        graceful_checks = [
            self.run_spec(spec, required=False)
            for spec in GRACEFUL_COMMANDS
        ]

        def counts(checks: list[CheckResult]) -> dict[str, int]:
            ok = sum(check.status == "OK" for check in checks)
            return {"ok": ok, "fail": len(checks) - ok, "total": len(checks)}

        summary = {
            "required": counts(required_checks),
            "graceful": counts(graceful_checks),
        }
        exit_code = int(
            summary["required"]["fail"] > 0
            or summary["graceful"]["fail"] > 0
        )
        report: dict[str, object] = {
            "result": (
                "CLI_SMOKE_NOT_READY" if exit_code else "CLI_SMOKE_READY"
            ),
            "exit_code": exit_code,
            "required_checks": [asdict(check) for check in required_checks],
            "graceful_checks": [asdict(check) for check in graceful_checks],
            "summary": summary,
        }
        return report, exit_code


def print_human(report: dict[str, object]) -> None:
    print("Sovereign AI SOC CLI Smoke Validation")
    print()
    for group, key in (
        ("required", "required_checks"),
        ("graceful", "graceful_checks"),
    ):
        for check in report[key]:
            suffix = ""
            if check["status"] != "OK":
                suffix = f": {check['message']}"
            elif group == "graceful":
                suffix = f" {check['message']}"
            print(f"[{check['status']}] {group}: {check['command']}{suffix}")

    print()
    for label, key in (
        ("Required commands", "required"),
        ("Graceful commands", "graceful"),
    ):
        counts = report["summary"][key]
        print(f"{label}: {counts['ok']} OK, {counts['fail']} FAIL")
    print(f"Result: {report['result']}")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run safe root CLI smoke checks without requiring runtime services."
        )
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable JSON report.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report, exit_code = CliSmokeValidator().report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
