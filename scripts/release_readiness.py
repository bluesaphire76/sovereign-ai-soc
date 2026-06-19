#!/usr/bin/env python3
"""Read-only release-readiness checks for Sovereign AI SOC."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
REPORT_DIR = REPO_ROOT / "reports" / "validation"
STATUS_OK = "OK"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_SKIP = "SKIP"
RESULT_READY = "RELEASE_READY"
RESULT_WARNINGS = "RELEASE_READY_WITH_WARNINGS"
RESULT_NOT_READY = "RELEASE_NOT_READY"

DIRECT_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)\bauthorization:\s*(?:bearer|basic)\s+\S{20,}"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bPRIVATE KEY\b"),
)
KEY_VALUE_SECRET_PATTERN = re.compile(
    r"""(?ix)
    \b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)\b
    \s*[:=]\s*
    (?P<value>"[^"]*"|'[^']*'|[^\s,;]+)
    """
)
UNHANDLED_ERROR_MARKERS = ("Traceback (most recent call last):",)


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error: str | None = None


@dataclass(frozen=True)
class Check:
    name: str
    category: str
    status: str
    command: str | None
    returncode: int | None
    summary: str
    duration_seconds: float
    strict_blocking: bool = False


Runner = Callable[..., CommandResult]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run read-only checks before creating or sharing a release.",
    )
    parser.add_argument("--json", action="store_true", help="Emit one JSON document.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat release-significant warnings as blockers.",
    )
    parser.add_argument(
        "--no-runtime",
        action="store_true",
        help="Skip the runtime validation check.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Also run pytest, the frontend build, and Compose config validation.",
    )
    parser.add_argument(
        "--write-report",
        action="store_true",
        help="Write Markdown and JSON reports under reports/validation.",
    )
    return parser.parse_args(argv)


def run_command(
    args: list[str],
    *,
    cwd: Path = REPO_ROOT,
    timeout: int = 60,
    env: dict[str, str] | None = None,
) -> CommandResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            returncode=None,
            stdout=_to_text(exc.stdout),
            stderr=_to_text(exc.stderr),
            duration_seconds=round(time.monotonic() - started, 3),
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(
            returncode=None,
            stdout="",
            stderr="",
            duration_seconds=round(time.monotonic() - started, 3),
            error=f"{type(exc).__name__}: {exc}",
        )

    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_seconds=round(time.monotonic() - started, 3),
    )


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def command_display(args: Iterable[str]) -> str:
    rendered: list[str] = []
    for arg in args:
        try:
            rendered.append(str(Path(arg).relative_to(REPO_ROOT)))
        except (ValueError, TypeError):
            rendered.append(arg)
    return shlex.join(rendered)


def contains_secret(text: str) -> bool:
    if any(pattern.search(text) for pattern in DIRECT_SECRET_PATTERNS):
        return True
    for match in KEY_VALUE_SECRET_PATTERN.finditer(text):
        value = match.group("value").strip("\"'")
        if re.fullmatch(r"<[^>]+>", value):
            continue
        if re.fullmatch(r"\$(?:\{[A-Z0-9_]+\}|[A-Z0-9_]+)", value):
            continue
        return True
    return False


def contains_unhandled_error(text: str) -> bool:
    return any(marker in text for marker in UNHANDLED_ERROR_MARKERS)


def concise_output(text: str, limit: int = 240) -> str:
    lines = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
    if not lines:
        return "No output."
    value = lines[-1]
    return value if len(value) <= limit else f"{value[: limit - 3]}..."


def command_check(
    *,
    name: str,
    category: str,
    args: list[str],
    runner: Runner = run_command,
    timeout: int = 60,
    cwd: Path = REPO_ROOT,
    env: dict[str, str] | None = None,
    strict_blocking: bool = False,
    display_command: str | None = None,
    classify: Callable[[CommandResult], tuple[str, str]] | None = None,
) -> Check:
    result = runner(args, cwd=cwd, timeout=timeout, env=env)
    combined = "\n".join((result.stdout, result.stderr))
    display = display_command or command_display(args)

    if contains_secret(combined):
        return Check(
            name,
            category,
            STATUS_FAIL,
            display,
            result.returncode,
            "[REDACTED secret-like output]",
            result.duration_seconds,
            True,
        )
    if contains_unhandled_error(combined):
        return Check(
            name,
            category,
            STATUS_FAIL,
            display,
            result.returncode,
            "Command emitted an unhandled traceback.",
            result.duration_seconds,
            True,
        )
    if result.timed_out:
        return Check(
            name,
            category,
            STATUS_FAIL,
            display,
            None,
            f"Timed out after {timeout} seconds.",
            result.duration_seconds,
            True,
        )
    if result.error:
        return Check(
            name,
            category,
            STATUS_FAIL,
            display,
            None,
            result.error,
            result.duration_seconds,
            True,
        )

    if classify is not None:
        status, summary = classify(result)
    elif result.returncode == 0:
        status, summary = STATUS_OK, concise_output(result.stdout or result.stderr)
    else:
        status = STATUS_FAIL
        summary = f"Command exited with status {result.returncode}."

    return Check(
        name,
        category,
        status,
        display,
        result.returncode,
        summary,
        result.duration_seconds,
        strict_blocking if status == STATUS_WARN else status == STATUS_FAIL,
    )


def json_classifier(
    status_map: dict[str, str],
    *,
    result_field: str = "result",
) -> Callable[[CommandResult], tuple[str, str]]:
    def classify(result: CommandResult) -> tuple[str, str]:
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return STATUS_FAIL, "Command did not return valid JSON."
        value = str(payload.get(result_field, "UNKNOWN"))
        status = status_map.get(value)
        if status is None:
            return STATUS_FAIL, f"Unexpected result: {value}."
        if status == STATUS_OK and result.returncode != 0:
            return STATUS_FAIL, f"{value}; command exited with status {result.returncode}."
        summary_bits = [value]
        message = payload.get("message")
        if isinstance(message, str) and message.strip():
            summary_bits.append(" ".join(message.split()))
        return status, "; ".join(summary_bits)

    return classify


def python_executable() -> Path:
    venv_python = REPO_ROOT / ".venv" / "bin" / "python"
    if venv_python.is_file() and os.access(venv_python, os.X_OK):
        return venv_python
    discovered = shutil.which("python3")
    return Path(discovered) if discovered else Path(sys.executable)


def repository_checks(runner: Runner = run_command) -> tuple[dict[str, object], list[Check]]:
    checks: list[Check] = []

    def git(args: list[str]) -> CommandResult:
        return runner(["git", *args], cwd=REPO_ROOT, timeout=30, env=None)

    root_result = git(["rev-parse", "--show-toplevel"])
    branch_result = git(["branch", "--show-current"])
    commit_result = git(["rev-parse", "--short", "HEAD"])
    status_result = git(["status", "--short"])

    root = root_result.stdout.strip() if root_result.returncode == 0 else str(REPO_ROOT)
    branch = branch_result.stdout.strip() if branch_result.returncode == 0 else "unknown"
    commit = commit_result.stdout.strip() if commit_result.returncode == 0 else "unknown"
    status_short = status_result.stdout.rstrip() if status_result.returncode == 0 else ""
    clean = status_result.returncode == 0 and not status_short

    git_failed = any(
        result.returncode != 0
        for result in (root_result, branch_result, commit_result, status_result)
    )
    if git_failed:
        checks.append(
            Check(
                "Git repository metadata",
                "Repository",
                STATUS_FAIL,
                "git rev-parse / branch / status",
                None,
                "Could not inspect all required Git metadata.",
                round(
                    sum(
                        result.duration_seconds
                        for result in (root_result, branch_result, commit_result, status_result)
                    ),
                    3,
                ),
                True,
            )
        )
    else:
        checks.append(
            Check(
                "Git repository metadata",
                "Repository",
                STATUS_OK,
                "git rev-parse / branch / status",
                0,
                f"Repository {root}; commit {commit}.",
                round(
                    sum(
                        result.duration_seconds
                        for result in (root_result, branch_result, commit_result, status_result)
                    ),
                    3,
                ),
            )
        )

    checks.append(
        Check(
            "Working tree",
            "Repository",
            STATUS_OK if clean else STATUS_WARN,
            "git status --short",
            status_result.returncode,
            "Working tree is clean." if clean else "Working tree contains uncommitted changes.",
            status_result.duration_seconds,
            not clean,
        )
    )
    checks.append(
        Check(
            "Release branch",
            "Repository",
            STATUS_OK if branch == "main" else STATUS_WARN,
            "git branch --show-current",
            branch_result.returncode,
            "Current branch is main." if branch == "main" else f"Current branch is {branch}, not main.",
            branch_result.duration_seconds,
            False,
        )
    )

    repository = {
        "root": root,
        "branch": branch,
        "commit": commit,
        "clean_worktree": clean,
        "status_short": status_short,
    }
    return repository, checks


def documentation_check() -> Check:
    required = (
        REPO_ROOT / "README.md",
        REPO_ROOT / "INSTALL.md",
        REPO_ROOT / "requirements.txt",
        REPO_ROOT / ".github" / "workflows" / "ci.yml",
    )
    missing = [str(path.relative_to(REPO_ROOT)) for path in required if not path.is_file()]
    readme = REPO_ROOT / "README.md"
    if readme.is_file() and "INSTALL.md" not in readme.read_text(encoding="utf-8"):
        missing.append("README.md link to INSTALL.md")
    if missing:
        return Check(
            "Release documentation",
            "Documentation",
            STATUS_FAIL,
            None,
            None,
            f"Missing required release material: {', '.join(missing)}.",
            0.0,
            True,
        )
    return Check(
        "Release documentation",
        "Documentation",
        STATUS_OK,
        None,
        None,
        "README, INSTALL, requirements, and CI workflow are present.",
        0.0,
    )


def core_checks(python: Path, runner: Runner = run_command) -> list[Check]:
    wrapper = str(REPO_ROOT / "ai-soc")
    return [
        command_check(
            name="CLI help",
            category="Core CLI",
            args=[wrapper, "--help"],
            runner=runner,
        ),
        command_check(
            name="CLI version",
            category="Core CLI",
            args=[wrapper, "version"],
            runner=runner,
        ),
        command_check(
            name="Doctor",
            category="Core CLI",
            args=[wrapper, "doctor", "--json"],
            runner=runner,
            strict_blocking=True,
            classify=json_classifier(
                {
                    "READY": STATUS_OK,
                    "READY_WITH_WARNINGS": STATUS_WARN,
                    "NOT_READY": STATUS_FAIL,
                }
            ),
        ),
        command_check(
            name="Static validation",
            category="Core CLI",
            args=[wrapper, "validate"],
            runner=runner,
        ),
        command_check(
            name="CLI smoke validation",
            category="Core CLI",
            args=[str(python), str(REPO_ROOT / "scripts" / "validate_cli_smoke.py"), "--json"],
            runner=runner,
            timeout=180,
            classify=json_classifier({"CLI_SMOKE_READY": STATUS_OK}),
        ),
    ]


def runtime_checks(no_runtime: bool, runner: Runner = run_command) -> list[Check]:
    wrapper = str(REPO_ROOT / "ai-soc")
    checks: list[Check] = []
    if no_runtime:
        checks.append(
            Check(
                "Runtime validation",
                "Runtime and demo",
                STATUS_SKIP,
                f"{command_display([wrapper, 'validate-runtime', '--json'])}",
                None,
                "Skipped by --no-runtime.",
                0.0,
            )
        )
    else:
        checks.append(
            command_check(
                name="Runtime validation",
                category="Runtime and demo",
                args=[wrapper, "validate-runtime", "--json"],
                runner=runner,
                strict_blocking=True,
                classify=json_classifier(
                    {
                        "READY": STATUS_OK,
                        "READY_WITH_WARNINGS": STATUS_WARN,
                        "NOT_READY": STATUS_FAIL,
                    }
                ),
            )
        )

    checks.extend(
        [
            command_check(
                name="Demo seed status",
                category="Runtime and demo",
                args=[wrapper, "demo-seed", "--status", "--json"],
                runner=runner,
                strict_blocking=True,
                classify=json_classifier(
                    {
                        "PRESENT": STATUS_OK,
                        "NOT_PRESENT": STATUS_WARN,
                        "UNAVAILABLE": STATUS_WARN,
                        "NOT_READY": STATUS_WARN,
                        "FAILED": STATUS_FAIL,
                    }
                ),
            ),
            command_check(
                name="Demo validation",
                category="Runtime and demo",
                args=[wrapper, "demo-validate", "--no-runtime", "--json"],
                runner=runner,
                strict_blocking=True,
                classify=json_classifier(
                    {
                        "DEMO_READY": STATUS_OK,
                        "DEMO_READY_WITH_WARNINGS": STATUS_WARN,
                        "DEMO_NOT_READY": STATUS_WARN,
                    }
                ),
            ),
            command_check(
                name="Demo runtime status",
                category="Runtime and demo",
                args=[wrapper, "demo-status", "--json"],
                runner=runner,
                strict_blocking=True,
                classify=json_classifier(
                    {
                        "DEMO_RUNTIME_READY": STATUS_OK,
                        "DEMO_RUNTIME_READY_WITH_WARNINGS": STATUS_WARN,
                        "DEMO_RUNTIME_NOT_READY": STATUS_WARN,
                    }
                ),
            ),
        ]
    )
    return checks


def python_checks(python: Path, runner: Runner = run_command) -> list[Check]:
    pip_version = runner(
        [str(python), "-m", "pip", "--version"],
        cwd=REPO_ROOT,
        timeout=30,
        env=None,
    )
    if pip_version.returncode == 0:
        pip_check = command_check(
            name="Python dependency consistency",
            category="Python",
            args=[str(python), "-m", "pip", "check"],
            runner=runner,
            timeout=120,
        )
    else:
        pip_check = Check(
            "Python dependency consistency",
            "Python",
            STATUS_WARN,
            command_display([str(python), "-m", "pip", "check"]),
            pip_version.returncode,
            "pip is unavailable for the selected Python interpreter.",
            pip_version.duration_seconds,
            True,
        )

    tracked = runner(
        ["git", "ls-files", "-z", "*.py"],
        cwd=REPO_ROOT,
        timeout=30,
        env=None,
    )
    if tracked.returncode != 0:
        compile_check = Check(
            "Python compilation",
            "Python",
            STATUS_FAIL,
            "git ls-files -z '*.py'",
            tracked.returncode,
            "Could not list tracked Python files.",
            tracked.duration_seconds,
            True,
        )
    else:
        files = [item for item in tracked.stdout.split("\0") if item]
        if not files:
            compile_check = Check(
                "Python compilation",
                "Python",
                STATUS_FAIL,
                None,
                None,
                "No tracked Python files were found.",
                tracked.duration_seconds,
                True,
            )
        else:
            compile_check = command_check(
                name="Python compilation",
                category="Python",
                args=[str(python), "-m", "py_compile", *files],
                runner=runner,
                timeout=180,
                display_command=f"{command_display([str(python)])} -m py_compile <tracked-python-files>",
            )
    return [pip_check, compile_check]


def skipped_full_checks() -> list[Check]:
    return [
        Check(
            "Backend test suite",
            "Full validation",
            STATUS_SKIP,
            "python -m pytest -q",
            None,
            "Skipped; use --full to run the backend test suite.",
            0.0,
        ),
        Check(
            "Frontend production build",
            "Full validation",
            STATUS_SKIP,
            "npm run build",
            None,
            "Skipped; use --full to run the frontend build.",
            0.0,
        ),
        Check(
            "Compose configuration",
            "Full validation",
            STATUS_SKIP,
            "docker compose -f <file> config --quiet",
            None,
            "Skipped; use --full to validate Compose files.",
            0.0,
        ),
    ]


def full_checks(python: Path, runner: Runner = run_command) -> list[Check]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    checks = [
        command_check(
            name="Backend test suite",
            category="Full validation",
            args=[str(python), "-m", "pytest", "-q"],
            runner=runner,
            timeout=900,
            env=env,
        )
    ]

    frontend = REPO_ROOT / "frontend"
    npm = shutil.which("npm")
    if not (frontend / "package.json").is_file():
        checks.append(
            Check(
                "Frontend production build",
                "Full validation",
                STATUS_FAIL,
                "npm run build",
                None,
                "frontend/package.json is missing.",
                0.0,
                True,
            )
        )
    elif npm is None:
        checks.append(
            Check(
                "Frontend production build",
                "Full validation",
                STATUS_WARN,
                "npm run build",
                None,
                "npm is unavailable; frontend build was not run.",
                0.0,
                True,
            )
        )
    elif not (frontend / "node_modules").is_dir():
        checks.append(
            Check(
                "Frontend production build",
                "Full validation",
                STATUS_WARN,
                "npm run build",
                None,
                "frontend/node_modules is missing; install dependencies before the release check.",
                0.0,
                True,
            )
        )
    else:
        checks.append(
            command_check(
                name="Frontend production build",
                category="Full validation",
                args=[npm, "run", "build"],
                runner=runner,
                timeout=600,
                cwd=frontend,
                env=os.environ.copy(),
            )
        )

    compose_files = (
        REPO_ROOT / "deploy" / "observability" / "docker-compose.loki.yml",
        REPO_ROOT / "deploy" / "suricata" / "docker-compose.yml",
        REPO_ROOT / "deploy" / "observability" / "docker-compose.yml",
    )
    docker = shutil.which("docker")
    if docker is None:
        checks.append(
            Check(
                "Compose configuration",
                "Full validation",
                STATUS_WARN,
                "docker compose -f <file> config --quiet",
                None,
                "docker is unavailable; Compose configuration was not validated.",
                0.0,
                True,
            )
        )
    else:
        for compose_file in compose_files:
            relative = compose_file.relative_to(REPO_ROOT)
            name = f"Compose config: {relative}"
            if not compose_file.is_file():
                checks.append(
                    Check(
                        name,
                        "Full validation",
                        STATUS_SKIP,
                        None,
                        None,
                        "Compose file is not present.",
                        0.0,
                    )
                )
                continue
            if (
                relative == Path("deploy/observability/docker-compose.yml")
                and not (compose_file.parent / "ntfy-bridge" / ".env").is_file()
            ):
                checks.append(
                    Check(
                        name,
                        "Full validation",
                        STATUS_SKIP,
                        command_display(
                            [docker, "compose", "-f", str(compose_file), "config", "--quiet"]
                        ),
                        None,
                        "Skipped because deploy/observability/ntfy-bridge/.env is absent.",
                        0.0,
                    )
                )
                continue
            checks.append(
                command_check(
                    name=name,
                    category="Full validation",
                    args=[docker, "compose", "-f", str(compose_file), "config", "--quiet"],
                    runner=runner,
                    timeout=90,
                )
            )
    return checks


def summarize(checks: list[Check]) -> dict[str, int]:
    return {
        "ok": sum(check.status == STATUS_OK for check in checks),
        "warn": sum(check.status == STATUS_WARN for check in checks),
        "fail": sum(check.status == STATUS_FAIL for check in checks),
        "skip": sum(check.status == STATUS_SKIP for check in checks),
    }


def release_result(checks: list[Check], strict: bool) -> tuple[str, int]:
    if any(check.status == STATUS_FAIL for check in checks):
        return RESULT_NOT_READY, 1
    if strict and any(
        check.status == STATUS_WARN and check.strict_blocking for check in checks
    ):
        return RESULT_NOT_READY, 1
    if any(check.status == STATUS_WARN for check in checks):
        return RESULT_WARNINGS, 0
    return RESULT_READY, 0


def report_filenames(now: datetime) -> tuple[str, str]:
    stamp = now.strftime("%Y%m%d-%H%M%S")
    base = f"release-readiness-{stamp}"
    return f"{base}.md", f"{base}.json"


def build_report(
    *,
    args: argparse.Namespace,
    repository: dict[str, object],
    checks: list[Check],
    report_paths: list[str],
) -> dict[str, object]:
    result, exit_code = release_result(checks, args.strict)
    report: dict[str, object] = {
        "result": result,
        "exit_code": exit_code,
        "strict": args.strict,
        "full": args.full,
        "no_runtime": args.no_runtime,
        "repository": repository,
        "summary": summarize(checks),
        "checks": [asdict(check) for check in checks],
    }
    if args.write_report:
        report["report_paths"] = report_paths
    return report


def markdown_report(report: dict[str, object]) -> str:
    repository = report["repository"]
    summary = report["summary"]
    lines = [
        "# Release readiness",
        "",
        f"- Result: `{report['result']}`",
        f"- Exit code: `{report['exit_code']}`",
        f"- Branch: `{repository['branch']}`",
        f"- Commit: `{repository['commit']}`",
        f"- Clean worktree: `{str(repository['clean_worktree']).lower()}`",
        (
            f"- Checks: {summary['ok']} OK, {summary['warn']} warnings, "
            f"{summary['fail']} failures, {summary['skip']} skipped"
        ),
        "",
        "| Category | Check | Status | Summary |",
        "| --- | --- | --- | --- |",
    ]
    for check in report["checks"]:
        cells = (
            str(check["category"]),
            str(check["name"]),
            str(check["status"]),
            str(check["summary"]),
        )
        lines.append("| " + " | ".join(cell.replace("|", r"\|") for cell in cells) + " |")
    lines.append("")
    return "\n".join(lines)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def write_reports(
    *,
    args: argparse.Namespace,
    repository: dict[str, object],
    checks: list[Check],
) -> tuple[dict[str, object], list[Check]]:
    markdown_name, json_name = report_filenames(datetime.now().astimezone())
    markdown_path = REPORT_DIR / markdown_name
    json_path = REPORT_DIR / json_name
    relative_paths = [
        str(markdown_path.relative_to(REPO_ROOT)),
        str(json_path.relative_to(REPO_ROOT)),
    ]
    report_check = Check(
        "Release readiness report",
        "Report",
        STATUS_OK,
        None,
        None,
        f"Wrote {relative_paths[0]} and {relative_paths[1]}.",
        0.0,
    )
    final_checks = [*checks, report_check]
    report = build_report(
        args=args,
        repository=repository,
        checks=final_checks,
        report_paths=relative_paths,
    )
    try:
        atomic_write(json_path, json.dumps(report, indent=2, sort_keys=True) + "\n")
        atomic_write(markdown_path, markdown_report(report))
    except OSError as exc:
        failed_check = Check(
            "Release readiness report",
            "Report",
            STATUS_FAIL,
            None,
            None,
            f"Could not write reports: {type(exc).__name__}.",
            0.0,
            True,
        )
        final_checks = [*checks, failed_check]
        report = build_report(
            args=args,
            repository=repository,
            checks=final_checks,
            report_paths=[],
        )
    return report, final_checks


def print_human(report: dict[str, object]) -> None:
    repository = report["repository"]
    print("Sovereign AI SOC release readiness")
    print(f"Repository: {repository['root']}")
    print(f"Branch: {repository['branch']}  Commit: {repository['commit']}")
    current_category: str | None = None
    for check in report["checks"]:
        if check["category"] != current_category:
            current_category = str(check["category"])
            print(f"\n{current_category}")
        print(f"  [{check['status']}] {check['name']}: {check['summary']}")
    summary = report["summary"]
    print(
        f"\nResult: {report['result']} "
        f"({summary['ok']} OK, {summary['warn']} WARN, "
        f"{summary['fail']} FAIL, {summary['skip']} SKIP)"
    )
    if report.get("report_paths"):
        print("Reports:")
        for path in report["report_paths"]:
            print(f"  {path}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    python = python_executable()
    repository, checks = repository_checks()
    checks.extend(core_checks(python))
    checks.extend(runtime_checks(args.no_runtime))
    checks.extend(python_checks(python))
    checks.append(documentation_check())
    checks.extend(full_checks(python) if args.full else skipped_full_checks())

    if args.write_report:
        report, checks = write_reports(
            args=args,
            repository=repository,
            checks=checks,
        )
    else:
        report = build_report(
            args=args,
            repository=repository,
            checks=checks,
            report_paths=[],
        )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
    return int(report["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
