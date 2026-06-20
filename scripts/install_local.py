#!/usr/bin/env python3
"""Safely prepare a local Sovereign AI SOC checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

STATUS_OK = "OK"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_INFO = "INFO"
STATUS_DRY_RUN = "DRY-RUN"

RESULT_INSTALL_READY = "INSTALL_READY"
RESULT_INSTALL_WARNINGS = "INSTALL_READY_WITH_WARNINGS"
RESULT_INSTALL_NOT_READY = "INSTALL_NOT_READY"
RESULT_DRY_RUN_READY = "DRY_RUN_READY"
RESULT_DRY_RUN_WARNINGS = "DRY_RUN_READY_WITH_WARNINGS"

SECRET_PATTERNS = (
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)\bauthorization:\s*(?:bearer|basic)\s+\S{20,}"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(
        r"(?i)\b(?:password|secret|token|api[_-]?key)\b\s*[:=]\s*"
        r"(?!(?:<[^>]+>|\$(?:\{[A-Z0-9_]+\}|[A-Z0-9_]+))\b)\S+"
    ),
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    timed_out: bool = False
    error: str | None = None


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    summary: str
    command: str | None = None
    returncode: int | None = None
    duration_seconds: float = 0.0


Runner = Callable[..., CommandResult]
Which = Callable[[str], str | None]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare a local checkout without starting runtime services.",
    )
    parser.add_argument("--profile", required=True, choices=("demo", "local"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument("--skip-frontend", action="store_true")
    parser.add_argument("--skip-python-install", action="store_true")
    parser.add_argument("--skip-env-init", action="store_true")
    parser.add_argument("--skip-validation", action="store_true")
    args = parser.parse_args(argv)
    if not args.apply:
        args.dry_run = True
    return args


def run_command(
    args: list[str],
    *,
    cwd: Path,
    timeout: int,
) -> CommandResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            None,
            _to_text(exc.stdout),
            _to_text(exc.stderr),
            round(time.monotonic() - started, 3),
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(
            None,
            duration_seconds=round(time.monotonic() - started, 3),
            error=f"{type(exc).__name__}: {exc}",
        )
    return CommandResult(
        completed.returncode,
        completed.stdout,
        completed.stderr,
        round(time.monotonic() - started, 3),
    )


def _to_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def contains_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)


def command_display(args: list[str], repository_root: Path) -> str:
    rendered: list[str] = []
    for arg in args:
        try:
            rendered.append(str(Path(arg).relative_to(repository_root)))
        except (TypeError, ValueError):
            rendered.append(arg)
    return shlex.join(rendered)


def file_digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


class Installer:
    def __init__(
        self,
        args: argparse.Namespace,
        *,
        repository_root: Path = REPOSITORY_ROOT,
        runner: Runner = run_command,
        which: Which = shutil.which,
    ) -> None:
        self.args = args
        self.repository_root = repository_root
        self.runner = runner
        self.which = which
        self.checks: list[Check] = []
        self.planned_actions: list[str] = []
        self.executed_actions: list[str] = []
        self.warnings: list[str] = []
        self.python3: str | None = None

    @property
    def dry_run(self) -> bool:
        return bool(self.args.dry_run)

    def add(
        self,
        name: str,
        status: str,
        summary: str,
        *,
        command: str | None = None,
        returncode: int | None = None,
        duration_seconds: float = 0.0,
    ) -> None:
        self.checks.append(
            Check(
                name,
                status,
                summary,
                command,
                returncode,
                duration_seconds,
            )
        )
        if status == STATUS_WARN:
            self.warnings.append(summary)

    def execute(
        self,
        name: str,
        args: list[str],
        *,
        cwd: Path | None = None,
        timeout: int = 120,
    ) -> bool:
        working_directory = cwd or self.repository_root
        display = command_display(args, self.repository_root)
        self.executed_actions.append(display)
        result = self.runner(
            args,
            cwd=working_directory,
            timeout=timeout,
        )
        combined = f"{result.stdout}\n{result.stderr}"
        if contains_secret(combined):
            self.add(
                name,
                STATUS_FAIL,
                "[REDACTED secret-like output]",
                command=display,
                returncode=result.returncode,
                duration_seconds=result.duration_seconds,
            )
            return False
        if "Traceback (most recent call last):" in combined:
            self.add(
                name,
                STATUS_FAIL,
                "Command emitted an unhandled traceback.",
                command=display,
                returncode=result.returncode,
                duration_seconds=result.duration_seconds,
            )
            return False
        if result.timed_out:
            self.add(
                name,
                STATUS_FAIL,
                f"Timed out after {timeout} seconds.",
                command=display,
                duration_seconds=result.duration_seconds,
            )
            return False
        if result.error:
            self.add(
                name,
                STATUS_FAIL,
                result.error,
                command=display,
                duration_seconds=result.duration_seconds,
            )
            return False
        if result.returncode != 0:
            self.add(
                name,
                STATUS_FAIL,
                f"Command exited with status {result.returncode}.",
                command=display,
                returncode=result.returncode,
                duration_seconds=result.duration_seconds,
            )
            return False
        self.add(
            name,
            STATUS_OK,
            "Command completed successfully.",
            command=display,
            returncode=result.returncode,
            duration_seconds=result.duration_seconds,
        )
        return True

    def collect_repository(self) -> None:
        required = (
            "ai-soc",
            "requirements.txt",
            "frontend/package.json",
            "scripts/doctor.py",
            "scripts/init_env.py",
            "INSTALL.md",
        )
        missing = [
            relative
            for relative in required
            if not (self.repository_root / relative).is_file()
        ]
        repository_detected = (self.repository_root / ".git").exists()
        if not repository_detected:
            missing.append(".git")
        self.add(
            "Repository structure",
            STATUS_FAIL if missing else STATUS_OK,
            (
                f"Missing required repository paths: {', '.join(missing)}."
                if missing
                else f"Repository root detected at {self.repository_root}."
            ),
        )

    def collect_prerequisites(self) -> None:
        tool_specs = (
            ("Git", "git", ["--version"]),
            ("Python 3", "python3", ["--version"]),
            ("Node.js", "node", ["--version"]),
            ("npm", "npm", ["--version"]),
            ("Docker", "docker", ["--version"]),
        )
        for label, executable_name, arguments in tool_specs:
            executable = self.which(executable_name)
            if executable is None:
                self.add(
                    label,
                    STATUS_FAIL,
                    f"{executable_name} is missing; install it through the supported OS package workflow.",
                )
                continue
            if executable_name == "python3":
                self.python3 = executable
            self.execute(
                label,
                [executable, *arguments],
                timeout=30,
            )

        if self.python3:
            self.execute(
                "Python venv capability",
                [self.python3, "-m", "venv", "--help"],
                timeout=30,
            )

        docker = self.which("docker")
        if docker:
            self.execute(
                "Docker Compose plugin",
                [docker, "compose", "version"],
                timeout=30,
            )

    def plan(self) -> None:
        venv = self.repository_root / ".venv"
        if venv.is_dir():
            self.planned_actions.append("Reuse existing .venv.")
        else:
            self.planned_actions.append("Create .venv with python3 -m venv .venv.")

        if self.args.skip_python_install:
            self.planned_actions.append("Skip Python dependency installation.")
        else:
            self.planned_actions.extend(
                (
                    "Upgrade pip inside .venv.",
                    "Install Python requirements from requirements.txt.",
                    "Run pip check.",
                )
            )

        if self.args.skip_frontend:
            self.planned_actions.append("Skip frontend dependency installation.")
        else:
            self.planned_actions.append("Install frontend dependencies with npm ci.")

        if self.args.skip_env_init:
            self.planned_actions.append("Skip safe environment initialization.")
        else:
            suffix = " --dry-run" if self.dry_run else ""
            self.planned_actions.append(
                f"Run ./ai-soc init --profile {self.args.profile}{suffix}."
            )

        if self.args.skip_validation:
            self.planned_actions.append("Skip post-install validation.")
        else:
            self.planned_actions.extend(
                (
                    "Run ./ai-soc doctor.",
                    "Run ./ai-soc validate.",
                    "Run ./ai-soc package-validate.",
                    "Run scripts/validate_cli_smoke.py.",
                )
            )

    def prepare_python(self) -> bool:
        venv_dir = self.repository_root / ".venv"
        venv_python = venv_dir / "bin" / "python"
        if not venv_dir.is_dir():
            if self.dry_run:
                self.add(
                    "Python virtual environment",
                    STATUS_DRY_RUN,
                    "Would create .venv; no files were written.",
                )
            elif self.python3 and not self.execute(
                "Create Python virtual environment",
                [self.python3, "-m", "venv", str(venv_dir)],
                timeout=180,
            ):
                return False
        else:
            self.add(
                "Python virtual environment",
                STATUS_OK,
                "Reusing existing .venv.",
            )

        if self.dry_run:
            if self.args.skip_python_install:
                self.add(
                    "Python dependency installation",
                    STATUS_INFO,
                    "Skipped by --skip-python-install.",
                )
            else:
                self.add(
                    "Python dependency installation",
                    STATUS_DRY_RUN,
                    "Would upgrade pip, install requirements, and run pip check.",
                )
            return True

        if not venv_python.is_file():
            self.add(
                "Python virtual environment",
                STATUS_FAIL,
                ".venv/bin/python is unavailable after virtual environment preparation.",
            )
            return False
        if self.args.skip_python_install:
            self.add(
                "Python dependency installation",
                STATUS_INFO,
                "Skipped by --skip-python-install.",
            )
            return True
        commands = (
            (
                "Upgrade pip",
                [str(venv_python), "-m", "pip", "install", "--upgrade", "pip"],
                600,
            ),
            (
                "Install Python requirements",
                [
                    str(venv_python),
                    "-m",
                    "pip",
                    "install",
                    "-r",
                    str(self.repository_root / "requirements.txt"),
                ],
                1800,
            ),
            (
                "Python dependency consistency",
                [str(venv_python), "-m", "pip", "check"],
                180,
            ),
        )
        return all(
            self.execute(name, command, timeout=timeout)
            for name, command, timeout in commands
        )

    def prepare_frontend(self) -> bool:
        if self.args.skip_frontend:
            self.add(
                "Frontend dependencies",
                STATUS_INFO,
                "Skipped by --skip-frontend.",
            )
            return True
        if self.dry_run:
            self.add(
                "Frontend dependencies",
                STATUS_DRY_RUN,
                "Would run npm ci in frontend; no files were changed.",
            )
            return True

        npm = self.which("npm")
        if npm is None:
            self.add("Frontend dependencies", STATUS_FAIL, "npm is unavailable.")
            return False
        lockfile = self.repository_root / "frontend" / "package-lock.json"
        before = file_digest(lockfile)
        succeeded = self.execute(
            "Install frontend dependencies",
            [npm, "ci"],
            cwd=self.repository_root / "frontend",
            timeout=1200,
        )
        after = file_digest(lockfile)
        if succeeded and before != after:
            self.add(
                "Frontend lockfile",
                STATUS_WARN,
                "npm ci changed frontend/package-lock.json unexpectedly; review the diff.",
            )
        elif succeeded:
            self.add(
                "Frontend lockfile",
                STATUS_OK,
                "frontend/package-lock.json is unchanged.",
            )
        return succeeded

    def initialize_environment(self) -> bool:
        if self.args.skip_env_init:
            self.add(
                "Environment initialization",
                STATUS_INFO,
                "Skipped by --skip-env-init.",
            )
            return True
        wrapper = str(self.repository_root / "ai-soc")
        command = [wrapper, "init", "--profile", self.args.profile]
        if self.dry_run:
            command.append("--dry-run")
        env_path = self.repository_root / ".env"
        before_exists = env_path.exists()
        before_mtime = env_path.stat().st_mtime_ns if before_exists else None
        if not self.execute(
            "Safe environment initialization",
            command,
            timeout=60,
        ):
            return False
        after_exists = env_path.exists()
        after_mtime = env_path.stat().st_mtime_ns if after_exists else None
        if self.dry_run and (before_exists != after_exists or before_mtime != after_mtime):
            self.add(
                "Environment safety",
                STATUS_FAIL,
                "Dry-run changed the local .env state.",
            )
            return False
        if before_exists:
            unchanged = before_mtime == after_mtime
            self.add(
                "Environment safety",
                STATUS_OK if unchanged else STATUS_FAIL,
                (
                    "Existing .env was left unchanged."
                    if unchanged
                    else "Existing .env was modified unexpectedly."
                ),
            )
            return unchanged
        self.add(
            "Environment safety",
            STATUS_DRY_RUN if self.dry_run else STATUS_OK,
            (
                ".env was not created during dry-run."
                if self.dry_run
                else "A new .env was created through the safe initializer."
            ),
        )
        return True

    def validate(self) -> bool:
        if self.args.skip_validation:
            self.add(
                "Post-install validation",
                STATUS_INFO,
                "Skipped by --skip-validation.",
            )
            return True
        if not self.python3:
            self.add(
                "Post-install validation",
                STATUS_FAIL,
                "python3 is unavailable.",
            )
            return False
        wrapper = str(self.repository_root / "ai-soc")
        commands = (
            ("Install doctor", [wrapper, "doctor"], 90),
            ("Public baseline", [wrapper, "validate"], 90),
            ("Docker packaging", [wrapper, "package-validate"], 180),
            (
                "CLI smoke validation",
                [
                    self.python3,
                    str(self.repository_root / "scripts" / "validate_cli_smoke.py"),
                ],
                240,
            ),
        )
        return all(
            self.execute(name, command, timeout=timeout)
            for name, command, timeout in commands
        )

    def result(self) -> tuple[str, int]:
        if any(check.status == STATUS_FAIL for check in self.checks):
            return RESULT_INSTALL_NOT_READY, 1
        has_warnings = any(check.status == STATUS_WARN for check in self.checks)
        if self.dry_run:
            return (
                RESULT_DRY_RUN_WARNINGS if has_warnings else RESULT_DRY_RUN_READY,
                0,
            )
        return (
            RESULT_INSTALL_WARNINGS if has_warnings else RESULT_INSTALL_READY,
            0,
        )

    def run(self) -> dict[str, object]:
        self.collect_repository()
        self.collect_prerequisites()
        self.plan()
        if not any(check.status == STATUS_FAIL for check in self.checks):
            if self.prepare_python():
                if self.prepare_frontend():
                    if self.initialize_environment():
                        self.validate()
        result, exit_code = self.result()
        return {
            "result": result,
            "exit_code": exit_code,
            "profile": self.args.profile,
            "dry_run": self.dry_run,
            "apply": bool(self.args.apply),
            "checks": [asdict(check) for check in self.checks],
            "planned_actions": self.planned_actions,
            "executed_actions": self.executed_actions,
            "warnings": self.warnings,
        }


def print_next_steps() -> None:
    print("\nNext steps")
    print("  ./ai-soc validate-runtime")
    print("  ./ai-soc demo-seed --dry-run")
    print("  ./ai-soc demo-seed --apply")
    print("  ./ai-soc demo-validate")
    print("  ./ai-soc demo-status")
    print("  ./ai-soc package-validate --build")
    print(
        "  Ollama models are not pulled automatically; install the selected "
        "model manually only after the runtime is available."
    )


def print_human(payload: dict[str, object]) -> None:
    print("Sovereign AI SOC Guided Local Installer")
    print(f"[INFO] Profile: {payload['profile']}")
    print(f"[INFO] Mode: {'dry-run' if payload['dry_run'] else 'apply'}")
    print("\nPlan")
    for action in payload["planned_actions"]:
        print(f"[INFO] {action}")
    print("\nChecks and actions")
    for check in payload["checks"]:
        print(f"[{check['status']}] {check['name']}: {check['summary']}")
    print(f"\nResult: {payload['result']}")
    print_next_steps()


def main(
    argv: list[str] | None = None,
    *,
    repository_root: Path = REPOSITORY_ROOT,
    runner: Runner = run_command,
    which: Which = shutil.which,
) -> int:
    args = parse_args(argv)
    payload = Installer(
        args,
        repository_root=repository_root,
        runner=runner,
        which=which,
    ).run()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print_human(payload)
    return int(payload["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
