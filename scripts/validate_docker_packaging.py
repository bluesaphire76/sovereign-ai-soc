#!/usr/bin/env python3
"""Read-only validation for the Sovereign AI SOC Docker packaging foundation."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = REPO_ROOT / "deploy" / "demo" / "docker-compose.demo.yml"

STATUS_OK = "OK"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
RESULT_READY = "DOCKER_PACKAGING_READY"
RESULT_WARNINGS = "DOCKER_PACKAGING_READY_WITH_WARNINGS"
RESULT_NOT_READY = "DOCKER_PACKAGING_NOT_READY"

REQUIRED_SERVICES = {
    "ai-soc-api",
    "ai-soc-frontend",
    "postgres",
    "qdrant",
    "ollama",
}
EXCLUDED_SERVICES = {
    "wazuh",
    "suricata",
    "grafana",
    "prometheus",
    "loki",
    "alertmanager",
}
REQUIRED_VOLUMES = {
    "postgres_demo_data",
    "qdrant_demo_data",
    "ollama_demo_models",
}
SECRET_PATTERNS = (
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)authorization:\s*bearer\s+\S{20,}"),
    re.compile(r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)


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
    status: str
    summary: str
    command: str | None = None
    returncode: int | None = None
    duration_seconds: float = 0.0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Docker packaging without starting containers.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    parser.add_argument(
        "--build",
        action="store_true",
        help="Build API and frontend images without running containers.",
    )
    return parser.parse_args(argv)


def run_command(
    args: list[str],
    *,
    timeout: int = 120,
    cwd: Path = REPO_ROOT,
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
            _text(exc.stdout),
            _text(exc.stderr),
            round(time.monotonic() - started, 3),
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(
            None,
            "",
            "",
            round(time.monotonic() - started, 3),
            error=f"{type(exc).__name__}: {exc}",
        )
    return CommandResult(
        completed.returncode,
        completed.stdout,
        completed.stderr,
        round(time.monotonic() - started, 3),
    )


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def command_text(args: list[str]) -> str:
    rendered: list[str] = []
    for arg in args:
        try:
            rendered.append(str(Path(arg).relative_to(REPO_ROOT)))
        except (TypeError, ValueError):
            rendered.append(arg)
    return shlex.join(rendered)


def contains_secret(value: str) -> bool:
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)


def command_check(
    name: str,
    args: list[str],
    *,
    timeout: int = 120,
    cwd: Path = REPO_ROOT,
) -> Check:
    result = run_command(args, timeout=timeout, cwd=cwd)
    combined = f"{result.stdout}\n{result.stderr}"
    display = command_text(args)
    if contains_secret(combined):
        return Check(
            name,
            STATUS_FAIL,
            "[REDACTED secret-like output]",
            display,
            result.returncode,
            result.duration_seconds,
        )
    if result.timed_out:
        return Check(
            name,
            STATUS_FAIL,
            f"Timed out after {timeout} seconds.",
            display,
            None,
            result.duration_seconds,
        )
    if result.error:
        return Check(
            name,
            STATUS_FAIL,
            result.error,
            display,
            None,
            result.duration_seconds,
        )
    if result.returncode != 0:
        return Check(
            name,
            STATUS_FAIL,
            f"Command exited with status {result.returncode}.",
            display,
            result.returncode,
            result.duration_seconds,
        )
    return Check(
        name,
        STATUS_OK,
        "Command completed successfully.",
        display,
        result.returncode,
        result.duration_seconds,
    )


def file_checks() -> list[Check]:
    required = (
        ".dockerignore",
        "Dockerfile.api",
        "frontend/Dockerfile",
        "frontend/.dockerignore",
        "deploy/demo/docker-compose.demo.yml",
        "deploy/demo/.env.demo.example",
        "docs/operations/docker-demo-packaging.md",
    )
    checks: list[Check] = []
    for relative in required:
        path = REPO_ROOT / relative
        checks.append(
            Check(
                f"Packaging file: {relative}",
                STATUS_OK if path.is_file() else STATUS_FAIL,
                "File exists." if path.is_file() else "Required file is missing.",
            )
        )
    return checks


def dockerfile_checks() -> list[Check]:
    api = (REPO_ROOT / "Dockerfile.api").read_text(encoding="utf-8")
    frontend = (REPO_ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    frontend_dockerignore = (
        REPO_ROOT / "frontend" / ".dockerignore"
    ).read_text(encoding="utf-8")

    api_markers = (
        "FROM python:3.12-slim",
        "COPY requirements.txt",
        "python -m pip install -r requirements.txt",
        '"api:app"',
        "EXPOSE 8008",
        "USER ai-soc",
    )
    frontend_markers = (
        "FROM node:20-alpine AS deps",
        "FROM node:20-alpine AS builder",
        "FROM node:20-alpine AS runner",
        "RUN npm ci",
        "RUN npm run build",
        "EXPOSE 3000",
        '"start"',
    )
    ignore_markers = (
        ".git",
        ".venv",
        ".env",
        "frontend/node_modules",
        "frontend/.next",
        "reports/",
        "storage/",
        "data/",
        "backups/",
    )
    frontend_ignore_markers = (
        ".env",
        "node_modules/",
        ".next/",
        "out/",
    )

    checks = [
        marker_check("API Dockerfile contract", api, api_markers),
        marker_check("Frontend Dockerfile contract", frontend, frontend_markers),
        marker_check("Docker build-context exclusions", dockerignore, ignore_markers),
        marker_check(
            "Frontend build-context exclusions",
            frontend_dockerignore,
            frontend_ignore_markers,
        ),
    ]
    return checks


def marker_check(name: str, content: str, markers: tuple[str, ...]) -> Check:
    missing = [marker for marker in markers if marker not in content]
    if missing:
        return Check(name, STATUS_FAIL, f"Missing expected markers: {', '.join(missing)}.")
    return Check(name, STATUS_OK, "Required packaging markers are present.")


def compose_static_checks() -> list[Check]:
    content = COMPOSE_FILE.read_text(encoding="utf-8")
    lowered = content.lower()
    forbidden = []
    if re.search(r"(?im)^\s*privileged\s*:\s*true\s*$", content):
        forbidden.append("privileged: true")
    if re.search(r"(?im)^\s*network_mode\s*:\s*host\s*$", content):
        forbidden.append("network_mode: host")
    if re.search(r"(?i)\bollama\s+pull\b", content):
        forbidden.append("automatic Ollama model pull")
    checks = [
        Check(
            "Demo Compose safety",
            STATUS_FAIL if forbidden else STATUS_OK,
            (
                f"Forbidden settings found: {', '.join(forbidden)}."
                if forbidden
                else "No privileged mode, host networking, or automatic model pull."
            ),
        )
    ]
    required_urls = (
        "POSTGRES_HOST: postgres",
        "QDRANT_URL: http://qdrant:6333",
        "OLLAMA_BASE_URL: http://ollama:11434",
        "AI_OLLAMA_BASE_URL: http://ollama:11434",
    )
    checks.append(marker_check("Internal service DNS configuration", content, required_urls))
    if "wazuh" in lowered or "suricata" in lowered:
        checks.append(
            Check(
                "Demo Compose scope",
                STATUS_FAIL,
                "Wazuh or Suricata references were found in the demo Compose file.",
            )
        )
    return checks


def compose_runtime_checks(docker: str) -> list[Check]:
    checks: list[Check] = []
    quiet_args = [
        docker,
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "config",
        "--quiet",
    ]
    quiet_check = command_check(
        "Demo Compose configuration",
        quiet_args,
        cwd=COMPOSE_FILE.parent,
    )
    checks.append(quiet_check)
    if quiet_check.status == STATUS_FAIL:
        return checks

    json_args = [
        docker,
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "config",
        "--format",
        "json",
    ]
    rendered = run_command(json_args, cwd=COMPOSE_FILE.parent)
    if rendered.returncode != 0 or rendered.timed_out or rendered.error:
        checks.append(
            Check(
                "Rendered Compose model",
                STATUS_FAIL,
                "Could not render the Compose model as JSON.",
                command_text(json_args),
                rendered.returncode,
                rendered.duration_seconds,
            )
        )
        return checks
    if contains_secret(f"{rendered.stdout}\n{rendered.stderr}"):
        checks.append(
            Check(
                "Rendered Compose model",
                STATUS_FAIL,
                "[REDACTED secret-like output]",
                command_text(json_args),
                rendered.returncode,
                rendered.duration_seconds,
            )
        )
        return checks
    try:
        model = json.loads(rendered.stdout)
    except json.JSONDecodeError:
        checks.append(
            Check(
                "Rendered Compose model",
                STATUS_FAIL,
                "Docker Compose returned invalid JSON.",
                command_text(json_args),
                rendered.returncode,
                rendered.duration_seconds,
            )
        )
        return checks

    services = set(model.get("services", {}))
    missing_services = sorted(REQUIRED_SERVICES - services)
    excluded_services = sorted(EXCLUDED_SERVICES & services)
    checks.append(
        Check(
            "Required demo services",
            STATUS_FAIL if missing_services else STATUS_OK,
            (
                f"Missing services: {', '.join(missing_services)}."
                if missing_services
                else "API, frontend, PostgreSQL, Qdrant, and Ollama are present."
            ),
        )
    )
    checks.append(
        Check(
            "Excluded advanced services",
            STATUS_FAIL if excluded_services else STATUS_OK,
            (
                f"Out-of-scope services found: {', '.join(excluded_services)}."
                if excluded_services
                else "No advanced SOC/observability services are included."
            ),
        )
    )
    volumes = set(model.get("volumes", {}))
    missing_volumes = sorted(REQUIRED_VOLUMES - volumes)
    checks.append(
        Check(
            "Persistent demo volumes",
            STATUS_FAIL if missing_volumes else STATUS_OK,
            (
                f"Missing volumes: {', '.join(missing_volumes)}."
                if missing_volumes
                else "PostgreSQL, Qdrant, and Ollama volumes are defined."
            ),
        )
    )
    return checks


def build_checks(docker: str) -> list[Check]:
    return [
        command_check(
            "API image build",
            [
                docker,
                "build",
                "-f",
                str(REPO_ROOT / "Dockerfile.api"),
                "-t",
                "ai-soc-api:local",
                str(REPO_ROOT),
            ],
            timeout=1800,
        ),
        command_check(
            "Frontend image build",
            [
                docker,
                "build",
                "-f",
                str(REPO_ROOT / "frontend" / "Dockerfile"),
                "-t",
                "ai-soc-frontend:local",
                str(REPO_ROOT / "frontend"),
            ],
            timeout=1200,
        ),
    ]


def result_for(checks: list[Check]) -> tuple[str, int]:
    if any(check.status == STATUS_FAIL for check in checks):
        return RESULT_NOT_READY, 1
    if any(check.status == STATUS_WARN for check in checks):
        return RESULT_WARNINGS, 0
    return RESULT_READY, 0


def build_payload(
    checks: list[Check],
    *,
    build_requested: bool,
    build_results: list[Check],
) -> dict[str, object]:
    all_checks = [*checks, *build_results]
    result, exit_code = result_for(all_checks)
    payload: dict[str, object] = {
        "result": result,
        "exit_code": exit_code,
        "checks": [asdict(check) for check in checks],
    }
    if build_requested:
        payload["build_results"] = [asdict(check) for check in build_results]
    return payload


def print_human(payload: dict[str, object]) -> None:
    print("Sovereign AI SOC Docker Packaging Validation")
    for check in payload["checks"]:
        print(f"[{check['status']}] {check['name']}: {check['summary']}")
    if "build_results" in payload:
        print("\nImage builds")
        for check in payload["build_results"]:
            print(f"[{check['status']}] {check['name']}: {check['summary']}")
    print(f"\nResult: {payload['result']}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    checks = file_checks()
    if all(check.status == STATUS_OK for check in checks):
        checks.extend(dockerfile_checks())
        checks.extend(compose_static_checks())

    docker = shutil.which("docker")
    build_results: list[Check] = []
    if docker is None:
        checks.append(Check("Docker CLI", STATUS_FAIL, "docker is not installed."))
        checks.append(
            Check("Docker Compose plugin", STATUS_FAIL, "Docker Compose cannot be checked.")
        )
    else:
        checks.append(command_check("Docker CLI", [docker, "--version"], timeout=30))
        compose_check = command_check(
            "Docker Compose plugin",
            [docker, "compose", "version"],
            timeout=30,
        )
        checks.append(compose_check)
        if compose_check.status == STATUS_OK and COMPOSE_FILE.is_file():
            checks.extend(compose_runtime_checks(docker))
        if args.build:
            build_results = build_checks(docker)

    payload = build_payload(
        checks,
        build_requested=args.build,
        build_results=build_results,
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print_human(payload)
    return int(payload["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
