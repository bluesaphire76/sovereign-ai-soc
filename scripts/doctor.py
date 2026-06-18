#!/usr/bin/env python3
"""Check local readiness for Sovereign AI SOC without modifying the system."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
COMMAND_TIMEOUT = 3
NETWORK_TIMEOUT = 1


@dataclass(frozen=True)
class Check:
    check_id: str
    category: str
    status: str
    message: str


def command_version(command: list[str]) -> tuple[bool, str]:
    executable = shutil.which(command[0])
    if not executable:
        return False, f"{command[0]} is not available on PATH"

    try:
        result = subprocess.run(
            [executable, *command[1:]],
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"check failed: {exc.__class__.__name__}"

    output = (result.stdout or result.stderr).strip().splitlines()
    detail = output[0] if output else f"exit code {result.returncode}"
    return result.returncode == 0, detail


def local_http(url: str) -> tuple[bool, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json, text/plain, */*"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=NETWORK_TIMEOUT) as response:
            return 200 <= response.status < 400, f"HTTP {response.status} at {url}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code} at {url}"
    except (OSError, urllib.error.URLError, TimeoutError):
        return False, f"unavailable at {url}"


def local_tcp(host: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=NETWORK_TIMEOUT):
            return True, f"TCP reachable at {host}:{port}"
    except OSError:
        return False, f"unavailable at {host}:{port}"


class Doctor:
    def __init__(self, *, strict: bool) -> None:
        self.strict = strict
        self.checks: list[Check] = []

    def add(
        self,
        check_id: str,
        category: str,
        status: str,
        message: str,
    ) -> None:
        self.checks.append(Check(check_id, category, status, message))

    def required_path(
        self,
        check_id: str,
        relative_path: str,
        label: str,
    ) -> None:
        exists = (REPOSITORY_ROOT / relative_path).exists()
        self.add(
            check_id,
            "required",
            "OK" if exists else "FAIL",
            f"{label} {'exists' if exists else 'is missing'}",
        )

    def tool(
        self,
        check_id: str,
        label: str,
        command: list[str],
        *,
        strict_only: bool,
    ) -> None:
        available, detail = command_version(command)
        if available:
            self.add(check_id, "required", "OK", f"{label}: {detail}")
            return

        status = "FAIL" if self.strict or not strict_only else "WARN"
        requirement = (
            "required in strict mode"
            if strict_only and not self.strict
            else "required for this check"
        )
        self.add(
            check_id,
            "required",
            status,
            f"{label}: {detail}; {requirement}",
        )

    def optional_http(self, check_id: str, label: str, url: str) -> None:
        available, detail = local_http(url)
        self.add(
            check_id,
            "optional",
            "OK" if available else "WARN",
            f"{label}: {detail}",
        )

    def collect(self) -> None:
        self.add(
            "python",
            "required",
            "OK",
            f"Python {sys.version.split()[0]} at {sys.executable}",
        )
        self.tool("git", "Git", ["git", "--version"], strict_only=False)

        repository_detected = (REPOSITORY_ROOT / ".git").exists()
        self.add(
            "repository_root",
            "required",
            "OK" if repository_detected else "FAIL",
            (
                f"Repository root detected at {REPOSITORY_ROOT}"
                if repository_detected
                else f"Repository root not detected at {REPOSITORY_ROOT}"
            ),
        )

        self.required_path("readme", "README.md", "README.md")

        dependency_files = [
            path
            for path in ("pyproject.toml", "requirements.txt")
            if (REPOSITORY_ROOT / path).exists()
        ]
        self.add(
            "python_dependencies",
            "required",
            "OK" if dependency_files else "FAIL",
            (
                f"Python dependency config detected: {', '.join(dependency_files)}"
                if dependency_files
                else "Neither requirements.txt nor pyproject.toml exists"
            ),
        )

        self.required_path(
            "frontend_package",
            "frontend/package.json",
            "frontend/package.json",
        )
        for check_id, label, command in (
            ("node", "Node.js", ["node", "--version"]),
            ("npm", "npm", ["npm", "--version"]),
            ("docker", "Docker", ["docker", "--version"]),
        ):
            self.tool(check_id, label, command, strict_only=True)

        compose_available, compose_detail = command_version(
            ["docker", "compose", "version"]
        )
        if not compose_available:
            compose_available, compose_detail = command_version(
                ["docker-compose", "--version"]
            )
        self.add(
            "docker_compose",
            "required",
            "OK" if compose_available else ("FAIL" if self.strict else "WARN"),
            (
                f"Docker Compose: {compose_detail}"
                if compose_available
                else (
                    f"Docker Compose: {compose_detail}; "
                    + (
                        "required for this check"
                        if self.strict
                        else "required in strict mode"
                    )
                )
            ),
        )

        self.required_path("env_example", ".env.example", ".env.example")
        env_exists = (REPOSITORY_ROOT / ".env").exists()
        self.add(
            "env",
            "required",
            "OK" if env_exists else "WARN",
            (
                ".env exists"
                if env_exists
                else (
                    ".env is missing; copy .env.example to .env before "
                    "running the local runtime"
                )
            ),
        )
        self.required_path(
            "public_ci_validator",
            "scripts/validate_public_ci_baseline.py",
            "scripts/validate_public_ci_baseline.py",
        )
        self.required_path(
            "public_ci_workflow",
            ".github/workflows/ci.yml",
            ".github/workflows/ci.yml",
        )

        for check_id, label, url in (
            ("ollama", "Ollama", "http://127.0.0.1:11434/api/tags"),
            ("qdrant", "Qdrant", "http://127.0.0.1:6333/healthz"),
            (
                "grafana",
                "Grafana",
                "http://127.0.0.1:3002/grafana/api/health",
            ),
            ("prometheus", "Prometheus", "http://127.0.0.1:9090/-/ready"),
        ):
            self.optional_http(check_id, label, url)

        raw_port = os.getenv("POSTGRES_PORT", "5432")
        try:
            postgres_port = int(raw_port)
        except ValueError:
            self.add(
                "postgresql",
                "optional",
                "WARN",
                f"PostgreSQL: invalid POSTGRES_PORT value {raw_port!r}",
            )
        else:
            available, detail = local_tcp("127.0.0.1", postgres_port)
            self.add(
                "postgresql",
                "optional",
                "OK" if available else "WARN",
                f"PostgreSQL: {detail}",
            )

    def report(self) -> tuple[dict[str, object], int]:
        self.collect()
        summary = {
            category: {
                status.lower(): sum(
                    check.category == category and check.status == status
                    for check in self.checks
                )
                for status in ("OK", "WARN", "FAIL")
            }
            for category in ("required", "optional")
        }
        exit_code = 1 if summary["required"]["fail"] else 0
        if exit_code:
            result = "NOT_READY"
        elif summary["required"]["warn"] or summary["optional"]["warn"]:
            result = "READY_WITH_WARNINGS"
        else:
            result = "READY"

        return (
            {
                "doctor": "Sovereign AI SOC",
                "strict": self.strict,
                "repository_root": str(REPOSITORY_ROOT),
                "result": result,
                "exit_code": exit_code,
                "summary": summary,
                "checks": [asdict(check) for check in self.checks],
            },
            exit_code,
        )


def print_human(report: dict[str, object]) -> None:
    print("Sovereign AI SOC Doctor")
    print(f"[INFO] Repository: {report['repository_root']}")
    print(f"[INFO] Mode: {'strict' if report['strict'] else 'standard'}")
    print()
    for check in report["checks"]:
        print(f"[{check['status']}] {check['message']}")

    summary = report["summary"]
    print()
    for category in ("required", "optional"):
        counts = summary[category]
        print(
            f"{category.title()} checks: "
            f"{counts['ok']} OK, {counts['warn']} WARN, {counts['fail']} FAIL"
        )
    print(f"Result: {report['result']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check local readiness for Sovereign AI SOC.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat missing Node.js, npm, Docker or Docker Compose as failures.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of human-readable output.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report, exit_code = Doctor(strict=args.strict).report()
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_human(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
