#!/usr/bin/env python3
"""Read-only validation for a running local Sovereign AI SOC instance."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
NETWORK_TIMEOUT = 1.5


@dataclass(frozen=True)
class Check:
    check_id: str
    category: str
    status: str
    message: str


def is_loopback_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def safe_local_url(value: str) -> tuple[str | None, str | None]:
    candidate = value.strip()
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not is_loopback_host(
        parsed.hostname
    ):
        return None, f"refused non-local URL {candidate!r}"
    return candidate, None


def join_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def configured_base_url(
    environment_names: tuple[str, ...],
    default: str,
) -> tuple[str | None, str | None]:
    selected_name = "default"
    value = default
    for name in environment_names:
        if os.getenv(name):
            selected_name = name
            value = os.environ[name]
            break

    url, error = safe_local_url(value)
    if error:
        return None, f"{selected_name}: {error}"
    return url, None


def local_http(url: str, *, auth_proof: bool = False) -> tuple[bool, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json, text/plain, */*"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=NETWORK_TIMEOUT) as response:
            reachable = 200 <= response.status < 400
            return reachable, f"HTTP {response.status} at {url}"
    except urllib.error.HTTPError as exc:
        if auth_proof and exc.code in {401, 403}:
            return True, f"HTTP {exc.code} (authentication required) at {url}"
        return False, f"HTTP {exc.code} at {url}"
    except (OSError, urllib.error.URLError, TimeoutError):
        return False, f"unavailable at {url}"


def local_tcp(host: str, port: int) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=NETWORK_TIMEOUT):
            return True, f"TCP reachable at {host}:{port}"
    except OSError:
        return False, f"unavailable at {host}:{port}"


class RuntimeValidator:
    def __init__(
        self,
        *,
        strict: bool,
        repository_root: Path = REPOSITORY_ROOT,
    ) -> None:
        self.strict = strict
        self.repository_root = repository_root
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
        exists = (self.repository_root / relative_path).is_file()
        self.add(
            check_id,
            "structure",
            "OK" if exists else "FAIL",
            f"{label} {'exists' if exists else 'is missing'}",
        )

    def runtime_http(
        self,
        check_id: str,
        label: str,
        url: str | None,
        configuration_error: str | None,
        *,
        strict_required: bool = False,
    ) -> None:
        if configuration_error or not url:
            self.add(
                check_id,
                "runtime",
                "FAIL" if self.strict and strict_required else "WARN",
                f"{label}: {configuration_error or 'no local URL configured'}",
            )
            return

        available, detail = local_http(url)
        status = "OK" if available else (
            "FAIL" if self.strict and strict_required else "WARN"
        )
        self.add(check_id, "runtime", status, f"{label}: {detail}")

    def backend(self) -> None:
        base_url, error = configured_base_url(
            ("AI_SOC_API_BASE_URL", "NEXT_PUBLIC_API_BASE_URL"),
            "http://127.0.0.1:8008",
        )
        if error or not base_url:
            self.add(
                "backend",
                "runtime",
                "FAIL" if self.strict else "WARN",
                f"Backend: {error or 'no local URL configured'}",
            )
            return

        candidates = (
            (join_url(base_url, "/health"), False),
            (join_url(base_url, "/platform/health"), True),
        )
        details: list[str] = []
        for url, auth_proof in candidates:
            available, detail = local_http(url, auth_proof=auth_proof)
            details.append(detail)
            if available:
                self.add("backend", "runtime", "OK", f"Backend: {detail}")
                return

        self.add(
            "backend",
            "runtime",
            "FAIL" if self.strict else "WARN",
            f"Backend: {'; '.join(details)}",
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
        self.required_path("wrapper", "ai-soc", "ai-soc wrapper")
        self.required_path("doctor", "scripts/doctor.py", "doctor script")
        self.required_path(
            "public_ci_validator",
            "scripts/validate_public_ci_baseline.py",
            "public CI validator",
        )

        env_exists = (self.repository_root / ".env").is_file()
        self.add(
            "env",
            "structure",
            "OK" if env_exists else "WARN",
            (
                ".env exists"
                if env_exists
                else ".env is missing; runtime configuration may be incomplete"
            ),
        )

    def collect_runtime(self) -> None:
        self.backend()

        frontend_url, frontend_error = configured_base_url(
            ("AI_SOC_FRONTEND_URL",),
            "http://127.0.0.1:3000",
        )
        self.runtime_http(
            "frontend",
            "Frontend",
            frontend_url,
            frontend_error,
            strict_required=True,
        )

        ollama_base, ollama_error = configured_base_url(
            ("AI_OLLAMA_BASE_URL", "OLLAMA_BASE_URL"),
            "http://127.0.0.1:11434",
        )
        self.runtime_http(
            "ollama",
            "Ollama",
            join_url(ollama_base, "/api/tags") if ollama_base else None,
            ollama_error,
        )

        qdrant_base, qdrant_error = configured_base_url(
            ("QDRANT_URL",),
            "http://127.0.0.1:6333",
        )
        self.runtime_http(
            "qdrant",
            "Qdrant",
            join_url(qdrant_base, "/healthz") if qdrant_base else None,
            qdrant_error,
        )

        grafana_base, grafana_error = configured_base_url(
            ("GRAFANA_URL",),
            "http://127.0.0.1:3002/grafana",
        )
        self.runtime_http(
            "grafana",
            "Grafana",
            join_url(grafana_base, "/api/health") if grafana_base else None,
            grafana_error,
        )

        prometheus_url, prometheus_error = configured_base_url(
            ("PROMETHEUS_HEALTH_URL",),
            "http://127.0.0.1:9090/-/ready",
        )
        self.runtime_http(
            "prometheus",
            "Prometheus",
            prometheus_url,
            prometheus_error,
        )

        postgres_host = os.getenv("POSTGRES_HOST", "127.0.0.1").strip()
        if not is_loopback_host(postgres_host):
            self.add(
                "postgresql",
                "runtime",
                "WARN",
                f"PostgreSQL: refused non-local host {postgres_host!r}",
            )
            return

        raw_port = os.getenv("POSTGRES_PORT", "5432")
        try:
            postgres_port = int(raw_port)
            if not 1 <= postgres_port <= 65535:
                raise ValueError
        except ValueError:
            self.add(
                "postgresql",
                "runtime",
                "WARN",
                f"PostgreSQL: invalid POSTGRES_PORT value {raw_port!r}",
            )
            return

        available, detail = local_tcp(postgres_host, postgres_port)
        self.add(
            "postgresql",
            "runtime",
            "OK" if available else "WARN",
            f"PostgreSQL: {detail}",
        )

    def report(self) -> tuple[dict[str, object], int]:
        self.collect_structure()
        self.collect_runtime()

        summary = {
            status.lower(): sum(check.status == status for check in self.checks)
            for status in ("OK", "WARN", "FAIL")
        }
        summary["total"] = len(self.checks)
        exit_code = 1 if summary["fail"] else 0
        if exit_code:
            result = "NOT_READY"
        elif summary["warn"]:
            result = "READY_WITH_WARNINGS"
        else:
            result = "READY"

        return (
            {
                "validator": "Sovereign AI SOC runtime",
                "strict": self.strict,
                "repository_root": str(self.repository_root),
                "result": result,
                "exit_code": exit_code,
                "summary": summary,
                "checks": [asdict(check) for check in self.checks],
            },
            exit_code,
        )


def print_human(report: dict[str, object]) -> None:
    print("Sovereign AI SOC Runtime Validation")
    print(f"[INFO] Repository: {report['repository_root']}")
    print(f"[INFO] Mode: {'strict' if report['strict'] else 'standard'}")
    print("[INFO] Read-only checks; no credentials are sent")
    print()
    for check in report["checks"]:
        print(f"[{check['status']}] {check['message']}")
    print()
    print(f"[INFO] Result: {report['result']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a running local Sovereign AI SOC instance.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a machine-readable JSON report.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Require the backend and frontend to be reachable.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report, exit_code = RuntimeValidator(strict=args.strict).report()
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print_human(report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
