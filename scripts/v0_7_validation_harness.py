#!/usr/bin/env python3
"""Expanded validation harness for AI SOC v0.7.

The harness is intentionally read-first and non-destructive by default. It
validates repository shape, compile/import health, optional runtime endpoints,
demo artifacts, observability wiring, and security guardrails without applying
detection configuration or restarting services.
"""

from __future__ import annotations

import argparse
import compileall
import importlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


VERSION = "v0.7.0"
REPORT_SUMMARY_JSON = "v0.7-validation-summary.json"
REPORT_SUMMARY_MD = "v0.7-validation-summary.md"
REPORT_DETAILS_JSON = "v0.7-validation-details.json"
SKIPPED_AUTH_REQUIRED = "SKIPPED_AUTH_REQUIRED"

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_SKIP = "SKIP"

SECRET_KEYWORDS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
)


@dataclass
class CheckResult:
    id: str
    category: str
    name: str
    status: str
    severity: str
    message: str
    duration_ms: int
    started_at: str
    finished_at: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class HttpResult:
    ok: bool
    status: int | None
    body: Any
    error: str | None = None
    content_type: str | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(keyword in key_text for keyword in SECRET_KEYWORDS):
                redacted[str(key)] = "***REDACTED***"
            else:
                redacted[str(key)] = redact(item)
        return redacted

    if isinstance(value, list):
        return [redact(item) for item in value]

    if isinstance(value, tuple):
        return [redact(item) for item in value]

    return value


def summarize_payload(value: Any, *, max_items: int = 5) -> Any:
    value = redact(value)

    if isinstance(value, dict):
        summary: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= max_items:
                summary["_truncated_keys"] = max(0, len(value) - max_items)
                break
            summary[str(key)] = summarize_payload(item, max_items=max_items)
        return summary

    if isinstance(value, list):
        return {
            "type": "list",
            "count": len(value),
            "sample": [summarize_payload(item, max_items=max_items) for item in value[:2]],
        }

    text = str(value)
    if len(text) > 240:
        return text[:240] + "...[truncated]"
    return value


def run_command(
    args: list[str],
    *,
    timeout: int = 60,
    cwd: Path = REPO_ROOT,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd),
        text=True,
        capture_output=capture_output,
        timeout=timeout,
        check=False,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI SOC v0.7 expanded CI/demo validation harness.",
    )
    parser.add_argument("--mode", choices=("local", "ci", "demo"), default="local")
    parser.add_argument("--base-url", default=os.getenv("AI_SOC_BASE_URL", "http://127.0.0.1:8008"))
    parser.add_argument(
        "--frontend-url",
        default=os.getenv("AI_SOC_FRONTEND_URL", "http://127.0.0.1:3000"),
    )
    parser.add_argument("--output-dir", default="reports/validation")
    parser.add_argument("--token", default=os.getenv("AI_SOC_API_TOKEN"))
    parser.add_argument("--username", default=os.getenv("AI_SOC_USERNAME"))
    parser.add_argument("--password", default=os.getenv("AI_SOC_PASSWORD"))
    parser.add_argument("--no-destructive", action="store_true", default=True)
    parser.add_argument(
        "--allow-destructive",
        dest="no_destructive",
        action="store_false",
        help="Allow controlled write/restart checks. Disabled by default.",
    )
    parser.add_argument("--skip-frontend-build", action="store_true")
    parser.add_argument("--skip-api", action="store_true")
    parser.add_argument("--skip-db", action="store_true")
    parser.add_argument("--skip-demo-data", action="store_true")
    parser.add_argument("--skip-reports", action="store_true")
    parser.add_argument("--skip-rbac", action="store_true")
    parser.add_argument("--skip-service-operations", action="store_true")
    parser.add_argument("--demo-scenario-pack", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json-only", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--http-timeout", type=float, default=5.0)
    return parser.parse_args(argv)


class ValidationHarness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base_url = str(args.base_url).rstrip("/")
        self.frontend_url = str(args.frontend_url).rstrip("/")
        self.output_dir = (REPO_ROOT / args.output_dir).resolve()
        self.token = args.token
        self.checks: list[CheckResult] = []
        self.context: dict[str, Any] = {
            "incident_id": None,
            "case_id": None,
            "service_key": None,
            "api_available": False,
            "db_available": False,
        }

    def run(self) -> int:
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.record("ENV-001", "Environment and repository", "Repository shape", "high", self.check_repo_shape)
        self.record("ENV-002", "Environment and repository", "Git hygiene", "medium", self.check_git_hygiene)
        self.record("ENV-003", "Environment and repository", "Frontend build readiness", "medium", self.check_frontend_build)

        self.record("PY-001", "Backend compile and imports", "Python compile health", "high", self.check_python_compile)
        self.record("PY-002", "Backend compile and imports", "Core module imports", "high", self.check_core_imports)

        if self.args.skip_db:
            self.add_skip("DB-001", "Database", "Database connectivity", "Skipped by --skip-db.")
            self.add_skip("DB-002", "Database", "v0.7 table coverage", "Skipped by --skip-db.")
        elif self.args.mode == "ci":
            self.add_skip("DB-001", "Database", "Database connectivity", "CI mode does not require live database.")
            self.add_skip("DB-002", "Database", "v0.7 table coverage", "CI mode does not require live database.")
        else:
            self.record("DB-001", "Database", "Database connectivity", "high", self.check_db_connectivity)
            self.record("DB-002", "Database", "v0.7 table coverage", "high", self.check_db_tables)

        if self.args.skip_api:
            self.add_skip("API-001", "API health", "Public API health", "Skipped by --skip-api.")
            self.add_skip("API-002", "API health", "Authenticated platform health", "Skipped by --skip-api.")
            self.add_skip("API-003", "API health", "Prometheus metrics endpoint", "Skipped by --skip-api.")
        elif self.args.mode == "ci":
            self.add_skip("API-001", "API health", "Public API health", "CI mode does not require live API.")
            self.add_skip("API-002", "API health", "Authenticated platform health", "CI mode does not require live API.")
            self.add_skip("API-003", "API health", "Prometheus metrics endpoint", "CI mode does not require live API.")
        else:
            self.record("API-001", "API health", "Public API health", "high", self.check_public_health)
            self.record("API-002", "API health", "Authenticated platform health", "medium", self.check_platform_health)
            self.record("API-003", "API health", "Prometheus metrics endpoint", "low", self.check_prometheus_metrics)

        if self.args.skip_rbac:
            self.add_skip("AUTH-001", "Auth and RBAC", "Authentication token or credentials", "Skipped by --skip-rbac.")
            self.add_skip("AUTH-002", "Auth and RBAC", "Protected endpoint enforcement", "Skipped by --skip-rbac.")
        elif self.args.mode == "ci":
            self.add_skip("AUTH-001", "Auth and RBAC", "Authentication token or credentials", "CI mode does not require live API.")
            self.add_skip("AUTH-002", "Auth and RBAC", "Protected endpoint enforcement", "CI mode does not require live API.")
        else:
            self.record("AUTH-001", "Auth and RBAC", "Authentication token or credentials", "high", self.check_auth_context)
            self.record("AUTH-002", "Auth and RBAC", "Protected endpoint enforcement", "high", self.check_protected_endpoint)

        self.run_detection_control_checks()
        self.run_service_operation_checks()
        self.run_timeline_graph_report_checks()

        if self.args.skip_demo_data:
            self.add_skip("DEMO-001", "Demo scenario pack", "Synthetic scenario script", "Skipped by --skip-demo-data.")
            self.add_skip("DEMO-002", "Demo scenario pack", "Dry-run event generation", "Skipped by --skip-demo-data.")
        else:
            self.record("DEMO-001", "Demo scenario pack", "Synthetic scenario script", "medium", self.check_demo_script)
            self.record("DEMO-002", "Demo scenario pack", "Dry-run event generation", "medium", self.check_demo_generation)

        self.record("OBS-001", "Observability", "Observability artifacts", "medium", self.check_observability_artifacts)
        self.record("OBS-002", "Observability", "Optional observability endpoints", "low", self.check_observability_endpoints)

        self.record("SEC-001", "Security guardrails", "Tracked secret files", "critical", self.check_no_tracked_secret_files)
        self.record("SEC-002", "Security guardrails", "Validation report ignore rules", "medium", self.check_report_gitignore)
        self.record("SEC-003", "Security guardrails", "No api.py monolith change", "medium", self.check_api_py_unchanged)
        self.record("SEC-004", "Security guardrails", "Service restart command guardrail", "high", self.check_service_guardrails)

        report = self.write_reports()
        if self.args.verbose:
            for check in self.checks:
                print(f"{check.status:4} {check.id} {check.name}: {check.message}")
        print(
            f"{report['overall_status']} - {len(self.checks)} checks, "
            f"{report['counts'].get(STATUS_FAIL, 0)} fail, "
            f"{report['counts'].get(STATUS_WARN, 0)} warn, "
            f"{report['counts'].get(STATUS_SKIP, 0)} skip"
        )
        print(f"Reports: {self.display_path(self.output_dir)}")
        return 1 if report["counts"].get(STATUS_FAIL, 0) else 0

    @staticmethod
    def display_path(path: Path) -> str:
        try:
            return str(path.relative_to(REPO_ROOT))
        except ValueError:
            return str(path)

    def add_skip(self, check_id: str, category: str, name: str, message: str) -> None:
        now = utc_now()
        self.checks.append(
            CheckResult(
                id=check_id,
                category=category,
                name=name,
                status=STATUS_SKIP,
                severity="low",
                message=message,
                duration_ms=0,
                started_at=now,
                finished_at=now,
                details={},
            )
        )

    def record(
        self,
        check_id: str,
        category: str,
        name: str,
        severity: str,
        fn: Callable[[], tuple[str, str, dict[str, Any] | None]],
    ) -> None:
        started_at = utc_now()
        start = time.monotonic()
        try:
            status, message, details = fn()
        except Exception as exc:  # noqa: BLE001 - validation output must capture unexpected failures.
            status = STATUS_FAIL
            message = f"{exc.__class__.__name__}: {exc}"
            details = {}

        if self.args.strict and status == STATUS_WARN and severity in {"critical", "high"}:
            status = STATUS_FAIL
            message = f"Strict mode escalated warning: {message}"

        finished_at = utc_now()
        self.checks.append(
            CheckResult(
                id=check_id,
                category=category,
                name=name,
                status=status,
                severity=severity,
                message=message,
                duration_ms=int((time.monotonic() - start) * 1000),
                started_at=started_at,
                finished_at=finished_at,
                details=redact(details or {}),
            )
        )

    def auth_headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"Bearer {self.token}"}

    def http_request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        auth: bool = True,
    ) -> HttpResult:
        url = self.base_url + path
        headers = {"Accept": "application/json"}
        body: bytes | None = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        if auth:
            headers.update(self.auth_headers())

        request = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=self.args.http_timeout) as response:
                raw = response.read()
                content_type = response.headers.get("content-type", "")
                parsed = self.parse_body(raw, content_type)
                return HttpResult(
                    ok=200 <= response.status < 300,
                    status=response.status,
                    body=parsed,
                    content_type=content_type,
                )
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            content_type = exc.headers.get("content-type", "") if exc.headers else ""
            return HttpResult(
                ok=False,
                status=exc.code,
                body=self.parse_body(raw, content_type),
                error=f"HTTP {exc.code}",
                content_type=content_type,
            )
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            return HttpResult(ok=False, status=None, body=None, error=str(exc), content_type=None)

    @staticmethod
    def parse_body(raw: bytes, content_type: str) -> Any:
        if not raw:
            return None
        text = raw.decode("utf-8", errors="replace")
        if "json" in content_type.lower():
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        return text

    def auth_required_result(self, check_name: str) -> tuple[str, str, dict[str, Any]]:
        return (
            STATUS_SKIP,
            f"{SKIPPED_AUTH_REQUIRED}: provide --token or --username/--password to validate {check_name}.",
            {"auth_provided": False},
        )

    def check_repo_shape(self) -> tuple[str, str, dict[str, Any]]:
        required = [
            "api.py",
            "database.py",
            "models.py",
            "routers/detection_control.py",
            "routers/service_operations.py",
            "routers/incident_timeline.py",
            "routers/investigation_graph.py",
            "routers/reports.py",
            "frontend/package.json",
            "tools/synthetic_scenarios/emit_demo_scenario_pack.py",
        ]
        missing = [path for path in required if not (REPO_ROOT / path).exists()]
        if missing:
            return STATUS_FAIL, "Required repository files are missing.", {"missing": missing}
        return STATUS_PASS, "Repository shape matches the v0.7 validation scope.", {"checked": required}

    def check_git_hygiene(self) -> tuple[str, str, dict[str, Any]]:
        branch = run_command(["git", "branch", "--show-current"], timeout=10).stdout.strip()
        status = run_command(["git", "status", "--short"], timeout=10).stdout.splitlines()
        details = {"branch": branch, "dirty_entries": status}
        if branch == "main":
            return STATUS_FAIL, "Validation work is running on main; use a dedicated branch.", details
        expected_step_files = {
            ".gitignore",
            "README.md",
            "docs/v0.7-expanded-validation-harness.md",
            "scripts/v0_7_validation_harness.py",
            "tests/test_v0_7_validation_harness.py",
        }
        unrelated = []
        for line in status:
            path = line[3:] if len(line) > 3 else line
            if " -> " in path:
                path = path.split(" -> ", 1)[1]
            if path not in expected_step_files:
                unrelated.append(line)
        if unrelated:
            return STATUS_WARN, "Working tree has changes; verify they belong to this step.", details
        if status:
            return STATUS_PASS, "Working tree only contains expected validation harness changes.", details
        return STATUS_PASS, "Dedicated branch detected with a clean working tree before generated reports.", details

    def check_frontend_build(self) -> tuple[str, str, dict[str, Any]]:
        package_json = REPO_ROOT / "frontend/package.json"
        if not package_json.exists():
            return STATUS_FAIL, "frontend/package.json is missing.", {}
        if self.args.skip_frontend_build:
            return STATUS_SKIP, "Skipped by --skip-frontend-build.", {}

        npm = shutil.which("npm")
        if not npm:
            return STATUS_WARN, "npm is not available on PATH.", {}

        if self.args.mode == "ci":
            proc = run_command(["npm", "--prefix", "frontend", "run", "build"], timeout=180)
            if proc.returncode != 0:
                return (
                    STATUS_FAIL,
                    "Frontend build failed.",
                    {
                        "returncode": proc.returncode,
                        "stdout_tail": proc.stdout[-2000:],
                        "stderr_tail": proc.stderr[-2000:],
                    },
                )
            return STATUS_PASS, "Frontend production build completed.", {"command": "npm --prefix frontend run build"}

        build_id = REPO_ROOT / "frontend/.next/BUILD_ID"
        if build_id.exists():
            return STATUS_PASS, "Existing frontend build artifact detected.", {"artifact": "frontend/.next/BUILD_ID"}
        return STATUS_SKIP, "Local/demo mode does not force frontend build; run npm build for release validation.", {}

    def check_python_compile(self) -> tuple[str, str, dict[str, Any]]:
        compile_targets = [
            REPO_ROOT / "api.py",
            REPO_ROOT / "models.py",
            REPO_ROOT / "database.py",
            REPO_ROOT / "routers",
            REPO_ROOT / "ai_governance",
            REPO_ROOT / "detection_engineering",
            REPO_ROOT / "investigation_ai",
            REPO_ROOT / "remediation",
            REPO_ROOT / "scripts",
        ]
        failures: list[str] = []
        checked: list[str] = []
        for target in compile_targets:
            if not target.exists():
                continue
            checked.append(str(target.relative_to(REPO_ROOT)))
            if target.is_dir():
                ok = compileall.compile_dir(str(target), quiet=1, force=False)
            else:
                ok = compileall.compile_file(str(target), quiet=1, force=False)
            if not ok:
                failures.append(str(target.relative_to(REPO_ROOT)))

        if failures:
            return STATUS_FAIL, "Python compile check failed.", {"failures": failures, "checked": checked}
        return STATUS_PASS, "Python compile check passed.", {"checked": checked}

    def check_core_imports(self) -> tuple[str, str, dict[str, Any]]:
        modules = [
            "api",
            "models",
            "database",
            "platform_health",
            "detection_control_plane",
            "detection_config_versioning",
            "detection_control_validation",
            "detection_operations",
            "detection_rule_lifecycle",
            "service_operations",
            "incident_timeline",
            "investigation_graph",
            "report_builder",
            "evidence_pack_builder",
            "routers.detection_control",
            "routers.service_operations",
            "routers.incident_timeline",
            "routers.investigation_graph",
            "routers.reports",
        ]
        failures: dict[str, str] = {}
        for module_name in modules:
            try:
                importlib.import_module(module_name)
            except Exception as exc:  # noqa: BLE001 - import validation should capture module failure.
                failures[module_name] = f"{exc.__class__.__name__}: {exc}"

        if failures:
            return STATUS_FAIL, "One or more core modules failed to import.", {"failures": failures}
        return STATUS_PASS, "Core modules import successfully.", {"modules": modules}

    def check_db_connectivity(self) -> tuple[str, str, dict[str, Any]]:
        try:
            from sqlalchemy import text

            from database import SessionLocal

            db = SessionLocal()
            try:
                db.execute(text("select 1"))
                self.context["db_available"] = True
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001
            return STATUS_WARN, f"Database unavailable: {exc.__class__.__name__}: {exc}", {}

        return STATUS_PASS, "Database connection succeeded.", {}

    def check_db_tables(self) -> tuple[str, str, dict[str, Any]]:
        try:
            from sqlalchemy import inspect, select

            from database import engine, SessionLocal
            from models import Incident, IncidentCase

            inspector = inspect(engine)
            table_names = set(inspector.get_table_names())
            required = {
                "raw_events",
                "security_alerts",
                "incidents",
                "incident_cases",
                "app_users",
                "security_audit_events",
                "detection_control_rules",
                "detection_config_versions",
                "detection_rule_lifecycle_items",
                "detection_rule_lifecycle_events",
                "service_operations",
                "wazuh_ingest_watermarks",
            }
            optional_memory = {
                "investigation_sessions",
                "investigation_snapshots",
                "investigation_hypothesis_history",
                "investigation_confidence_history",
                "investigation_retrieval_history",
                "investigation_similarity_history",
                "investigation_feedback",
            }
            missing = sorted(required - table_names)
            missing_optional = sorted(optional_memory - table_names)

            db = SessionLocal()
            try:
                incident = db.execute(select(Incident.id).order_by(Incident.id.desc()).limit(1)).scalar_one_or_none()
                case = db.execute(select(IncidentCase.id).order_by(IncidentCase.id.desc()).limit(1)).scalar_one_or_none()
                self.context["incident_id"] = incident
                self.context["case_id"] = case
            finally:
                db.close()

            details = {
                "required_tables": sorted(required),
                "optional_investigation_memory_tables": sorted(optional_memory),
                "missing_tables": missing,
                "missing_optional_tables": missing_optional,
                "latest_incident_id": self.context["incident_id"],
                "latest_case_id": self.context["case_id"],
            }
            if missing:
                return STATUS_FAIL, "Required v0.7 database tables are missing.", details
            if missing_optional:
                return (
                    STATUS_WARN,
                    "Optional investigation memory tables are missing; graph validation will use fallback data.",
                    details,
                )
            return STATUS_PASS, "Required and optional v0.7 database tables exist.", details
        except Exception as exc:  # noqa: BLE001
            return STATUS_WARN, f"Database table validation unavailable: {exc.__class__.__name__}: {exc}", {}

    def check_public_health(self) -> tuple[str, str, dict[str, Any]]:
        result = self.http_request("GET", "/health", auth=False)
        if result.status and 200 <= result.status < 300:
            self.context["api_available"] = True
            return STATUS_PASS, "Public health endpoint responded.", {"status": result.status}
        return STATUS_WARN, "Public health endpoint is unavailable.", {"status": result.status, "error": result.error}

    def check_platform_health(self) -> tuple[str, str, dict[str, Any]]:
        result = self.http_request("GET", "/platform/health")
        if not self.token and result.status in {401, 403}:
            return STATUS_PASS, "Platform health is protected without credentials.", {"status": result.status}
        if self.token and result.status == 200:
            return STATUS_PASS, "Authenticated platform health responded.", {"status": result.status}
        if not self.token:
            return self.auth_required_result("platform health")
        return STATUS_WARN, "Platform health did not return 200 with supplied auth.", {"status": result.status, "error": result.error}

    def check_prometheus_metrics(self) -> tuple[str, str, dict[str, Any]]:
        result = self.http_request("GET", "/metrics", auth=False)
        if result.status == 200:
            return STATUS_PASS, "Prometheus metrics endpoint responded.", {"status": result.status}
        return STATUS_WARN, "Metrics endpoint is unavailable or protected.", {"status": result.status, "error": result.error}

    def check_auth_context(self) -> tuple[str, str, dict[str, Any]]:
        if self.token:
            me = self.http_request("GET", "/auth/me")
            if me.status == 200:
                return STATUS_PASS, "Token authenticated successfully.", {"user": summarize_payload(me.body)}
            return STATUS_WARN, "Token was provided but /auth/me did not return 200.", {"status": me.status, "error": me.error}

        if self.args.username and self.args.password:
            result = self.http_request(
                "POST",
                "/auth/login",
                payload={"username": self.args.username, "password": self.args.password},
                auth=False,
            )
            if result.status == 200 and isinstance(result.body, dict):
                token = result.body.get("access_token") or result.body.get("token")
                if token:
                    self.token = str(token)
                    return STATUS_PASS, "Credentials authenticated and token stored in memory.", {"token_received": True}
            return STATUS_WARN, "Credential login failed.", {"status": result.status, "body": summarize_payload(result.body)}

        return self.auth_required_result("authenticated API checks")

    def check_protected_endpoint(self) -> tuple[str, str, dict[str, Any]]:
        result = self.http_request("GET", "/incidents?limit=1", auth=False)
        if result.status in {401, 403}:
            return STATUS_PASS, "Protected endpoint rejects unauthenticated requests.", {"status": result.status}
        if result.status is None:
            return STATUS_WARN, "Protected endpoint could not be reached.", {"error": result.error}
        return STATUS_FAIL, "Protected endpoint did not reject unauthenticated request.", {"status": result.status}

    def run_detection_control_checks(self) -> None:
        if self.args.mode == "ci" or self.args.skip_api:
            self.add_skip("DCP-001", "Detection Control", "Inventory endpoints", "CI/API skip does not require live API.")
            self.add_skip("DCP-002", "Detection Control", "Config validation/diff endpoints", "CI/API skip does not require live API.")
            return
        self.record("DCP-001", "Detection Control", "Inventory endpoints", "high", self.check_detection_inventory)
        self.record("DCP-002", "Detection Control", "Config validation/diff endpoints", "medium", self.check_detection_config_dry_run)

    def check_detection_inventory(self) -> tuple[str, str, dict[str, Any]]:
        if not self.token:
            return self.auth_required_result("detection control inventory")

        paths = [
            "/settings/detection-control",
            "/detection-control/rules",
            "/detection-control/config-versions",
            "/detection-control/lifecycle/items?limit=1",
            "/detection-control/operations/overview",
            "/detection-control/operations/noise-suppression?limit=1",
            "/detection-control/operations/exceptions?limit=1",
            "/detection-control/operations/rules?limit=1",
        ]
        failures: dict[str, Any] = {}
        samples: dict[str, Any] = {}
        for path in paths:
            result = self.http_request("GET", path)
            if result.status != 200:
                failures[path] = {"status": result.status, "error": result.error}
            else:
                samples[path] = summarize_payload(result.body)

        if failures:
            return STATUS_FAIL, "One or more Detection Control inventory endpoints failed.", {"failures": failures}
        return STATUS_PASS, "Detection Control inventory endpoints responded.", {"samples": samples}

    def check_detection_config_dry_run(self) -> tuple[str, str, dict[str, Any]]:
        if not self.token:
            return self.auth_required_result("detection config validation/diff")
        if self.args.no_destructive:
            return (
                STATUS_SKIP,
                "Skipped in non-destructive mode because validate/diff endpoints create audit records.",
                {"endpoints": ["validate", "diff"]},
            )

        payload = {"items": [], "version": "validation-harness"}
        validate = self.http_request("POST", "/detection-control/config-versions/noise_suppression/validate", payload=payload)
        diff = self.http_request("POST", "/detection-control/config-versions/noise_suppression/diff", payload=payload)
        details = {"validate": {"status": validate.status}, "diff": {"status": diff.status}}
        if validate.status == 200 and diff.status == 200:
            return STATUS_PASS, "Detection config validate/diff endpoints responded.", details
        return STATUS_WARN, "Detection config validate/diff did not both return 200.", details

    def run_service_operation_checks(self) -> None:
        if self.args.skip_service_operations:
            self.add_skip("SVC-001", "Service Operations", "Service inventory", "Skipped by --skip-service-operations.")
            self.add_skip("SVC-002", "Service Operations", "Restart preview", "Skipped by --skip-service-operations.")
            return
        if self.args.mode == "ci" or self.args.skip_api:
            self.add_skip("SVC-001", "Service Operations", "Service inventory", "CI/API skip does not require live API.")
            self.add_skip("SVC-002", "Service Operations", "Restart preview", "CI/API skip does not require live API.")
            return
        self.record("SVC-001", "Service Operations", "Service inventory", "medium", self.check_service_inventory)
        self.record("SVC-002", "Service Operations", "Restart preview", "medium", self.check_service_preview)

    def check_service_inventory(self) -> tuple[str, str, dict[str, Any]]:
        if not self.token:
            return self.auth_required_result("service operations inventory")

        result = self.http_request("GET", "/service-operations/services")
        if result.status != 200:
            return STATUS_WARN, "Service inventory endpoint did not return 200.", {"status": result.status, "error": result.error}

        services = result.body if isinstance(result.body, list) else result.body.get("items", []) if isinstance(result.body, dict) else []
        if services:
            first = services[0]
            if isinstance(first, dict):
                self.context["service_key"] = first.get("key") or first.get("service_key") or first.get("name")
        return STATUS_PASS, "Service inventory endpoint responded.", {"services": summarize_payload(services)}

    def check_service_preview(self) -> tuple[str, str, dict[str, Any]]:
        if not self.token:
            return self.auth_required_result("service restart preview")
        if self.args.no_destructive:
            return (
                STATUS_SKIP,
                "Skipped in non-destructive mode because restart preview records an operation audit.",
                {"service_key": self.context.get("service_key")},
            )

        service_key = self.context.get("service_key") or "ai-soc-worker"
        result = self.http_request(
            "POST",
            f"/service-operations/services/{urllib.parse.quote(str(service_key))}/restart-preview",
            payload={"reason": "v0.7 validation harness preview"},
        )
        if result.status == 200:
            return STATUS_PASS, "Service restart preview responded without restarting service.", {"service_key": service_key}
        return STATUS_WARN, "Service restart preview did not return 200.", {"status": result.status, "error": result.error}

    def run_timeline_graph_report_checks(self) -> None:
        if self.args.mode == "ci" or self.args.skip_api:
            self.add_skip("TLN-001", "Advanced Incident Timeline", "Timeline endpoints", "CI/API skip does not require live API.")
            self.add_skip("GRF-001", "Investigation Graph", "Graph endpoints", "CI/API skip does not require live API.")
            self.add_skip("RPT-001", "Report/export", "Report endpoints", "CI/API skip does not require live API.")
            return
        self.record("TLN-001", "Advanced Incident Timeline", "Timeline endpoints", "high", self.check_timeline_endpoints)
        self.record("GRF-001", "Investigation Graph", "Graph endpoints", "high", self.check_graph_endpoints)
        if self.args.skip_reports:
            self.add_skip("RPT-001", "Report/export", "Report endpoints", "Skipped by --skip-reports.")
        else:
            self.record("RPT-001", "Report/export", "Report endpoints", "medium", self.check_report_endpoints)

    def check_timeline_endpoints(self) -> tuple[str, str, dict[str, Any]]:
        if not self.token:
            return self.auth_required_result("timeline endpoints")
        incident_id = self.context.get("incident_id")
        if not incident_id:
            return STATUS_SKIP, "No incident id available for timeline validation.", {}

        paths = [
            f"/incidents/{incident_id}/timeline?limit=20&sort=asc",
            f"/incidents/{incident_id}/timeline/summary",
            f"/incidents/{incident_id}/timeline/capabilities",
        ]
        failures: dict[str, Any] = {}
        for path in paths:
            result = self.http_request("GET", path)
            if result.status != 200:
                failures[path] = {"status": result.status, "error": result.error}

        if failures:
            return STATUS_FAIL, "One or more timeline endpoints failed.", {"incident_id": incident_id, "failures": failures}
        return STATUS_PASS, "Timeline endpoints responded for latest incident.", {"incident_id": incident_id}

    def check_graph_endpoints(self) -> tuple[str, str, dict[str, Any]]:
        if not self.token:
            return self.auth_required_result("investigation graph endpoints")
        incident_id = self.context.get("incident_id")
        case_id = self.context.get("case_id")
        if not incident_id and not case_id:
            return STATUS_SKIP, "No incident or case id available for graph validation.", {}

        paths = ["/investigation-graph/capabilities"]
        if incident_id:
            paths.extend(
                [
                    f"/investigation-graph/incidents/{incident_id}?limit_nodes=80&limit_edges=160",
                    f"/investigation-graph/incidents/{incident_id}/summary",
                ]
            )
        if case_id:
            paths.extend(
                [
                    f"/investigation-graph/cases/{case_id}?limit_nodes=80&limit_edges=160",
                    f"/investigation-graph/cases/{case_id}/summary",
                ]
            )

        failures: dict[str, Any] = {}
        samples: dict[str, Any] = {}
        for path in paths:
            result = self.http_request("GET", path)
            if result.status != 200:
                failures[path] = {"status": result.status, "error": result.error}
            else:
                samples[path] = summarize_payload(result.body)

        if failures:
            return STATUS_FAIL, "One or more investigation graph endpoints failed.", {"failures": failures}
        return STATUS_PASS, "Investigation graph endpoints responded.", {"samples": samples}

    def check_report_endpoints(self) -> tuple[str, str, dict[str, Any]]:
        if not self.token:
            return self.auth_required_result("report endpoints")
        incident_id = self.context.get("incident_id")
        case_id = self.context.get("case_id")
        if not incident_id and not case_id:
            return STATUS_SKIP, "No incident or case id available for report validation.", {}

        paths = []
        if incident_id:
            paths.append(f"/reports/incidents/{incident_id}?format=json")
        if case_id:
            paths.append(f"/reports/cases/{case_id}?format=json")
            paths.append(f"/reports/cases/{case_id}/evidence-pack?format=json")

        failures: dict[str, Any] = {}
        for path in paths:
            result = self.http_request("GET", path)
            if result.status != 200:
                failures[path] = {"status": result.status, "error": result.error}

        if failures:
            return STATUS_WARN, "One or more report endpoints failed.", {"failures": failures}
        return STATUS_PASS, "Report/export endpoints responded.", {"checked": paths}

    def check_demo_script(self) -> tuple[str, str, dict[str, Any]]:
        script = REPO_ROOT / "tools/synthetic_scenarios/emit_demo_scenario_pack.py"
        if not script.exists():
            return STATUS_FAIL, "Demo scenario pack script is missing.", {}
        module = run_command([sys.executable, str(script), "--help"], timeout=20)
        if module.returncode != 0:
            return STATUS_FAIL, "Demo scenario pack --help failed.", {"stderr_tail": module.stderr[-1200:]}
        return STATUS_PASS, "Demo scenario pack script is available.", {"script": str(script.relative_to(REPO_ROOT))}

    def check_demo_generation(self) -> tuple[str, str, dict[str, Any]]:
        script = REPO_ROOT / "tools/synthetic_scenarios/emit_demo_scenario_pack.py"
        if not script.exists():
            return STATUS_FAIL, "Demo scenario pack script is missing.", {}

        temp_output = self.output_dir / "v0.7-demo-scenario-dry-run.jsonl"
        temp_output.unlink(missing_ok=True)
        args = [
            sys.executable,
            str(script),
            "--scenario",
            "case_ready",
            "--count",
            "2",
            "--output",
            str(temp_output),
            "--created-by",
            "v0.7-validation-harness",
        ]
        proc = run_command(args, timeout=30)
        if proc.returncode != 0:
            temp_output.unlink(missing_ok=True)
            return STATUS_WARN, "Demo scenario dry-run generation failed.", {"stderr_tail": proc.stderr[-1200:]}
        lines = temp_output.read_text(encoding="utf-8").splitlines() if temp_output.exists() else []
        temp_output.unlink(missing_ok=True)
        if len(lines) < 2:
            return STATUS_WARN, "Demo scenario dry-run generated fewer events than expected.", {"line_count": len(lines)}
        try:
            sample = json.loads(lines[0])
        except json.JSONDecodeError as exc:
            return STATUS_FAIL, f"Demo scenario output is not valid JSONL: {exc}", {}
        if not sample.get("synthetic") or not sample.get("demo"):
            return STATUS_FAIL, "Demo scenario event is not clearly marked synthetic/demo.", {"sample": summarize_payload(sample)}
        return STATUS_PASS, "Demo scenario pack dry-run generated synthetic events.", {"line_count": len(lines)}

    def check_observability_artifacts(self) -> tuple[str, str, dict[str, Any]]:
        expected = [
            "deploy/observability/docker-compose.yml",
            "deploy/observability/docker-compose.loki.yml",
            "deploy/observability/prometheus",
            "deploy/observability/grafana",
            "deploy/observability/alertmanager",
            "deploy/observability/ntfy-bridge",
        ]
        missing = [path for path in expected if not (REPO_ROOT / path).exists()]
        if missing:
            return STATUS_WARN, "Some optional observability artifacts are missing.", {"missing": missing}
        return STATUS_PASS, "Observability deployment artifacts are present.", {"checked": expected}

    def check_observability_endpoints(self) -> tuple[str, str, dict[str, Any]]:
        if self.args.mode == "ci":
            return STATUS_SKIP, "CI mode does not require live observability endpoints.", {}

        endpoints = [
            ("grafana", "http://127.0.0.1:3002/api/health"),
            ("prometheus", "http://127.0.0.1:9090/-/healthy"),
            ("alertmanager", "http://127.0.0.1:9093/-/healthy"),
        ]
        results: dict[str, Any] = {}
        available = 0
        for name, url in endpoints:
            try:
                request = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
                with urllib.request.urlopen(request, timeout=2) as response:
                    results[name] = {"status": response.status}
                    if 200 <= response.status < 300:
                        available += 1
            except Exception as exc:  # noqa: BLE001
                results[name] = {"status": None, "error": str(exc)}

        if available == len(endpoints):
            return STATUS_PASS, "Optional observability endpoints are reachable.", results
        return STATUS_WARN, "Optional observability endpoints are not all reachable; non-blocking.", results

    def check_no_tracked_secret_files(self) -> tuple[str, str, dict[str, Any]]:
        candidates = [
            ".env",
            ".env.local",
            "frontend/.env.local",
            "deploy/observability/.env",
            "deploy/observability/ntfy-bridge/.env",
            ".runtime/auth_secret",
        ]
        proc = run_command(["git", "ls-files", *candidates], timeout=10)
        tracked = [line for line in proc.stdout.splitlines() if line.strip()]
        if tracked:
            return STATUS_FAIL, "Secret/environment files are tracked by git.", {"tracked": tracked}
        return STATUS_PASS, "No known local secret files are tracked by git.", {"checked": candidates}

    def check_report_gitignore(self) -> tuple[str, str, dict[str, Any]]:
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
        required = ["reports/validation/*.json", "reports/validation/*.md", "reports/validation/*.pdf"]
        missing = [pattern for pattern in required if pattern not in gitignore]
        if missing:
            return STATUS_FAIL, "Validation report ignore rules are incomplete.", {"missing": missing}
        return STATUS_PASS, "Validation report outputs are ignored by git.", {"required": required}

    def check_api_py_unchanged(self) -> tuple[str, str, dict[str, Any]]:
        proc = run_command(["git", "diff", "--name-only", "--", "api.py"], timeout=10)
        changed = [line for line in proc.stdout.splitlines() if line.strip()]
        if changed:
            return STATUS_WARN, "api.py has local changes; confirm they are unrelated and intentional.", {"changed": changed}
        return STATUS_PASS, "api.py has no local changes from this validation step.", {}

    def check_service_guardrails(self) -> tuple[str, str, dict[str, Any]]:
        source = (REPO_ROOT / "service_operations.py").read_text(encoding="utf-8")
        risky_markers = ["shell=True", "os.system(", "subprocess.Popen("]
        found = [marker for marker in risky_markers if marker in source]
        if found:
            return STATUS_FAIL, "Service operation code contains risky command execution markers.", {"found": found}
        return STATUS_PASS, "Service restart code avoids shell=True/os.system style execution.", {}

    def write_reports(self) -> dict[str, Any]:
        counts: dict[str, int] = {status: 0 for status in (STATUS_PASS, STATUS_WARN, STATUS_FAIL, STATUS_SKIP)}
        for check in self.checks:
            counts[check.status] = counts.get(check.status, 0) + 1

        if counts.get(STATUS_FAIL, 0):
            overall = STATUS_FAIL
        elif counts.get(STATUS_WARN, 0):
            overall = STATUS_WARN
        else:
            overall = STATUS_PASS

        sanitized_args = {
            "mode": self.args.mode,
            "base_url": self.base_url,
            "frontend_url": self.frontend_url,
            "output_dir": self.display_path(self.output_dir),
            "token_provided": bool(self.token),
            "username_provided": bool(self.args.username),
            "password_provided": bool(self.args.password),
            "no_destructive": bool(self.args.no_destructive),
            "strict": bool(self.args.strict),
            "json_only": bool(self.args.json_only),
        }
        checks = [asdict(check) for check in self.checks]
        summary = {
            "version": VERSION,
            "mode": self.args.mode,
            "generated_at": utc_now(),
            "overall_status": overall,
            "counts": counts,
            "reports": {
                "summary_json": REPORT_SUMMARY_JSON,
                "summary_md": None if self.args.json_only else REPORT_SUMMARY_MD,
                "details_json": REPORT_DETAILS_JSON,
            },
            "checks": [
                {
                    "id": check.id,
                    "category": check.category,
                    "name": check.name,
                    "status": check.status,
                    "severity": check.severity,
                    "message": check.message,
                    "duration_ms": check.duration_ms,
                }
                for check in self.checks
            ],
        }
        details = {
            **summary,
            "arguments": sanitized_args,
            "context": redact(self.context),
            "checks": checks,
        }

        (self.output_dir / REPORT_SUMMARY_JSON).write_text(
            json.dumps(redact(summary), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (self.output_dir / REPORT_DETAILS_JSON).write_text(
            json.dumps(redact(details), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not self.args.json_only:
            (self.output_dir / REPORT_SUMMARY_MD).write_text(self.render_markdown(summary), encoding="utf-8")
        return summary

    def render_markdown(self, summary: dict[str, Any]) -> str:
        lines = [
            "# AI SOC v0.7 Validation Summary",
            "",
            f"- Version: `{summary['version']}`",
            f"- Mode: `{summary['mode']}`",
            f"- Generated: `{summary['generated_at']}`",
            f"- Overall status: `{summary['overall_status']}`",
            "",
            "## Counts",
            "",
            "| Status | Count |",
            "|---|---:|",
        ]
        for status in (STATUS_PASS, STATUS_WARN, STATUS_FAIL, STATUS_SKIP):
            lines.append(f"| {status} | {summary['counts'].get(status, 0)} |")

        lines.extend(
            [
                "",
                "## Checks",
                "",
                "| ID | Category | Status | Severity | Message |",
                "|---|---|---|---|---|",
            ]
        )
        for check in self.checks:
            message = str(check.message).replace("|", "\\|")
            lines.append(
                f"| {check.id} | {check.category} | {check.status} | {check.severity} | {message} |"
            )
        lines.append("")
        return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return ValidationHarness(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
