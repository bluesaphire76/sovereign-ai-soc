from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


BASE_URL = os.getenv("SMOKE_BASE_URL", "http://127.0.0.1:8008").rstrip("/")
AUTH_TOKEN = os.getenv("SMOKE_AUTH_TOKEN", "").strip()
REPORT_DIR = Path(os.getenv("SMOKE_REPORT_DIR", "reports/validation"))

CORE_IMPORTS = [
    "api",
    "models",
    "database",
    "platform_health",
    "ai_soc_worker",
    "ai_triage_hardening",
    "risk_normalization",
    "correlation_precheck",
    "noise_suppression",
    "event_aggregation",
    "event_records",
    "report_builder",
    "evidence_pack_builder",
    "executive_pdf_builder",
    "enterprise_report_templates",
    "ai_runtime_observability",
]

REQUIRED_TABLES = [
    "raw_events",
    "security_alerts",
    "event_aggregates",
    "incidents",
    "incident_cases",
    "incident_audit",
    "security_audit_events",
    "wazuh_ingest_watermarks",
    "worker_heartbeats",
    "app_users",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def result(
    name: str,
    status: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "message": message,
        "details": details or {},
    }


def http_get(path: str, token: str | None = None, timeout: int = 10) -> dict[str, Any]:
    url = f"{BASE_URL}{path}"
    headers = {"Accept": "application/json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = Request(url, headers=headers, method="GET")
    started_at = time.perf_counter()

    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)

            try:
                parsed = json.loads(body) if body else None
            except json.JSONDecodeError:
                parsed = body[:500]

            return {
                "ok": True,
                "status_code": response.status,
                "elapsed_ms": elapsed_ms,
                "body": parsed,
            }

    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)

        try:
            parsed = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = body[:500]

        return {
            "ok": False,
            "status_code": exc.code,
            "elapsed_ms": elapsed_ms,
            "body": parsed,
        }

    except URLError as exc:
        elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)
        return {
            "ok": False,
            "status_code": None,
            "elapsed_ms": elapsed_ms,
            "body": str(exc.reason),
        }


def check_imports() -> list[dict[str, Any]]:
    checks = []

    for module_name in CORE_IMPORTS:
        try:
            importlib.import_module(module_name)
            checks.append(result(f"import:{module_name}", "PASS", "Module import succeeded."))

        except Exception as exc:
            checks.append(
                result(
                    f"import:{module_name}",
                    "FAIL",
                    "Module import failed.",
                    {
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
            )

    return checks


def check_database() -> list[dict[str, Any]]:
    checks = []

    try:
        from database import SessionLocal

        db = SessionLocal()

        try:
            db.execute(text("select 1")).scalar()
            checks.append(result("db:connectivity", "PASS", "Database connectivity OK."))

            rows = db.execute(
                text(
                    """
                    select table_name
                    from information_schema.tables
                    where table_schema = 'public'
                    """
                )
            ).fetchall()

            available = {row[0] for row in rows}
            missing = [table for table in REQUIRED_TABLES if table not in available]

            if missing:
                checks.append(
                    result(
                        "db:required_tables",
                        "FAIL",
                        "Missing required tables.",
                        {"missing_tables": missing},
                    )
                )
            else:
                checks.append(
                    result(
                        "db:required_tables",
                        "PASS",
                        "All required tables are present.",
                        {"tables": REQUIRED_TABLES},
                    )
                )

            count_rows = db.execute(
                text(
                    """
                    select 'raw_events' as table_name, count(*) from raw_events
                    union all
                    select 'security_alerts', count(*) from security_alerts
                    union all
                    select 'event_aggregates', count(*) from event_aggregates
                    union all
                    select 'incidents', count(*) from incidents
                    union all
                    select 'incident_cases', count(*) from incident_cases
                    """
                )
            ).fetchall()

            checks.append(
                result(
                    "db:core_counts",
                    "PASS",
                    "Core table counts collected.",
                    {"counts": {row[0]: int(row[1]) for row in count_rows}},
                )
            )

        finally:
            db.close()

    except Exception as exc:
        checks.append(
            result(
                "db:connectivity",
                "FAIL",
                "Database check failed.",
                {
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        )

    return checks


def check_http_endpoints() -> list[dict[str, Any]]:
    checks = []

    health = http_get("/health")

    if health["status_code"] == 200:
        checks.append(
            result(
                "http:/health",
                "PASS",
                "Public health endpoint returned HTTP 200.",
                health,
            )
        )
    else:
        checks.append(
            result(
                "http:/health",
                "FAIL",
                "Public health endpoint did not return HTTP 200.",
                health,
            )
        )

    platform_health = http_get("/platform/health", token=AUTH_TOKEN or None)

    if AUTH_TOKEN:
        if platform_health["status_code"] == 200:
            checks.append(
                result(
                    "http:/platform/health-authenticated",
                    "PASS",
                    "Authenticated platform health endpoint returned HTTP 200.",
                    platform_health,
                )
            )
        else:
            checks.append(
                result(
                    "http:/platform/health-authenticated",
                    "FAIL",
                    "Authenticated platform health endpoint did not return HTTP 200.",
                    platform_health,
                )
            )
    else:
        if platform_health["status_code"] in {401, 403}:
            checks.append(
                result(
                    "http:/platform/health-protection",
                    "PASS",
                    "Protected platform health endpoint rejects unauthenticated requests.",
                    platform_health,
                )
            )
        else:
            checks.append(
                result(
                    "http:/platform/health-protection",
                    "WARN",
                    "Protected platform health endpoint returned an unexpected unauthenticated status.",
                    platform_health,
                )
            )

    incidents = http_get("/incidents?page=1&limit=1", token=AUTH_TOKEN or None)

    if AUTH_TOKEN:
        expected = 200
        status = "PASS" if incidents["status_code"] == expected else "FAIL"
        message = "Authenticated incidents endpoint check completed."
    else:
        status = "PASS" if incidents["status_code"] in {401, 403} else "WARN"
        message = "Unauthenticated incidents endpoint protection check completed."

    checks.append(
        result(
            "http:/incidents",
            status,
            message,
            incidents,
        )
    )

    return checks


def check_retention_dry_run() -> list[dict[str, Any]]:
    checks = []

    command = [
        sys.executable,
        str(PROJECT_ROOT / "scripts" / "db_retention_cleanup.py"),
    ]

    try:
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

        details = {
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-2000:],
            "stderr_tail": completed.stderr[-2000:],
        }

        if completed.returncode == 0 and '"mode": "DRY_RUN"' in completed.stdout:
            checks.append(
                result(
                    "retention:dry_run",
                    "PASS",
                    "DB retention dry-run completed successfully.",
                    details,
                )
            )
        else:
            checks.append(
                result(
                    "retention:dry_run",
                    "FAIL",
                    "DB retention dry-run failed or did not report DRY_RUN mode.",
                    details,
                )
            )

    except Exception as exc:
        checks.append(
            result(
                "retention:dry_run",
                "FAIL",
                "DB retention dry-run execution failed.",
                {
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        )

    return checks


def summarize(checks: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "pass": sum(1 for item in checks if item["status"] == "PASS"),
        "warn": sum(1 for item in checks if item["status"] == "WARN"),
        "fail": sum(1 for item in checks if item["status"] == "FAIL"),
    }


def write_report(report: dict[str, Any]) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = REPORT_DIR / f"v0.4-smoke-validation-{timestamp}.json"

    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
    return path


def main() -> int:
    checks: list[dict[str, Any]] = []

    checks.extend(check_imports())
    checks.extend(check_database())
    checks.extend(check_http_endpoints())
    checks.extend(check_retention_dry_run())

    summary = summarize(checks)

    report = {
        "generated_at": utc_now(),
        "base_url": BASE_URL,
        "authenticated": bool(AUTH_TOKEN),
        "summary": summary,
        "checks": checks,
    }

    report_path = write_report(report)

    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    print(f"\nReport written to: {report_path}")

    return 1 if summary["fail"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
