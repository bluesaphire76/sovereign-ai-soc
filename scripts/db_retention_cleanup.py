from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import SessionLocal


DEFAULT_RAW_EVENTS_DAYS = int(os.getenv("RETENTION_RAW_EVENTS_DAYS", "90"))
DEFAULT_SECURITY_ALERTS_DAYS = int(os.getenv("RETENTION_SECURITY_ALERTS_DAYS", "180"))
DEFAULT_EVENT_AGGREGATES_DAYS = int(os.getenv("RETENTION_EVENT_AGGREGATES_DAYS", "90"))
DEFAULT_MAX_DELETE_ROWS = int(os.getenv("RETENTION_MAX_DELETE_ROWS", "10000"))
DEFAULT_REPORT_DIR = os.getenv("RETENTION_REPORT_DIR", "reports/retention")


RETENTION_TARGETS = {
    "raw_events": {
        "retention_arg": "raw_events_days",
        "cutoff_column": "created_at",
        "count_sql": """
            select count(*)
            from raw_events
            where created_at < :cutoff
              and not exists (
                select 1
                from incidents
                where incidents.raw_event_id = raw_events.id
              )
        """,
        "delete_sql": """
            delete from raw_events
            where created_at < :cutoff
              and not exists (
                select 1
                from incidents
                where incidents.raw_event_id = raw_events.id
              )
        """,
        "reason": "Raw Wazuh event records not linked to incidents.",
    },
    "security_alerts": {
        "retention_arg": "security_alerts_days",
        "cutoff_column": "created_at",
        "count_sql": """
            select count(*)
            from security_alerts
            where created_at < :cutoff
              and not exists (
                select 1
                from incidents
                where incidents.security_alert_id = security_alerts.id
              )
        """,
        "delete_sql": """
            delete from security_alerts
            where created_at < :cutoff
              and not exists (
                select 1
                from incidents
                where incidents.security_alert_id = security_alerts.id
              )
        """,
        "reason": "Normalized security alerts not linked to incidents.",
    },
    "event_aggregates": {
        "retention_arg": "event_aggregates_days",
        "cutoff_column": "updated_at",
        "count_sql": """
            select count(*)
            from event_aggregates
            where coalesce(updated_at, created_at) < :cutoff
        """,
        "delete_sql": """
            delete from event_aggregates
            where coalesce(updated_at, created_at) < :cutoff
        """,
        "reason": "Operational deduplication aggregates outside the active retention window.",
    },
}


PROTECTED_TABLES = [
    "incidents",
    "incident_cases",
    "case_incidents",
    "incident_audit",
    "incident_notes",
    "case_audit",
    "case_actions",
    "case_closure_checklists",
    "case_ai_analyses",
    "security_audit_events",
    "app_users",
    "wazuh_ingest_watermarks",
    "worker_heartbeats",
]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Dry-run by default DB retention cleanup for Sovereign AI SOC. "
            "Only raw/operational tables are targeted. Investigation and audit tables are protected."
        )
    )

    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete eligible rows. Without this flag the script only reports candidates.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow apply even when candidate rows exceed RETENTION_MAX_DELETE_ROWS.",
    )
    parser.add_argument(
        "--raw-events-days",
        type=int,
        default=DEFAULT_RAW_EVENTS_DAYS,
        help=f"Retention window for raw_events. Default: {DEFAULT_RAW_EVENTS_DAYS}",
    )
    parser.add_argument(
        "--security-alerts-days",
        type=int,
        default=DEFAULT_SECURITY_ALERTS_DAYS,
        help=f"Retention window for security_alerts. Default: {DEFAULT_SECURITY_ALERTS_DAYS}",
    )
    parser.add_argument(
        "--event-aggregates-days",
        type=int,
        default=DEFAULT_EVENT_AGGREGATES_DAYS,
        help=f"Retention window for event_aggregates. Default: {DEFAULT_EVENT_AGGREGATES_DAYS}",
    )
    parser.add_argument(
        "--max-delete-rows",
        type=int,
        default=DEFAULT_MAX_DELETE_ROWS,
        help=f"Safety threshold for apply mode. Default: {DEFAULT_MAX_DELETE_ROWS}",
    )
    parser.add_argument(
        "--report-dir",
        default=DEFAULT_REPORT_DIR,
        help=f"Directory for retention reports. Default: {DEFAULT_REPORT_DIR}",
    )

    return parser.parse_args()


def retention_days(args: argparse.Namespace, target: dict[str, Any]) -> int:
    return int(getattr(args, target["retention_arg"]))


def cutoff_for_days(days: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


def scalar_int(db, sql: str, params: dict[str, Any] | None = None) -> int:
    return int(db.execute(text(sql), params or {}).scalar() or 0)


def run_target(db, name: str, target: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    days = retention_days(args, target)

    result: dict[str, Any] = {
        "table": name,
        "reason": target["reason"],
        "retention_days": days,
        "cutoff_column": target["cutoff_column"],
        "mode": "APPLY" if args.apply else "DRY_RUN",
        "candidate_rows": 0,
        "deleted_rows": 0,
        "skipped": False,
        "skip_reason": None,
    }

    if days <= 0:
        result["skipped"] = True
        result["skip_reason"] = "Retention days must be greater than zero."
        return result

    cutoff = cutoff_for_days(days)
    result["cutoff_utc"] = cutoff.isoformat()

    candidate_rows = scalar_int(db, target["count_sql"], {"cutoff": cutoff})
    result["candidate_rows"] = candidate_rows

    if not args.apply:
        return result

    if candidate_rows > args.max_delete_rows and not args.force:
        result["skipped"] = True
        result["skip_reason"] = (
            f"Candidate rows {candidate_rows} exceed max delete threshold "
            f"{args.max_delete_rows}. Re-run with --force only after manual review."
        )
        return result

    delete_result = db.execute(text(target["delete_sql"]), {"cutoff": cutoff})
    result["deleted_rows"] = int(delete_result.rowcount or 0)

    return result


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total_candidate_rows": sum(item.get("candidate_rows", 0) for item in results),
        "total_deleted_rows": sum(item.get("deleted_rows", 0) for item in results),
        "skipped_targets": [
            {
                "table": item["table"],
                "reason": item.get("skip_reason"),
            }
            for item in results
            if item.get("skipped")
        ],
    }


def write_report(report: dict[str, Any], report_dir: str) -> Path:
    out_dir = Path(report_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    mode = "apply" if report["mode"] == "APPLY" else "dry-run"
    path = out_dir / f"db-retention-{mode}-{timestamp}.json"

    path.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n")
    return path


def main() -> None:
    args = parse_args()

    report: dict[str, Any] = {
        "generated_at": utc_now_iso(),
        "mode": "APPLY" if args.apply else "DRY_RUN",
        "safety": {
            "dry_run_by_default": True,
            "apply_requires_flag": "--apply",
            "force_threshold_flag": "--force",
            "max_delete_rows": args.max_delete_rows,
            "protected_tables": PROTECTED_TABLES,
            "linked_raw_and_alert_rows_are_preserved": True,
        },
        "retention_policy": {
            "raw_events_days": args.raw_events_days,
            "security_alerts_days": args.security_alerts_days,
            "event_aggregates_days": args.event_aggregates_days,
        },
        "targets": [],
    }

    db = SessionLocal()

    try:
        for name, target in RETENTION_TARGETS.items():
            report["targets"].append(run_target(db, name, target, args))

        report["summary"] = build_summary(report["targets"])

        if args.apply:
            db.commit()
        else:
            db.rollback()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()

    report_path = write_report(report, args.report_dir)

    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    print(f"\nReport written to: {report_path}")


if __name__ == "__main__":
    main()
