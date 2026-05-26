from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text

from database import engine


REPORT_DIR = Path("reports/backfill")


SENSITIVE_EXACT = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/ssh",
    "/usr/sbin/sshd",
    "/usr/bin/systemctl",
}

SENSITIVE_PREFIXES = (
    "/etc/ssh/",
    "/etc/pam.d/",
    "/etc/sudoers.d/",
    "/etc/cron.",
    "/etc/cron/",
    "/var/spool/cron/",
    "/root/.ssh/",
    "/home/",
    "/etc/systemd/system/",
    "/lib/systemd/system/",
)

SENSITIVE_FRAGMENTS = (
    "authorized_keys",
    "id_rsa",
    "id_ed25519",
    "known_hosts",
)

PACKAGE_MANAGED_PREFIXES = (
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/libexec/",
    "/usr/share/",
    "/lib/",
    "/lib64/",
    "/bin/",
    "/sbin/",
)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def parse_json(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value

    if not isinstance(value, str):
        return value

    try:
        return json.loads(value)
    except Exception:
        return value


def get_syscheck(payload: Any) -> dict[str, Any]:
    payload = parse_json(payload)

    if not isinstance(payload, dict):
        return {}

    syscheck = payload.get("syscheck")
    if isinstance(syscheck, dict):
        return syscheck

    data = payload.get("data")
    if isinstance(data, dict) and isinstance(data.get("syscheck"), dict):
        return data["syscheck"]

    return {}


def is_sensitive_path(path: str | None) -> bool:
    normalized = str(path or "").strip().lower()

    if not normalized:
        return True

    if normalized in SENSITIVE_EXACT:
        return True

    if any(normalized.startswith(prefix) for prefix in SENSITIVE_PREFIXES):
        return True

    return any(fragment in normalized for fragment in SENSITIVE_FRAGMENTS)


def is_package_managed_path(path: str | None) -> bool:
    normalized = str(path or "").strip().lower()

    return any(normalized.startswith(prefix) for prefix in PACKAGE_MANAGED_PREFIXES)


def is_candidate(row: dict[str, Any]) -> tuple[bool, str, str]:
    payload = parse_json(row.get("raw_alert"))
    syscheck = get_syscheck(payload)

    path = str(syscheck.get("path") or "").strip()
    mode = str(syscheck.get("mode") or "").strip().lower()
    event = str(syscheck.get("event") or "").strip().lower()

    if mode != "scheduled":
        return False, path, "syscheck_mode_not_scheduled"

    if event and event != "modified":
        return False, path, "syscheck_event_not_modified"

    if not is_package_managed_path(path):
        return False, path, "path_not_package_managed"

    if is_sensitive_path(path):
        return False, path, "path_is_security_sensitive"

    return True, path, "package_update_file_integrity_context"


def parse_incident_ids(raw: str | None) -> list[int]:
    if not raw:
        return []

    result = []
    for item in raw.split(","):
        item = item.strip()
        if item:
            result.append(int(item))

    return result


def load_candidates(
    only_new: bool,
    agent: str | None,
    incident_ids: list[int],
) -> list[dict[str, Any]]:
    conditions = [
        "i.rule ilike '%Integrity checksum changed%'",
    ]
    params: dict[str, Any] = {}

    if only_new:
        conditions.append("coalesce(i.status, '') = 'NEW'")

    if agent:
        conditions.append("i.agent = :agent")
        params["agent"] = agent

    if incident_ids:
        conditions.append("i.id = any(:incident_ids)")
        params["incident_ids"] = incident_ids

    where_clause = " AND ".join(conditions)

    query = text(f"""
        select
            i.id as incident_id,
            i.timestamp,
            i.agent,
            i.rule,
            i.risk_score,
            i.correlation_score,
            i.status as incident_status,
            i.recommended_priority,
            i.correlation_type,
            i.security_alert_id,
            i.raw_alert,
            sa.rule_id as security_alert_rule_id,
            sa.rule_description as security_alert_rule_description,
            sa.status as security_alert_status,
            sa.created_at as security_alert_created_at
        from incidents i
        left join security_alerts sa
          on sa.id = i.security_alert_id
        where {where_clause}
        order by i.id asc
    """)

    with engine.begin() as conn:
        rows = conn.execute(query, params).mappings().all()

    candidates: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        include, syscheck_path, candidate_reason = is_candidate(item)
        item["syscheck_path"] = syscheck_path
        item["candidate_reason"] = candidate_reason

        if include:
            candidates.append(item)

    return candidates


def write_report(rows: list[dict[str, Any]], apply: bool) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    mode = "apply" if apply else "dry_run"
    path = REPORT_DIR / f"v0.6.0-package-update-fim-backfill-{mode}-{utc_stamp()}.csv"

    fieldnames = [
        "incident_id",
        "timestamp",
        "agent",
        "rule",
        "syscheck_path",
        "candidate_reason",
        "risk_score",
        "correlation_score",
        "incident_status",
        "recommended_priority",
        "correlation_type",
        "security_alert_id",
        "security_alert_rule_id",
        "security_alert_status",
        "planned_incident_status",
        "planned_risk_score",
        "planned_correlation_score",
        "planned_recommended_priority",
        "planned_correlation_type",
        "planned_security_alert_status",
    ]

    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for row in rows:
            output = {key: row.get(key) for key in fieldnames}
            output["planned_incident_status"] = "FALSE_POSITIVE"
            output["planned_risk_score"] = 10
            output["planned_correlation_score"] = 0
            output["planned_recommended_priority"] = "INFORMATIONAL"
            output["planned_correlation_type"] = "package_update_file_integrity_context"
            output["planned_security_alert_status"] = "SUPPRESSED_NOISE"
            writer.writerow(output)

    return path


def apply_backfill(rows: list[dict[str, Any]]) -> dict[str, int]:
    incident_ids = [row["incident_id"] for row in rows]
    security_alert_ids = [
        row["security_alert_id"]
        for row in rows
        if row.get("security_alert_id") is not None
    ]

    if not incident_ids:
        return {"incidents_updated": 0, "security_alerts_updated": 0}

    note = (
        "Backfilled as package update file integrity context. "
        "The FIM change affected a package-managed runtime path and is preserved "
        "as raw/security telemetry, but it should not remain an open SOC incident "
        "without explicit malicious context."
    )

    with engine.begin() as conn:
        incident_result = conn.execute(
            text("""
                update incidents
                set
                    status = 'FALSE_POSITIVE',
                    risk_score = 10,
                    correlation_score = 0,
                    recommended_priority = 'INFORMATIONAL',
                    correlation_type = 'package_update_file_integrity_context',
                    escalation_reason = :note
                where id = any(:incident_ids)
            """),
            {
                "incident_ids": incident_ids,
                "note": note,
            },
        )

        security_alert_count = 0
        if security_alert_ids:
            security_alert_result = conn.execute(
                text("""
                    update security_alerts
                    set
                        status = 'SUPPRESSED_NOISE',
                        updated_at = now()
                    where id = any(:security_alert_ids)
                      and (
                          rule_id = '550'
                          or rule_description ilike '%Integrity checksum changed%'
                      )
                """),
                {"security_alert_ids": security_alert_ids},
            )
            security_alert_count = security_alert_result.rowcount or 0

    return {
        "incidents_updated": incident_result.rowcount or 0,
        "security_alerts_updated": security_alert_count,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Backfill package-update FIM incidents created before maintenance-aware suppression."
    )
    parser.add_argument("--agent", default=None)
    parser.add_argument("--incident-ids", default=None, help="Comma-separated incident IDs, e.g. 5016,5017,5018")
    parser.add_argument("--include-non-new", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    rows = load_candidates(
        only_new=not args.include_non_new,
        agent=args.agent,
        incident_ids=parse_incident_ids(args.incident_ids),
    )

    report_path = write_report(rows, apply=args.apply)

    print(f"candidates: {len(rows)}")
    print(f"report: {report_path}")

    if rows:
        print("\nfirst candidates:")
        for row in rows[:50]:
            print(
                row["incident_id"],
                row["timestamp"],
                row["agent"],
                row["rule"],
                row["syscheck_path"],
                row["risk_score"],
                row["incident_status"],
                "security_alert_status=",
                row["security_alert_status"],
            )

    if not args.apply:
        print("\nDRY RUN ONLY. Re-run with --apply to update records.")
        return

    result = apply_backfill(rows)
    print("\napplied:")
    for key, value in result.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    main()
