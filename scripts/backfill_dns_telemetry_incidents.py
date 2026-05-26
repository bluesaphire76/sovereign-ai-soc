from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from database import engine


REPORT_DIR = Path("reports/backfill")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_candidates(only_new: bool, agent: str | None) -> list[dict]:
    conditions = [
        "i.rule ilike 'AI SOC DNS telemetry query:%'",
    ]
    params: dict = {}

    if only_new:
        conditions.append("coalesce(i.status, '') = 'NEW'")

    if agent:
        conditions.append("i.agent = :agent")
        params["agent"] = agent

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

    return [dict(row) for row in rows]


def write_report(rows: list[dict], apply: bool) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    mode = "apply" if apply else "dry_run"
    path = REPORT_DIR / f"v0.6.0-dns-telemetry-incident-backfill-{mode}-{utc_stamp()}.csv"

    fieldnames = [
        "incident_id",
        "timestamp",
        "agent",
        "rule",
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
            output["planned_risk_score"] = 5
            output["planned_correlation_score"] = 0
            output["planned_recommended_priority"] = "INFORMATIONAL"
            output["planned_correlation_type"] = "dns_telemetry_context"
            output["planned_security_alert_status"] = "SUPPRESSED_NOISE"
            writer.writerow(output)

    return path


def apply_backfill(rows: list[dict]) -> dict[str, int]:
    incident_ids = [row["incident_id"] for row in rows]
    security_alert_ids = [
        row["security_alert_id"]
        for row in rows
        if row.get("security_alert_id") is not None
    ]

    if not incident_ids:
        return {"incidents_updated": 0, "security_alerts_updated": 0}

    note = (
        "Backfilled as DNS telemetry context. "
        "AI SOC DNS telemetry queries are preserved as raw/security telemetry "
        "and normalized dns_events, but normal DNS queries should not create "
        "SOC incidents without explicit malicious detection context."
    )

    with engine.begin() as conn:
        incident_result = conn.execute(
            text("""
                update incidents
                set
                    status = 'FALSE_POSITIVE',
                    risk_score = 5,
                    correlation_score = 0,
                    recommended_priority = 'INFORMATIONAL',
                    correlation_type = 'dns_telemetry_context',
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
                          rule_id = '100510'
                          or rule_description ilike 'AI SOC DNS telemetry query:%'
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
        description="Backfill DNS telemetry incidents created before suppression policy."
    )
    parser.add_argument("--agent", default="atomicstar")
    parser.add_argument("--include-non-new", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    rows = load_candidates(
        only_new=not args.include_non_new,
        agent=args.agent,
    )

    report_path = write_report(rows, apply=args.apply)

    print(f"candidates: {len(rows)}")
    print(f"report: {report_path}")

    if rows:
        print("\nfirst candidates:")
        for row in rows[:30]:
            print(
                row["incident_id"],
                row["timestamp"],
                row["agent"],
                row["rule"],
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
