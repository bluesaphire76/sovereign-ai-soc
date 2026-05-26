from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from database import engine


REPORT_DIR = Path("reports/backfill")

LEGACY_CORRELATION_TYPES = [
    "RECON_TO_AUTH_CHAIN",
    "POSSIBLE_HOST_COMPROMISE",
    "POSSIBLE_PERSISTENCE",
]

CUTOFF = "2026-05-18T00:00:00Z"


def stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def load_candidates() -> list[dict]:
    query = text("""
        select
            i.id,
            i.timestamp,
            i.agent,
            i.rule,
            i.level,
            i.risk_score,
            i.correlation_score,
            i.correlation_type,
            i.recommended_priority,
            i.status
        from incidents i
        where i.status = 'ESCALATED'
          and i.correlation_type = any(:legacy_types)
          and i.timestamp::timestamptz < cast(:cutoff as timestamptz)
          and not exists (
              select 1
              from case_incidents ci
              join incident_cases c on c.id = ci.case_id
              where ci.incident_id = i.id
                and upper(coalesce(c.status, '')) not in ('CLOSED', 'FALSE_POSITIVE')
          )
        order by i.id asc
    """)

    with engine.begin() as conn:
        return [
            dict(row)
            for row in conn.execute(
                query,
                {"legacy_types": LEGACY_CORRELATION_TYPES, "cutoff": CUTOFF},
            ).mappings().all()
        ]


def write_report(rows: list[dict], apply: bool) -> Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    mode = "apply" if apply else "dry_run"
    path = REPORT_DIR / f"v0.6.0-legacy-escalated-normalization-{mode}-{stamp()}.csv"

    fields = [
        "id",
        "timestamp",
        "agent",
        "rule",
        "level",
        "status",
        "risk_score",
        "correlation_score",
        "correlation_type",
        "recommended_priority",
        "planned_status",
        "planned_risk_score",
        "planned_correlation_score",
        "planned_correlation_type",
        "planned_recommended_priority",
    ]

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()

        for row in rows:
            output = {field: row.get(field) for field in fields}
            output["planned_status"] = "TRIAGED"
            output["planned_risk_score"] = 35
            output["planned_correlation_score"] = 35
            output["planned_correlation_type"] = "LEGACY_ESCALATION_NORMALIZED"
            output["planned_recommended_priority"] = "LOW"
            writer.writerow(output)

    return path


def apply_backfill(rows: list[dict]) -> int:
    ids = [row["id"] for row in rows]

    if not ids:
        return 0

    note = (
        "Backfilled as legacy escalation normalization. "
        "This incident was created by early project correlation logic before the current "
        "triage, noise suppression, risk normalization and lifecycle governance were introduced. "
        "No active linked case was found during the controlled backfill. "
        "The event remains preserved for audit/history but no longer requires executive escalation."
    )

    with engine.begin() as conn:
        result = conn.execute(
            text("""
                update incidents
                set
                    status = 'TRIAGED',
                    risk_score = 35,
                    correlation_score = 35,
                    recommended_priority = 'LOW',
                    correlation_type = 'LEGACY_ESCALATION_NORMALIZED',
                    escalation_reason = :note
                where id = any(:ids)
            """),
            {"ids": ids, "note": note},
        )

    return result.rowcount or 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize legacy ESCALATED incidents created by early correlation logic."
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    rows = load_candidates()
    report_path = write_report(rows, apply=args.apply)

    print("candidates:", len(rows))
    print("report:", report_path)

    print("\nfirst candidates:")
    for row in rows[:120]:
        print(
            row["id"],
            row["timestamp"],
            row["agent"],
            row["rule"],
            row["risk_score"],
            row["correlation_score"],
            row["correlation_type"],
        )

    if not args.apply:
        print("\nDRY RUN ONLY. Re-run with --apply to update records.")
        return

    print("\nupdated:", apply_backfill(rows))


if __name__ == "__main__":
    main()
