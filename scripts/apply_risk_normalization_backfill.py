import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import SessionLocal
from models import CaseIncident, Incident, IncidentAudit, IncidentCase, utc_now
from risk_normalization import (
    normalize_correlation_score,
    severity_from_score,
    should_auto_escalate,
)


TERMINAL_STATUSES = {"CLOSED", "FALSE_POSITIVE"}


def safe_json(value):
    if not value:
        return {}

    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def safe_int(value, default=0):
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def utc_label():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def short(value, length=140):
    text = str(value or "")
    if len(text) <= length:
        return text
    return text[: length - 1] + "…"


def load_candidate_incidents(
    db,
    *,
    include_closed: bool,
    include_attack_chain: bool,
    limit: int | None,
):
    query = (
        db.query(Incident)
        .filter(Incident.correlated == True)
        .order_by(Incident.id.asc())
    )

    if not include_closed:
        query = query.filter(
            Incident.status.notin_(TERMINAL_STATUSES)
        )

    if limit:
        query = query.limit(limit)

    candidates = []

    for incident in query.all():
        summary = safe_json(incident.correlation_summary)
        matched_chains = summary.get("matched_attack_chains") or []

        if matched_chains and not include_attack_chain:
            continue

        candidates.append(incident)

    return candidates


def recalculate_incident(
    incident: Incident,
    *,
    update_status: bool,
) -> dict:
    summary = safe_json(incident.correlation_summary)
    matched_chains = summary.get("matched_attack_chains") or []

    normalized = normalize_correlation_score(
        level=incident.level,
        pattern_score=summary.get("pattern_score"),
        volume_score=summary.get("volume_score"),
        aggregate_score=0,
        chain_bonus=summary.get("chain_bonus"),
        matched_chains=matched_chains,
    )

    old_status = incident.status or "NEW"
    new_status = old_status

    if update_status:
        if should_auto_escalate(
            score=normalized["final_score"],
            matched_chains=matched_chains,
        ):
            if new_status in {"NEW", "TRIAGED"}:
                new_status = "ESCALATED"
        elif new_status == "ESCALATED":
            new_status = "TRIAGED"

    old_values = {
        "risk_score": incident.risk_score,
        "correlation_score": incident.correlation_score,
        "recommended_priority": incident.recommended_priority,
        "status": old_status,
    }

    new_values = {
        "risk_score": normalized["final_score"],
        "correlation_score": normalized["final_score"],
        "recommended_priority": normalized["recommended_priority"],
        "status": new_status,
    }

    changed_fields = [
        key for key in old_values
        if old_values.get(key) != new_values.get(key)
    ]

    return {
        "id": incident.id,
        "agent": incident.agent,
        "rule": incident.rule,
        "level": incident.level,
        "old_values": old_values,
        "new_values": new_values,
        "changed_fields": changed_fields,
        "matched_chain_count": normalized["matched_chain_count"],
        "cap": normalized["cap"],
        "normalization": normalized,
    }


def build_case_status_from_incident_statuses(
    current_status: str | None,
    incident_statuses: list[str],
) -> str:
    current = current_status or "OPEN"

    if current in TERMINAL_STATUSES:
        return current

    statuses = {status or "NEW" for status in incident_statuses}

    if "ESCALATED" in statuses:
        return "ESCALATED"

    if current == "ESCALATED":
        return "TRIAGED"

    return current


def recalculate_case(
    case: IncidentCase,
    linked_incidents: list[Incident],
    incident_changes_by_id: dict[int, dict],
    *,
    update_case_status: bool,
) -> dict:
    old_values = {
        "risk_score": case.risk_score,
        "severity": case.severity,
        "status": case.status or "OPEN",
    }

    projected_risks = []
    projected_statuses = []

    for incident in linked_incidents:
        change = incident_changes_by_id.get(incident.id)

        if change:
            projected_risks.append(
                safe_int(change["new_values"].get("risk_score"))
            )
            projected_statuses.append(
                change["new_values"].get("status") or incident.status or "NEW"
            )
        else:
            projected_risks.append(safe_int(incident.risk_score))
            projected_statuses.append(incident.status or "NEW")

    new_risk = max(projected_risks, default=0)
    new_severity = severity_from_score(new_risk)

    if update_case_status:
        new_status = build_case_status_from_incident_statuses(
            current_status=case.status,
            incident_statuses=projected_statuses,
        )
    else:
        new_status = case.status or "OPEN"

    new_values = {
        "risk_score": new_risk,
        "severity": new_severity,
        "status": new_status,
    }

    changed_fields = [
        key for key in old_values
        if old_values.get(key) != new_values.get(key)
    ]

    return {
        "id": case.id,
        "title": case.title,
        "old_values": old_values,
        "new_values": new_values,
        "changed_fields": changed_fields,
        "linked_incident_count": len(linked_incidents),
    }


def collect_case_changes(
    db,
    incident_changes: list[dict],
    *,
    include_closed: bool,
    update_case_status: bool,
):
    changed_incident_ids = [item["id"] for item in incident_changes]

    if not changed_incident_ids:
        return []

    linked_case_ids = {
        row.case_id
        for row in db.query(CaseIncident)
        .filter(CaseIncident.incident_id.in_(changed_incident_ids))
        .all()
    }

    if not linked_case_ids:
        return []

    incident_changes_by_id = {
        item["id"]: item
        for item in incident_changes
    }

    case_changes = []

    for case_id in sorted(linked_case_ids):
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            continue

        if not include_closed and (case.status or "OPEN") in TERMINAL_STATUSES:
            continue

        linked_rows = (
            db.query(CaseIncident)
            .filter(CaseIncident.case_id == case.id)
            .all()
        )

        linked_ids = [row.incident_id for row in linked_rows]

        linked_incidents = (
            db.query(Incident)
            .filter(Incident.id.in_(linked_ids))
            .all()
        )

        item = recalculate_case(
            case,
            linked_incidents,
            incident_changes_by_id,
            update_case_status=update_case_status,
        )

        if item["changed_fields"]:
            case_changes.append(item)

    return case_changes


def write_incident_csv(path: Path, changes: list[dict]):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "id",
                "agent",
                "level",
                "old_risk_score",
                "new_risk_score",
                "old_correlation_score",
                "new_correlation_score",
                "old_priority",
                "new_priority",
                "old_status",
                "new_status",
                "changed_fields",
                "matched_chain_count",
                "cap",
                "rule",
            ],
        )
        writer.writeheader()

        for item in changes:
            writer.writerow(
                {
                    "id": item["id"],
                    "agent": item["agent"],
                    "level": item["level"],
                    "old_risk_score": item["old_values"]["risk_score"],
                    "new_risk_score": item["new_values"]["risk_score"],
                    "old_correlation_score": item["old_values"]["correlation_score"],
                    "new_correlation_score": item["new_values"]["correlation_score"],
                    "old_priority": item["old_values"]["recommended_priority"],
                    "new_priority": item["new_values"]["recommended_priority"],
                    "old_status": item["old_values"]["status"],
                    "new_status": item["new_values"]["status"],
                    "changed_fields": ",".join(item["changed_fields"]),
                    "matched_chain_count": item["matched_chain_count"],
                    "cap": item["cap"],
                    "rule": item["rule"],
                }
            )


def write_case_csv(path: Path, changes: list[dict]):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "id",
                "title",
                "old_risk_score",
                "new_risk_score",
                "old_severity",
                "new_severity",
                "old_status",
                "new_status",
                "changed_fields",
                "linked_incident_count",
            ],
        )
        writer.writeheader()

        for item in changes:
            writer.writerow(
                {
                    "id": item["id"],
                    "title": item["title"],
                    "old_risk_score": item["old_values"]["risk_score"],
                    "new_risk_score": item["new_values"]["risk_score"],
                    "old_severity": item["old_values"]["severity"],
                    "new_severity": item["new_values"]["severity"],
                    "old_status": item["old_values"]["status"],
                    "new_status": item["new_values"]["status"],
                    "changed_fields": ",".join(item["changed_fields"]),
                    "linked_incident_count": item["linked_incident_count"],
                }
            )


def apply_incident_change(db, item: dict):
    incident = (
        db.query(Incident)
        .filter(Incident.id == item["id"])
        .first()
    )

    if not incident:
        return

    old_values = item["old_values"]
    new_values = item["new_values"]

    incident.risk_score = new_values["risk_score"]
    incident.correlation_score = new_values["correlation_score"]
    incident.recommended_priority = new_values["recommended_priority"]
    incident.status = new_values["status"]

    summary = safe_json(incident.correlation_summary)
    summary["historical_risk_normalization_backfill"] = {
        "applied_at": utc_now().isoformat(),
        "policy": "v0.4_controlled_risk_backfill",
        "old_values": old_values,
        "new_values": new_values,
        "normalization": item["normalization"],
    }
    incident.correlation_summary = json.dumps(summary, ensure_ascii=False)

    db.add(
        IncidentAudit(
            incident_id=incident.id,
            event_type="RISK_NORMALIZATION_BACKFILL",
            old_value=json.dumps(old_values, ensure_ascii=False),
            new_value=json.dumps(new_values, ensure_ascii=False),
            comment=(
                "Historical v0.4 risk normalization backfill. "
                f"Changed fields: {', '.join(item['changed_fields'])}"
            ),
            created_by="system",
        )
    )


def apply_case_change(db, item: dict, *, update_case_status: bool):
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == item["id"])
        .first()
    )

    if not case:
        return

    new_values = item["new_values"]

    case.risk_score = new_values["risk_score"]
    case.severity = new_values["severity"]

    if update_case_status:
        case.status = new_values["status"]

    case.updated_at = utc_now()


def print_distribution(label: str, values):
    counter = Counter(values)
    print(label)

    if not counter:
        print("  none")
        return

    for key, value in counter.most_common():
        print(f"  {key}: {value}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Controlled historical backfill for v0.4 risk normalization. "
            "Dry-run by default. Use --apply to modify data."
        )
    )
    parser.add_argument("--apply", action="store_true", help="Apply changes to the database.")
    parser.add_argument("--limit", type=int, default=None, help="Limit evaluated incidents.")
    parser.add_argument(
        "--include-closed",
        action="store_true",
        help="Include CLOSED and FALSE_POSITIVE incidents/cases.",
    )
    parser.add_argument(
        "--include-attack-chain",
        action="store_true",
        help="Include incidents with matched attack chains.",
    )
    parser.add_argument(
        "--update-status",
        action="store_true",
        help="Update incident status when normalization removes auto-escalation.",
    )
    parser.add_argument(
        "--update-cases",
        action="store_true",
        help="Update linked case risk_score and severity.",
    )
    parser.add_argument(
        "--update-case-status",
        action="store_true",
        help="Also update linked case status. Requires --update-cases.",
    )
    parser.add_argument(
        "--output-dir",
        default="reports/backfill",
        help="Directory for CSV/JSON exports.",
    )

    args = parser.parse_args()

    if args.update_case_status and not args.update_cases:
        parser.error("--update-case-status requires --update-cases")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    run_id = utc_label()

    db = SessionLocal()

    try:
        candidates = load_candidate_incidents(
            db,
            include_closed=args.include_closed,
            include_attack_chain=args.include_attack_chain,
            limit=args.limit,
        )

        incident_changes = []

        for incident in candidates:
            item = recalculate_incident(
                incident,
                update_status=args.update_status,
            )

            if item["changed_fields"]:
                incident_changes.append(item)

        case_changes = []

        if args.update_cases:
            case_changes = collect_case_changes(
                db,
                incident_changes,
                include_closed=args.include_closed,
                update_case_status=args.update_case_status,
            )

        incident_csv = output_dir / f"risk-backfill-incidents-{run_id}.csv"
        case_csv = output_dir / f"risk-backfill-cases-{run_id}.csv"
        summary_json = output_dir / f"risk-backfill-summary-{run_id}.json"

        write_incident_csv(incident_csv, incident_changes)
        write_case_csv(case_csv, case_changes)

        summary = {
            "run_id": run_id,
            "mode": "APPLY" if args.apply else "DRY_RUN",
            "options": {
                "include_closed": args.include_closed,
                "include_attack_chain": args.include_attack_chain,
                "update_status": args.update_status,
                "update_cases": args.update_cases,
                "update_case_status": args.update_case_status,
                "limit": args.limit,
            },
            "candidate_incidents": len(candidates),
            "incident_changes": len(incident_changes),
            "case_changes": len(case_changes),
            "exports": {
                "incident_csv": str(incident_csv),
                "case_csv": str(case_csv),
                "summary_json": str(summary_json),
            },
            "incident_old_priority": Counter(
                item["old_values"]["recommended_priority"] or "NULL"
                for item in incident_changes
            ),
            "incident_new_priority": Counter(
                item["new_values"]["recommended_priority"] or "NULL"
                for item in incident_changes
            ),
            "incident_old_status": Counter(
                item["old_values"]["status"] or "NULL"
                for item in incident_changes
            ),
            "incident_new_status": Counter(
                item["new_values"]["status"] or "NULL"
                for item in incident_changes
            ),
            "case_old_severity": Counter(
                item["old_values"]["severity"] or "NULL"
                for item in case_changes
            ),
            "case_new_severity": Counter(
                item["new_values"]["severity"] or "NULL"
                for item in case_changes
            ),
        }

        with summary_json.open("w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, ensure_ascii=False, default=dict)

        print("=== Controlled risk normalization backfill ===")
        print(f"Mode: {'APPLY' if args.apply else 'DRY_RUN'}")
        print(f"Candidate incidents evaluated: {len(candidates)}")
        print(f"Incident changes: {len(incident_changes)}")
        print(f"Case changes: {len(case_changes)}")
        print(f"Incident CSV: {incident_csv}")
        print(f"Case CSV: {case_csv}")
        print(f"Summary JSON: {summary_json}")

        print_distribution(
            "\nIncident old priority:",
            [item["old_values"]["recommended_priority"] or "NULL" for item in incident_changes],
        )
        print_distribution(
            "\nIncident new priority:",
            [item["new_values"]["recommended_priority"] or "NULL" for item in incident_changes],
        )
        print_distribution(
            "\nIncident old status:",
            [item["old_values"]["status"] or "NULL" for item in incident_changes],
        )
        print_distribution(
            "\nIncident new status:",
            [item["new_values"]["status"] or "NULL" for item in incident_changes],
        )
        print_distribution(
            "\nCase old severity:",
            [item["old_values"]["severity"] or "NULL" for item in case_changes],
        )
        print_distribution(
            "\nCase new severity:",
            [item["new_values"]["severity"] or "NULL" for item in case_changes],
        )

        print("\nSample incident changes:")
        for item in incident_changes[:20]:
            print(
                {
                    "id": item["id"],
                    "level": item["level"],
                    "old": item["old_values"],
                    "new": item["new_values"],
                    "matched_chain_count": item["matched_chain_count"],
                    "cap": item["cap"],
                    "rule": short(item["rule"], 90),
                }
            )

        print("\nSample case changes:")
        for item in case_changes[:20]:
            print(
                {
                    "id": item["id"],
                    "old": item["old_values"],
                    "new": item["new_values"],
                    "linked_incident_count": item["linked_incident_count"],
                    "title": short(item["title"], 90),
                }
            )

        if args.apply:
            for item in incident_changes:
                apply_incident_change(db, item)

            if args.update_cases:
                for item in case_changes:
                    apply_case_change(
                        db,
                        item,
                        update_case_status=args.update_case_status,
                    )

            db.commit()
            print("\nApplied successfully.")
        else:
            db.rollback()
            print("\nDry-run only. No database changes applied.")

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


if __name__ == "__main__":
    main()
