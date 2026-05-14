import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import SessionLocal
from models import CaseIncident, Incident, IncidentCase, utc_now


def severity_from_score(score: int | None) -> str:
    value = score or 0

    if value >= 85:
        return "CRITICAL"
    if value >= 65:
        return "HIGH"
    if value >= 35:
        return "MEDIUM"
    return "LOW"


def case_status_from_incidents(incidents: list[Incident]) -> str:
    statuses = {incident.status or "NEW" for incident in incidents}

    if "ESCALATED" in statuses:
        return "ESCALATED"

    if statuses and statuses.issubset({"CLOSED", "FALSE_POSITIVE"}):
        return "CLOSED"

    if "TRIAGED" in statuses:
        return "TRIAGED"

    return "OPEN"


def event_day(timestamp: str | None) -> str:
    if not timestamp:
        return "unknown-date"

    return timestamp[:10]


def normalize_group_value(value: str | None, fallback: str) -> str:
    cleaned = (value or "").strip()

    if not cleaned:
        return fallback

    return cleaned


def build_group_key(incident: Incident) -> str:
    agent = normalize_group_value(incident.agent, "unknown-agent")
    correlation_type = normalize_group_value(
        incident.correlation_type,
        "UNCLASSIFIED_CORRELATION",
    )
    day = event_day(incident.timestamp)

    return f"{agent}|{correlation_type}|{day}"


def load_candidate_incidents(db, limit: int | None) -> list[Incident]:
    query = (
        db.query(Incident)
        .filter(Incident.correlated == True)
        .order_by(Incident.timestamp.desc().nullslast(), Incident.id.desc())
    )

    if limit:
        query = query.limit(limit)

    return query.all()


def build_case_summary(
    group_key: str,
    incidents: list[Incident],
    max_risk: int,
    severity: str,
) -> str:
    incident_ids = [incident.id for incident in incidents]
    rules = sorted({incident.rule or "-" for incident in incidents})
    correlation_types = sorted(
        {
            incident.correlation_type or "UNCLASSIFIED_CORRELATION"
            for incident in incidents
        }
    )

    summary = {
        "group_key": group_key,
        "incident_count": len(incidents),
        "incident_ids": incident_ids,
        "agent": incidents[0].agent,
        "correlation_types": correlation_types,
        "max_risk_score": max_risk,
        "severity": severity,
        "rules": rules,
        "first_timestamp": min(
            (incident.timestamp for incident in incidents if incident.timestamp),
            default=None,
        ),
        "last_timestamp": max(
            (incident.timestamp for incident in incidents if incident.timestamp),
            default=None,
        ),
    }

    return json.dumps(summary, ensure_ascii=False)


def upsert_case(db, group_key: str, incidents: list[Incident]) -> IncidentCase:
    sorted_incidents = sorted(
        incidents,
        key=lambda item: (item.timestamp or "", item.id),
    )

    agent = normalize_group_value(sorted_incidents[0].agent, "unknown-agent")
    correlation_type = normalize_group_value(
        sorted_incidents[0].correlation_type,
        "UNCLASSIFIED_CORRELATION",
    )
    day = event_day(sorted_incidents[0].timestamp)

    max_risk = max((incident.risk_score or 0 for incident in sorted_incidents), default=0)
    severity = severity_from_score(max_risk)
    status = case_status_from_incidents(sorted_incidents)
    title = f"{agent} / {correlation_type} / {day}"

    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.group_key == group_key)
        .first()
    )

    if not case:
        case = IncidentCase(
            group_key=group_key,
            title=title,
            created_by="system",
        )
        db.add(case)
        db.flush()

    case.title = title
    case.status = status
    case.severity = severity
    case.agent = agent
    case.correlation_type = correlation_type
    case.risk_score = max_risk
    case.summary = build_case_summary(
        group_key=group_key,
        incidents=sorted_incidents,
        max_risk=max_risk,
        severity=severity,
    )
    case.updated_at = utc_now()

    existing_links = {
        row.incident_id
        for row in db.query(CaseIncident)
        .filter(CaseIncident.case_id == case.id)
        .all()
    }

    for incident in sorted_incidents:
        if incident.id in existing_links:
            continue

        db.add(
            CaseIncident(
                case_id=case.id,
                incident_id=incident.id,
                relationship_type="CORRELATED",
            )
        )

    return case


def main():
    parser = argparse.ArgumentParser(
        description="Build investigation cases from correlated incidents."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of latest correlated incidents to evaluate. Default: all.",
    )
    parser.add_argument(
        "--min-size",
        type=int,
        default=2,
        help="Minimum number of incidents required to create a case.",
    )

    args = parser.parse_args()

    db = SessionLocal()

    try:
        incidents = load_candidate_incidents(db, args.limit)

        groups: dict[str, list[Incident]] = defaultdict(list)

        for incident in incidents:
            groups[build_group_key(incident)].append(incident)

        created_or_updated = 0

        for group_key, grouped_incidents in groups.items():
            if len(grouped_incidents) < args.min_size:
                continue

            upsert_case(db, group_key, grouped_incidents)
            created_or_updated += 1

        db.commit()

        print(f"Candidate incidents: {len(incidents)}")
        print(f"Candidate groups: {len(groups)}")
        print(f"Cases created/updated: {created_or_updated}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
