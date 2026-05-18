import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import SessionLocal
from models import Incident, IncidentCase
from risk_normalization import normalize_correlation_score, should_auto_escalate


def safe_json(value):
    if not value:
        return {}

    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def recalculate_incident(incident: Incident) -> dict:
    summary = safe_json(incident.correlation_summary)

    matched_chains = summary.get("matched_attack_chains") or []

    pattern_score = summary.get("pattern_score")
    volume_score = summary.get("volume_score")
    chain_bonus = summary.get("chain_bonus")

    normalized = normalize_correlation_score(
        level=incident.level,
        pattern_score=pattern_score,
        volume_score=volume_score,
        aggregate_score=0,
        chain_bonus=chain_bonus,
        matched_chains=matched_chains,
    )

    new_status = incident.status or "NEW"

    if should_auto_escalate(
        score=normalized["final_score"],
        matched_chains=matched_chains,
    ):
        if new_status in {None, "NEW", "TRIAGED"}:
            new_status = "ESCALATED"
    elif new_status == "ESCALATED":
        new_status = "TRIAGED"

    return {
        "id": incident.id,
        "agent": incident.agent,
        "rule": incident.rule,
        "level": incident.level,
        "old_risk_score": incident.risk_score,
        "new_risk_score": normalized["final_score"],
        "old_priority": incident.recommended_priority,
        "new_priority": normalized["recommended_priority"],
        "old_status": incident.status,
        "new_status": new_status,
        "old_correlation_score": incident.correlation_score,
        "new_correlation_score": normalized["final_score"],
        "matched_chain_count": normalized["matched_chain_count"],
        "cap": normalized["cap"],
    }


def main():
    db = SessionLocal()

    try:
        incidents = (
            db.query(Incident)
            .filter(Incident.correlated == True)
            .order_by(Incident.id.desc())
            .all()
        )

        changes = []

        for incident in incidents:
            item = recalculate_incident(incident)

            changed = any(
                [
                    item["old_risk_score"] != item["new_risk_score"],
                    item["old_priority"] != item["new_priority"],
                    item["old_status"] != item["new_status"],
                    item["old_correlation_score"] != item["new_correlation_score"],
                ]
            )

            if changed:
                changes.append(item)

        print("=== Risk normalization dry-run ===")
        print(f"Correlated incidents evaluated: {len(incidents)}")
        print(f"Incidents that would change: {len(changes)}")

        old_priority = Counter(item["old_priority"] or "NULL" for item in changes)
        new_priority = Counter(item["new_priority"] or "NULL" for item in changes)
        old_status = Counter(item["old_status"] or "NULL" for item in changes)
        new_status = Counter(item["new_status"] or "NULL" for item in changes)

        print("\nOld priority distribution among changed incidents:")
        for key, value in old_priority.most_common():
            print(f"{key}: {value}")

        print("\nNew priority distribution among changed incidents:")
        for key, value in new_priority.most_common():
            print(f"{key}: {value}")

        print("\nOld status distribution among changed incidents:")
        for key, value in old_status.most_common():
            print(f"{key}: {value}")

        print("\nNew status distribution among changed incidents:")
        for key, value in new_status.most_common():
            print(f"{key}: {value}")

        print("\nSample changes:")
        for item in changes[:30]:
            print(
                {
                    "id": item["id"],
                    "level": item["level"],
                    "old_risk": item["old_risk_score"],
                    "new_risk": item["new_risk_score"],
                    "old_priority": item["old_priority"],
                    "new_priority": item["new_priority"],
                    "old_status": item["old_status"],
                    "new_status": item["new_status"],
                    "matched_chain_count": item["matched_chain_count"],
                    "cap": item["cap"],
                    "rule": (item["rule"] or "-")[:90],
                }
            )

        print("\nCase distribution current state:")
        case_rows = db.query(IncidentCase).all()
        case_severity = Counter((case.severity or "NULL") for case in case_rows)
        case_status = Counter((case.status or "NULL") for case in case_rows)

        print("Case severity:")
        for key, value in case_severity.most_common():
            print(f"{key}: {value}")

        print("Case status:")
        for key, value in case_status.most_common():
            print(f"{key}: {value}")

    finally:
        db.close()


if __name__ == "__main__":
    main()
