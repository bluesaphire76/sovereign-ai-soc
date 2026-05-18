import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import SessionLocal
from models import Incident, utc_now
from risk_normalization import normalize_correlation_score


TARGET_RULES = {
    "PAM: Login session opened.",
    "PAM: Login session closed.",
    "Successful sudo to ROOT executed.",
}

TERMINAL_STATUSES = {"CLOSED", "FALSE_POSITIVE"}


def utc_label():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def safe_json(value):
    if not value:
        return {}

    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def main():
    parser = argparse.ArgumentParser(
        description="Targeted historical backfill for PAM/sudo operational false attack chains."
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output-dir", default="reports/backfill")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    run_id = utc_label()
    csv_path = output_dir / f"pam-sudo-operational-backfill-{run_id}.csv"

    db = SessionLocal()

    try:
        candidates = (
            db.query(Incident)
            .filter(Incident.rule.in_(TARGET_RULES))
            .filter(Incident.risk_score >= 80)
            .filter(Incident.correlated == True)
            .filter(Incident.status.notin_(TERMINAL_STATUSES))
            .order_by(Incident.id.asc())
            .all()
        )

        changes = []

        for incident in candidates:
            summary = safe_json(incident.correlation_summary)
            matched_chains = summary.get("matched_attack_chains") or []

            if not matched_chains:
                continue

            normalized = normalize_correlation_score(
                level=incident.level,
                pattern_score=0,
                volume_score=0,
                aggregate_score=0,
                chain_bonus=0,
                matched_chains=[],
            )

            old_values = {
                "risk_score": incident.risk_score,
                "correlation_score": incident.correlation_score,
                "recommended_priority": incident.recommended_priority,
                "status": incident.status,
            }

            new_values = {
                "risk_score": normalized["final_score"],
                "correlation_score": normalized["final_score"],
                "recommended_priority": normalized["recommended_priority"],
                "status": "TRIAGED" if incident.status == "ESCALATED" else incident.status,
            }

            changed_fields = [
                key for key in old_values
                if old_values[key] != new_values[key]
            ]

            if not changed_fields:
                continue

            changes.append({
                "incident": incident,
                "old_values": old_values,
                "new_values": new_values,
                "changed_fields": changed_fields,
                "matched_chain_count": len(matched_chains),
                "normalization": normalized,
            })

        with csv_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "id",
                    "rule",
                    "level",
                    "old_risk_score",
                    "new_risk_score",
                    "old_priority",
                    "new_priority",
                    "old_status",
                    "new_status",
                    "matched_chain_count",
                    "changed_fields",
                ],
            )
            writer.writeheader()

            for item in changes:
                incident = item["incident"]
                writer.writerow({
                    "id": incident.id,
                    "rule": incident.rule,
                    "level": incident.level,
                    "old_risk_score": item["old_values"]["risk_score"],
                    "new_risk_score": item["new_values"]["risk_score"],
                    "old_priority": item["old_values"]["recommended_priority"],
                    "new_priority": item["new_values"]["recommended_priority"],
                    "old_status": item["old_values"]["status"],
                    "new_status": item["new_values"]["status"],
                    "matched_chain_count": item["matched_chain_count"],
                    "changed_fields": ",".join(item["changed_fields"]),
                })

        print("=== PAM/sudo operational chain backfill ===")
        print(f"Mode: {'APPLY' if args.apply else 'DRY_RUN'}")
        print(f"Candidates: {len(candidates)}")
        print(f"Changes: {len(changes)}")
        print(f"CSV: {csv_path}")

        print("\nSample changes:")
        for item in changes[:30]:
            incident = item["incident"]
            print({
                "id": incident.id,
                "rule": incident.rule,
                "level": incident.level,
                "old": item["old_values"],
                "new": item["new_values"],
                "matched_chain_count": item["matched_chain_count"],
            })

        if args.apply:
            for item in changes:
                incident = item["incident"]
                incident.risk_score = item["new_values"]["risk_score"]
                incident.correlation_score = item["new_values"]["correlation_score"]
                incident.recommended_priority = item["new_values"]["recommended_priority"]
                incident.status = item["new_values"]["status"]

                summary = safe_json(incident.correlation_summary)
                summary["historical_pam_sudo_operational_backfill"] = {
                    "applied_at": utc_now().isoformat(),
                    "policy": "v0.4_pam_sudo_operational_false_chain_backfill",
                    "old_values": item["old_values"],
                    "new_values": item["new_values"],
                    "matched_chain_count": item["matched_chain_count"],
                    "normalization": item["normalization"],
                    "note": "Historical PAM/sudo operational event treated as false positive attack-chain correlation.",
                }
                incident.correlation_summary = json.dumps(summary, ensure_ascii=False)

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
