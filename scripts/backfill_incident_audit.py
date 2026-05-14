import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import SessionLocal
from models import Incident, IncidentAudit


def main():
    db = SessionLocal()
    created = 0

    try:
        incidents = db.query(Incident).all()

        for incident in incidents:
            existing = (
                db.query(IncidentAudit)
                .filter(IncidentAudit.incident_id == incident.id)
                .first()
            )

            if existing:
                continue

            audit = IncidentAudit(
                incident_id=incident.id,
                event_type="INCIDENT_CREATED",
                old_value=None,
                new_value=incident.status or "NEW",
                comment="Backfilled initial audit event from existing incident.",
                created_by="system",
            )

            db.add(audit)
            created += 1

        db.commit()
        print(f"Created {created} audit event(s).")

    finally:
        db.close()


if __name__ == "__main__":
    main()
