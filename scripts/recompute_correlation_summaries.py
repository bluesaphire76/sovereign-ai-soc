import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from correlation_engine import correlate_incident
from database import SessionLocal
from models import Incident


def load_incident_ids(limit: int | None):
    db = SessionLocal()

    try:
        query = db.query(Incident.id).order_by(Incident.id.desc())

        if limit:
            query = query.limit(limit)

        return [row.id for row in query.all()]

    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Recompute structured correlation summaries for existing incidents."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of latest incidents to recompute. Default: all incidents.",
    )

    args = parser.parse_args()

    ids = load_incident_ids(args.limit)

    print(f"Recomputing correlation for {len(ids)} incident(s).")

    for incident_id in ids:
        print(f"Recomputing incident {incident_id}")
        correlate_incident(incident_id)

    print("Done.")


if __name__ == "__main__":
    main()
