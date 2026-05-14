import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import SessionLocal
from models import Incident


EMPTY_VALUES = {None, "", "{}", "null", "None"}


def extract_mitre(raw_alert):
    if not raw_alert:
        return None

    try:
        data = json.loads(raw_alert)
    except json.JSONDecodeError:
        return None

    mitre = data.get("rule", {}).get("mitre")

    if not mitre:
        return None

    return json.dumps(mitre, ensure_ascii=False)


def main():
    db = SessionLocal()
    updated = 0

    try:
        incidents = db.query(Incident).all()

        for incident in incidents:
            current = incident.mitre

            if current not in EMPTY_VALUES:
                continue

            mitre = extract_mitre(incident.raw_alert)

            if mitre:
                incident.mitre = mitre
                updated += 1

        db.commit()
        print(f"Updated {updated} incident MITRE field(s).")

    finally:
        db.close()


if __name__ == "__main__":
    main()
