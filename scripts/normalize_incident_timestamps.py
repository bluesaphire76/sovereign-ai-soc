from database import SessionLocal
from models import Incident
from timezone_utils import normalize_timestamp_utc


def main():
    db = SessionLocal()
    updated = 0

    try:
        incidents = db.query(Incident).all()

        for incident in incidents:
            old_value = incident.timestamp
            new_value = normalize_timestamp_utc(old_value)

            if new_value and new_value != old_value:
                incident.timestamp = new_value
                updated += 1

        db.commit()
        print(f"Updated {updated} incident timestamp(s).")

    finally:
        db.close()


if __name__ == "__main__":
    main()
