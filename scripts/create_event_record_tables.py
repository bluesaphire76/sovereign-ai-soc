import sys
from pathlib import Path

from sqlalchemy import inspect, text

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import engine
from models import Base


def add_column_if_missing(table_name: str, column_name: str, ddl: str):
    inspector = inspect(engine)
    existing_columns = {
        column["name"] for column in inspector.get_columns(table_name)
    }

    if column_name in existing_columns:
        print(f"{table_name}.{column_name} already exists")
        return

    with engine.begin() as connection:
        connection.execute(text(ddl))

    print(f"Added {table_name}.{column_name}")


def main():
    Base.metadata.create_all(bind=engine)

    add_column_if_missing(
        "incidents",
        "raw_event_id",
        "ALTER TABLE incidents ADD COLUMN raw_event_id INTEGER",
    )
    add_column_if_missing(
        "incidents",
        "security_alert_id",
        "ALTER TABLE incidents ADD COLUMN security_alert_id INTEGER",
    )

    with engine.begin() as connection:
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_incidents_raw_event_id ON incidents (raw_event_id)")
        )
        connection.execute(
            text("CREATE INDEX IF NOT EXISTS ix_incidents_security_alert_id ON incidents (security_alert_id)")
        )

    print("raw_events, security_alerts and incident reference columns ensured.")


if __name__ == "__main__":
    main()
