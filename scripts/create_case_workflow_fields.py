import sys
from pathlib import Path

from sqlalchemy import inspect, text

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import engine
from models import Base


WORKFLOW_COLUMNS = {
    "owner": "VARCHAR",
    "sla_due_at": "TIMESTAMP WITH TIME ZONE",
    "severity_review": "VARCHAR",
    "status_reason": "TEXT",
    "last_reviewed_by": "VARCHAR",
    "last_reviewed_at": "TIMESTAMP WITH TIME ZONE",
}


def main():
    inspector = inspect(engine)

    if "incident_cases" not in inspector.get_table_names():
        raise SystemExit("incident_cases table does not exist. Create case tables first.")

    existing_columns = {
        column["name"] for column in inspector.get_columns("incident_cases")
    }

    with engine.begin() as connection:
        for column_name, column_type in WORKFLOW_COLUMNS.items():
            if column_name not in existing_columns:
                connection.execute(
                    text(
                        f"ALTER TABLE incident_cases "
                        f"ADD COLUMN {column_name} {column_type}"
                    )
                )
                print(f"Added incident_cases.{column_name}")
            else:
                print(f"incident_cases.{column_name} already exists")

    Base.metadata.create_all(bind=engine)
    print("case workflow fields and case_audit table ensured.")


if __name__ == "__main__":
    main()

