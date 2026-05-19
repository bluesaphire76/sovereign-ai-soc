#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import inspect, text

from database import engine


DDL = {
    ("incident_cases", "assignee"): (
        "ALTER TABLE incident_cases ADD COLUMN assignee VARCHAR"
    ),
    ("case_closure_checklists", "closure_approved"): (
        "ALTER TABLE case_closure_checklists ADD COLUMN closure_approved BOOLEAN DEFAULT FALSE"
    ),
    ("case_closure_checklists", "closure_approved_by"): (
        "ALTER TABLE case_closure_checklists ADD COLUMN closure_approved_by VARCHAR"
    ),
    ("case_closure_checklists", "closure_approved_at"): (
        "ALTER TABLE case_closure_checklists ADD COLUMN closure_approved_at TIMESTAMP WITH TIME ZONE"
    ),
}


def existing_columns() -> dict[str, set[str]]:
    inspector = inspect(engine)
    result: dict[str, set[str]] = {}

    for table_name in inspector.get_table_names():
      result[table_name] = {
          column["name"] for column in inspector.get_columns(table_name)
      }

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Add v0.5 case ownership/SLA fields."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the schema changes. Without this flag the script only prints the pending DDL.",
    )
    args = parser.parse_args()

    columns = existing_columns()
    pending = []

    for (table_name, column_name), ddl in DDL.items():
        if column_name not in columns.get(table_name, set()):
            pending.append((table_name, column_name, ddl))

    if not pending:
        print("No schema changes required.")
        return 0

    for table_name, column_name, ddl in pending:
        print(f"Pending: {table_name}.{column_name}")
        print(f"  {ddl}")

    if not args.apply:
        print("Dry-run only. Re-run with --apply to execute.")
        return 0

    with engine.begin() as conn:
        for _, _, ddl in pending:
            conn.execute(text(ddl))

    print(f"Applied {len(pending)} schema change(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
