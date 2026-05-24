from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import text
from database import engine


TABLES = [
    "incidents",
    "raw_events",
    "security_alerts",
    "network_events",
    "suricata_ingest_state",
    "wazuh_ingest_watermarks",
]

TIME_COLUMN_HINTS = {
    "timestamp",
    "event_timestamp",
    "created_at",
    "updated_at",
    "first_seen_at",
    "last_seen_at",
    "ingested_at",
    "processed_at",
    "last_success_at",
}


def main() -> None:
    print("=== Python runtime time ===")
    print("local_zurich:", datetime.now(ZoneInfo("Europe/Zurich")).isoformat())
    print("utc:", datetime.now(timezone.utc).isoformat())

    with engine.begin() as conn:
        db_time = conn.execute(text("""
            select
                now() as db_now,
                now() at time zone 'utc' as db_utc,
                current_setting('TimeZone') as db_timezone
        """)).fetchone()

        print("\n=== PostgreSQL time ===")
        print("db_now:", db_time.db_now)
        print("db_utc:", db_time.db_utc)
        print("db_timezone:", db_time.db_timezone)

        print("\n=== Known table time columns ===")

        for table in TABLES:
            exists = conn.execute(text("""
                select exists (
                    select 1
                    from information_schema.tables
                    where table_schema = 'public'
                      and table_name = :table
                )
            """), {"table": table}).scalar()

            if not exists:
                print(f"{table}: table not found")
                continue

            columns = conn.execute(text("""
                select column_name, data_type
                from information_schema.columns
                where table_schema = 'public'
                  and table_name = :table
                order by ordinal_position
            """), {"table": table}).fetchall()

            candidate_columns = [
                col.column_name
                for col in columns
                if col.column_name in TIME_COLUMN_HINTS
                or "time" in col.column_name.lower()
                or "date" in col.column_name.lower()
            ]

            if not candidate_columns:
                print(f"{table}: no obvious time columns")
                continue

            print(f"{table}: {candidate_columns}")

            for column in candidate_columns:
                try:
                    value = conn.execute(text(
                        f"select max({column}) from {table}"
                    )).scalar()
                    print(f"  max({column}): {value}")
                except Exception as exc:
                    print(f"  max({column}): ERROR {type(exc).__name__}")


if __name__ == "__main__":
    main()
