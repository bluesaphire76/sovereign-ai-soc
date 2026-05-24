from sqlalchemy import text
from database import engine

DDL = """
CREATE TABLE IF NOT EXISTS suricata_ingest_state (
    source TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_inode BIGINT NULL,
    byte_offset BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);
"""

with engine.begin() as conn:
    conn.execute(text(DDL))

print("suricata_ingest_state table ready")
