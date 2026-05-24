from sqlalchemy import text
from database import engine

DDL = """
ALTER TABLE network_events
ADD COLUMN IF NOT EXISTS event_fingerprint TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_network_events_event_fingerprint
ON network_events(event_fingerprint)
WHERE event_fingerprint IS NOT NULL;
"""

with engine.begin() as conn:
    conn.execute(text(DDL))

print("network_events event_fingerprint ready")
