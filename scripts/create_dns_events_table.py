from __future__ import annotations

from sqlalchemy import text

from database import engine


DDL = """
CREATE TABLE IF NOT EXISTS dns_events (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'wazuh',
    raw_event_id INTEGER,
    source_event_id TEXT,
    event_timestamp TIMESTAMPTZ,
    agent_name TEXT,
    agent_ip TEXT,
    client_ip TEXT,
    client_port INTEGER,
    resolver_ip TEXT,
    resolver_port INTEGER,
    query_name TEXT,
    query_type TEXT,
    query_status TEXT,
    process_name TEXT,
    process_path TEXT,
    user_name TEXT,
    collector TEXT,
    raw_line TEXT,
    raw_event JSONB,
    event_fingerprint TEXT UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_dns_events_event_timestamp
    ON dns_events (event_timestamp DESC);

CREATE INDEX IF NOT EXISTS ix_dns_events_agent_name
    ON dns_events (agent_name);

CREATE INDEX IF NOT EXISTS ix_dns_events_client_ip
    ON dns_events (client_ip);

CREATE INDEX IF NOT EXISTS ix_dns_events_query_name
    ON dns_events (query_name);

CREATE INDEX IF NOT EXISTS ix_dns_events_resolver_ip
    ON dns_events (resolver_ip);

CREATE INDEX IF NOT EXISTS ix_dns_events_raw_event_id
    ON dns_events (raw_event_id);
"""


def main() -> None:
    with engine.begin() as conn:
        conn.execute(text(DDL))

    print("dns_events table ready")


if __name__ == "__main__":
    main()
