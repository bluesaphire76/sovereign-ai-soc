from sqlalchemy import text
from database import engine

DDL = """
CREATE TABLE IF NOT EXISTS network_events (
    id BIGSERIAL PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'suricata',
    event_type TEXT NOT NULL,
    event_timestamp TIMESTAMPTZ NULL,
    flow_id TEXT NULL,
    src_ip TEXT NULL,
    src_port INTEGER NULL,
    dest_ip TEXT NULL,
    dest_port INTEGER NULL,
    proto TEXT NULL,
    app_proto TEXT NULL,
    hostname TEXT NULL,
    url TEXT NULL,
    http_method TEXT NULL,
    http_user_agent TEXT NULL,
    tls_sni TEXT NULL,
    alert_signature TEXT NULL,
    alert_category TEXT NULL,
    alert_severity INTEGER NULL,
    raw_event JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_network_events_timestamp ON network_events(event_timestamp);
CREATE INDEX IF NOT EXISTS idx_network_events_type ON network_events(event_type);
CREATE INDEX IF NOT EXISTS idx_network_events_src_ip ON network_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_network_events_dest_ip ON network_events(dest_ip);
CREATE INDEX IF NOT EXISTS idx_network_events_hostname ON network_events(hostname);
CREATE INDEX IF NOT EXISTS idx_network_events_flow_id ON network_events(flow_id);
"""
with engine.begin() as conn:
    conn.execute(text(DDL))

print("network_events table ready")
