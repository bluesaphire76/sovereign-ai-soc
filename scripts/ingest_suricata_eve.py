import argparse
import hashlib
import json
from pathlib import Path

from sqlalchemy import text
from database import engine


DEFAULT_EVE_PATH = "deploy/suricata/logs/eve.json"
SUPPORTED_TYPES = {"alert", "dns", "http", "tls", "flow"}


def as_int(value):
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def event_fingerprint(event: dict) -> str:
    material = {
        "timestamp": event.get("timestamp"),
        "event_type": event.get("event_type"),
        "flow_id": event.get("flow_id"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
        "http": event.get("http"),
        "tls": event.get("tls"),
        "dns": event.get("dns"),
        "alert": event.get("alert"),
    }
    payload = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def extract_fields(event):
    event_type = event.get("event_type")
    http = event.get("http") or {}
    tls = event.get("tls") or {}
    dns = event.get("dns") or {}
    alert = event.get("alert") or {}

    hostname = http.get("hostname") or tls.get("sni") or dns.get("rrname")

    return {
        "event_fingerprint": event_fingerprint(event),
        "event_type": event_type,
        "event_timestamp": event.get("timestamp"),
        "flow_id": str(event.get("flow_id")) if event.get("flow_id") is not None else None,
        "src_ip": event.get("src_ip"),
        "src_port": as_int(event.get("src_port")),
        "dest_ip": event.get("dest_ip"),
        "dest_port": as_int(event.get("dest_port")),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto"),
        "hostname": hostname,
        "url": http.get("url"),
        "http_method": http.get("http_method"),
        "http_user_agent": http.get("http_user_agent"),
        "tls_sni": tls.get("sni"),
        "alert_signature": alert.get("signature"),
        "alert_category": alert.get("category"),
        "alert_severity": as_int(alert.get("severity")),
        "raw_event": json.dumps(event),
    }


INSERT_SQL = text("""
INSERT INTO network_events (
    source, event_fingerprint, event_type, event_timestamp, flow_id,
    src_ip, src_port, dest_ip, dest_port,
    proto, app_proto, hostname, url, http_method,
    http_user_agent, tls_sni, alert_signature,
    alert_category, alert_severity, raw_event
) VALUES (
    'suricata', :event_fingerprint, :event_type, :event_timestamp, :flow_id,
    :src_ip, :src_port, :dest_ip, :dest_port,
    :proto, :app_proto, :hostname, :url, :http_method,
    :http_user_agent, :tls_sni, :alert_signature,
    :alert_category, :alert_severity, CAST(:raw_event AS JSONB)
)
ON CONFLICT (event_fingerprint) WHERE event_fingerprint IS NOT NULL DO NOTHING
""")


def ingest(path: Path, limit: int | None, dry_run: bool) -> dict:
    stats = {
        "seen": 0,
        "inserted": 0,
        "duplicates": 0,
        "skipped_invalid_json": 0,
        "skipped_unsupported_type": 0,
    }

    if not path.exists():
        raise FileNotFoundError(f"EVE file not found: {path}")

    rows = []

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if limit is not None and stats["seen"] >= limit:
                break

            line = line.strip()
            if not line:
                continue

            stats["seen"] += 1

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                stats["skipped_invalid_json"] += 1
                continue

            if event.get("event_type") not in SUPPORTED_TYPES:
                stats["skipped_unsupported_type"] += 1
                continue

            rows.append(extract_fields(event))

    if dry_run:
        stats["inserted"] = len(rows)
        return stats

    with engine.begin() as conn:
        for row in rows:
            result = conn.execute(INSERT_SQL, row)
            if result.rowcount == 1:
                stats["inserted"] += 1
            else:
                stats["duplicates"] += 1

    return stats


def main():
    parser = argparse.ArgumentParser(description="Ingest Suricata EVE JSON into network_events.")
    parser.add_argument("--path", default=DEFAULT_EVE_PATH)
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    stats = ingest(Path(args.path), args.limit, args.dry_run)
    print(json.dumps(stats, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
