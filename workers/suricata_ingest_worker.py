import argparse
import hashlib
import json
import time
from pathlib import Path

from sqlalchemy import text
from database import engine


DEFAULT_EVE_PATH = "deploy/suricata/logs/eve.json"
SOURCE = "suricata"
SUPPORTED_TYPES = {"alert", "dns", "http", "tls", "flow"}


CREATE_STATE_SQL = text("""
CREATE TABLE IF NOT EXISTS suricata_ingest_state (
    source TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    file_inode BIGINT NULL,
    byte_offset BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    details JSONB NOT NULL DEFAULT '{}'::jsonb
)
""")


GET_STATE_SQL = text("""
SELECT file_inode, byte_offset
FROM suricata_ingest_state
WHERE source = :source
""")


UPSERT_STATE_SQL = text("""
INSERT INTO suricata_ingest_state (
    source, file_path, file_inode, byte_offset, updated_at, details
) VALUES (
    :source, :file_path, :file_inode, :byte_offset, now(), CAST(:details AS JSONB)
)
ON CONFLICT (source)
DO UPDATE SET
    file_path = EXCLUDED.file_path,
    file_inode = EXCLUDED.file_inode,
    byte_offset = EXCLUDED.byte_offset,
    updated_at = now(),
    details = EXCLUDED.details
""")


INSERT_EVENT_SQL = text("""
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


def extract_fields(event: dict) -> dict:
    http = event.get("http") or {}
    tls = event.get("tls") or {}
    dns = event.get("dns") or {}
    alert = event.get("alert") or {}

    hostname = http.get("hostname") or tls.get("sni") or dns.get("rrname")

    return {
        "event_fingerprint": event_fingerprint(event),
        "event_type": event.get("event_type"),
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


def ensure_state_table() -> None:
    with engine.begin() as conn:
        conn.execute(CREATE_STATE_SQL)


def load_offset(path: Path) -> tuple[int | None, int]:
    stat = path.stat()

    with engine.begin() as conn:
        state = conn.execute(GET_STATE_SQL, {"source": SOURCE}).fetchone()

    if not state:
        return stat.st_ino, 0

    previous_inode, previous_offset = state

    if previous_inode != stat.st_ino:
        return stat.st_ino, 0

    if previous_offset is None or previous_offset < 0:
        return stat.st_ino, 0

    if previous_offset > stat.st_size:
        return stat.st_ino, 0

    return stat.st_ino, previous_offset


def save_offset(path: Path, inode: int, offset: int, details: dict) -> None:
    with engine.begin() as conn:
        conn.execute(
            UPSERT_STATE_SQL,
            {
                "source": SOURCE,
                "file_path": str(path),
                "file_inode": inode,
                "byte_offset": offset,
                "details": json.dumps(details, sort_keys=True),
            },
        )


def ingest_once(path: Path, batch_size: int, dry_run: bool) -> dict:
    ensure_state_table()

    if not path.exists():
        raise FileNotFoundError(f"EVE file not found: {path}")

    inode, offset = load_offset(path)

    stats = {
        "source": SOURCE,
        "path": str(path),
        "start_offset": offset,
        "end_offset": offset,
        "lines_read": 0,
        "supported_events": 0,
        "inserted": 0,
        "duplicates": 0,
        "skipped_invalid_json": 0,
        "skipped_unsupported_type": 0,
        "dry_run": dry_run,
    }

    rows = []

    with path.open("rb") as handle:
        handle.seek(offset)

        while stats["lines_read"] < batch_size:
            raw_line = handle.readline()
            if not raw_line:
                break

            stats["lines_read"] += 1
            stats["end_offset"] = handle.tell()

            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                stats["skipped_invalid_json"] += 1
                continue

            if event.get("event_type") not in SUPPORTED_TYPES:
                stats["skipped_unsupported_type"] += 1
                continue

            stats["supported_events"] += 1
            rows.append(extract_fields(event))

    if not dry_run:
        with engine.begin() as conn:
            for row in rows:
                result = conn.execute(INSERT_EVENT_SQL, row)
                if result.rowcount == 1:
                    stats["inserted"] += 1
                else:
                    stats["duplicates"] += 1

        save_offset(path, inode, stats["end_offset"], stats)

    return stats


def run_loop(path: Path, batch_size: int, interval_seconds: int, dry_run: bool) -> None:
    while True:
        stats = ingest_once(path, batch_size=batch_size, dry_run=dry_run)
        print(json.dumps(stats, indent=2, sort_keys=True), flush=True)
        time.sleep(interval_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Suricata EVE JSON incremental ingest worker.")
    parser.add_argument("--path", default=DEFAULT_EVE_PATH)
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--interval-seconds", type=int, default=15)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    path = Path(args.path)

    if args.once:
        stats = ingest_once(path, batch_size=args.batch_size, dry_run=args.dry_run)
        print(json.dumps(stats, indent=2, sort_keys=True))
        return

    run_loop(
        path=path,
        batch_size=args.batch_size,
        interval_seconds=args.interval_seconds,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
