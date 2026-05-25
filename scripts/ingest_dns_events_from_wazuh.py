from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from database import engine


def safe_json(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, (dict, list)):
        return value

    if not isinstance(value, str):
        return value

    try:
        return json.loads(value)
    except Exception:
        return value


def parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None

    raw = str(value).strip()

    if not raw:
        return None

    normalized = raw.replace("Z", "+00:00")

    if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def deep_get(payload: Any, *paths: tuple[str, ...]) -> Any:
    for path in paths:
        current = payload

        for key in path:
            if not isinstance(current, dict):
                current = None
                break

            current = current.get(key)

        if current not in {None, ""}:
            return current

    return None


def to_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def normalize_payload(raw_payload: Any) -> dict[str, Any] | None:
    payload = safe_json(raw_payload)

    if not isinstance(payload, dict):
        return None

    # Wazuh JSON decoder may keep custom JSON either at root or under data.
    event_type = deep_get(
        payload,
        ("event_type",),
        ("data", "event_type"),
    )

    if event_type != "ai_soc_dns_query":
        return None

    agent = payload.get("agent") if isinstance(payload.get("agent"), dict) else {}

    return {
        "source_event_id": deep_get(payload, ("_wazuh_doc_id",), ("id",)),
        "event_timestamp": parse_timestamp(
            deep_get(
                payload,
                ("event_timestamp",),
                ("data", "event_timestamp"),
                ("@timestamp",),
                ("timestamp",),
            )
        ),
        "agent_name": deep_get(payload, ("agent", "name")) or deep_get(payload, ("host",)),
        "agent_ip": deep_get(payload, ("agent", "ip")),
        "client_ip": deep_get(payload, ("src_ip",), ("data", "src_ip")),
        "client_port": to_int(deep_get(payload, ("src_port",), ("data", "src_port"))),
        "resolver_ip": deep_get(payload, ("resolver_ip",), ("data", "resolver_ip")),
        "resolver_port": to_int(deep_get(payload, ("resolver_port",), ("data", "resolver_port"))),
        "query_name": deep_get(payload, ("query_name",), ("data", "query_name")),
        "query_type": deep_get(payload, ("query_type",), ("data", "query_type")),
        "query_status": deep_get(payload, ("query_status",), ("data", "query_status")),
        "process_name": deep_get(payload, ("process_name",), ("data", "process_name")),
        "process_path": deep_get(payload, ("process_path",), ("data", "process_path")),
        "user_name": deep_get(payload, ("user_name",), ("data", "user_name")),
        "collector": deep_get(payload, ("collector",), ("data", "collector")),
        "raw_line": deep_get(payload, ("raw_line",), ("data", "raw_line")),
        "raw_event": payload,
    }


def fingerprint(raw_event_id: int, event: dict[str, Any]) -> str:
    stable = {
        "raw_event_id": raw_event_id,
        "source_event_id": event.get("source_event_id"),
        "event_timestamp": event.get("event_timestamp").isoformat()
        if event.get("event_timestamp")
        else None,
        "agent_name": event.get("agent_name"),
        "client_ip": event.get("client_ip"),
        "resolver_ip": event.get("resolver_ip"),
        "query_name": event.get("query_name"),
        "query_type": event.get("query_type"),
        "raw_line": event.get("raw_line"),
    }

    encoded = json.dumps(stable, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_candidate_raw_events(limit: int) -> list[dict[str, Any]]:
    with engine.begin() as conn:
        rows = conn.execute(
            text("""
                select id, source_event_id, event_timestamp, agent, payload_json
                from raw_events
                where payload_json::text ilike '%ai_soc_dns_query%'
                order by id asc
                limit :limit
            """),
            {"limit": limit},
        ).mappings().all()

    return [dict(row) for row in rows]


def insert_dns_event(raw_event: dict[str, Any], dry_run: bool) -> bool:
    event = normalize_payload(raw_event.get("payload_json"))

    if not event:
        return False

    event["raw_event_id"] = raw_event["id"]
    event["event_fingerprint"] = fingerprint(raw_event["id"], event)

    if dry_run:
        return True

    with engine.begin() as conn:
        result = conn.execute(
            text("""
                insert into dns_events (
                    source,
                    raw_event_id,
                    source_event_id,
                    event_timestamp,
                    agent_name,
                    agent_ip,
                    client_ip,
                    client_port,
                    resolver_ip,
                    resolver_port,
                    query_name,
                    query_type,
                    query_status,
                    process_name,
                    process_path,
                    user_name,
                    collector,
                    raw_line,
                    raw_event,
                    event_fingerprint
                )
                values (
                    'wazuh',
                    :raw_event_id,
                    :source_event_id,
                    :event_timestamp,
                    :agent_name,
                    :agent_ip,
                    :client_ip,
                    :client_port,
                    :resolver_ip,
                    :resolver_port,
                    :query_name,
                    :query_type,
                    :query_status,
                    :process_name,
                    :process_path,
                    :user_name,
                    :collector,
                    :raw_line,
                    cast(:raw_event as jsonb),
                    :event_fingerprint
                )
                on conflict (event_fingerprint) do nothing
            """),
            {
                **event,
                "raw_event": json.dumps(event["raw_event"], ensure_ascii=False, default=str),
            },
        )

    return result.rowcount > 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize AI SOC DNS telemetry from Wazuh raw_events.")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    candidates = load_candidate_raw_events(args.limit)

    seen = 0
    inserted = 0
    normalized = 0

    for raw_event in candidates:
        seen += 1
        event = normalize_payload(raw_event.get("payload_json"))

        if not event:
            continue

        normalized += 1

        if insert_dns_event(raw_event, dry_run=args.dry_run):
            inserted += 1

    print(
        json.dumps(
            {
                "seen": seen,
                "normalized": normalized,
                "inserted": inserted,
                "dry_run": args.dry_run,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
