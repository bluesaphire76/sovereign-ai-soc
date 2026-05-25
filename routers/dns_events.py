from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import text

from database import SessionLocal


router = APIRouter(tags=["DNS Events"])


def parse_timestamp_utc(value: Any) -> datetime | None:
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


def iso(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()

    return value


def row_to_dict(row: Any, include_raw: bool = False) -> dict[str, Any]:
    item = dict(row)

    for key in ["event_timestamp", "created_at"]:
        if key in item:
            item[key] = iso(item[key])

    if not include_raw:
        item.pop("raw_event", None)

    return item


def parse_raw_alert(value: Any) -> dict[str, Any]:
    if not value:
        return {}

    if isinstance(value, dict):
        return value

    try:
        parsed = json.loads(value)
    except Exception:
        return {}

    return parsed if isinstance(parsed, dict) else {}


def deep_get(payload: dict[str, Any], *path: str) -> Any:
    current: Any = payload

    for key in path:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

    return current


@router.get("/dns-events")
def list_dns_events(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    query_name: str | None = Query(default=None),
    client_ip: str | None = Query(default=None),
    resolver_ip: str | None = Query(default=None),
    agent_name: str | None = Query(default=None),
    query_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    from_ts: str | None = Query(default=None),
    to_ts: str | None = Query(default=None),
    include_raw: bool = Query(default=False),
) -> dict[str, Any]:
    conditions = ["1=1"]
    params: dict[str, Any] = {
        "limit": limit,
        "offset": offset,
    }

    if query_name:
        conditions.append("query_name ILIKE :query_name")
        params["query_name"] = f"%{query_name.strip()}%"

    if client_ip:
        conditions.append("client_ip = :client_ip")
        params["client_ip"] = client_ip.strip()

    if resolver_ip:
        conditions.append("resolver_ip = :resolver_ip")
        params["resolver_ip"] = resolver_ip.strip()

    if agent_name:
        conditions.append("agent_name ILIKE :agent_name")
        params["agent_name"] = f"%{agent_name.strip()}%"

    if query_type:
        conditions.append("upper(query_type) = upper(:query_type)")
        params["query_type"] = query_type.strip()

    if source:
        conditions.append("source = :source")
        params["source"] = source.strip()

    parsed_from = parse_timestamp_utc(from_ts)
    parsed_to = parse_timestamp_utc(to_ts)

    if from_ts and not parsed_from:
        raise HTTPException(status_code=400, detail="Invalid from_ts timestamp.")

    if to_ts and not parsed_to:
        raise HTTPException(status_code=400, detail="Invalid to_ts timestamp.")

    if parsed_from:
        conditions.append("event_timestamp >= :from_ts")
        params["from_ts"] = parsed_from

    if parsed_to:
        conditions.append("event_timestamp <= :to_ts")
        params["to_ts"] = parsed_to

    where_clause = " AND ".join(conditions)

    db = SessionLocal()

    try:
        total = db.execute(
            text(f"""
                SELECT count(*)
                FROM dns_events
                WHERE {where_clause}
            """),
            params,
        ).scalar()

        rows = (
            db.execute(
                text(f"""
                    SELECT
                        id,
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
                        event_fingerprint,
                        created_at
                    FROM dns_events
                    WHERE {where_clause}
                    ORDER BY event_timestamp DESC NULLS LAST, id DESC
                    LIMIT :limit OFFSET :offset
                """),
                params,
            )
            .mappings()
            .all()
        )

        return {
            "items": [row_to_dict(row, include_raw=include_raw) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            "filters": {
                "query_name": query_name,
                "client_ip": client_ip,
                "resolver_ip": resolver_ip,
                "agent_name": agent_name,
                "query_type": query_type,
                "source": source,
                "from_ts": from_ts,
                "to_ts": to_ts,
            },
        }

    finally:
        db.close()


@router.get("/dns-events/recent")
def recent_dns_events(
    limit: int = Query(default=25, ge=1, le=200),
) -> dict[str, Any]:
    db = SessionLocal()

    try:
        rows = (
            db.execute(
                text("""
                    SELECT
                        id,
                        source,
                        event_timestamp,
                        agent_name,
                        agent_ip,
                        client_ip,
                        resolver_ip,
                        query_name,
                        query_type,
                        query_status,
                        collector,
                        created_at
                    FROM dns_events
                    ORDER BY event_timestamp DESC NULLS LAST, id DESC
                    LIMIT :limit
                """),
                {"limit": limit},
            )
            .mappings()
            .all()
        )

        return {
            "items": [row_to_dict(row) for row in rows],
            "limit": limit,
        }

    finally:
        db.close()


@router.get("/dns-events/summary")
def dns_events_summary() -> dict[str, Any]:
    db = SessionLocal()

    try:
        total = db.execute(text("SELECT count(*) FROM dns_events")).scalar()

        latest = (
            db.execute(
                text("""
                    SELECT
                        id,
                        event_timestamp,
                        agent_name,
                        client_ip,
                        resolver_ip,
                        query_name,
                        query_type,
                        created_at
                    FROM dns_events
                    ORDER BY event_timestamp DESC NULLS LAST, id DESC
                    LIMIT 1
                """)
            )
            .mappings()
            .fetchone()
        )

        by_type = (
            db.execute(
                text("""
                    SELECT query_type, count(*) AS count
                    FROM dns_events
                    GROUP BY query_type
                    ORDER BY count DESC
                    LIMIT 20
                """)
            )
            .mappings()
            .all()
        )

        top_domains = (
            db.execute(
                text("""
                    SELECT query_name, count(*) AS count
                    FROM dns_events
                    WHERE query_name IS NOT NULL
                    GROUP BY query_name
                    ORDER BY count DESC
                    LIMIT 20
                """)
            )
            .mappings()
            .all()
        )

        top_clients = (
            db.execute(
                text("""
                    SELECT coalesce(agent_name, client_ip, '-') AS client, count(*) AS count
                    FROM dns_events
                    GROUP BY coalesce(agent_name, client_ip, '-')
                    ORDER BY count DESC
                    LIMIT 20
                """)
            )
            .mappings()
            .all()
        )

        latest_event = row_to_dict(latest) if latest else None
        freshness_seconds = None

        if latest and latest.get("event_timestamp"):
            freshness_seconds = int(
                (
                    datetime.now(timezone.utc)
                    - latest["event_timestamp"].astimezone(timezone.utc)
                ).total_seconds()
            )

        return {
            "total": total,
            "latest_event": latest_event,
            "latest_event_freshness_seconds": freshness_seconds,
            "by_query_type": [dict(row) for row in by_type],
            "top_domains": [dict(row) for row in top_domains],
            "top_clients": [dict(row) for row in top_clients],
        }

    finally:
        db.close()


@router.get("/incidents/{incident_id}/dns-evidence")
def incident_dns_evidence(
    incident_id: int,
    window_minutes: int = Query(default=120, ge=5, le=1440),
    limit: int = Query(default=50, ge=1, le=300),
) -> dict[str, Any]:
    db = SessionLocal()

    try:
        incident = (
            db.execute(
                text("""
                    SELECT id, timestamp, agent, raw_alert
                    FROM incidents
                    WHERE id = :incident_id
                """),
                {"incident_id": incident_id},
            )
            .mappings()
            .fetchone()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found.")

        incident_ts = parse_timestamp_utc(incident.get("timestamp"))

        if not incident_ts:
            return {
                "incident_id": incident_id,
                "source": "dns_events",
                "available": False,
                "reason": "incident_timestamp_unavailable",
                "window_minutes": window_minutes,
                "matched_agents": [],
                "matched_client_ips": [],
                "summary": {
                    "total": 0,
                    "unique_domains": 0,
                    "query_types": [],
                },
                "items": [],
            }

        raw_alert = parse_raw_alert(incident.get("raw_alert"))

        candidate_agents = {
            str(incident.get("agent") or "").strip(),
            str(deep_get(raw_alert, "agent", "name") or "").strip(),
        }
        candidate_agents = {value for value in candidate_agents if value and value != "-"}

        candidate_ips = {
            str(deep_get(raw_alert, "agent", "ip") or "").strip(),
            str(deep_get(raw_alert, "data", "srcip") or "").strip(),
            str(deep_get(raw_alert, "data", "src_ip") or "").strip(),
        }
        candidate_ips = {value for value in candidate_ips if value and value != "-"}

        start_ts = incident_ts - timedelta(minutes=window_minutes)
        end_ts = incident_ts + timedelta(minutes=window_minutes)

        conditions = ["event_timestamp BETWEEN :start_ts AND :end_ts"]
        params: dict[str, Any] = {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "limit": limit,
        }

        match_clauses: list[str] = []

        for index, agent in enumerate(sorted(candidate_agents)[:20]):
            key = f"agent_{index}"
            params[key] = agent
            match_clauses.append(f"agent_name = :{key}")

        for index, ip in enumerate(sorted(candidate_ips)[:20]):
            key = f"ip_{index}"
            params[key] = ip
            match_clauses.append(f"client_ip = :{key}")

        if not match_clauses:
            return {
                "incident_id": incident_id,
                "source": "dns_events",
                "available": False,
                "reason": "no_agent_or_client_ip_candidates",
                "window_minutes": window_minutes,
                "matched_agents": [],
                "matched_client_ips": [],
                "summary": {
                    "total": 0,
                    "unique_domains": 0,
                    "query_types": [],
                },
                "items": [],
            }

        conditions.append("(" + " OR ".join(match_clauses) + ")")
        where_clause = " AND ".join(conditions)

        rows = (
            db.execute(
                text(f"""
                    SELECT
                        id,
                        source,
                        raw_event_id,
                        source_event_id,
                        event_timestamp,
                        agent_name,
                        agent_ip,
                        client_ip,
                        resolver_ip,
                        query_name,
                        query_type,
                        query_status,
                        collector,
                        raw_line,
                        created_at
                    FROM dns_events
                    WHERE {where_clause}
                    ORDER BY event_timestamp DESC NULLS LAST, id DESC
                    LIMIT :limit
                """),
                params,
            )
            .mappings()
            .all()
        )

        query_types = (
            db.execute(
                text(f"""
                    SELECT query_type, count(*) AS count
                    FROM dns_events
                    WHERE {where_clause}
                    GROUP BY query_type
                    ORDER BY count DESC
                """),
                params,
            )
            .mappings()
            .all()
        )

        unique_domains = db.execute(
            text(f"""
                SELECT count(DISTINCT query_name)
                FROM dns_events
                WHERE {where_clause}
            """),
            params,
        ).scalar()

        items = [row_to_dict(row) for row in rows]

        return {
            "incident_id": incident_id,
            "source": "dns_events",
            "available": len(items) > 0,
            "reason": "matched_dns_telemetry" if items else "no_related_dns_events_found",
            "window_minutes": window_minutes,
            "matched_agents": sorted(candidate_agents),
            "matched_client_ips": sorted(candidate_ips),
            "summary": {
                "total": len(items),
                "unique_domains": unique_domains or 0,
                "query_types": [dict(row) for row in query_types],
            },
            "items": items,
        }

    finally:
        db.close()
