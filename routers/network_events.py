from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import text

from database import engine


router = APIRouter(prefix="/network-events", tags=["network-events"])


class NetworkEventItem(BaseModel):
    id: int
    source: str | None = None
    event_type: str
    event_timestamp: datetime | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    proto: str | None = None
    app_proto: str | None = None
    hostname: str | None = None
    url: str | None = None
    http_method: str | None = None
    http_user_agent: str | None = None
    tls_sni: str | None = None
    alert_signature: str | None = None
    alert_category: str | None = None
    alert_severity: int | None = None
    created_at: datetime | None = None


class NetworkEventsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[NetworkEventItem]


class NetworkEventsSummary(BaseModel):
    total: int
    by_event_type: list[dict[str, Any]]
    top_destinations: list[dict[str, Any]]
    top_hostnames: list[dict[str, Any]]
    latest_event_timestamp: datetime | None = None
    latest_insert_timestamp: datetime | None = None


@router.get("", response_model=NetworkEventsResponse)
def list_network_events(
    event_type: str | None = Query(default=None),
    src_ip: str | None = Query(default=None),
    dest_ip: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> NetworkEventsResponse:
    filters = []
    params: dict[str, Any] = {"limit": limit, "offset": offset}

    if event_type:
        filters.append("event_type = :event_type")
        params["event_type"] = event_type

    if src_ip:
        filters.append("src_ip = :src_ip")
        params["src_ip"] = src_ip

    if dest_ip:
        filters.append("dest_ip = :dest_ip")
        params["dest_ip"] = dest_ip

    if hostname:
        filters.append("hostname ILIKE :hostname")
        params["hostname"] = f"%{hostname}%"

    where_clause = ""
    if filters:
        where_clause = "WHERE " + " AND ".join(filters)

    with engine.begin() as conn:
        total = conn.execute(
            text(f"SELECT count(*) FROM network_events {where_clause}"),
            params,
        ).scalar() or 0

        rows = conn.execute(
            text(f"""
                SELECT
                    id, source, event_type, event_timestamp,
                    src_ip, src_port, dest_ip, dest_port,
                    proto, app_proto, hostname, url, http_method,
                    http_user_agent, tls_sni, alert_signature,
                    alert_category, alert_severity, created_at
                FROM network_events
                {where_clause}
                ORDER BY event_timestamp DESC NULLS LAST, id DESC
                LIMIT :limit OFFSET :offset
            """),
            params,
        ).mappings().all()

    return NetworkEventsResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[NetworkEventItem(**dict(row)) for row in rows],
    )


@router.get("/recent", response_model=list[NetworkEventItem])
def recent_network_events(
    limit: int = Query(default=25, ge=1, le=100),
) -> list[NetworkEventItem]:
    with engine.begin() as conn:
        rows = conn.execute(
            text("""
                SELECT
                    id, source, event_type, event_timestamp,
                    src_ip, src_port, dest_ip, dest_port,
                    proto, app_proto, hostname, url, http_method,
                    http_user_agent, tls_sni, alert_signature,
                    alert_category, alert_severity, created_at
                FROM network_events
                ORDER BY event_timestamp DESC NULLS LAST, id DESC
                LIMIT :limit
            """),
            {"limit": limit},
        ).mappings().all()

    return [NetworkEventItem(**dict(row)) for row in rows]


@router.get("/summary", response_model=NetworkEventsSummary)
def network_events_summary() -> NetworkEventsSummary:
    with engine.begin() as conn:
        total = conn.execute(text("SELECT count(*) FROM network_events")).scalar() or 0

        by_event_type = conn.execute(text("""
            SELECT event_type, count(*)::int AS count
            FROM network_events
            GROUP BY event_type
            ORDER BY count DESC
        """)).mappings().all()

        top_destinations = conn.execute(text("""
            SELECT dest_ip, count(*)::int AS count
            FROM network_events
            WHERE dest_ip IS NOT NULL
            GROUP BY dest_ip
            ORDER BY count DESC
            LIMIT 10
        """)).mappings().all()

        top_hostnames = conn.execute(text("""
            SELECT hostname, count(*)::int AS count
            FROM network_events
            WHERE hostname IS NOT NULL
            GROUP BY hostname
            ORDER BY count DESC
            LIMIT 10
        """)).mappings().all()

        latest = conn.execute(text("""
            SELECT
                max(event_timestamp) AS latest_event_timestamp,
                max(created_at) AS latest_insert_timestamp
            FROM network_events
        """)).mappings().one()

    return NetworkEventsSummary(
        total=total,
        by_event_type=[dict(row) for row in by_event_type],
        top_destinations=[dict(row) for row in top_destinations],
        top_hostnames=[dict(row) for row in top_hostnames],
        latest_event_timestamp=latest["latest_event_timestamp"],
        latest_insert_timestamp=latest["latest_insert_timestamp"],
    )
