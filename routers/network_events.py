from __future__ import annotations

import os
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import text

from database import engine

try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
except ImportError:  # optional local GeoIP enrichment
    geoip2 = None
    AddressNotFoundError = Exception


router = APIRouter(prefix="/network-events", tags=["network-events"])

GEOIP_COUNTRY_DB_PATH = Path(
    os.getenv(
        "AI_SOC_GEOIP_COUNTRY_DB",
        "/home/lele/lab/ai-soc-assistant/data/geoip/GeoLite2-Country.mmdb",
    )
)
_GEOIP_COUNTRY_READER = None


def get_geoip_country_reader():
    global _GEOIP_COUNTRY_READER

    if geoip2 is None:
        return None

    if not GEOIP_COUNTRY_DB_PATH.exists():
        return None

    if _GEOIP_COUNTRY_READER is None:
        _GEOIP_COUNTRY_READER = geoip2.database.Reader(str(GEOIP_COUNTRY_DB_PATH))

    return _GEOIP_COUNTRY_READER




def classify_destination_ip(value: str | None) -> dict[str, Any]:
    """Return conservative local-only destination IP context.

    This intentionally does not perform online GeoIP lookups. Public IP country
    is reported as Unknown unless a local GeoIP database is introduced later.
    """

    if not value:
        return {
            "country": "Unknown",
            "country_code": "UNKNOWN",
            "country_source": "not_available",
            "ip_scope": "unknown",
        }

    try:
        parsed = ip_address(value)
    except ValueError:
        return {
            "country": "Unknown",
            "country_code": "UNKNOWN",
            "country_source": "invalid_ip",
            "ip_scope": "invalid",
        }

    if parsed.is_loopback:
        return {
            "country": "Loopback",
            "country_code": "LOOPBACK",
            "country_source": "local_ip_classification",
            "ip_scope": "loopback",
        }

    if parsed.is_private:
        return {
            "country": "Private / Local network",
            "country_code": "PRIVATE",
            "country_source": "local_ip_classification",
            "ip_scope": "private",
        }

    if parsed.is_link_local:
        return {
            "country": "Link-local",
            "country_code": "LINK_LOCAL",
            "country_source": "local_ip_classification",
            "ip_scope": "link_local",
        }

    if parsed.is_multicast:
        return {
            "country": "Multicast",
            "country_code": "MULTICAST",
            "country_source": "local_ip_classification",
            "ip_scope": "multicast",
        }

    if parsed.is_reserved:
        return {
            "country": "Reserved",
            "country_code": "RESERVED",
            "country_source": "local_ip_classification",
            "ip_scope": "reserved",
        }

    reader = get_geoip_country_reader()
    if reader is not None:
        try:
            response = reader.country(value)
            country = response.country.name or "Unknown"
            country_code = response.country.iso_code or "UNKNOWN"

            return {
                "country": country,
                "country_code": country_code,
                "country_source": "GeoLite2-Country",
                "ip_scope": "public",
            }
        except AddressNotFoundError:
            return {
                "country": "Unknown",
                "country_code": "UNKNOWN",
                "country_source": "geoip_address_not_found",
                "ip_scope": "public",
            }
        except Exception:
            return {
                "country": "Unknown",
                "country_code": "UNKNOWN",
                "country_source": "geoip_lookup_failed",
                "ip_scope": "public",
            }

    return {
        "country": "Unknown",
        "country_code": "UNKNOWN",
        "country_source": "geoip_database_not_configured",
        "ip_scope": "public",
    }


def build_resolver_context(
    dest_ip: str | None,
    resolver_rows: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Return DNS resolver context without implying DNS resolution causality."""

    if not dest_ip or dest_ip not in resolver_rows:
        return {
            "is_observed_resolver": False,
            "label": "not observed as DNS resolver",
            "resolver_ip": None,
            "dns_event_count": 0,
            "latest_dns_event_timestamp": None,
        }

    row = resolver_rows[dest_ip]

    return {
        "is_observed_resolver": True,
        "label": "observed DNS resolver",
        "resolver_ip": dest_ip,
        "dns_event_count": row.get("dns_event_count") or 0,
        "latest_dns_event_timestamp": row.get("latest_dns_event_timestamp"),
    }



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

        top_destination_rows = conn.execute(text("""
            SELECT dest_ip, count(*)::int AS count
            FROM network_events
            WHERE dest_ip IS NOT NULL
            GROUP BY dest_ip
            ORDER BY count DESC
            LIMIT 10
        """)).mappings().all()

        destination_ips = [
            row["dest_ip"]
            for row in top_destination_rows
            if row.get("dest_ip")
        ]

        resolver_context_rows: dict[str, dict[str, Any]] = {}
        if destination_ips:
            resolver_context_rows = {
                row["resolver_ip"]: dict(row)
                for row in conn.execute(
                    text("""
                        SELECT
                            resolver_ip,
                            count(*)::int AS dns_event_count,
                            max(event_timestamp) AS latest_dns_event_timestamp
                        FROM dns_events
                        WHERE resolver_ip = ANY(:destination_ips)
                        GROUP BY resolver_ip
                    """),
                    {"destination_ips": destination_ips},
                ).mappings().all()
                if row.get("resolver_ip")
            }

        top_destinations = []
        for row in top_destination_rows:
            item = dict(row)
            item.update(classify_destination_ip(item.get("dest_ip")))
            item["resolver_context"] = build_resolver_context(
                item.get("dest_ip"),
                resolver_context_rows,
            )
            top_destinations.append(item)

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
        top_destinations=top_destinations,
        top_hostnames=[dict(row) for row in top_hostnames],
        latest_event_timestamp=latest["latest_event_timestamp"],
        latest_insert_timestamp=latest["latest_insert_timestamp"],
    )
