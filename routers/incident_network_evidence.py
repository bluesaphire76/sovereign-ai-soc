from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import text

from database import engine


router = APIRouter(tags=["incident-network-evidence"])

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class NetworkEvidenceItem(BaseModel):
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


class IncidentNetworkEvidenceResponse(BaseModel):
    incident_id: int
    incident_timestamp: datetime | None = None
    correlation_window_minutes: int
    matched_ips: list[str]
    matched_hostnames: list[str]
    summary: dict[str, int]
    items: list[NetworkEvidenceItem]


def parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    normalized = raw.replace("Z", "+00:00")

    # Convert +0000 / -0500 into +00:00 / -05:00 for fromisoformat.
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = f"{normalized[:-2]}:{normalized[-2:]}"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def load_json_maybe(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, (dict, list)):
        return value

    if not isinstance(value, str):
        return value

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def walk_values(value: Any) -> list[str]:
    values: list[str] = []

    if value is None:
        return values

    if isinstance(value, dict):
        for child in value.values():
            values.extend(walk_values(child))
        return values

    if isinstance(value, list):
        for child in value:
            values.extend(walk_values(child))
        return values

    if isinstance(value, (str, int, float)):
        values.append(str(value))

    return values


def extract_ips(*payloads: Any) -> set[str]:
    candidates: set[str] = set()

    for payload in payloads:
        for value in walk_values(load_json_maybe(payload)):
            for match in IPV4_RE.findall(value):
                octets = match.split(".")
                if all(0 <= int(octet) <= 255 for octet in octets):
                    candidates.add(match)

    return candidates


def add_hostname_candidate(candidates: set[str], value: Any) -> None:
    if not value:
        return

    text_value = str(value).strip()
    if not text_value:
        return

    if IPV4_RE.fullmatch(text_value):
        return

    candidates.add(text_value)


def summarize(rows: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": len(rows),
        "alert": 0,
        "dns": 0,
        "http": 0,
        "tls": 0,
        "flow": 0,
    }

    for row in rows:
        event_type = str(row.get("event_type") or "")
        if event_type in summary:
            summary[event_type] += 1

    return summary


@router.get(
    "/incidents/{incident_id}/network-evidence",
    response_model=IncidentNetworkEvidenceResponse,
)
def get_incident_network_evidence(
    incident_id: int,
    window_minutes: int = Query(default=60, ge=5, le=1440),
    limit: int = Query(default=50, ge=1, le=200),
) -> IncidentNetworkEvidenceResponse:
    with engine.begin() as conn:
        incident = conn.execute(
            text("""
                SELECT
                    id,
                    timestamp,
                    agent,
                    raw_alert,
                    raw_event_id,
                    security_alert_id
                FROM incidents
                WHERE id = :incident_id
            """),
            {"incident_id": incident_id},
        ).mappings().fetchone()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found.")

        raw_event = None
        if incident["raw_event_id"]:
            raw_event = conn.execute(
                text("""
                    SELECT event_timestamp, agent, payload_json
                    FROM raw_events
                    WHERE id = :raw_event_id
                """),
                {"raw_event_id": incident["raw_event_id"]},
            ).mappings().fetchone()

        security_alert = None
        if incident["security_alert_id"]:
            security_alert = conn.execute(
                text("""
                    SELECT event_timestamp, agent, source_event_id
                    FROM security_alerts
                    WHERE id = :security_alert_id
                """),
                {"security_alert_id": incident["security_alert_id"]},
            ).mappings().fetchone()

        incident_timestamp = (
            parse_timestamp(incident["timestamp"])
            or parse_timestamp(raw_event["event_timestamp"] if raw_event else None)
            or parse_timestamp(security_alert["event_timestamp"] if security_alert else None)
        )

        candidate_ips = extract_ips(
            incident["raw_alert"],
            raw_event["payload_json"] if raw_event else None,
            incident["agent"],
            raw_event["agent"] if raw_event else None,
            security_alert["agent"] if security_alert else None,
        )

        candidate_hostnames: set[str] = set()
        add_hostname_candidate(candidate_hostnames, incident["agent"])
        if raw_event:
            add_hostname_candidate(candidate_hostnames, raw_event["agent"])
        if security_alert:
            add_hostname_candidate(candidate_hostnames, security_alert["agent"])

        if incident_timestamp is None or (not candidate_ips and not candidate_hostnames):
            return IncidentNetworkEvidenceResponse(
                incident_id=incident_id,
                incident_timestamp=incident_timestamp,
                correlation_window_minutes=window_minutes,
                matched_ips=sorted(candidate_ips),
                matched_hostnames=sorted(candidate_hostnames),
                summary=summarize([]),
                items=[],
            )

        start_ts = incident_timestamp - timedelta(minutes=window_minutes)
        end_ts = incident_timestamp + timedelta(minutes=window_minutes)

        params: dict[str, Any] = {
            "start_ts": start_ts,
            "end_ts": end_ts,
            "limit": limit,
        }

        match_clauses: list[str] = []

        for index, ip in enumerate(sorted(candidate_ips)[:50]):
            key = f"ip_{index}"
            params[key] = ip
            match_clauses.append(f"(src_ip = :{key} OR dest_ip = :{key})")

        for index, hostname in enumerate(sorted(candidate_hostnames)[:20]):
            key = f"host_{index}"
            params[key] = f"%{hostname}%"
            match_clauses.append(f"(hostname ILIKE :{key} OR tls_sni ILIKE :{key})")

        rows = conn.execute(
            text(f"""
                SELECT
                    id, source, event_type, event_timestamp,
                    src_ip, src_port, dest_ip, dest_port,
                    proto, app_proto, hostname, url, http_method,
                    http_user_agent, tls_sni, alert_signature,
                    alert_category, alert_severity, created_at
                FROM network_events
                WHERE event_timestamp BETWEEN :start_ts AND :end_ts
                  AND ({' OR '.join(match_clauses)})
                ORDER BY event_timestamp DESC NULLS LAST, id DESC
                LIMIT :limit
            """),
            params,
        ).mappings().all()

    item_dicts = [dict(row) for row in rows]

    return IncidentNetworkEvidenceResponse(
        incident_id=incident_id,
        incident_timestamp=incident_timestamp,
        correlation_window_minutes=window_minutes,
        matched_ips=sorted(candidate_ips),
        matched_hostnames=sorted(candidate_hostnames),
        summary=summarize(item_dicts),
        items=[NetworkEvidenceItem(**row) for row in item_dicts],
    )
