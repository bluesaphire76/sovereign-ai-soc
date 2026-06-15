from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func

from models import Incident, IncidentCase, RawEvent, SecurityAlert


TERMINAL_STATUSES = {"CLOSED", "FALSE_POSITIVE"}
DEFAULT_TREND_DAYS = 7
MAX_TREND_DAYS = 30
ROW_SCAN_LIMIT = 10_000


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _iso_date(value: date) -> str:
    return value.isoformat()


def _normalize_days(days: int | None) -> int:
    try:
        value = int(days or DEFAULT_TREND_DAYS)
    except (TypeError, ValueError):
        value = DEFAULT_TREND_DAYS

    return max(1, min(value, MAX_TREND_DAYS))


def _status_open(value: str | None) -> bool:
    return str(value or "NEW").upper() not in TERMINAL_STATUSES


def _age_bucket(timestamp: datetime | None, now: datetime) -> str:
    if timestamp is None:
        return "Unknown"

    age_seconds = max((now - timestamp).total_seconds(), 0)
    age_days = age_seconds / 86_400

    if age_days <= 1:
        return "0-24h"
    if age_days <= 3:
        return "1-3d"
    if age_days <= 7:
        return "3-7d"
    return ">7d"


def build_incident_trend(
    db,
    *,
    days: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    window_days = _normalize_days(days)
    effective_now = now or utc_now()
    end_date = effective_now.date()
    start_date = end_date - timedelta(days=window_days - 1)

    buckets = {
        start_date + timedelta(days=offset): {
            "date": _iso_date(start_date + timedelta(days=offset)),
            "label": (start_date + timedelta(days=offset)).strftime("%d/%m"),
            "total": 0,
            "high_or_critical": 0,
            "critical": 0,
            "risk_sum": 0,
            "risk_count": 0,
        }
        for offset in range(window_days)
    }

    rows = (
        db.query(Incident.timestamp, Incident.risk_score)
        .order_by(Incident.id.desc())
        .limit(ROW_SCAN_LIMIT)
        .all()
    )

    for row in rows:
        timestamp = _parse_datetime(row.timestamp)
        if not timestamp:
            continue

        bucket_date = timestamp.date()
        bucket = buckets.get(bucket_date)
        if bucket is None:
            continue

        risk_score = int(row.risk_score or 0)
        bucket["total"] += 1
        bucket["risk_sum"] += risk_score
        bucket["risk_count"] += 1

        if risk_score >= 60:
            bucket["high_or_critical"] += 1
        if risk_score >= 80:
            bucket["critical"] += 1

    items = []
    for bucket in buckets.values():
        risk_count = bucket.pop("risk_count")
        risk_sum = bucket.pop("risk_sum")
        bucket["average_risk"] = round(risk_sum / risk_count, 2) if risk_count else 0
        items.append(bucket)

    return {
        "window_days": window_days,
        "start_date": _iso_date(start_date),
        "end_date": _iso_date(end_date),
        "items": items,
    }


def build_queue_aging(db, *, now: datetime | None = None) -> dict[str, Any]:
    effective_now = now or utc_now()
    ordered_buckets = ["0-24h", "1-3d", "3-7d", ">7d", "Unknown"]
    buckets = {
        name: {
            "name": name,
            "incidents": 0,
            "cases": 0,
            "total": 0,
            "sla_breached": 0,
        }
        for name in ordered_buckets
    }

    incidents = (
        db.query(Incident.timestamp, Incident.status)
        .order_by(Incident.id.desc())
        .limit(ROW_SCAN_LIMIT)
        .all()
    )

    for incident in incidents:
        if not _status_open(incident.status):
            continue

        bucket = buckets[_age_bucket(_parse_datetime(incident.timestamp), effective_now)]
        bucket["incidents"] += 1
        bucket["total"] += 1

    cases = (
        db.query(IncidentCase.created_at, IncidentCase.status, IncidentCase.sla_due_at)
        .order_by(IncidentCase.id.desc())
        .limit(ROW_SCAN_LIMIT)
        .all()
    )

    for case in cases:
        if not _status_open(case.status):
            continue

        bucket = buckets[_age_bucket(_parse_datetime(case.created_at), effective_now)]
        bucket["cases"] += 1
        bucket["total"] += 1

        due_at = _parse_datetime(case.sla_due_at)
        if due_at and due_at < effective_now:
            bucket["sla_breached"] += 1

    return {
        "generated_at": effective_now.isoformat(),
        "items": [
            buckets[name]
            for name in ordered_buckets
            if buckets[name]["total"] > 0 or name != "Unknown"
        ],
    }


def build_detection_funnel(db) -> dict[str, Any]:
    raw_events = int(db.query(func.count(RawEvent.id)).scalar() or 0)
    security_alerts = int(db.query(func.count(SecurityAlert.id)).scalar() or 0)
    incidents = int(db.query(func.count(Incident.id)).scalar() or 0)
    cases = int(db.query(func.count(IncidentCase.id)).scalar() or 0)

    status_rows = (
        db.query(SecurityAlert.status, func.count(SecurityAlert.id).label("count"))
        .group_by(SecurityAlert.status)
        .all()
    )
    status_counts = {
        str(row.status or "OBSERVED").upper(): int(row.count or 0)
        for row in status_rows
    }

    suppressed_noise = sum(
        count
        for status, count in status_counts.items()
        if "SUPPRESS" in status or "NOISE" in status
    )
    aggregated_duplicate = sum(
        count
        for status, count in status_counts.items()
        if "AGGREGATED" in status or "DUPLICATE" in status
    )
    observed_no_incident = sum(
        count for status, count in status_counts.items() if "NO_INCIDENT" in status
    )

    return {
        "items": [
            {"name": "Raw events", "value": raw_events},
            {"name": "Security alerts", "value": security_alerts},
            {"name": "Incidents", "value": incidents},
            {"name": "Cases", "value": cases},
        ],
        "secondary_items": [
            {"name": "Suppressed", "value": suppressed_noise},
            {"name": "Duplicates", "value": aggregated_duplicate},
            {"name": "Observed only", "value": observed_no_incident},
        ],
        "status_counts": status_counts,
    }
