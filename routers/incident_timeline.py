from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request

from database import SessionLocal
from incident_timeline import (
    TimelineQuery,
    build_incident_timeline_capabilities,
    build_incident_timeline_payload,
    build_incident_timeline_summary,
)


router = APIRouter(tags=["Incident Timeline"])


def _current_user(request: Request) -> dict:
    return getattr(request.state, "current_user", None) or {}


def _parse_categories(values: list[str] | None) -> set[str] | None:
    if not values:
        return None

    categories: set[str] = set()
    for value in values:
        for item in str(value or "").split(","):
            cleaned = item.strip().upper()
            if cleaned:
                categories.add(cleaned)

    return categories or None


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid datetime: {value}") from exc


def _timeline_query(
    *,
    category: list[str] | None,
    source: str | None,
    severity: str | None,
    time_from: str | None,
    time_to: str | None,
    include_raw_payload: bool,
    limit: int,
    cursor: str | None,
    sort: str,
    key_only: bool,
    entity: str | None,
) -> TimelineQuery:
    try:
        cursor_value = int(cursor or 0)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid cursor.") from exc

    return TimelineQuery(
        categories=_parse_categories(category),
        source=source,
        severity=severity,
        time_from=_parse_datetime(time_from),
        time_to=_parse_datetime(time_to),
        include_raw_payload=include_raw_payload,
        limit=limit,
        cursor=cursor_value,
        sort=sort,
        key_only=key_only,
        entity=entity,
    )


@router.get("/incidents/{incident_id}/timeline")
def incident_timeline(
    incident_id: int,
    request: Request,
    category: list[str] | None = Query(default=None),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    time_from: str | None = Query(default=None),
    time_to: str | None = Query(default=None),
    include_raw_payload: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=500),
    cursor: str | None = Query(default=None),
    sort: str = Query(default="asc", pattern="^(asc|desc)$"),
    key_only: bool = Query(default=False),
    entity: str | None = Query(default=None),
):
    db = SessionLocal()

    try:
        return build_incident_timeline_payload(
            db,
            incident_id,
            _timeline_query(
                category=category,
                source=source,
                severity=severity,
                time_from=time_from,
                time_to=time_to,
                include_raw_payload=include_raw_payload,
                limit=limit,
                cursor=cursor,
                sort=sort,
                key_only=key_only,
                entity=entity,
            ),
            current_user=_current_user(request),
            request=request,
        )

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Incident not found.") from exc

    finally:
        db.close()


@router.get("/incidents/{incident_id}/timeline/summary")
def incident_timeline_summary(
    incident_id: int,
    category: list[str] | None = Query(default=None),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    time_from: str | None = Query(default=None),
    time_to: str | None = Query(default=None),
    key_only: bool = Query(default=False),
    entity: str | None = Query(default=None),
):
    db = SessionLocal()

    try:
        return build_incident_timeline_summary(
            db,
            incident_id,
            _timeline_query(
                category=category,
                source=source,
                severity=severity,
                time_from=time_from,
                time_to=time_to,
                include_raw_payload=False,
                limit=500,
                cursor=None,
                sort="asc",
                key_only=key_only,
                entity=entity,
            ),
        )

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Incident not found.") from exc

    finally:
        db.close()


@router.get("/incidents/{incident_id}/timeline/capabilities")
def incident_timeline_capabilities(incident_id: int):
    db = SessionLocal()

    try:
        return build_incident_timeline_capabilities(db, incident_id)

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Incident not found.") from exc

    finally:
        db.close()
