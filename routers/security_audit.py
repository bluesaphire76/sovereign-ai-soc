from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_

from database import SessionLocal
from models import SecurityAuditEvent
from security.auth import require_admin


router = APIRouter()


def serialize_security_audit_event(row: SecurityAuditEvent) -> dict:
    details = None

    if row.details_json:
        try:
            details = json.loads(row.details_json)
        except json.JSONDecodeError:
            details = {"raw": row.details_json}

    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "event_type": row.event_type,
        "outcome": row.outcome,
        "actor_user_id": row.actor_user_id,
        "actor_username": row.actor_username,
        "actor_role": row.actor_role,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "target_username": row.target_username,
        "method": row.method,
        "path": row.path,
        "client_ip": row.client_ip,
        "user_agent": row.user_agent,
        "details": details,
    }


def parse_security_audit_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    normalized = value.strip()

    if not normalized:
        return None

    try:
        if len(normalized) == 10:
            normalized = f"{normalized}T00:00:00+00:00"

        return datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="date_from/date_to must be ISO timestamps or YYYY-MM-DD dates.",
        ) from exc


@router.get("/security-audit/events")
def list_security_audit_events(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    event_type: str | None = Query(None),
    outcome: str | None = Query(None),
    actor_username: str | None = Query(None),
    target_type: str | None = Query(None),
    target_id: str | None = Query(None),
    search: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    current_user: dict = Depends(require_admin),
):
    db = SessionLocal()

    try:
        offset = (page - 1) * limit
        query = db.query(SecurityAuditEvent)

        if event_type and event_type.upper() != "ALL":
            query = query.filter(SecurityAuditEvent.event_type == event_type.upper().strip())

        if outcome and outcome.upper() != "ALL":
            query = query.filter(SecurityAuditEvent.outcome == outcome.upper().strip())

        if actor_username:
            query = query.filter(SecurityAuditEvent.actor_username.ilike(f"%{actor_username.strip()}%"))

        if target_type and target_type.upper() != "ALL":
            query = query.filter(SecurityAuditEvent.target_type == target_type.upper().strip())

        if target_id:
            query = query.filter(SecurityAuditEvent.target_id == target_id.strip())

        parsed_date_from = parse_security_audit_datetime(date_from)
        parsed_date_to = parse_security_audit_datetime(date_to)

        if parsed_date_from:
            query = query.filter(SecurityAuditEvent.created_at >= parsed_date_from)

        if parsed_date_to:
            if date_to and len(date_to.strip()) == 10:
                parsed_date_to = parsed_date_to.replace(
                    hour=23,
                    minute=59,
                    second=59,
                    microsecond=999999,
                )

            query = query.filter(SecurityAuditEvent.created_at <= parsed_date_to)

        if search:
            value = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    SecurityAuditEvent.event_type.ilike(value),
                    SecurityAuditEvent.outcome.ilike(value),
                    SecurityAuditEvent.actor_username.ilike(value),
                    SecurityAuditEvent.actor_role.ilike(value),
                    SecurityAuditEvent.target_type.ilike(value),
                    SecurityAuditEvent.target_id.ilike(value),
                    SecurityAuditEvent.target_username.ilike(value),
                    SecurityAuditEvent.method.ilike(value),
                    SecurityAuditEvent.path.ilike(value),
                    SecurityAuditEvent.client_ip.ilike(value),
                    SecurityAuditEvent.details_json.ilike(value),
                )
            )

        total = query.with_entities(func.count(SecurityAuditEvent.id)).scalar() or 0

        rows = (
            query.order_by(
                SecurityAuditEvent.created_at.desc().nullslast(),
                SecurityAuditEvent.id.desc(),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

        total_pages = max((total + limit - 1) // limit, 1)

        return {
            "items": [serialize_security_audit_event(row) for row in rows],
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        }
    finally:
        db.close()
