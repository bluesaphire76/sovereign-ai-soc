from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, or_

from database import SessionLocal
from demo_data_management import (
    demo_incident_filter,
    incident_demo_origin,
)
from models import (
    CaseClosureChecklist,
    CaseIncident,
    Incident,
    IncidentAudit,
    IncidentCase,
    IncidentNote,
    utc_now,
)
from qdrant_auto_index import schedule_incident_auto_index
from schemas.incidents import IncidentNoteCreate, IncidentStatusUpdate
from security.audit import security_audit_actor, write_security_audit
from services.cases import serialize_case
from timezone_utils import APP_TIMEZONE, format_timestamp_local, normalize_timestamp_utc


router = APIRouter()


VALID_INCIDENT_STATUSES = {
    "NEW",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
    "FALSE_POSITIVE",
    # Legacy-compatible status kept for existing records and executive metrics.
    "ESCALATED",
}


@router.get("/incidents")
def list_incidents(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    risk: str | None = Query(None),
    host: str | None = Query(None),
    search: str | None = Query(None),
    priority: str | None = Query(None),
    correlation_type: str | None = Query(None),
    correlated: str | None = Query(None),
    mitre: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    demo_only: bool = Query(False),
):
    db = SessionLocal()

    try:
        offset = (page - 1) * limit

        query = db.query(Incident)

        if demo_only:
            query = query.filter(demo_incident_filter())

        if status and status.upper() != "ALL":
            query = query.filter(Incident.status == status.upper())

        if host:
            query = query.filter(Incident.agent.ilike(f"%{host}%"))

        if search:
            query = query.filter(Incident.rule.ilike(f"%{search}%"))

        if priority and priority.upper() != "ALL":
            query = query.filter(Incident.recommended_priority == priority.upper())

        if correlation_type:
            query = query.filter(Incident.correlation_type.ilike(f"%{correlation_type}%"))

        if mitre:
            query = query.filter(Incident.mitre.ilike(f"%{mitre}%"))

        if correlated and correlated.upper() != "ALL":
            correlated_value = correlated.lower()

            if correlated_value in {"true", "yes", "1"}:
                query = query.filter(Incident.correlated == True)
            elif correlated_value in {"false", "no", "0"}:
                query = query.filter(Incident.correlated == False)

        if date_from:
            query = query.filter(Incident.timestamp >= f"{date_from}T00:00:00+00:00")

        if date_to:
            query = query.filter(Incident.timestamp <= f"{date_to}T23:59:59+00:00")

        if risk and risk.upper() != "ALL":
            risk_value = risk.lower()

            if risk_value == "low":
                query = query.filter(
                    or_(
                        Incident.risk_score.is_(None),
                        Incident.risk_score <= 39,
                    )
                )
            elif risk_value == "medium":
                query = query.filter(
                    Incident.risk_score >= 40,
                    Incident.risk_score <= 59,
                )
            elif risk_value == "high":
                query = query.filter(
                    Incident.risk_score >= 60,
                    Incident.risk_score <= 79,
                )
            elif risk_value == "critical":
                query = query.filter(Incident.risk_score >= 80)

        total = query.with_entities(func.count(Incident.id)).scalar() or 0

        incidents = (
            query.order_by(Incident.timestamp.desc().nullslast(), Incident.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        total_pages = max((total + limit - 1) // limit, 1)

        return {
            "items": [
                {
                    "id": item.id,
                    "status": item.status,
                    "timestamp": normalize_timestamp_utc(item.timestamp),
                    "timestamp_local": format_timestamp_local(item.timestamp),
                    "timezone": APP_TIMEZONE,
                    "agent": item.agent,
                    "rule": item.rule,
                    "level": item.level,
                    "mitre": item.mitre,
                    "risk_score": item.risk_score,
                    "correlation_score": item.correlation_score,
                    "correlated": item.correlated,
                    "correlation_type": item.correlation_type,
                    "recommended_priority": item.recommended_priority,
                    "is_demo": incident_demo_origin(item) is not None,
                    "demo_origin": incident_demo_origin(item),
                }
                for item in incidents
            ],
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        }

    finally:
        db.close()


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        return {
            "id": incident.id,
            "status": incident.status,
            "wazuh_doc_id": incident.wazuh_doc_id,
            "timestamp": normalize_timestamp_utc(incident.timestamp),
            "timestamp_local": format_timestamp_local(incident.timestamp),
            "timezone": APP_TIMEZONE,
            "agent": incident.agent,
            "rule": incident.rule,
            "level": incident.level,
            "mitre": incident.mitre,
            "risk_score": incident.risk_score,
            "ai_analysis": incident.ai_analysis,
            "correlated": incident.correlated,
            "correlation_score": incident.correlation_score,
            "correlation_summary": incident.correlation_summary,
            "raw_alert": incident.raw_alert,
            "attack_chain": incident.attack_chain,
            "correlation_type": incident.correlation_type,
            "escalation_reason": incident.escalation_reason,
            "recommended_priority": incident.recommended_priority,
        }

    finally:
        db.close()


@router.patch("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    request: Request,
):
    requested_status = payload.status.upper()

    if requested_status not in VALID_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed values: {sorted(VALID_INCIDENT_STATUSES)}",
        )

    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        old_status = incident.status or "NEW"

        if old_status != requested_status:
            audit = IncidentAudit(
                incident_id=incident.id,
                event_type="STATUS_CHANGE",
                old_value=old_status,
                new_value=requested_status,
                comment=payload.comment,
                created_by="local_analyst",
            )

            db.add(audit)
            incident.status = requested_status

        db.commit()
        db.refresh(incident)

        if old_status != requested_status:
            schedule_incident_auto_index(
                incident.id,
                reason="incident_status_updated",
            )
            write_security_audit(
                event_type="INCIDENT_STATUS_UPDATED",
                outcome="SUCCESS",
                current_user=security_audit_actor(request),
                target_type="INCIDENT",
                target_id=incident.id,
                request=request,
                details={
                    "old_status": old_status,
                    "new_status": requested_status,
                    "comment_present": bool(payload.comment),
                },
            )

        return {
            "id": incident.id,
            "status": incident.status,
            "message": "Incident status updated",
        }

    finally:
        db.close()


@router.post("/incidents/{incident_id}/case")
def create_case_from_incident(incident_id: int, request: Request):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found.")

        existing_link = (
            db.query(CaseIncident)
            .filter(CaseIncident.incident_id == incident.id)
            .order_by(CaseIncident.id.desc())
            .first()
        )

        if existing_link:
            existing_case = (
                db.query(IncidentCase)
                .filter(IncidentCase.id == existing_link.case_id)
                .first()
            )

            if existing_case:
                incident_count = (
                    db.query(CaseIncident)
                    .filter(CaseIncident.case_id == existing_case.id)
                    .count()
                )

                return {
                    "created": False,
                    "case_id": existing_case.id,
                    "item": serialize_case(existing_case, incident_count),
                }

        actor = security_audit_actor(request) or {}
        actor_username = actor.get("username") or "local_analyst"
        now = utc_now()

        risk_score = incident.risk_score or incident.level or 0
        group_key = f"incident:{incident.id}"

        existing_case_by_group = (
            db.query(IncidentCase)
            .filter(IncidentCase.group_key == group_key)
            .first()
        )

        if existing_case_by_group:
            incident_count = (
                db.query(CaseIncident)
                .filter(CaseIncident.case_id == existing_case_by_group.id)
                .count()
            )

            return {
                "created": False,
                "case_id": existing_case_by_group.id,
                "item": serialize_case(
                    existing_case_by_group,
                    incident_count,
                ),
            }

        if risk_score >= 81:
            severity = "CRITICAL"
        elif risk_score >= 61:
            severity = "HIGH"
        elif risk_score >= 31:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        case_fields = {}

        def set_case_field(name, value):
            if hasattr(IncidentCase, name):
                case_fields[name] = value

        set_case_field("group_key", group_key)
        set_case_field("title", f"Incident #{incident.id} investigation")
        set_case_field("status", "OPEN")
        set_case_field("severity", severity)
        set_case_field("severity_review", severity)
        set_case_field("agent", incident.agent)
        set_case_field("correlation_type", incident.correlation_type or "manual_incident_escalation")
        set_case_field("risk_score", risk_score)
        set_case_field("owner", actor_username)
        set_case_field("created_by", actor_username)
        set_case_field("created_at", now)
        set_case_field("updated_at", now)
        set_case_field(
            "summary",
            f"Case created from incident #{incident.id}: {incident.rule or 'Wazuh alert'}",
        )

        case_row = IncidentCase(**case_fields)
        db.add(case_row)
        db.flush()

        link_fields = {
            "case_id": case_row.id,
            "incident_id": incident.id,
        }

        if hasattr(CaseIncident, "created_at"):
            link_fields["created_at"] = now

        db.add(CaseIncident(**link_fields))

        if hasattr(CaseClosureChecklist, "case_id"):
            closure_fields = {"case_id": case_row.id}

            if hasattr(CaseClosureChecklist, "created_at"):
                closure_fields["created_at"] = now

            if hasattr(CaseClosureChecklist, "updated_at"):
                closure_fields["updated_at"] = now

            db.add(CaseClosureChecklist(**closure_fields))

        write_security_audit(
            event_type="CASE_CREATED_FROM_INCIDENT",
            outcome="SUCCESS",
            current_user=actor,
            target_type="CASE",
            target_id=case_row.id,
            request=request,
            details={
                "incident_id": incident.id,
                "case_id": case_row.id,
                "severity": severity,
                "risk_score": risk_score,
            },
        )

        db.commit()
        db.refresh(case_row)
        schedule_incident_auto_index(
            incident.id,
            reason="incident_case_link_created",
        )

        return {
            "created": True,
            "case_id": case_row.id,
            "item": serialize_case(case_row, 1),
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception as exc:
        db.rollback()
        write_security_audit(
            event_type="CASE_CREATED_FROM_INCIDENT",
            outcome="FAILURE",
            current_user=security_audit_actor(request),
            target_type="INCIDENT",
            target_id=incident_id,
            request=request,
            details={"error": "internal_error"},
        )
        raise

    finally:
        db.close()


@router.get("/incidents/{incident_id}/audit")
def get_incident_audit(incident_id: int):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        rows = (
            db.query(IncidentAudit)
            .filter(IncidentAudit.incident_id == incident_id)
            .order_by(IncidentAudit.created_at.asc(), IncidentAudit.id.asc())
            .all()
        )

        return [
            {
                "id": row.id,
                "incident_id": row.incident_id,
                "event_type": row.event_type,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment": row.comment,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]

    finally:
        db.close()


@router.get("/incidents/{incident_id}/notes")
def get_incident_notes(incident_id: int):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        rows = (
            db.query(IncidentNote)
            .filter(IncidentNote.incident_id == incident_id)
            .order_by(IncidentNote.created_at.desc(), IncidentNote.id.desc())
            .all()
        )

        return [
            {
                "id": row.id,
                "incident_id": row.incident_id,
                "note": row.note,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]

    finally:
        db.close()


@router.post("/incidents/{incident_id}/notes")
def create_incident_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    request: Request,
):
    note_text = payload.note.strip()

    if not note_text:
        raise HTTPException(status_code=400, detail="Note cannot be empty")

    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        created_by = payload.created_by or "local_analyst"

        note = IncidentNote(
            incident_id=incident.id,
            note=note_text,
            created_by=created_by,
        )

        db.add(note)
        db.flush()

        audit = IncidentAudit(
            incident_id=incident.id,
            event_type="NOTE_ADDED",
            old_value=None,
            new_value=f"note:{note.id}",
            comment=note_text,
            created_by=created_by,
        )

        db.add(audit)
        db.commit()
        db.refresh(note)
        schedule_incident_auto_index(
            incident.id,
            reason="incident_note_created",
        )

        write_security_audit(
            event_type="INCIDENT_NOTE_CREATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="INCIDENT",
            target_id=incident.id,
            request=request,
            details={
                "note_id": note.id,
                "created_by": created_by,
                "note_length": len(note.note or ""),
            },
        )

        return {
            "id": note.id,
            "incident_id": note.incident_id,
            "note": note.note,
            "created_by": note.created_by,
            "created_at": note.created_at.isoformat() if note.created_at else None,
        }

    finally:
        db.close()
