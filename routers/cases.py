from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import func, case as sql_case

from database import SessionLocal
from demo_data_management import DEMO_CASE_GROUP_KEY
from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseAudit,
    CaseClosureChecklist,
    CaseIncident,
    Incident,
    IncidentCase,
)
from qdrant_auto_index import schedule_case_closure_auto_index, schedule_incident_auto_index
from schemas.cases import (
    CaseActionCreate,
    CaseActionUpdate,
    CaseClosureChecklistUpdate,
    CaseWorkflowUpdate,
)
from security.audit import security_audit_actor, write_security_audit
from services.cases import (
    TERMINAL_CASE_STATUSES,
    VALID_CASE_ACTION_CATEGORIES,
    VALID_CASE_ACTION_PRIORITIES,
    VALID_CASE_ACTION_STATUSES,
    VALID_CASE_SEVERITIES,
    VALID_CASE_STATUSES,
    VALID_CLOSURE_DECISIONS,
    build_case_queue_enrichment,
    ensure_case_exists,
    get_case_closure_checklist,
    parse_optional_iso_datetime,
    serialize_case,
    serialize_case_action,
    serialize_case_closure_checklist,
    validate_case_closure_readiness,
)
from timezone_utils import APP_TIMEZONE, format_timestamp_local, normalize_timestamp_utc


router = APIRouter()


@router.get("/cases")
def list_cases(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    host: str | None = Query(None),
    demo_only: bool = Query(False),
):
    db = SessionLocal()

    try:
        offset = (page - 1) * limit

        incident_count_subquery = (
            db.query(
                CaseIncident.case_id.label("case_id"),
                func.count(CaseIncident.incident_id).label("incident_count"),
            )
            .group_by(CaseIncident.case_id)
            .subquery()
        )

        query = (
            db.query(
                IncidentCase,
                func.coalesce(incident_count_subquery.c.incident_count, 0).label(
                    "incident_count"
                ),
            )
            .outerjoin(
                incident_count_subquery,
                IncidentCase.id == incident_count_subquery.c.case_id,
            )
        )

        if demo_only:
            query = query.filter(
                IncidentCase.group_key == DEMO_CASE_GROUP_KEY
            )

        if status and status.upper() != "ALL":
            query = query.filter(IncidentCase.status == status.upper())

        if severity and severity.upper() != "ALL":
            query = query.filter(IncidentCase.severity == severity.upper())

        if host:
            query = query.filter(IncidentCase.agent.ilike(f"%{host}%"))

        total = query.with_entities(func.count(IncidentCase.id)).scalar() or 0

        rows = (
            query.order_by(IncidentCase.updated_at.desc(), IncidentCase.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        total_pages = max((total + limit - 1) // limit, 1)

        case_ids = [case_row.id for case_row, _ in rows]

        action_stats_by_case = {}
        latest_analysis_by_case = {}
        closure_checklist_by_case = {}

        if case_ids:
            action_rows = (
                db.query(
                    CaseAction.case_id.label("case_id"),
                    func.count(CaseAction.id).label("action_count"),
                    func.sum(
                        sql_case(
                            (
                                CaseAction.status.in_(["OPEN", "IN_PROGRESS"]),
                                1,
                            ),
                            else_=0,
                        )
                    ).label("open_action_count"),
                    func.sum(
                        sql_case((CaseAction.status == "DONE", 1), else_=0)
                    ).label("completed_action_count"),
                    func.sum(
                        sql_case((CaseAction.status == "CANCELLED", 1), else_=0)
                    ).label("cancelled_action_count"),
                    func.max(CaseAction.updated_at).label("latest_action_at"),
                )
                .filter(CaseAction.case_id.in_(case_ids))
                .group_by(CaseAction.case_id)
                .all()
            )

            for row in action_rows:
                action_stats_by_case[row.case_id] = {
                    "action_count": row.action_count,
                    "open_action_count": row.open_action_count,
                    "completed_action_count": row.completed_action_count,
                    "cancelled_action_count": row.cancelled_action_count,
                    "latest_action_at": row.latest_action_at,
                }

            analysis_rows = (
                db.query(CaseAIAnalysis)
                .filter(CaseAIAnalysis.case_id.in_(case_ids))
                .order_by(
                    CaseAIAnalysis.case_id.asc(),
                    CaseAIAnalysis.created_at.desc().nullslast(),
                    CaseAIAnalysis.id.desc(),
                )
                .all()
            )

            for row in analysis_rows:
                if row.case_id not in latest_analysis_by_case:
                    latest_analysis_by_case[row.case_id] = row

            closure_rows = (
                db.query(CaseClosureChecklist)
                .filter(CaseClosureChecklist.case_id.in_(case_ids))
                .all()
            )

            for row in closure_rows:
                closure_checklist_by_case[row.case_id] = row

        items = []

        for case_row, incident_count in rows:
            enrichment = build_case_queue_enrichment(
                case_row,
                action_stats=action_stats_by_case.get(case_row.id),
                latest_analysis=latest_analysis_by_case.get(case_row.id),
                closure_checklist=closure_checklist_by_case.get(case_row.id),
            )

            items.append(
                serialize_case(
                    case_row,
                    incident_count,
                    queue_enrichment=enrichment,
                )
            )

        return {
            "items": items,
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        }

    finally:
        db.close()


@router.get("/cases/{case_id}")
def get_case(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        incident_count = (
            db.query(CaseIncident)
            .filter(CaseIncident.case_id == case.id)
            .count()
        )

        return serialize_case(case, incident_count)

    finally:
        db.close()


@router.patch("/cases/{case_id}/workflow")
def update_case_workflow(
    case_id: int,
    payload: CaseWorkflowUpdate,
    request: Request,
):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        reviewed_by = payload.reviewed_by or "local_analyst"
        changes = {}

        if payload.owner is not None:
            owner = payload.owner.strip() or None
            if case.owner != owner:
                changes["owner"] = [case.owner, owner]
                case.owner = owner

        if payload.assignee is not None:
            assignee = payload.assignee.strip() or None
            if case.assignee != assignee:
                changes["assignee"] = [case.assignee, assignee]
                case.assignee = assignee

        if payload.status is not None:
            requested_status = payload.status.upper()

            if requested_status not in VALID_CASE_STATUSES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid case status. Allowed values: {sorted(VALID_CASE_STATUSES)}",
                )

            if requested_status in TERMINAL_CASE_STATUSES:
                validation = validate_case_closure_readiness(
                    db,
                    case,
                    requested_status=requested_status,
                )

                if not validation["ready"]:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "message": "Case cannot be closed until closure checklist is complete and all actions are resolved.",
                            "missing_items": validation["missing_items"],
                            "open_action_count": validation["open_action_count"],
                        },
                    )

            if case.status != requested_status:
                changes["status"] = [case.status, requested_status]
                case.status = requested_status

        if payload.severity is not None:
            requested_severity = payload.severity.upper()

            if requested_severity not in VALID_CASE_SEVERITIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid case severity. Allowed values: {sorted(VALID_CASE_SEVERITIES)}",
                )

            if case.severity != requested_severity:
                changes["severity"] = [case.severity, requested_severity]
                changes["severity_review"] = [case.severity_review, requested_severity]
                case.severity = requested_severity
                case.severity_review = requested_severity

        if payload.sla_due_at is not None:
            sla_due_at = None

            if payload.sla_due_at.strip():
                try:
                    sla_due_at = datetime.fromisoformat(
                        payload.sla_due_at.replace("Z", "+00:00")
                    )
                except ValueError as exc:
                    raise HTTPException(
                        status_code=400,
                        detail="sla_due_at must be a valid ISO timestamp",
                    ) from exc

            if case.sla_due_at != sla_due_at:
                old_value = case.sla_due_at.isoformat() if case.sla_due_at else None
                new_value = sla_due_at.isoformat() if sla_due_at else None
                changes["sla_due_at"] = [old_value, new_value]
                case.sla_due_at = sla_due_at

        if payload.status_reason is not None:
            status_reason = payload.status_reason.strip() or None

            if case.status_reason != status_reason:
                changes["status_reason"] = [case.status_reason, status_reason]
                case.status_reason = status_reason

        if changes:
            now = datetime.now(timezone.utc)
            case.last_reviewed_by = reviewed_by
            case.last_reviewed_at = now
            case.updated_at = now

            audit = CaseAudit(
                case_id=case.id,
                event_type="CASE_WORKFLOW_UPDATED",
                old_value=str({key: value[0] for key, value in changes.items()}),
                new_value=str({key: value[1] for key, value in changes.items()}),
                comment=payload.status_reason,
                created_by=reviewed_by,
            )

            db.add(audit)

        db.commit()
        db.refresh(case)

        if changes:
            write_security_audit(
                event_type="CASE_WORKFLOW_UPDATED",
                outcome="SUCCESS",
                current_user=security_audit_actor(request),
                target_type="CASE",
                target_id=case.id,
                request=request,
                details={
                    "reviewed_by": reviewed_by,
                    "changed_fields": sorted(changes.keys()),
                    "changes": changes,
                },
            )

        incident_count = (
            db.query(CaseIncident)
            .filter(CaseIncident.case_id == case.id)
            .count()
        )

        return serialize_case(case, incident_count)

    finally:
        db.close()


@router.get("/cases/{case_id}/audit")
def get_case_audit(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        rows = (
            db.query(CaseAudit)
            .filter(CaseAudit.case_id == case_id)
            .order_by(CaseAudit.created_at.asc(), CaseAudit.id.asc())
            .all()
        )

        return [
            {
                "id": row.id,
                "case_id": row.case_id,
                "event_type": row.event_type,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment": row.comment,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat()
                if row.created_at
                else None,
            }
            for row in rows
        ]

    finally:
        db.close()


@router.get("/cases/{case_id}/closure")
def get_case_closure(case_id: int):
    db = SessionLocal()

    try:
        case = ensure_case_exists(db, case_id)
        validation = validate_case_closure_readiness(db, case)

        return {
            "case_id": case.id,
            "case_status": case.status,
            "ready_to_close": validation["ready"],
            "missing_items": validation["missing_items"],
            "open_action_count": validation["open_action_count"],
            "checklist": validation["checklist"],
        }

    finally:
        db.close()


@router.patch("/cases/{case_id}/closure")
def update_case_closure(
    case_id: int,
    payload: CaseClosureChecklistUpdate,
    request: Request,
):
    db = SessionLocal()

    try:
        case = ensure_case_exists(db, case_id)
        checklist = get_case_closure_checklist(db, case.id)
        now = datetime.now(timezone.utc)
        reviewed_by = payload.reviewed_by or "local_analyst"

        old_value = serialize_case_closure_checklist(checklist)

        if not checklist:
            checklist = CaseClosureChecklist(
                case_id=case.id,
                reviewed_by=reviewed_by,
                reviewed_at=now,
                updated_at=now,
            )
            db.add(checklist)
            db.flush()

        text_fields = [
            "root_cause",
            "evidence_reviewed",
            "actions_summary",
            "closure_reason",
            "residual_risk",
        ]

        for field in text_fields:
            value = getattr(payload, field)
            if value is not None:
                setattr(checklist, field, value.strip() or None)

        if payload.final_severity is not None:
            final_severity = payload.final_severity.upper().strip()

            if final_severity and final_severity not in VALID_CASE_SEVERITIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid final severity. Allowed values: {sorted(VALID_CASE_SEVERITIES)}",
                )

            checklist.final_severity = final_severity or None

        if payload.closure_decision is not None:
            closure_decision = payload.closure_decision.upper().strip()

            if closure_decision and closure_decision not in VALID_CLOSURE_DECISIONS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid closure decision. Allowed values: {sorted(VALID_CLOSURE_DECISIONS)}",
                )

            checklist.closure_decision = closure_decision or None

        if payload.closure_approved is not None:
            closure_approved = bool(payload.closure_approved)
            checklist.closure_approved = closure_approved

            if closure_approved:
                approved_by = (
                    payload.closure_approved_by
                    or payload.reviewed_by
                    or reviewed_by
                    or "local_analyst"
                )
                checklist.closure_approved_by = approved_by.strip() or reviewed_by
                checklist.closure_approved_at = now
            else:
                checklist.closure_approved_by = None
                checklist.closure_approved_at = None

        checklist.reviewed_by = reviewed_by
        checklist.reviewed_at = now
        checklist.updated_at = now
        case.updated_at = now

        db.flush()

        new_value = serialize_case_closure_checklist(checklist)

        audit = CaseAudit(
            case_id=case.id,
            event_type="CASE_CLOSURE_CHECKLIST_UPDATED",
            old_value=str(old_value),
            new_value=str(new_value),
            comment=checklist.closure_reason,
            created_by=reviewed_by,
        )

        db.add(audit)
        db.commit()
        db.refresh(checklist)

        write_security_audit(
            event_type="CASE_CLOSURE_UPDATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="CASE",
            target_id=case.id,
            request=request,
            details={
                "checklist_id": checklist.id,
                "reviewed_by": reviewed_by,
                "closure_decision": checklist.closure_decision,
                "final_severity": checklist.final_severity,
            },
        )

        validation = validate_case_closure_readiness(db, case)
        linked_incident_ids = [
            item.incident_id
            for item in db.query(CaseIncident)
            .filter(CaseIncident.case_id == case.id)
            .all()
        ]
        schedule_case_closure_auto_index(
            case.id,
            reason="case_closure_updated",
        )
        for linked_incident_id in linked_incident_ids:
            schedule_incident_auto_index(
                linked_incident_id,
                reason="case_closure_updated",
            )

        return {
            "case_id": case.id,
            "case_status": case.status,
            "ready_to_close": validation["ready"],
            "missing_items": validation["missing_items"],
            "open_action_count": validation["open_action_count"],
            "checklist": serialize_case_closure_checklist(checklist),
        }

    finally:
        db.close()


@router.get("/cases/{case_id}/actions")
def list_case_actions(case_id: int):
    db = SessionLocal()

    try:
        ensure_case_exists(db, case_id)

        actions = (
            db.query(CaseAction)
            .filter(CaseAction.case_id == case_id)
            .order_by(CaseAction.created_at.asc(), CaseAction.id.asc())
            .all()
        )

        return [serialize_case_action(action) for action in actions]

    finally:
        db.close()


@router.post("/cases/{case_id}/actions")
def create_case_action(
    case_id: int,
    payload: CaseActionCreate,
    request: Request,
):
    title = payload.title.strip()

    if not title:
        raise HTTPException(status_code=400, detail="Action title cannot be empty")

    category = payload.category.upper()
    priority = payload.priority.upper()
    status = (payload.status or "OPEN").upper()

    if category not in VALID_CASE_ACTION_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action category. Allowed values: {sorted(VALID_CASE_ACTION_CATEGORIES)}",
        )

    if priority not in VALID_CASE_ACTION_PRIORITIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action priority. Allowed values: {sorted(VALID_CASE_ACTION_PRIORITIES)}",
        )

    if status not in VALID_CASE_ACTION_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action status. Allowed values: {sorted(VALID_CASE_ACTION_STATUSES)}",
        )

    db = SessionLocal()

    try:
        case = ensure_case_exists(db, case_id)
        created_by = payload.created_by or "local_analyst"
        now = datetime.now(timezone.utc)

        action = CaseAction(
            case_id=case.id,
            title=title,
            description=payload.description.strip()
            if payload.description
            else None,
            category=category,
            priority=priority,
            status=status,
            due_at=parse_optional_iso_datetime(payload.due_at),
            completed_at=now if status == "DONE" else None,
            created_by=created_by,
            updated_at=now,
        )

        db.add(action)
        db.flush()

        case.updated_at = now

        audit = CaseAudit(
            case_id=case.id,
            event_type="CASE_ACTION_CREATED",
            old_value=None,
            new_value=f"action:{action.id}:{action.title}",
            comment=action.description,
            created_by=created_by,
        )

        db.add(audit)
        db.commit()
        db.refresh(action)

        write_security_audit(
            event_type="CASE_ACTION_CREATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="CASE_ACTION",
            target_id=action.id,
            request=request,
            details={
                "case_id": case.id,
                "category": action.category,
                "priority": action.priority,
                "status": action.status,
                "created_by": created_by,
            },
        )

        return serialize_case_action(action)

    finally:
        db.close()


@router.patch("/cases/{case_id}/actions/{action_id}")
def update_case_action(
    case_id: int,
    action_id: int,
    payload: CaseActionUpdate,
    request: Request,
):
    db = SessionLocal()

    try:
        case = ensure_case_exists(db, case_id)

        action = (
            db.query(CaseAction)
            .filter(
                CaseAction.id == action_id,
                CaseAction.case_id == case_id,
            )
            .first()
        )

        if not action:
            raise HTTPException(status_code=404, detail="Case action not found")

        updated_by = payload.updated_by or "local_analyst"
        now = datetime.now(timezone.utc)
        changes = {}

        if payload.title is not None:
            title = payload.title.strip()

            if not title:
                raise HTTPException(
                    status_code=400,
                    detail="Action title cannot be empty",
                )

            if action.title != title:
                changes["title"] = [action.title, title]
                action.title = title

        if payload.description is not None:
            description = payload.description.strip() or None

            if action.description != description:
                changes["description"] = [action.description, description]
                action.description = description

        if payload.category is not None:
            category = payload.category.upper()

            if category not in VALID_CASE_ACTION_CATEGORIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid action category. Allowed values: {sorted(VALID_CASE_ACTION_CATEGORIES)}",
                )

            if action.category != category:
                changes["category"] = [action.category, category]
                action.category = category

        if payload.priority is not None:
            priority = payload.priority.upper()

            if priority not in VALID_CASE_ACTION_PRIORITIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid action priority. Allowed values: {sorted(VALID_CASE_ACTION_PRIORITIES)}",
                )

            if action.priority != priority:
                changes["priority"] = [action.priority, priority]
                action.priority = priority

        if payload.status is not None:
            status = payload.status.upper()

            if status not in VALID_CASE_ACTION_STATUSES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid action status. Allowed values: {sorted(VALID_CASE_ACTION_STATUSES)}",
                )

            if action.status != status:
                changes["status"] = [action.status, status]
                action.status = status
                action.completed_at = now if status == "DONE" else None

        if payload.due_at is not None:
            due_at = parse_optional_iso_datetime(payload.due_at)
            old_due_at = action.due_at.isoformat() if action.due_at else None
            new_due_at = due_at.isoformat() if due_at else None

            if old_due_at != new_due_at:
                changes["due_at"] = [old_due_at, new_due_at]
                action.due_at = due_at

        if changes:
            action.updated_at = now
            case.updated_at = now

            audit = CaseAudit(
                case_id=case.id,
                event_type="CASE_ACTION_UPDATED",
                old_value=str({key: value[0] for key, value in changes.items()}),
                new_value=str({key: value[1] for key, value in changes.items()}),
                comment=payload.description,
                created_by=updated_by,
            )

            db.add(audit)

        db.commit()
        db.refresh(action)

        if changes:
            write_security_audit(
                event_type="CASE_ACTION_UPDATED",
                outcome="SUCCESS",
                current_user=security_audit_actor(request),
                target_type="CASE_ACTION",
                target_id=action.id,
                request=request,
                details={
                    "case_id": case.id,
                    "updated_by": updated_by,
                    "changed_fields": sorted(changes.keys()),
                    "changes": changes,
                },
            )

        return serialize_case_action(action)

    finally:
        db.close()


@router.get("/cases/{case_id}/incidents")
def get_case_incidents(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        rows = (
            db.query(Incident)
            .join(CaseIncident, CaseIncident.incident_id == Incident.id)
            .filter(CaseIncident.case_id == case_id)
            .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
            .all()
        )

        return [
            {
                "id": item.id,
                "status": item.status,
                "timestamp": normalize_timestamp_utc(item.timestamp),
                "timestamp_local": format_timestamp_local(item.timestamp),
                "timezone": APP_TIMEZONE,
                "agent": item.agent,
                "rule": item.rule,
                "level": item.level,
                "risk_score": item.risk_score,
                "correlation_score": item.correlation_score,
                "correlated": item.correlated,
                "correlation_type": item.correlation_type,
                "recommended_priority": item.recommended_priority,
            }
            for item in rows
        ]

    finally:
        db.close()
