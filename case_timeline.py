from __future__ import annotations

from datetime import datetime, timezone

from database import SessionLocal
from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseAudit,
    CaseClosureChecklist,
    CaseIncident,
    Incident,
    IncidentCase,
)


def safe_isoformat(value):
    if not value:
        return None

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return str(value)


def sort_key(value):
    timestamp = value.get("timestamp")

    if not timestamp:
        return datetime.min.replace(tzinfo=timezone.utc)

    if isinstance(timestamp, datetime):
        parsed = timestamp
    else:
        try:
            parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed


def timeline_item(
    *,
    timestamp,
    event_type: str,
    title: str,
    description: str | None = None,
    actor: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    reference_id: int | str | None = None,
    details: dict | None = None,
) -> dict:
    return {
        "timestamp": safe_isoformat(timestamp),
        "event_type": event_type,
        "title": title,
        "description": description,
        "actor": actor,
        "severity": severity,
        "status": status,
        "source": source,
        "reference_id": reference_id,
        "details": details or {},
    }


def build_case_timeline_payload(db, case_id: int) -> dict:
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id)
        .first()
    )

    if not case:
        raise ValueError(f"Case {case_id} not found")

    items = []

    items.append(
        timeline_item(
            timestamp=case.created_at,
            event_type="CASE_CREATED",
            title="Case created",
            description=case.title,
            actor=case.created_by,
            severity=case.severity,
            status=case.status,
            source="case",
            reference_id=case.id,
            details={
                "group_key": case.group_key,
                "agent": case.agent,
                "correlation_type": case.correlation_type,
                "risk_score": case.risk_score,
            },
        )
    )

    if case.updated_at and case.updated_at != case.created_at:
        items.append(
            timeline_item(
                timestamp=case.updated_at,
                event_type="CASE_UPDATED",
                title="Case updated",
                description=case.status_reason,
                actor=case.last_reviewed_by,
                severity=case.severity_review or case.severity,
                status=case.status,
                source="case",
                reference_id=case.id,
            )
        )

    incidents = (
        db.query(Incident)
        .join(CaseIncident, CaseIncident.incident_id == Incident.id)
        .filter(CaseIncident.case_id == case_id)
        .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
        .all()
    )

    for incident in incidents:
        items.append(
            timeline_item(
                timestamp=incident.timestamp,
                event_type="INCIDENT_LINKED",
                title=f"Incident #{incident.id} linked",
                description=incident.rule,
                actor=None,
                severity=incident.recommended_priority,
                status=incident.status,
                source="incident",
                reference_id=incident.id,
                details={
                    "agent": incident.agent,
                    "level": incident.level,
                    "risk_score": incident.risk_score,
                    "correlation_score": incident.correlation_score,
                    "correlation_type": incident.correlation_type,
                    "wazuh_doc_id": incident.wazuh_doc_id,
                },
            )
        )

    analyses = (
        db.query(CaseAIAnalysis)
        .filter(CaseAIAnalysis.case_id == case_id)
        .order_by(CaseAIAnalysis.created_at.asc(), CaseAIAnalysis.id.asc())
        .all()
    )

    for analysis in analyses:
        items.append(
            timeline_item(
                timestamp=analysis.created_at,
                event_type="AI_ANALYSIS_GENERATED",
                title="AI case analysis generated",
                description=(
                    analysis.analysis[:240] + "..."
                    if analysis.analysis and len(analysis.analysis) > 240
                    else analysis.analysis
                ),
                actor=analysis.created_by,
                severity=analysis.recommended_severity,
                status=analysis.recommended_status,
                source="case_ai_analysis",
                reference_id=analysis.id,
                details={
                    "model": analysis.model,
                    "recommended_status": analysis.recommended_status,
                    "recommended_severity": analysis.recommended_severity,
                },
            )
        )

    actions = (
        db.query(CaseAction)
        .filter(CaseAction.case_id == case_id)
        .order_by(CaseAction.created_at.asc(), CaseAction.id.asc())
        .all()
    )

    for action in actions:
        items.append(
            timeline_item(
                timestamp=action.created_at,
                event_type="ACTION_CREATED",
                title=f"Action #{action.id} created",
                description=action.title,
                actor=action.created_by,
                severity=action.priority,
                status=action.status,
                source="case_action",
                reference_id=action.id,
                details={
                    "category": action.category,
                    "due_at": safe_isoformat(action.due_at),
                    "description": action.description,
                },
            )
        )

        if action.updated_at and action.updated_at != action.created_at:
            items.append(
                timeline_item(
                    timestamp=action.updated_at,
                    event_type="ACTION_UPDATED",
                    title=f"Action #{action.id} updated",
                    description=action.title,
                    actor=None,
                    severity=action.priority,
                    status=action.status,
                    source="case_action",
                    reference_id=action.id,
                    details={
                        "category": action.category,
                        "completed_at": safe_isoformat(action.completed_at),
                    },
                )
            )

        if action.completed_at:
            items.append(
                timeline_item(
                    timestamp=action.completed_at,
                    event_type="ACTION_COMPLETED",
                    title=f"Action #{action.id} completed",
                    description=action.title,
                    actor=None,
                    severity=action.priority,
                    status=action.status,
                    source="case_action",
                    reference_id=action.id,
                )
            )

    closure_checklist = (
        db.query(CaseClosureChecklist)
        .filter(CaseClosureChecklist.case_id == case_id)
        .first()
    )

    if closure_checklist:
        items.append(
            timeline_item(
                timestamp=closure_checklist.reviewed_at or closure_checklist.updated_at,
                event_type="CLOSURE_CHECKLIST_REVIEWED",
                title="Closure checklist reviewed",
                description=closure_checklist.closure_reason,
                actor=closure_checklist.reviewed_by,
                severity=closure_checklist.final_severity,
                status=closure_checklist.closure_decision,
                source="case_closure_checklist",
                reference_id=closure_checklist.id,
                details={
                    "closure_decision": closure_checklist.closure_decision,
                    "final_severity": closure_checklist.final_severity,
                    "residual_risk": closure_checklist.residual_risk,
                },
            )
        )

    audit_events = (
        db.query(CaseAudit)
        .filter(CaseAudit.case_id == case_id)
        .order_by(CaseAudit.created_at.asc(), CaseAudit.id.asc())
        .all()
    )

    for event in audit_events:
        items.append(
            timeline_item(
                timestamp=event.created_at,
                event_type=event.event_type or "CASE_AUDIT_EVENT",
                title=(event.event_type or "Case audit event").replace("_", " ").title(),
                description=event.comment,
                actor=event.created_by,
                source="case_audit",
                reference_id=event.id,
                details={
                    "old_value": event.old_value,
                    "new_value": event.new_value,
                },
            )
        )

    items = sorted(items, key=sort_key)

    return {
        "case_id": case.id,
        "generated_at": safe_isoformat(datetime.now(timezone.utc)),
        "count": len(items),
        "items": items,
    }


def build_case_timeline(case_id: int) -> dict:
    db = SessionLocal()

    try:
        return build_case_timeline_payload(db, case_id)

    finally:
        db.close()
