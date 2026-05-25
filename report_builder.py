import json
from datetime import datetime, timezone

from database import SessionLocal
from enterprise_report_templates import (
    build_enterprise_case_markdown,
    build_enterprise_incident_markdown,
)
from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseAudit,
    CaseClosureChecklist,
    CaseIncident,
    Incident,
    IncidentAudit,
    IncidentCase,
    IncidentNote,
)
from report_naming import (
    case_enterprise_report_filename,
    incident_enterprise_report_filename,
)
from report_network_evidence import (
    append_case_network_evidence_markdown,
    append_incident_network_evidence_markdown,
    attach_case_network_evidence,
    attach_incident_network_evidence,
)


def safe_json(value):
    if not value:
        return None

    try:
        return json.loads(value)
    except Exception:
        return value


def pretty_json(value):
    parsed = safe_json(value)

    if parsed is None:
        return ""

    if isinstance(parsed, str):
        return parsed

    return json.dumps(parsed, ensure_ascii=False, indent=2)


def format_value(value):
    if value is None:
        return "-"

    return str(value)


def safe_filename(value: str) -> str:
    cleaned = "".join(
        char if char.isalnum() or char in {"-", "_"} else "_"
        for char in value.strip().lower()
    )

    return cleaned.strip("_") or "report"


def now_label():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def incident_ai_brief_preview(incident_id: int) -> dict | None:
    try:
        from incident_ai_brief import build_ai_brief_preview

        return build_ai_brief_preview(incident_id)
    except Exception:
        return None


def calculate_case_sla_status(case: IncidentCase) -> str:
    status = (case.status or "OPEN").upper()

    if status in {"CLOSED", "FALSE_POSITIVE"}:
        return "COMPLETED"

    if not case.sla_due_at:
        return "NOT_SET"

    due_at = case.sla_due_at

    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    if now <= due_at:
        return "WITHIN_SLA"

    return "BREACHED"


def serialize_case_closure_checklist(row: CaseClosureChecklist | None) -> dict | None:
    if not row:
        return None

    return {
        "id": row.id,
        "case_id": row.case_id,
        "root_cause": row.root_cause,
        "evidence_reviewed": row.evidence_reviewed,
        "actions_summary": row.actions_summary,
        "closure_reason": row.closure_reason,
        "closure_decision": row.closure_decision,
        "final_severity": row.final_severity,
        "residual_risk": row.residual_risk,
        "closure_approved": row.closure_approved,
        "closure_approved_by": row.closure_approved_by,
        "closure_approved_at": row.closure_approved_at.isoformat()
        if row.closure_approved_at
        else None,
        "reviewed_by": row.reviewed_by,
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def calculate_case_closure_readiness(
    checklist: CaseClosureChecklist | None,
    case_actions: list[CaseAction],
) -> dict:
    open_actions = [
        action for action in case_actions
        if action.status not in {"DONE", "CANCELLED"}
    ]

    missing_items = []

    if open_actions:
        missing_items.append(
            f"{len(open_actions)} action(s) are still OPEN or IN_PROGRESS"
        )

    required_fields = {
        "root_cause": "Root cause / conclusion",
        "evidence_reviewed": "Evidence reviewed",
        "actions_summary": "Actions summary",
        "closure_reason": "Closure reason",
        "closure_decision": "Closure decision",
        "final_severity": "Final severity",
        "residual_risk": "Residual risk",
    }

    if not checklist:
        missing_items.extend(required_fields.values())
    else:
        for field, label in required_fields.items():
            value = getattr(checklist, field, None)
            if not value or not str(value).strip():
                missing_items.append(label)

    return {
        "ready_to_close": len(missing_items) == 0,
        "missing_items": missing_items,
        "open_action_count": len(open_actions),
    }


def build_incident_payload(db, incident_id: int):
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )

    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    notes = (
        db.query(IncidentNote)
        .filter(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at.asc(), IncidentNote.id.asc())
        .all()
    )

    audit_events = (
        db.query(IncidentAudit)
        .filter(IncidentAudit.incident_id == incident_id)
        .order_by(IncidentAudit.created_at.asc(), IncidentAudit.id.asc())
        .all()
    )

    return {
        "generated_at": now_label(),
        "incident": {
            "id": incident.id,
            "status": incident.status,
            "wazuh_doc_id": incident.wazuh_doc_id,
            "timestamp": incident.timestamp,
            "agent": incident.agent,
            "rule": incident.rule,
            "level": incident.level,
            "mitre": safe_json(incident.mitre),
            "risk_score": incident.risk_score,
            "recommended_priority": incident.recommended_priority,
            "correlated": incident.correlated,
            "correlation_score": incident.correlation_score,
            "correlation_type": incident.correlation_type,
            "attack_chain": safe_json(incident.attack_chain),
            "escalation_reason": incident.escalation_reason,
            "correlation_summary": safe_json(incident.correlation_summary),
            "ai_analysis": incident.ai_analysis,
            "raw_alert": safe_json(incident.raw_alert),
        },
        "ai_brief": incident_ai_brief_preview(incident_id),
        "notes": [
            {
                "id": row.id,
                "note": row.note,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in notes
        ],
        "audit_trail": [
            {
                "id": row.id,
                "event_type": row.event_type,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment": row.comment,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in audit_events
        ],
    }


def incident_payload_to_markdown(payload: dict) -> str:
    return build_enterprise_incident_markdown(payload)


def build_incident_report(incident_id: int):
    db = SessionLocal()

    try:
        payload = build_incident_payload(db, incident_id)
        attach_incident_network_evidence(payload)
        markdown = append_incident_network_evidence_markdown(
            incident_payload_to_markdown(payload),
            payload,
        )
        filename = incident_enterprise_report_filename(incident_id)

        return {
            "filename": filename,
            "markdown": markdown,
            "payload": payload,
        }

    finally:
        db.close()


def build_case_payload(db, case_id: int):
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id)
        .first()
    )

    if not case:
        raise ValueError(f"Case {case_id} not found")

    incidents = (
        db.query(Incident)
        .join(CaseIncident, CaseIncident.incident_id == Incident.id)
        .filter(CaseIncident.case_id == case_id)
        .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
        .all()
    )

    latest_analysis = (
        db.query(CaseAIAnalysis)
        .filter(CaseAIAnalysis.case_id == case_id)
        .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
        .first()
    )

    case_audit_events = (
        db.query(CaseAudit)
        .filter(CaseAudit.case_id == case_id)
        .order_by(CaseAudit.created_at.asc(), CaseAudit.id.asc())
        .all()
    )

    case_actions = (
        db.query(CaseAction)
        .filter(CaseAction.case_id == case_id)
        .order_by(CaseAction.created_at.asc(), CaseAction.id.asc())
        .all()
    )


    case_closure_checklist = (
        db.query(CaseClosureChecklist)
        .filter(CaseClosureChecklist.case_id == case_id)
        .first()
    )

    case_closure_readiness = calculate_case_closure_readiness(
        case_closure_checklist,
        case_actions,
    )

    return {
        "generated_at": now_label(),
        "case": {
            "id": case.id,
            "group_key": case.group_key,
            "title": case.title,
            "status": case.status,
            "severity": case.severity,
            "agent": case.agent,
            "correlation_type": case.correlation_type,
            "risk_score": case.risk_score,
            "summary": safe_json(case.summary),
            "owner": case.owner,
            "assignee": case.assignee,
            "sla_due_at": case.sla_due_at.isoformat() if case.sla_due_at else None,
            "sla_status": calculate_case_sla_status(case),
            "severity_review": case.severity_review,
            "status_reason": case.status_reason,
            "last_reviewed_by": case.last_reviewed_by,
            "last_reviewed_at": case.last_reviewed_at.isoformat()
            if case.last_reviewed_at
            else None,
            "created_by": case.created_by,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        },
        "case_ai_analysis": {
            "id": latest_analysis.id,
            "model": latest_analysis.model,
            "analysis": latest_analysis.analysis,
            "recommended_status": latest_analysis.recommended_status,
            "recommended_severity": latest_analysis.recommended_severity,
            "created_by": latest_analysis.created_by,
            "created_at": latest_analysis.created_at.isoformat()
            if latest_analysis.created_at
            else None,
        }
        if latest_analysis
        else None,
        "case_audit_trail": [
            {
                "id": row.id,
                "event_type": row.event_type,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment": row.comment,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in case_audit_events
        ],
        "case_actions": [
            {
                "id": row.id,
                "title": row.title,
                "description": row.description,
                "category": row.category,
                "priority": row.priority,
                "status": row.status,
                "due_at": row.due_at.isoformat() if row.due_at else None,
                "completed_at": row.completed_at.isoformat()
                if row.completed_at
                else None,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            }
            for row in case_actions
        ],
        "case_closure_readiness": case_closure_readiness,
        "case_closure_checklist": serialize_case_closure_checklist(
            case_closure_checklist
        ),
        "incidents": [
            {
                "id": incident.id,
                "status": incident.status,
                "timestamp": incident.timestamp,
                "agent": incident.agent,
                "rule": incident.rule,
                "level": incident.level,
                "mitre": safe_json(incident.mitre),
                "risk_score": incident.risk_score,
                "recommended_priority": incident.recommended_priority,
                "correlated": incident.correlated,
                "correlation_score": incident.correlation_score,
                "correlation_type": incident.correlation_type,
                "escalation_reason": incident.escalation_reason,
                "ai_analysis": incident.ai_analysis,
                "correlation_summary": safe_json(incident.correlation_summary),
            }
            for incident in incidents
        ],
    }


def case_payload_to_markdown(payload: dict) -> str:
    return build_enterprise_case_markdown(payload)


def build_case_report(case_id: int):
    db = SessionLocal()

    try:
        payload = build_case_payload(db, case_id)
        attach_case_network_evidence(payload)
        markdown = append_case_network_evidence_markdown(
            case_payload_to_markdown(payload),
            payload,
        )
        filename = case_enterprise_report_filename(case_id)

        return {
            "filename": filename,
            "markdown": markdown,
            "payload": payload,
        }

    finally:
        db.close()
