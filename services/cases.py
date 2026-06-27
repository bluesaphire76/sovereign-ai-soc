from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException

from demo_data_management import case_demo_origin
from models import CaseAIAnalysis, CaseAction, CaseClosureChecklist, IncidentCase


VALID_CASE_STATUSES = {
    "OPEN",
    "TRIAGED",
    "INVESTIGATING",
    "ESCALATED",
    "CLOSED",
    "FALSE_POSITIVE",
}

VALID_CASE_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

VALID_CASE_ACTION_STATUSES = {
    "OPEN",
    "IN_PROGRESS",
    "DONE",
    "CANCELLED",
}

VALID_CASE_ACTION_CATEGORIES = {
    "INVESTIGATION",
    "CONTAINMENT",
    "EVIDENCE_REVIEW",
    "ESCALATION",
    "CLOSURE",
    "OTHER",
}

VALID_CASE_ACTION_PRIORITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


TERMINAL_CASE_STATUSES = {
    "CLOSED",
    "FALSE_POSITIVE",
}

VALID_CLOSURE_DECISIONS = {
    "RESOLVED",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "DUPLICATE",
    "OTHER",
}


CLOSURE_REQUIRED_FIELDS = {
    "root_cause": "Root cause / conclusion",
    "evidence_reviewed": "Evidence reviewed",
    "actions_summary": "Actions summary",
    "closure_reason": "Closure reason",
    "closure_decision": "Closure decision",
    "final_severity": "Final severity",
    "residual_risk": "Residual risk",
}


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


def calculate_case_sla_breach_risk(case: IncidentCase) -> str:
    status = (case.status or "OPEN").upper()

    if status in {"CLOSED", "FALSE_POSITIVE"}:
        return "NONE"

    if not case.sla_due_at:
        return "UNKNOWN"

    due_at = case.sla_due_at

    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    seconds_to_due = (due_at - now).total_seconds()

    if seconds_to_due < 0:
        return "BREACHED"

    if seconds_to_due <= 4 * 60 * 60:
        return "HIGH"

    if seconds_to_due <= 24 * 60 * 60:
        return "MEDIUM"

    return "LOW"


def serialize_case(
    case: IncidentCase,
    incident_count: int | None = None,
    queue_enrichment: dict | None = None,
) -> dict:
    payload = {
        "id": case.id,
        "group_key": case.group_key,
        "title": case.title,
        "status": case.status,
        "severity": case.severity,
        "agent": case.agent,
        "correlation_type": case.correlation_type,
        "risk_score": case.risk_score,
        "summary": case.summary,
        "created_by": case.created_by,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "incident_count": incident_count,
        "owner": case.owner,
        "assignee": case.assignee,
        "sla_due_at": case.sla_due_at.isoformat() if case.sla_due_at else None,
        "sla_status": calculate_case_sla_status(case),
        "sla_breach_risk": calculate_case_sla_breach_risk(case),
        "severity_review": case.severity_review,
        "status_reason": case.status_reason,
        "last_reviewed_by": case.last_reviewed_by,
        "last_reviewed_at": case.last_reviewed_at.isoformat()
        if case.last_reviewed_at
        else None,
        "is_demo": case_demo_origin(case) is not None,
        "demo_origin": case_demo_origin(case),
    }

    if queue_enrichment:
        payload.update(queue_enrichment)

    return payload


def parse_optional_iso_datetime(value: str | None):
    if value is None:
        return None

    cleaned = value.strip()

    if not cleaned:
        return None

    try:
        return datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Datetime values must be valid ISO timestamps",
        ) from exc


def serialize_case_action(action: CaseAction) -> dict:
    return {
        "id": action.id,
        "case_id": action.case_id,
        "title": action.title,
        "description": action.description,
        "category": action.category,
        "priority": action.priority,
        "status": action.status,
        "due_at": action.due_at.isoformat() if action.due_at else None,
        "completed_at": action.completed_at.isoformat()
        if action.completed_at
        else None,
        "created_by": action.created_by,
        "created_at": action.created_at.isoformat() if action.created_at else None,
        "updated_at": action.updated_at.isoformat() if action.updated_at else None,
    }


def ensure_case_exists(db, case_id: int) -> IncidentCase:
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id)
        .first()
    )

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return case


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
        "closure_approved": bool(row.closure_approved),
        "closure_approved_by": row.closure_approved_by,
        "closure_approved_at": row.closure_approved_at.isoformat()
        if row.closure_approved_at
        else None,
        "reviewed_by": row.reviewed_by,
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def get_case_closure_checklist(db, case_id: int) -> CaseClosureChecklist | None:
    return (
        db.query(CaseClosureChecklist)
        .filter(CaseClosureChecklist.case_id == case_id)
        .first()
    )


def validate_case_closure_readiness(
    db,
    case: IncidentCase,
    requested_status: str | None = None,
) -> dict:
    checklist = get_case_closure_checklist(db, case.id)

    open_action_count = (
        db.query(CaseAction)
        .filter(
            CaseAction.case_id == case.id,
            ~CaseAction.status.in_(["DONE", "CANCELLED"]),
        )
        .count()
    )

    missing_items = []

    if open_action_count > 0:
        missing_items.append(
            f"{open_action_count} action(s) are still OPEN or IN_PROGRESS"
        )

    if not checklist:
        missing_items.extend(CLOSURE_REQUIRED_FIELDS.values())
        missing_items.append("Closure approval")
    else:
        for field, label in CLOSURE_REQUIRED_FIELDS.items():
            value = getattr(checklist, field, None)
            if not value or not str(value).strip():
                missing_items.append(label)

        if not checklist.closure_approved:
            missing_items.append("Closure approval")

        if checklist.final_severity and checklist.final_severity not in VALID_CASE_SEVERITIES:
            missing_items.append(
                f"Final severity must be one of {sorted(VALID_CASE_SEVERITIES)}"
            )

        if checklist.closure_decision and checklist.closure_decision not in VALID_CLOSURE_DECISIONS:
            missing_items.append(
                f"Closure decision must be one of {sorted(VALID_CLOSURE_DECISIONS)}"
            )

        if requested_status == "FALSE_POSITIVE" and checklist.closure_decision != "FALSE_POSITIVE":
            missing_items.append(
                "FALSE_POSITIVE status requires closure_decision FALSE_POSITIVE"
            )

        if requested_status == "CLOSED" and checklist.closure_decision == "FALSE_POSITIVE":
            missing_items.append(
                "CLOSED status cannot use closure_decision FALSE_POSITIVE"
            )

    return {
        "ready": len(missing_items) == 0,
        "missing_items": missing_items,
        "open_action_count": open_action_count,
        "checklist": serialize_case_closure_checklist(checklist),
    }


def safe_isoformat(value):
    if not value:
        return None

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return str(value)


def build_closure_missing_items_from_row(
    checklist: CaseClosureChecklist | None,
    open_action_count: int,
) -> list[str]:
    missing_items = []

    if open_action_count > 0:
        missing_items.append(
            f"{open_action_count} action(s) are still OPEN or IN_PROGRESS"
        )

    if not checklist:
        missing_items.extend(CLOSURE_REQUIRED_FIELDS.values())
        return missing_items

    for field, label in CLOSURE_REQUIRED_FIELDS.items():
        value = getattr(checklist, field, None)
        if not value or not str(value).strip():
            missing_items.append(label)

    if checklist.final_severity and checklist.final_severity not in VALID_CASE_SEVERITIES:
        missing_items.append(
            f"Final severity must be one of {sorted(VALID_CASE_SEVERITIES)}"
        )

    if checklist.closure_decision and checklist.closure_decision not in VALID_CLOSURE_DECISIONS:
        missing_items.append(
            f"Closure decision must be one of {sorted(VALID_CLOSURE_DECISIONS)}"
        )

    return missing_items


def build_case_queue_flags(
    case: IncidentCase,
    *,
    action_stats: dict,
    latest_analysis: CaseAIAnalysis | None,
    closure_checklist: CaseClosureChecklist | None,
    ready_to_close: bool,
) -> list[str]:
    flags = []
    status = (case.status or "OPEN").upper()
    severity = (case.severity_review or case.severity or "LOW").upper()
    sla_status = calculate_case_sla_status(case)
    sla_breach_risk = calculate_case_sla_breach_risk(case)
    open_action_count = int(action_stats.get("open_action_count") or 0)

    if status not in TERMINAL_CASE_STATUSES and not case.owner:
        flags.append("NO_OWNER")

    if status not in TERMINAL_CASE_STATUSES and not case.assignee:
        flags.append("NO_ASSIGNEE")

    if sla_status == "BREACHED":
        flags.append("SLA_BREACHED")
    elif sla_breach_risk == "HIGH":
        flags.append("SLA_BREACH_RISK")

    if status == "ESCALATED":
        flags.append("ESCALATED")

    if severity in {"CRITICAL", "HIGH"}:
        flags.append("HIGH_RISK")

    if open_action_count > 0:
        flags.append("OPEN_ACTIONS")

    if status not in TERMINAL_CASE_STATUSES and not latest_analysis:
        flags.append("NO_AI_ANALYSIS")

    if status not in TERMINAL_CASE_STATUSES and not closure_checklist:
        flags.append("NO_CLOSURE_CHECKLIST")

    if (
        status not in TERMINAL_CASE_STATUSES
        and closure_checklist
        and not closure_checklist.closure_approved
    ):
        flags.append("CLOSURE_NOT_APPROVED")

    if ready_to_close and status not in TERMINAL_CASE_STATUSES:
        flags.append("READY_TO_CLOSE")

    return flags


def build_case_queue_enrichment(
    case: IncidentCase,
    *,
    action_stats: dict | None = None,
    latest_analysis: CaseAIAnalysis | None = None,
    closure_checklist: CaseClosureChecklist | None = None,
) -> dict:
    stats = action_stats or {}

    action_count = int(stats.get("action_count") or 0)
    open_action_count = int(stats.get("open_action_count") or 0)
    completed_action_count = int(stats.get("completed_action_count") or 0)
    cancelled_action_count = int(stats.get("cancelled_action_count") or 0)

    missing_items = build_closure_missing_items_from_row(
        closure_checklist,
        open_action_count,
    )
    ready_to_close = len(missing_items) == 0

    latest_action_at = stats.get("latest_action_at")

    enrichment = {
        "action_count": action_count,
        "open_action_count": open_action_count,
        "completed_action_count": completed_action_count,
        "cancelled_action_count": cancelled_action_count,
        "latest_action_at": safe_isoformat(latest_action_at),
        "sla_breach_risk": calculate_case_sla_breach_risk(case),
        "has_ai_analysis": latest_analysis is not None,
        "latest_ai_analysis_at": safe_isoformat(latest_analysis.created_at)
        if latest_analysis
        else None,
        "latest_ai_model": latest_analysis.model if latest_analysis else None,
        "latest_ai_recommended_status": latest_analysis.recommended_status
        if latest_analysis
        else None,
        "latest_ai_recommended_severity": latest_analysis.recommended_severity
        if latest_analysis
        else None,
        "has_closure_checklist": closure_checklist is not None,
        "ready_to_close": ready_to_close,
        "closure_missing_count": len(missing_items),
        "closure_missing_items": missing_items,
        "closure_decision": closure_checklist.closure_decision
        if closure_checklist
        else None,
        "final_severity": closure_checklist.final_severity
        if closure_checklist
        else None,
        "closure_reviewed_at": safe_isoformat(closure_checklist.reviewed_at)
        if closure_checklist
        else None,
        "closure_approved": bool(closure_checklist.closure_approved)
        if closure_checklist
        else False,
        "closure_approved_by": closure_checklist.closure_approved_by
        if closure_checklist
        else None,
        "closure_approved_at": safe_isoformat(closure_checklist.closure_approved_at)
        if closure_checklist
        else None,
    }

    enrichment["queue_flags"] = build_case_queue_flags(
        case,
        action_stats=stats,
        latest_analysis=latest_analysis,
        closure_checklist=closure_checklist,
        ready_to_close=ready_to_close,
    )

    return enrichment
