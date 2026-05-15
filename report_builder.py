import json
from datetime import datetime, timezone

from database import SessionLocal
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
    incident = payload["incident"]

    lines = [
        f"# Incident Report #{incident['id']}",
        "",
        f"Generated at: **{payload['generated_at']}**",
        "",
        "## Executive Summary",
        "",
        f"- **Status:** {format_value(incident['status'])}",
        f"- **Host:** {format_value(incident['agent'])}",
        f"- **Rule:** {format_value(incident['rule'])}",
        f"- **Risk score:** {format_value(incident['risk_score'])}",
        f"- **Recommended priority:** {format_value(incident['recommended_priority'])}",
        f"- **Correlated:** {format_value(incident['correlated'])}",
        f"- **Correlation score:** {format_value(incident['correlation_score'])}",
        "",
        "## Incident Details",
        "",
        f"- **Timestamp:** {format_value(incident['timestamp'])}",
        f"- **Wazuh document ID:** {format_value(incident['wazuh_doc_id'])}",
        f"- **Level:** {format_value(incident['level'])}",
        f"- **Correlation type:** {format_value(incident['correlation_type'])}",
        f"- **Escalation reason:** {format_value(incident['escalation_reason'])}",
        "",
        "## MITRE ATT&CK",
        "",
        "```json",
        json.dumps(incident["mitre"], ensure_ascii=False, indent=2),
        "```",
        "",
        "## AI Analysis",
        "",
        incident["ai_analysis"] or "No AI analysis available.",
        "",
        "## Correlation Explanation",
        "",
        "```json",
        json.dumps(incident["correlation_summary"], ensure_ascii=False, indent=2),
        "```",
        "",
        "## Attack Chain",
        "",
        "```json",
        json.dumps(incident["attack_chain"], ensure_ascii=False, indent=2),
        "```",
        "",
        "## Analyst Notes",
        "",
    ]

    if payload["notes"]:
        for note in payload["notes"]:
            lines.extend(
                [
                    f"### Note #{note['id']}",
                    "",
                    f"- **Created by:** {format_value(note['created_by'])}",
                    f"- **Created at:** {format_value(note['created_at'])}",
                    "",
                    note["note"],
                    "",
                ]
            )
    else:
        lines.append("No analyst notes available.")
        lines.append("")

    lines.extend(
        [
            "## Audit Trail",
            "",
        ]
    )

    if payload["audit_trail"]:
        for event in payload["audit_trail"]:
            lines.extend(
                [
                    f"### Audit Event #{event['id']}",
                    "",
                    f"- **Type:** {format_value(event['event_type'])}",
                    f"- **Old value:** {format_value(event['old_value'])}",
                    f"- **New value:** {format_value(event['new_value'])}",
                    f"- **Created by:** {format_value(event['created_by'])}",
                    f"- **Created at:** {format_value(event['created_at'])}",
                    f"- **Comment:** {format_value(event['comment'])}",
                    "",
                ]
            )
    else:
        lines.append("No audit events available.")
        lines.append("")

    lines.extend(
        [
            "## Raw Wazuh Alert",
            "",
            "```json",
            json.dumps(incident["raw_alert"], ensure_ascii=False, indent=2),
            "```",
            "",
        ]
    )

    return "\n".join(lines)


def build_incident_report(incident_id: int):
    db = SessionLocal()

    try:
        payload = build_incident_payload(db, incident_id)
        markdown = incident_payload_to_markdown(payload)
        filename = f"incident_{incident_id}_report.md"

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
    case = payload["case"]
    analysis = payload["case_ai_analysis"]
    actions = payload.get("case_actions", [])
    closure_readiness = payload.get("case_closure_readiness", {})
    closure_checklist = payload.get("case_closure_checklist")

    open_actions = [
        action for action in actions
        if action.get("status") in {"OPEN", "IN_PROGRESS"}
    ]
    completed_actions = [
        action for action in actions
        if action.get("status") == "DONE"
    ]
    cancelled_actions = [
        action for action in actions
        if action.get("status") == "CANCELLED"
    ]

    lines = [
        f"# Investigation Case Report #{case['id']}",
        "",
        f"Generated at: **{payload['generated_at']}**",
        "",
        "## Executive Summary",
        "",
        f"- **Title:** {format_value(case['title'])}",
        f"- **Status:** {format_value(case['status'])}",
        f"- **Severity:** {format_value(case['severity'])}",
        f"- **Severity review:** {format_value(case['severity_review'])}",
        f"- **Owner:** {format_value(case['owner'])}",
        f"- **SLA status:** {format_value(case['sla_status'])}",
        f"- **Host:** {format_value(case['agent'])}",
        f"- **Correlation type:** {format_value(case['correlation_type'])}",
        f"- **Risk score:** {format_value(case['risk_score'])}",
        f"- **Linked incidents:** {len(payload['incidents'])}",
        f"- **Case actions:** {len(actions)}",
        f"- **Open / in progress actions:** {len(open_actions)}",
        f"- **Completed actions:** {len(completed_actions)}",
        f"- **Cancelled actions:** {len(cancelled_actions)}",
        f"- **Closure readiness:** {'READY' if closure_readiness.get('ready_to_close') else 'BLOCKED'}",
        f"- **Open action blockers:** {format_value(closure_readiness.get('open_action_count'))}",
        f"- **Closure decision:** {format_value((closure_checklist or {}).get('closure_decision'))}",
        f"- **Final severity:** {format_value((closure_checklist or {}).get('final_severity'))}",
        "",
        "## Case Metadata",
        "",
        f"- **Group key:** {format_value(case['group_key'])}",
        f"- **Owner:** {format_value(case['owner'])}",
        f"- **SLA due at:** {format_value(case['sla_due_at'])}",
        f"- **SLA status:** {format_value(case['sla_status'])}",
        f"- **Severity review:** {format_value(case['severity_review'])}",
        f"- **Status reason:** {format_value(case['status_reason'])}",
        f"- **Last reviewed by:** {format_value(case['last_reviewed_by'])}",
        f"- **Last reviewed at:** {format_value(case['last_reviewed_at'])}",
        f"- **Created by:** {format_value(case['created_by'])}",
        f"- **Created at:** {format_value(case['created_at'])}",
        f"- **Updated at:** {format_value(case['updated_at'])}",
        "",
        "## Case Summary",
        "",
        "```json",
        json.dumps(case["summary"], ensure_ascii=False, indent=2),
        "```",
        "",
        "## Case AI Analysis",
        "",
    ]

    if analysis:
        lines.extend(
            [
                f"- **Model:** {format_value(analysis['model'])}",
                f"- **Recommended status:** {format_value(analysis['recommended_status'])}",
                f"- **Recommended severity:** {format_value(analysis['recommended_severity'])}",
                f"- **Generated at:** {format_value(analysis['created_at'])}",
                "",
                analysis["analysis"] or "No analysis text available.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "No case AI analysis available.",
                "",
            ]
        )

    lines.extend(
        [
            "## Case Action Plan",
            "",
        ]
    )

    if actions:
        for action in actions:
            lines.extend(
                [
                    f"### Action #{action['id']} — {format_value(action['title'])}",
                    "",
                    f"- **Status:** {format_value(action['status'])}",
                    f"- **Priority:** {format_value(action['priority'])}",
                    f"- **Category:** {format_value(action['category'])}",
                    f"- **Due at:** {format_value(action['due_at'])}",
                    f"- **Completed at:** {format_value(action['completed_at'])}",
                    f"- **Created by:** {format_value(action['created_by'])}",
                    f"- **Created at:** {format_value(action['created_at'])}",
                    f"- **Updated at:** {format_value(action['updated_at'])}",
                    "",
                    "#### Description",
                    "",
                    action["description"] or "No description available.",
                    "",
                ]
            )
    else:
        lines.append("No case actions available.")
        lines.append("")

    lines.extend(
        [
            "## Case Closure Readiness",
            "",
            f"- **Ready to close:** {format_value(closure_readiness.get('ready_to_close'))}",
            f"- **Open action count:** {format_value(closure_readiness.get('open_action_count'))}",
            "",
        ]
    )

    missing_items = closure_readiness.get("missing_items", [])

    if missing_items:
        lines.extend(
            [
                "### Blocking Items",
                "",
            ]
        )

        for item in missing_items:
            lines.append(f"- {item}")

        lines.append("")
    else:
        lines.extend(
            [
                "No blocking items. The case is ready for terminal workflow status.",
                "",
            ]
        )

    lines.extend(
        [
            "## Case Closure Checklist",
            "",
        ]
    )

    if closure_checklist:
        lines.extend(
            [
                f"- **Closure decision:** {format_value(closure_checklist.get('closure_decision'))}",
                f"- **Final severity:** {format_value(closure_checklist.get('final_severity'))}",
                f"- **Reviewed by:** {format_value(closure_checklist.get('reviewed_by'))}",
                f"- **Reviewed at:** {format_value(closure_checklist.get('reviewed_at'))}",
                "",
                "### Root Cause / Conclusion",
                "",
                closure_checklist.get("root_cause") or "Not documented.",
                "",
                "### Evidence Reviewed",
                "",
                closure_checklist.get("evidence_reviewed") or "Not documented.",
                "",
                "### Actions Summary",
                "",
                closure_checklist.get("actions_summary") or "Not documented.",
                "",
                "### Closure Reason",
                "",
                closure_checklist.get("closure_reason") or "Not documented.",
                "",
                "### Residual Risk",
                "",
                closure_checklist.get("residual_risk") or "Not documented.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "No closure checklist available.",
                "",
            ]
        )

    lines.extend(
        [
            "## Case Workflow Audit Trail",
            "",
        ]
    )

    if payload["case_audit_trail"]:
        for event in payload["case_audit_trail"]:
            lines.extend(
                [
                    f"### Workflow Event #{event['id']}",
                    "",
                    f"- **Type:** {format_value(event['event_type'])}",
                    f"- **Old value:** {format_value(event['old_value'])}",
                    f"- **New value:** {format_value(event['new_value'])}",
                    f"- **Created by:** {format_value(event['created_by'])}",
                    f"- **Created at:** {format_value(event['created_at'])}",
                    f"- **Comment:** {format_value(event['comment'])}",
                    "",
                ]
            )
    else:
        lines.append("No case workflow audit events available.")
        lines.append("")

    lines.extend(
        [
            "## Linked Incidents",
            "",
        ]
    )

    if payload["incidents"]:
        for incident in payload["incidents"]:
            lines.extend(
                [
                    f"### Incident #{incident['id']}",
                    "",
                    f"- **Status:** {format_value(incident['status'])}",
                    f"- **Timestamp:** {format_value(incident['timestamp'])}",
                    f"- **Host:** {format_value(incident['agent'])}",
                    f"- **Rule:** {format_value(incident['rule'])}",
                    f"- **Level:** {format_value(incident['level'])}",
                    f"- **Risk score:** {format_value(incident['risk_score'])}",
                    f"- **Recommended priority:** {format_value(incident['recommended_priority'])}",
                    f"- **Correlation score:** {format_value(incident['correlation_score'])}",
                    f"- **Correlation type:** {format_value(incident['correlation_type'])}",
                    "",
                    "#### MITRE",
                    "",
                    "```json",
                    json.dumps(incident["mitre"], ensure_ascii=False, indent=2),
                    "```",
                    "",
                    "#### AI Analysis",
                    "",
                    incident["ai_analysis"] or "No incident AI analysis available.",
                    "",
                    "#### Correlation Summary",
                    "",
                    "```json",
                    json.dumps(incident["correlation_summary"], ensure_ascii=False, indent=2),
                    "```",
                    "",
                ]
            )
    else:
        lines.append("No linked incidents available.")
        lines.append("")

    return "\n".join(lines)


def build_case_report(case_id: int):
    db = SessionLocal()

    try:
        payload = build_case_payload(db, case_id)
        markdown = case_payload_to_markdown(payload)
        filename = f"case_{case_id}_report.md"

        return {
            "filename": filename,
            "markdown": markdown,
            "payload": payload,
        }

    finally:
        db.close()
