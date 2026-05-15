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
    IncidentCase,
)


def now_label() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")


def safe_json(value):
    if not value:
        return None

    try:
        return json.loads(value)
    except Exception:
        return value


def format_value(value):
    if value is None:
        return "-"

    return str(value)


def safe_isoformat(value):
    if not value:
        return None

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return str(value)


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


def serialize_closure_checklist(row: CaseClosureChecklist | None) -> dict | None:
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
        "reviewed_at": safe_isoformat(row.reviewed_at),
        "created_at": safe_isoformat(row.created_at),
        "updated_at": safe_isoformat(row.updated_at),
    }


def calculate_closure_readiness(
    checklist: CaseClosureChecklist | None,
    actions: list[CaseAction],
) -> dict:
    open_actions = [
        action
        for action in actions
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


def build_case_evidence_payload(db, case_id: int) -> dict:
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

    actions = (
        db.query(CaseAction)
        .filter(CaseAction.case_id == case_id)
        .order_by(CaseAction.created_at.asc(), CaseAction.id.asc())
        .all()
    )

    audit_events = (
        db.query(CaseAudit)
        .filter(CaseAudit.case_id == case_id)
        .order_by(CaseAudit.created_at.asc(), CaseAudit.id.asc())
        .all()
    )

    latest_analysis = (
        db.query(CaseAIAnalysis)
        .filter(CaseAIAnalysis.case_id == case_id)
        .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
        .first()
    )

    closure_checklist = (
        db.query(CaseClosureChecklist)
        .filter(CaseClosureChecklist.case_id == case_id)
        .first()
    )

    closure_readiness = calculate_closure_readiness(
        closure_checklist,
        actions,
    )

    return {
        "generated_at": now_label(),
        "pack_type": "analyst_evidence_pack",
        "case": {
            "id": case.id,
            "group_key": case.group_key,
            "title": case.title,
            "status": case.status,
            "severity": case.severity,
            "owner": case.owner,
            "agent": case.agent,
            "correlation_type": case.correlation_type,
            "risk_score": case.risk_score,
            "summary": safe_json(case.summary),
            "sla_due_at": safe_isoformat(case.sla_due_at),
            "sla_status": calculate_case_sla_status(case),
            "status_reason": case.status_reason,
            "last_reviewed_by": case.last_reviewed_by,
            "last_reviewed_at": safe_isoformat(case.last_reviewed_at),
            "created_by": case.created_by,
            "created_at": safe_isoformat(case.created_at),
            "updated_at": safe_isoformat(case.updated_at),
        },
        "closure_readiness": closure_readiness,
        "closure_checklist": serialize_closure_checklist(closure_checklist),
        "case_ai_analysis": {
            "id": latest_analysis.id,
            "model": latest_analysis.model,
            "analysis": latest_analysis.analysis,
            "recommended_status": latest_analysis.recommended_status,
            "recommended_severity": latest_analysis.recommended_severity,
            "created_by": latest_analysis.created_by,
            "created_at": safe_isoformat(latest_analysis.created_at),
        }
        if latest_analysis
        else None,
        "actions": [
            {
                "id": action.id,
                "title": action.title,
                "description": action.description,
                "category": action.category,
                "priority": action.priority,
                "status": action.status,
                "due_at": safe_isoformat(action.due_at),
                "completed_at": safe_isoformat(action.completed_at),
                "created_by": action.created_by,
                "created_at": safe_isoformat(action.created_at),
                "updated_at": safe_isoformat(action.updated_at),
            }
            for action in actions
        ],
        "audit_trail": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "old_value": event.old_value,
                "new_value": event.new_value,
                "comment": event.comment,
                "created_by": event.created_by,
                "created_at": safe_isoformat(event.created_at),
            }
            for event in audit_events
        ],
        "incidents": [
            {
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
            }
            for incident in incidents
        ],
    }


def evidence_payload_to_markdown(payload: dict) -> str:
    case = payload["case"]
    readiness = payload["closure_readiness"]
    checklist = payload["closure_checklist"]
    analysis = payload["case_ai_analysis"]
    actions = payload["actions"]
    incidents = payload["incidents"]
    audit_trail = payload["audit_trail"]

    open_actions = [
        action
        for action in actions
        if action.get("status") in {"OPEN", "IN_PROGRESS"}
    ]

    lines = [
        f"# Analyst Evidence Pack — Case #{case['id']}",
        "",
        f"Generated at: **{payload['generated_at']}**",
        "",
        "## Evidence Pack Summary",
        "",
        f"- **Case title:** {format_value(case['title'])}",
        f"- **Case status:** {format_value(case['status'])}",
        f"- **Severity:** {format_value(case['severity'])}",
        f"- **Risk score:** {format_value(case['risk_score'])}",
        f"- **Owner:** {format_value(case['owner'])}",
        f"- **Host:** {format_value(case['agent'])}",
        f"- **Correlation type:** {format_value(case['correlation_type'])}",
        f"- **Linked incidents:** {len(incidents)}",
        f"- **Actions:** {len(actions)}",
        f"- **Open / in-progress actions:** {len(open_actions)}",
        f"- **Closure readiness:** {'READY' if readiness.get('ready_to_close') else 'BLOCKED'}",
        "",
        "## Closure Readiness",
        "",
        f"- **Ready to close:** {format_value(readiness.get('ready_to_close'))}",
        f"- **Open action count:** {format_value(readiness.get('open_action_count'))}",
        "",
    ]

    missing_items = readiness.get("missing_items", [])

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
                "No blocking items found.",
                "",
            ]
        )

    lines.extend(
        [
            "## Case Metadata",
            "",
            f"- **Group key:** {format_value(case['group_key'])}",
            f"- **SLA due at:** {format_value(case['sla_due_at'])}",
            f"- **SLA status:** {format_value(case['sla_status'])}",
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
    )

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
        lines.extend(["No case AI analysis available.", ""])

    lines.extend(
        [
            "## Action Plan Evidence",
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
        lines.extend(["No actions available.", ""])

    lines.extend(
        [
            "## Closure Checklist Evidence",
            "",
        ]
    )

    if checklist:
        lines.extend(
            [
                f"- **Closure decision:** {format_value(checklist.get('closure_decision'))}",
                f"- **Final severity:** {format_value(checklist.get('final_severity'))}",
                f"- **Reviewed by:** {format_value(checklist.get('reviewed_by'))}",
                f"- **Reviewed at:** {format_value(checklist.get('reviewed_at'))}",
                "",
                "### Root Cause / Conclusion",
                "",
                checklist.get("root_cause") or "Not documented.",
                "",
                "### Evidence Reviewed",
                "",
                checklist.get("evidence_reviewed") or "Not documented.",
                "",
                "### Actions Summary",
                "",
                checklist.get("actions_summary") or "Not documented.",
                "",
                "### Closure Reason",
                "",
                checklist.get("closure_reason") or "Not documented.",
                "",
                "### Residual Risk",
                "",
                checklist.get("residual_risk") or "Not documented.",
                "",
            ]
        )
    else:
        lines.extend(["No closure checklist available.", ""])

    lines.extend(
        [
            "## Linked Incident Evidence",
            "",
        ]
    )

    if incidents:
        for incident in incidents:
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
                    f"- **Correlated:** {format_value(incident['correlated'])}",
                    f"- **Correlation score:** {format_value(incident['correlation_score'])}",
                    f"- **Correlation type:** {format_value(incident['correlation_type'])}",
                    f"- **Escalation reason:** {format_value(incident['escalation_reason'])}",
                    f"- **Wazuh document ID:** {format_value(incident['wazuh_doc_id'])}",
                    "",
                    "#### MITRE ATT&CK",
                    "",
                    "```json",
                    json.dumps(incident["mitre"], ensure_ascii=False, indent=2),
                    "```",
                    "",
                    "#### Attack Chain",
                    "",
                    "```json",
                    json.dumps(incident["attack_chain"], ensure_ascii=False, indent=2),
                    "```",
                    "",
                    "#### Correlation Summary",
                    "",
                    "```json",
                    json.dumps(
                        incident["correlation_summary"],
                        ensure_ascii=False,
                        indent=2,
                    ),
                    "```",
                    "",
                    "#### Incident AI Analysis",
                    "",
                    incident["ai_analysis"] or "No incident AI analysis available.",
                    "",
                    "#### Raw Wazuh Alert",
                    "",
                    "```json",
                    json.dumps(incident["raw_alert"], ensure_ascii=False, indent=2),
                    "```",
                    "",
                ]
            )
    else:
        lines.extend(["No linked incidents available.", ""])

    lines.extend(
        [
            "## Case Audit Trail",
            "",
        ]
    )

    if audit_trail:
        for event in audit_trail:
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
        lines.extend(["No audit events available.", ""])

    return "\n".join(lines)


def build_case_evidence_pack(case_id: int) -> dict:
    db = SessionLocal()

    try:
        payload = build_case_evidence_payload(db, case_id)
        markdown = evidence_payload_to_markdown(payload)
        filename = f"case_{case_id}_evidence_pack.md"

        return {
            "filename": filename,
            "markdown": markdown,
            "payload": payload,
        }

    finally:
        db.close()
