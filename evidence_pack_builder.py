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
from report_naming import case_evidence_pack_filename
from report_dns_context import attach_case_dns_context, append_case_dns_context_markdown
from report_network_evidence import attach_case_network_evidence, append_case_network_evidence_markdown


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
    if value is None or value == "":
        return "Not available"

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)

    return str(value)


def json_block(value) -> str:
    return "```json\n" + json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n```"


def escape_table(value) -> str:
    return format_value(value).replace("|", "\\|").replace("\n", "<br/>")


def table(headers: list[str], rows: list[list[object]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]

    for row in rows:
        lines.append("| " + " | ".join(escape_table(item) for item in row) + " |")

    return "\n".join(lines)


def compact_correlation_summary(summary, max_related_events: int = 8):
    if not isinstance(summary, dict):
        return summary

    compact = dict(summary)
    details = compact.get("related_event_details")

    if isinstance(details, list) and len(details) > max_related_events:
        compact["related_event_details_sample"] = details[:max_related_events]
        compact["related_event_details_total"] = len(details)
        compact["related_event_details_truncated"] = True
        compact.pop("related_event_details", None)

    return compact


def short_text(value, max_chars: int = 280) -> str:
    text = format_value(value).replace("\n", " ").strip()

    if len(text) <= max_chars:
        return text

    return text[: max_chars - 3].rstrip() + "..."


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
        "closure_approved": row.closure_approved,
        "closure_approved_by": row.closure_approved_by,
        "closure_approved_at": safe_isoformat(row.closure_approved_at),
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
            "assignee": case.assignee,
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

    completed_actions = [
        action
        for action in actions
        if action.get("status") in {"DONE", "CANCELLED"}
    ]

    timeline_events = []

    for incident in incidents:
        timeline_events.append(
            {
                "time": incident.get("timestamp"),
                "type": "Incident",
                "source": "Wazuh",
                "detail": (
                    f"Incident #{incident.get('id')}: {format_value(incident.get('rule'))} "
                    f"on {format_value(incident.get('agent'))}"
                ),
            }
        )

    for action in actions:
        timeline_events.append(
            {
                "time": action.get("created_at"),
                "type": "Action",
                "source": "Case workflow",
                "detail": (
                    f"Action #{action.get('id')}: {format_value(action.get('title'))} "
                    f"({format_value(action.get('status'))})"
                ),
            }
        )

    for event in audit_trail:
        timeline_events.append(
            {
                "time": event.get("created_at"),
                "type": "Audit",
                "source": "Case audit",
                "detail": (
                    f"{format_value(event.get('event_type'))}: "
                    f"{format_value(event.get('old_value'))} -> {format_value(event.get('new_value'))}"
                ),
            }
        )

    timeline_events.sort(key=lambda item: format_value(item.get("time")))

    lines = [
        "# Analyst Evidence Pack",
        "",
        f"Case ID: **{case['id']}**",
        "",
        f"Generated at: **{payload['generated_at']}**",
        "",
        "## Evidence Summary",
        "",
        table(
            ["Field", "Value"],
            [
                ["Case title", case.get("title")],
                ["Case status", case.get("status")],
                ["Severity", case.get("severity")],
                ["Risk score", case.get("risk_score")],
                ["Owner / assignee", f"{format_value(case.get('owner'))} / {format_value(case.get('assignee'))}"],
                ["Host", case.get("agent")],
                ["Correlation type", case.get("correlation_type")],
                ["Linked incidents", len(incidents)],
                ["Open / in-progress actions", len(open_actions)],
                ["Closure readiness", "READY" if readiness.get("ready_to_close") else "BLOCKED"],
                ["SLA target", case.get("sla_due_at")],
                ["SLA status", case.get("sla_status")],
            ],
        ),
        "",
    ]

    missing_items = readiness.get("missing_items", [])

    if missing_items:
        lines.extend(["### Closure Blockers", ""])
        lines.extend([f"- {item}" for item in missing_items])
        lines.append("")
    else:
        lines.extend(["No closure blockers reported by the readiness check.", ""])

    lines.extend(
        [
            "## Timeline / Relevant Events",
            "",
        ]
    )

    if timeline_events:
        lines.extend(
            [
                table(
                    ["Time", "Type", "Source", "Detail"],
                    [
                        [
                            event.get("time"),
                            event.get("type"),
                            event.get("source"),
                            event.get("detail"),
                        ]
                        for event in timeline_events
                    ],
                ),
                "",
            ]
        )
    else:
        lines.extend(["No relevant timeline events available.", ""])

    lines.extend(["## AI Reasoning", ""])

    if analysis:
        lines.extend(
            [
                table(
                    ["Field", "Value"],
                    [
                        ["Model", analysis.get("model")],
                        ["Recommended status", analysis.get("recommended_status")],
                        ["Recommended severity", analysis.get("recommended_severity")],
                        ["Generated at", analysis.get("created_at")],
                    ],
                ),
                "",
                analysis.get("analysis") or "No analysis text available.",
                "",
            ]
        )
    else:
        lines.extend(["No case AI analysis available.", ""])

    incident_ai_rows = [
        [
            incident.get("id"),
            incident.get("risk_score"),
            incident.get("recommended_priority"),
            short_text(incident.get("ai_analysis") or "No incident AI analysis available."),
        ]
        for incident in incidents[:12]
    ]

    if incident_ai_rows:
        lines.extend(
            [
                "### Incident AI Highlights",
                "",
                table(["Incident", "Risk", "Priority", "AI analysis"], incident_ai_rows),
                "",
            ]
        )

        if len(incidents) > 12:
            lines.extend(
                [
                    f"Only the first 12 incident AI highlights are shown here. Full incident evidence remains in the Technical Appendix. Total linked incidents: {len(incidents)}.",
                    "",
                ]
            )

    lines.extend(
        [
            "## Analyst Notes",
            "",
        ]
    )

    if checklist:
        lines.extend(
            [
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
                "### Closure Decision",
                "",
                table(
                    ["Field", "Value"],
                    [
                        ["Closure decision", checklist.get("closure_decision")],
                        ["Final severity", checklist.get("final_severity")],
                        ["Closure approved", checklist.get("closure_approved")],
                        ["Approved by", checklist.get("closure_approved_by")],
                        ["Approved at", checklist.get("closure_approved_at")],
                        ["Closure reason", checklist.get("closure_reason")],
                        ["Residual risk", checklist.get("residual_risk")],
                        ["Reviewed by", checklist.get("reviewed_by")],
                        ["Reviewed at", checklist.get("reviewed_at")],
                    ],
                ),
                "",
            ]
        )
    else:
        lines.extend(["No closure checklist or standalone analyst notes available.", ""])

    lines.extend(["### Action Evidence", ""])

    if actions:
        lines.extend(
            [
                table(
                    ["ID", "Action", "Status", "Priority", "Due at", "Completed at", "Created by"],
                    [
                        [
                            action.get("id"),
                            action.get("title"),
                            action.get("status"),
                            action.get("priority"),
                            action.get("due_at"),
                            action.get("completed_at"),
                            action.get("created_by"),
                        ]
                        for action in actions
                    ],
                ),
                "",
                f"Open actions: **{len(open_actions)}**. Completed or cancelled actions: **{len(completed_actions)}**.",
                "",
            ]
        )
    else:
        lines.extend(["No actions available.", ""])

    lines.extend(
        [
            "## Audit Trail",
            "",
        ]
    )

    if audit_trail:
        lines.extend(
            [
                table(
                    ["ID", "Type", "Old value", "New value", "Actor", "Timestamp", "Comment"],
                    [
                        [
                            event.get("id"),
                            event.get("event_type"),
                            event.get("old_value"),
                            event.get("new_value"),
                            event.get("created_by"),
                            event.get("created_at"),
                            event.get("comment"),
                        ]
                        for event in audit_trail
                    ],
                ),
                "",
            ]
        )
    else:
        lines.extend(["No audit events available.", ""])

    lines.extend(
        [
            "## Technical Appendix",
            "",
            "### Case Metadata",
            "",
            table(
                ["Field", "Value"],
                [
                    ["Group key", case.get("group_key")],
                    ["Status reason", case.get("status_reason")],
                    ["Last reviewed by", case.get("last_reviewed_by")],
                    ["Last reviewed at", case.get("last_reviewed_at")],
                    ["Created by", case.get("created_by")],
                    ["Created at", case.get("created_at")],
                    ["Updated at", case.get("updated_at")],
                ],
            ),
            "",
            "### Case Summary Payload",
            "",
            json_block(case.get("summary")),
            "",
        ]
    )

    if incidents:
        for incident in incidents:
            lines.extend(
                [
                    f"### Incident #{incident['id']} Technical Evidence",
                    "",
                    table(
                        ["Field", "Value"],
                        [
                            ["Status", incident.get("status")],
                            ["Timestamp", incident.get("timestamp")],
                            ["Host", incident.get("agent")],
                            ["Rule", incident.get("rule")],
                            ["Level", incident.get("level")],
                            ["Risk score", incident.get("risk_score")],
                            ["Recommended priority", incident.get("recommended_priority")],
                            ["Correlated", incident.get("correlated")],
                            ["Correlation score", incident.get("correlation_score")],
                            ["Correlation type", incident.get("correlation_type")],
                            ["Escalation reason", incident.get("escalation_reason")],
                            ["Wazuh document ID", incident.get("wazuh_doc_id")],
                        ],
                    ),
                    "",
                    "#### Raw Wazuh Alert",
                    "",
                    json_block(incident.get("raw_alert")),
                    "",
                    "#### Incident AI Analysis",
                    "",
                    incident.get("ai_analysis") or "No incident AI analysis available.",
                    "",
                    "#### Correlation Summary",
                    "",
                    json_block(compact_correlation_summary(incident.get("correlation_summary"))),
                    "",
                    "#### MITRE / Metadata",
                    "",
                    json_block(incident.get("mitre")),
                    "",
                    "#### Attack Chain",
                    "",
                    json_block(incident.get("attack_chain")),
                    "",
                ]
            )
    else:
        lines.extend(["No linked incident technical evidence available.", ""])

    return "\n".join(lines).strip() + "\n"


def build_case_evidence_pack(case_id: int) -> dict:
    db = SessionLocal()

    try:
        payload = build_case_evidence_payload(db, case_id)
        attach_case_network_evidence(payload)
        attach_case_dns_context(payload)
        markdown = append_case_network_evidence_markdown(
            evidence_payload_to_markdown(payload),
            payload,
        )
        markdown = append_case_dns_context_markdown(markdown, payload, technical=True)
        filename = case_evidence_pack_filename(case_id)

        return {
            "filename": filename,
            "markdown": markdown,
            "payload": payload,
        }

    finally:
        db.close()
