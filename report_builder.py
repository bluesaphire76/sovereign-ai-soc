import json
from datetime import datetime, timezone

from database import SessionLocal
from models import (
    CaseAIAnalysis,
    CaseAudit,
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
