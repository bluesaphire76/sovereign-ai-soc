from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ai_provider_redaction import RedactionOptions, redact_text
from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseAudit,
    CaseClosureChecklist,
    CaseIncident,
    Incident,
    IncidentAudit,
    IncidentCase,
)
from qdrant_knowledge import QdrantKnowledgeBase
from schemas.assistant import AssistantQueryRequest
from services.assistant.sources import SourceRecord


SEMANTIC_SOURCE_TYPES = {
    "knowledge_base",
    "historical_incident",
    "detection_control",
    "case_closure",
}
SEMANTIC_PAYLOAD_FIELDS = [
    "title",
    "section",
    "incident_id",
    "case_id",
    "rule_id",
    "item_id",
    "file_path",
    "domain",
    "source",
]
SECRET_ONLY_REDACTION = RedactionOptions(
    redact_ips=False,
    redact_usernames=False,
    redact_hostnames=False,
    redact_file_paths=False,
)


class IncidentNotFound(Exception):
    pass


class CaseNotFound(Exception):
    pass


@dataclass(frozen=True)
class RetrievalResult:
    scope: str
    incident_id: int | None = None
    case_id: int | None = None
    sources: list[SourceRecord] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    semantic_memory_requested: bool = False
    semantic_memory_attempted: bool = False
    semantic_memory_available: bool = False
    semantic_error_category: str | None = None


def _short_text(value: Any, *, max_chars: int = 900) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        text = json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    text = " ".join(text.split())
    text = str(redact_text(text, SECRET_ONLY_REDACTION).value)
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _json_or_text(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except Exception:
        return value


def _append_field(lines: list[str], label: str, value: Any, *, max_chars: int = 700) -> None:
    text = _short_text(value, max_chars=max_chars)
    if text:
        lines.append(f"{label}: {text}")


def _format_audit_rows(rows: list[Any], *, max_rows: int = 5) -> str:
    items = []
    for row in rows[:max_rows]:
        items.append(
            {
                "event_type": row.event_type,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment_present": bool(row.comment),
            }
        )
    return _short_text(items, max_chars=900)


def _incident_excerpt(incident: Incident, audit_rows: list[IncidentAudit]) -> str:
    lines = [f"Incident {incident.id} authoritative operational facts"]
    _append_field(lines, "Status", incident.status)
    _append_field(lines, "Timestamp", incident.timestamp)
    _append_field(lines, "Agent or host", incident.agent)
    _append_field(lines, "Rule", incident.rule)
    _append_field(lines, "Level", incident.level)
    _append_field(lines, "Risk score", incident.risk_score)
    _append_field(lines, "MITRE", incident.mitre)
    _append_field(lines, "Correlated", incident.correlated)
    _append_field(lines, "Correlation type", incident.correlation_type)
    _append_field(lines, "Correlation score", incident.correlation_score)
    _append_field(lines, "Correlation summary", _json_or_text(incident.correlation_summary), max_chars=900)
    _append_field(lines, "Attack chain", incident.attack_chain, max_chars=900)
    _append_field(lines, "Escalation reason", incident.escalation_reason, max_chars=900)
    _append_field(lines, "Recommended priority", incident.recommended_priority)
    _append_field(lines, "Current AI analysis", incident.ai_analysis, max_chars=1000)
    if audit_rows:
        _append_field(lines, "Latest incident audit events", _format_audit_rows(audit_rows), max_chars=900)
    lines.append(f"Raw alert omitted from assistant context; raw_alert_present: {bool(incident.raw_alert)}")
    return "\n".join(lines)


def _case_excerpt(
    case: IncidentCase,
    *,
    incident_count: int,
    latest_analysis: CaseAIAnalysis | None,
    closure: CaseClosureChecklist | None,
    audit_rows: list[CaseAudit],
    action_rows: list[CaseAction],
) -> str:
    lines = [f"Case {case.id} authoritative operational facts"]
    _append_field(lines, "Title", case.title)
    _append_field(lines, "Status", case.status)
    _append_field(lines, "Severity", case.severity)
    _append_field(lines, "Owner", case.owner)
    _append_field(lines, "Assignee", case.assignee)
    _append_field(lines, "SLA due at", case.sla_due_at.isoformat() if case.sla_due_at else None)
    _append_field(lines, "Status reason", case.status_reason, max_chars=700)
    _append_field(lines, "Agent or host", case.agent)
    _append_field(lines, "Correlation type", case.correlation_type)
    _append_field(lines, "Risk score", case.risk_score)
    _append_field(lines, "Summary", _json_or_text(case.summary), max_chars=900)
    _append_field(lines, "Linked incident count", incident_count)

    if latest_analysis:
        _append_field(
            lines,
            "Latest stored AI analysis",
            {
                "model": latest_analysis.model,
                "recommended_status": latest_analysis.recommended_status,
                "recommended_severity": latest_analysis.recommended_severity,
                "analysis": latest_analysis.analysis,
            },
            max_chars=1000,
        )

    if closure:
        _append_field(
            lines,
            "Closure checklist",
            {
                "root_cause_present": bool(closure.root_cause),
                "evidence_reviewed_present": bool(closure.evidence_reviewed),
                "actions_summary_present": bool(closure.actions_summary),
                "closure_decision": closure.closure_decision,
                "final_severity": closure.final_severity,
                "closure_approved": bool(closure.closure_approved),
                "residual_risk_present": bool(closure.residual_risk),
            },
            max_chars=800,
        )

    if action_rows:
        _append_field(
            lines,
            "Bounded latest case actions",
            [
                {
                    "id": row.id,
                    "title": row.title,
                    "category": row.category,
                    "priority": row.priority,
                    "status": row.status,
                }
                for row in action_rows[:5]
            ],
            max_chars=900,
        )

    if audit_rows:
        _append_field(lines, "Latest case audit events", _format_audit_rows(audit_rows), max_chars=900)

    return "\n".join(lines)


def _linked_incidents_excerpt(incidents: list[Incident]) -> str:
    lines = ["Bounded linked incident summaries"]
    for incident in incidents[:10]:
        lines.append(
            _short_text(
                {
                    "id": incident.id,
                    "status": incident.status,
                    "timestamp": incident.timestamp,
                    "agent": incident.agent,
                    "rule": incident.rule,
                    "level": incident.level,
                    "risk_score": incident.risk_score,
                    "mitre": incident.mitre,
                    "correlation_type": incident.correlation_type,
                    "recommended_priority": incident.recommended_priority,
                },
                max_chars=600,
            )
        )
    return "\n".join(line for line in lines if line)


def _semantic_record_id(context: dict[str, Any], source_type: str) -> str | None:
    for key in ("incident_id", "case_id", "rule_id", "item_id"):
        value = context.get(key)
        if value is not None and str(value).strip():
            return str(value)

    source = _short_text(context.get("source"), max_chars=120)
    if source_type == "historical_incident" and source.startswith("incident:"):
        return source.split(":", 1)[1]
    if source_type == "case_closure" and source.startswith("case:"):
        return source.split(":", 1)[1]
    return None


def _semantic_url(source_type: str, record_id: str | None) -> str | None:
    if source_type == "historical_incident" and record_id:
        return f"/incidents/{record_id}"
    if source_type == "case_closure" and record_id:
        return f"/cases/{record_id}"
    if source_type == "detection_control":
        return "/settings/detection-control"
    return None


def _semantic_label(context: dict[str, Any], source_type: str, record_id: str | None) -> str:
    title = _short_text(context.get("title"), max_chars=140)
    if title:
        return title
    if source_type == "historical_incident" and record_id:
        return f"Historical incident {record_id}"
    if source_type == "case_closure" and record_id:
        return f"Case closure {record_id}"
    source = _short_text(context.get("source"), max_chars=140)
    if source:
        return source
    return source_type.replace("_", " ").title()


def _source_type(context: dict[str, Any]) -> str:
    source_type = _short_text(context.get("source_type"), max_chars=80)
    return source_type if source_type in SEMANTIC_SOURCE_TYPES else ""


def _semantic_sources(contexts: list[dict[str, Any]]) -> list[SourceRecord]:
    records = []
    for context in contexts:
        source_type = _source_type(context)
        if not source_type:
            continue
        excerpt = _short_text(context.get("text"), max_chars=1200)
        if not excerpt:
            continue
        record_id = _semantic_record_id(context, source_type)
        records.append(
            SourceRecord(
                source_type=source_type,
                authority="advisory",
                record_id=record_id,
                label=_semantic_label(context, source_type, record_id),
                url=_semantic_url(source_type, record_id),
                score=float(context["score"]) if isinstance(context.get("score"), (int, float)) else None,
                section=_short_text(context.get("section"), max_chars=160) or None,
                excerpt=excerpt,
            )
        )
    return records


def _semantic_query(payload: AssistantQueryRequest, authoritative_sources: list[SourceRecord]) -> str:
    parts = [payload.message]
    for source in authoritative_sources[:2]:
        parts.append(source.excerpt)
    return _short_text(" ".join(parts), max_chars=2000)


def _retrieve_semantic_sources(
    payload: AssistantQueryRequest,
    *,
    authoritative_sources: list[SourceRecord],
    settings: Any,
    knowledge_base_factory,
) -> tuple[list[SourceRecord], list[str], bool, bool, str | None]:
    if not payload.include_semantic_memory:
        return [], ["Semantic memory was not requested for this assistant query."], False, False, None

    kb = knowledge_base_factory()
    if not kb.config.enabled:
        return [], ["Semantic memory is disabled; continuing without advisory context."], False, False, None

    try:
        contexts = kb.retrieve_contexts(
            _semantic_query(payload, authoritative_sources),
            limit=max(1, min(int(settings.semantic_limit), 8)),
            payload_fields=SEMANTIC_PAYLOAD_FIELDS,
        )
    except Exception as exc:
        return (
            [],
            ["Semantic memory retrieval failed safely; exact operational facts remain usable."],
            True,
            False,
            exc.__class__.__name__,
        )

    return _semantic_sources(contexts), [], True, True, None


def retrieve_assistant_context(
    payload: AssistantQueryRequest,
    *,
    db,
    settings: Any,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> RetrievalResult:
    authoritative_sources: list[SourceRecord] = []
    limitations: list[str] = []
    incident_id = payload.incident_id
    case_id = payload.case_id

    if payload.scope == "incident":
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise IncidentNotFound()
        audit_rows = (
            db.query(IncidentAudit)
            .filter(IncidentAudit.incident_id == incident.id)
            .order_by(IncidentAudit.created_at.desc().nullslast(), IncidentAudit.id.desc())
            .limit(5)
            .all()
        )
        authoritative_sources.append(
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id=str(incident.id),
                label=f"Incident {incident.id}",
                url=f"/incidents/{incident.id}",
                excerpt=_incident_excerpt(incident, audit_rows),
            )
        )

    elif payload.scope == "case":
        case = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()
        if not case:
            raise CaseNotFound()

        incident_count = db.query(CaseIncident).filter(CaseIncident.case_id == case.id).count()
        latest_analysis = (
            db.query(CaseAIAnalysis)
            .filter(CaseAIAnalysis.case_id == case.id)
            .order_by(CaseAIAnalysis.created_at.desc().nullslast(), CaseAIAnalysis.id.desc())
            .first()
        )
        closure = (
            db.query(CaseClosureChecklist)
            .filter(CaseClosureChecklist.case_id == case.id)
            .first()
        )
        audit_rows = (
            db.query(CaseAudit)
            .filter(CaseAudit.case_id == case.id)
            .order_by(CaseAudit.created_at.desc().nullslast(), CaseAudit.id.desc())
            .limit(5)
            .all()
        )
        action_rows = (
            db.query(CaseAction)
            .filter(CaseAction.case_id == case.id)
            .order_by(CaseAction.updated_at.desc().nullslast(), CaseAction.id.desc())
            .limit(5)
            .all()
        )
        linked_incidents = (
            db.query(Incident)
            .join(CaseIncident, CaseIncident.incident_id == Incident.id)
            .filter(CaseIncident.case_id == case.id)
            .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
            .limit(10)
            .all()
        )
        authoritative_sources.append(
            SourceRecord(
                source_type="case",
                authority="authoritative",
                record_id=str(case.id),
                label=f"Case {case.id}",
                url=f"/cases/{case.id}",
                excerpt=_case_excerpt(
                    case,
                    incident_count=incident_count,
                    latest_analysis=latest_analysis,
                    closure=closure,
                    audit_rows=audit_rows,
                    action_rows=action_rows,
                ),
            )
        )
        if linked_incidents:
            authoritative_sources.append(
                SourceRecord(
                    source_type="case_linked_incidents",
                    authority="authoritative",
                    record_id=str(case.id),
                    label=f"Case {case.id} linked incidents",
                    url=f"/cases/{case.id}/incidents",
                    excerpt=_linked_incidents_excerpt(linked_incidents),
                )
            )

    else:
        limitations.append(
            "Exact operational retrieval requires incident or case scope; global scope uses advisory semantic memory only."
        )

    advisory_sources, semantic_limitations, semantic_attempted, semantic_available, semantic_error = (
        _retrieve_semantic_sources(
            payload,
            authoritative_sources=authoritative_sources,
            settings=settings,
            knowledge_base_factory=knowledge_base_factory,
        )
    )
    limitations.extend(semantic_limitations)

    return RetrievalResult(
        scope=payload.scope,
        incident_id=incident_id,
        case_id=case_id,
        sources=[*authoritative_sources, *advisory_sources],
        limitations=limitations,
        semantic_memory_requested=payload.include_semantic_memory,
        semantic_memory_attempted=semantic_attempted,
        semantic_memory_available=semantic_available,
        semantic_error_category=semantic_error,
    )
