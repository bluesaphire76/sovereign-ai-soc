from __future__ import annotations

import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

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
from qdrant_knowledge import (
    QdrantKnowledgeBase,
    SemanticEmbeddingNotReady,
    SemanticRetrievalTimeout,
    get_knowledge_base,
)
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
    "os",
    "platform",
    "rule",
    "event_family",
    "mitre",
    "mitre_tactics",
    "mitre_techniques",
    "tags",
]
SEMANTIC_GENERIC_TERMS = {
    "advisory",
    "alert",
    "analysis",
    "case",
    "correlated",
    "correlation",
    "event",
    "evidence",
    "historical",
    "incident",
    "priority",
    "risk",
    "score",
    "severity",
    "status",
}
EVENT_FAMILY_PATTERNS = {
    "authentication": (
        "authentication",
        "brute force",
        "credential",
        "failed login",
        "ssh",
        "t1110",
    ),
    "file_deletion": (
        "data destruction",
        "file deletion",
        "files deleted",
        "t1070.004",
        "t1485",
    ),
    "registry": (
        "modify registry",
        "reg.exe",
        "registry",
        "t1112",
    ),
    "systemd": (
        "linux service",
        "systemctl",
        "systemd",
        "unit failed",
    ),
}
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
    fact_inventory: dict[str, Any] = field(default_factory=dict)
    sources: list[SourceRecord] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    semantic_memory_requested: bool = False
    semantic_memory_attempted: bool = False
    semantic_memory_available: bool = False
    semantic_error_category: str | None = None
    authoritative_elapsed_ms: int = 0
    semantic_elapsed_ms: int = 0
    semantic_candidates: int = 0
    semantic_sources_accepted: int = 0
    semantic_sources_rejected: int = 0
    semantic_rejection_reason: str | None = None
    semantic_status: str = "not_requested"
    semantic_degraded: bool = False
    semantic_budget_ms: int = 0
    embedding_backend: str | None = None
    embedding_cache_state: str | None = None
    embedding_elapsed_ms: int = 0
    qdrant_elapsed_ms: int = 0
    relevance_filter_elapsed_ms: int = 0
    semantic_timeout_phase: str | None = None


@dataclass(frozen=True)
class SemanticRetrievalOutcome:
    sources: list[SourceRecord] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    attempted: bool = False
    available: bool = False
    error_category: str | None = None
    candidates: int = 0
    rejected: int = 0
    rejection_reason: str | None = None
    status: str = "not_requested"
    degraded: bool = False
    embedding_backend: str | None = None
    embedding_cache_state: str | None = None
    embedding_elapsed_ms: int = 0
    qdrant_elapsed_ms: int = 0
    relevance_filter_elapsed_ms: int = 0
    timeout_phase: str | None = None


def _iso_or_value(value: Any) -> Any:
    if value is None:
        return None
    isoformat = getattr(value, "isoformat", None)
    return isoformat() if callable(isoformat) else value


def _mitre_inventory(value: Any) -> list[dict[str, str | None]]:
    parsed = _json_or_text(value)
    items = parsed if isinstance(parsed, list) else [parsed]
    techniques: list[dict[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for item in items:
        technique_id: str | None = None
        name: str | None = None
        if isinstance(item, dict):
            technique_id = str(
                item.get("id")
                or item.get("technique_id")
                or item.get("technique")
                or ""
            ).strip() or None
            name = str(item.get("name") or item.get("label") or "").strip() or None
        elif item is not None:
            text = str(item).strip()
            match = re.search(r"\bT\d{4}(?:\.\d{3})?\b", text, re.IGNORECASE)
            technique_id = match.group(0).upper() if match else None
            remainder = (
                f"{text[:match.start()]} {text[match.end():]}".strip(" :-,")
                if match
                else text
            )
            name = remainder or None
        if technique_id is None and name is None:
            continue
        key = (technique_id or "", name)
        if key in seen:
            continue
        seen.add(key)
        techniques.append({"id": technique_id, "name": name})
    return techniques


def _risk_normalization_severity(correlation_summary: Any) -> str | None:
    parsed = _json_or_text(correlation_summary)
    if not isinstance(parsed, dict):
        return None
    risk_normalization = parsed.get("risk_normalization")
    if not isinstance(risk_normalization, dict):
        return None
    severity = risk_normalization.get("severity")
    if not isinstance(severity, str):
        return None
    normalized = severity.strip()
    return normalized or None


def _incident_facts(
    incident: Incident,
    *,
    audit_rows: list[IncidentAudit],
    linked_case_ids: list[int],
) -> dict[str, Any]:
    latest_audit = audit_rows[0] if audit_rows else None
    correlation_summary = _json_or_text(incident.correlation_summary)
    return {
        "source_type": "incident",
        "incident_id": incident.id,
        "status": incident.status,
        "severity": None,
        "risk_normalization_severity": _risk_normalization_severity(
            correlation_summary
        ),
        "timestamp": incident.timestamp,
        "agent": incident.agent,
        "rule": incident.rule,
        "wazuh_level": incident.level,
        "risk_score": incident.risk_score,
        "mitre": _mitre_inventory(incident.mitre),
        "correlated": incident.correlated,
        "correlation_type": incident.correlation_type,
        "correlation_score": incident.correlation_score,
        "correlation_summary": correlation_summary,
        "attack_chain": _json_or_text(incident.attack_chain),
        "escalation_reason": incident.escalation_reason,
        "recommended_priority": incident.recommended_priority,
        "linked_case_ids": linked_case_ids,
        "latest_timeline_event": (
            {
                "event_type": latest_audit.event_type,
                "created_at": _iso_or_value(latest_audit.created_at),
            }
            if latest_audit
            else None
        ),
        "compromise_confirmed": None,
    }


def _linked_incident_facts(incidents: list[Incident]) -> list[dict[str, Any]]:
    return [
        {
            "incident_id": incident.id,
            "status": incident.status,
            "timestamp": incident.timestamp,
            "agent": incident.agent,
            "rule": incident.rule,
            "wazuh_level": incident.level,
            "risk_score": incident.risk_score,
            "mitre": _mitre_inventory(incident.mitre),
            "correlation_type": incident.correlation_type,
            "recommended_priority": incident.recommended_priority,
        }
        for incident in incidents[:10]
    ]


def _case_facts(
    case: IncidentCase,
    *,
    incident_count: int,
    latest_analysis: CaseAIAnalysis | None,
    closure: CaseClosureChecklist | None,
    audit_rows: list[CaseAudit],
    action_rows: list[CaseAction],
    linked_incidents: list[Incident],
) -> dict[str, Any]:
    latest_audit = audit_rows[0] if audit_rows else None
    return {
        "source_type": "case",
        "case_id": case.id,
        "title": case.title,
        "status": case.status,
        "severity": case.severity,
        "agent": case.agent,
        "correlation_type": case.correlation_type,
        "risk_score": case.risk_score,
        "summary": _json_or_text(case.summary),
        "owner": case.owner,
        "assignee": case.assignee,
        "sla_due_at": _iso_or_value(case.sla_due_at),
        "status_reason": case.status_reason,
        "linked_incident_count": incident_count,
        "linked_incidents": _linked_incident_facts(linked_incidents),
        "latest_stored_analysis": (
            {
                "recommended_status": latest_analysis.recommended_status,
                "recommended_severity": latest_analysis.recommended_severity,
                "analysis": latest_analysis.analysis,
            }
            if latest_analysis
            else None
        ),
        "closure": (
            {
                "closure_decision": closure.closure_decision,
                "final_severity": closure.final_severity,
                "closure_approved": closure.closure_approved,
                "root_cause": closure.root_cause,
                "evidence_reviewed": closure.evidence_reviewed,
                "residual_risk": closure.residual_risk,
            }
            if closure
            else None
        ),
        "latest_actions": [
            {
                "id": row.id,
                "title": row.title,
                "category": row.category,
                "priority": row.priority,
                "status": row.status,
            }
            for row in action_rows[:3]
        ],
        "latest_timeline_event": (
            {
                "event_type": latest_audit.event_type,
                "created_at": _iso_or_value(latest_audit.created_at),
            }
            if latest_audit
            else None
        ),
        "compromise_confirmed": None,
    }


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
                "comment_present": bool(row.comment),
            }
        )
    return _short_text(items, max_chars=900)


def _incident_excerpt(
    incident: Incident,
    audit_rows: list[IncidentAudit],
    linked_case_ids: list[int],
) -> str:
    lines = [f"Incident {incident.id} authoritative operational facts"]
    _append_field(lines, "Status", incident.status)
    _append_field(lines, "Timestamp", incident.timestamp)
    _append_field(lines, "Agent or host", incident.agent)
    _append_field(lines, "Rule", incident.rule, max_chars=240)
    _append_field(lines, "Level", incident.level)
    _append_field(lines, "Risk score", incident.risk_score)
    _append_field(lines, "MITRE", incident.mitre)
    _append_field(lines, "Correlated", incident.correlated)
    _append_field(lines, "Correlation type", incident.correlation_type)
    _append_field(lines, "Correlation score", incident.correlation_score)
    _append_field(lines, "Correlation summary", _json_or_text(incident.correlation_summary), max_chars=300)
    _append_field(lines, "Attack chain", incident.attack_chain, max_chars=240)
    _append_field(lines, "Escalation reason", incident.escalation_reason, max_chars=240)
    _append_field(lines, "Recommended priority", incident.recommended_priority)
    if linked_case_ids:
        _append_field(lines, "Linked case IDs", linked_case_ids[:5], max_chars=120)
    if audit_rows:
        _append_field(
            lines,
            "Latest timeline events",
            _format_audit_rows(audit_rows, max_rows=3),
            max_chars=360,
        )
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
    _append_field(lines, "Status reason", case.status_reason, max_chars=240)
    _append_field(lines, "Agent or host", case.agent)
    _append_field(lines, "Correlation type", case.correlation_type)
    _append_field(lines, "Risk score", case.risk_score)
    _append_field(lines, "Summary", _json_or_text(case.summary), max_chars=300)
    _append_field(lines, "Linked incident count", incident_count)

    if latest_analysis:
        _append_field(
            lines,
            "Latest stored AI analysis",
            {
                "recommended_status": latest_analysis.recommended_status,
                "recommended_severity": latest_analysis.recommended_severity,
                "analysis_present": bool(latest_analysis.analysis),
            },
            max_chars=240,
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
            max_chars=360,
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
                for row in action_rows[:3]
            ],
            max_chars=420,
        )

    if audit_rows:
        _append_field(
            lines,
            "Latest case timeline events",
            _format_audit_rows(audit_rows, max_rows=3),
            max_chars=360,
        )

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
    if (
        source_type == "historical_incident"
        and record_id
        and record_id.isdigit()
    ):
        return f"/incidents/{record_id}"
    if source_type == "case_closure" and record_id and record_id.isdigit():
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


def _semantic_text(context: dict[str, Any]) -> str:
    return " ".join(
        _short_text(context.get(field), max_chars=500)
        for field in (
            "title",
            "section",
            "text",
            "os",
            "platform",
            "rule",
            "event_family",
            "mitre",
            "mitre_tactics",
            "mitre_techniques",
            "tags",
        )
        if context.get(field) is not None
    ).lower()


def _event_families(text: str) -> set[str]:
    normalized = str(text or "").lower()
    return {
        family
        for family, patterns in EVENT_FAMILY_PATTERNS.items()
        if any(pattern in normalized for pattern in patterns)
    }


def _operating_systems(text: str) -> set[str]:
    normalized = str(text or "").lower()
    systems: set[str] = set()
    if any(token in normalized for token in ("windows", "registry", "powershell")):
        systems.add("windows")
    if any(token in normalized for token in ("linux", "systemd", "systemctl")):
        systems.add("linux")
    return systems


def _mitre_techniques(text: str) -> set[str]:
    return {
        match.upper()
        for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(text or ""), re.IGNORECASE)
    }


def _meaningful_terms(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z][a-z0-9_.-]{3,}", str(text or "").lower())
        if token not in SEMANTIC_GENERIC_TERMS
    }


def _semantic_relevance(
    context: dict[str, Any],
    *,
    authoritative_text: str,
    analyst_question: str,
) -> tuple[bool, str | None]:
    candidate_text = _semantic_text(context)
    if not candidate_text.strip():
        return False, "empty_content"

    authoritative_families = _event_families(authoritative_text)
    candidate_families = _event_families(candidate_text)
    authoritative_os = _operating_systems(authoritative_text)
    candidate_os = _operating_systems(candidate_text)
    if authoritative_os and candidate_os and authoritative_os.isdisjoint(candidate_os):
        return False, "os_mismatch"
    if (
        authoritative_families
        and candidate_families
        and authoritative_families.isdisjoint(candidate_families)
    ):
        return False, "event_family_mismatch"

    authoritative_mitre = _mitre_techniques(authoritative_text)
    candidate_mitre = _mitre_techniques(candidate_text)
    if authoritative_mitre & candidate_mitre:
        return True, None
    if authoritative_families & candidate_families:
        return True, None

    reference_terms = _meaningful_terms(
        f"{authoritative_text} {analyst_question}"
    )
    overlap = reference_terms & _meaningful_terms(candidate_text)
    if len(overlap) >= 2:
        return True, None
    return False, "insufficient_relevance"


def _semantic_sources(
    contexts: list[dict[str, Any]],
    *,
    authoritative_sources: list[SourceRecord],
    analyst_question: str,
    score_threshold: float | None,
    deadline_monotonic: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[list[SourceRecord], Counter[str]]:
    records = []
    rejected: Counter[str] = Counter()
    authoritative_text = " ".join(
        f"{source.label} {source.excerpt}" for source in authoritative_sources
    )
    for context in contexts:
        if deadline_monotonic is not None and clock() >= deadline_monotonic:
            raise SemanticRetrievalTimeout("relevance")
        source_type = _source_type(context)
        if not source_type:
            rejected["unsupported_source_type"] += 1
            continue
        score = (
            float(context["score"])
            if isinstance(context.get("score"), (int, float))
            else None
        )
        if score_threshold is not None and (
            score is None or score < score_threshold
        ):
            rejected["below_score_threshold"] += 1
            continue
        relevant, reason = _semantic_relevance(
            context,
            authoritative_text=authoritative_text,
            analyst_question=analyst_question,
        )
        if not relevant:
            rejected[reason or "insufficient_relevance"] += 1
            continue
        excerpt = _short_text(context.get("text"), max_chars=500)
        if not excerpt:
            rejected["empty_content"] += 1
            continue
        record_id = _semantic_record_id(context, source_type)
        records.append(
            SourceRecord(
                source_type=source_type,
                authority="advisory",
                record_id=record_id,
                label=_semantic_label(context, source_type, record_id),
                url=_semantic_url(source_type, record_id),
                score=score,
                section=_short_text(context.get("section"), max_chars=160) or None,
                excerpt=excerpt,
            )
        )
    return records, rejected


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
    deadline_monotonic: float | None,
    clock: Callable[[], float],
) -> SemanticRetrievalOutcome:
    if not payload.include_semantic_memory:
        return SemanticRetrievalOutcome(status="not_requested")
    if deadline_monotonic is not None and deadline_monotonic - clock() < 0.05:
        return SemanticRetrievalOutcome(
            limitations=[
                "Semantic memory was skipped because the assistant request budget was exhausted."
            ],
            status="timed_out",
            degraded=True,
            timeout_phase="semantic_retrieval_timeout",
        )

    kb = knowledge_base_factory()
    if not kb.config.enabled:
        return SemanticRetrievalOutcome(
            limitations=[
                "Semantic memory is disabled; continuing without advisory context."
            ],
            status="disabled",
        )

    diagnostics: dict[str, Any] = {}
    try:
        query = _semantic_query(payload, authoritative_sources)
        retrieve_with_diagnostics = getattr(
            kb,
            "retrieve_contexts_with_diagnostics",
            None,
        )
        if callable(retrieve_with_diagnostics):
            contexts, diagnostics = retrieve_with_diagnostics(
                query,
                limit=max(1, min(int(settings.semantic_limit), 8)),
                payload_fields=SEMANTIC_PAYLOAD_FIELDS,
                deadline_monotonic=deadline_monotonic,
                require_ready_embedding=True,
                clock=clock,
            )
        else:
            remaining = (
                max(0.0, deadline_monotonic - clock())
                if deadline_monotonic is not None
                else None
            )
            contexts = kb.retrieve_contexts(
                query,
                limit=max(1, min(int(settings.semantic_limit), 8)),
                payload_fields=SEMANTIC_PAYLOAD_FIELDS,
                timeout_seconds=remaining,
            )
            if deadline_monotonic is not None and clock() >= deadline_monotonic:
                raise SemanticRetrievalTimeout("qdrant")
    except SemanticEmbeddingNotReady as exc:
        return SemanticRetrievalOutcome(
            limitations=[
                "Semantic memory was unavailable within its time budget; the answer uses authoritative platform data."
            ],
            attempted=True,
            error_category="EmbeddingNotReady",
            status="failed",
            degraded=True,
            embedding_backend="sentence_transformers_local",
            embedding_cache_state=exc.cache_state,
            timeout_phase="semantic_embedding_timeout",
        )
    except SemanticRetrievalTimeout as exc:
        phase = {
            "embedding": "semantic_embedding_timeout",
            "qdrant": "semantic_qdrant_timeout",
            "normalization": "semantic_retrieval_timeout",
            "relevance": "semantic_retrieval_timeout",
        }.get(exc.phase, "semantic_retrieval_timeout")
        return SemanticRetrievalOutcome(
            limitations=[
                "Semantic memory was unavailable within its time budget; the answer uses authoritative platform data."
            ],
            attempted=True,
            error_category="SemanticRetrievalTimeout",
            status="timed_out",
            degraded=True,
            embedding_backend=diagnostics.get("embedding_backend"),
            embedding_cache_state=diagnostics.get("embedding_cache_state"),
            embedding_elapsed_ms=int(
                diagnostics.get("embedding_elapsed_ms") or 0
            ),
            qdrant_elapsed_ms=int(diagnostics.get("qdrant_elapsed_ms") or 0),
            timeout_phase=phase,
        )
    except TimeoutError:
        return SemanticRetrievalOutcome(
            limitations=[
                "Semantic memory was unavailable within its time budget; the answer uses authoritative platform data."
            ],
            attempted=True,
            error_category="TimeoutError",
            status="timed_out",
            degraded=True,
            embedding_backend=diagnostics.get("embedding_backend"),
            embedding_cache_state=diagnostics.get("embedding_cache_state"),
            embedding_elapsed_ms=int(
                diagnostics.get("embedding_elapsed_ms") or 0
            ),
            qdrant_elapsed_ms=int(diagnostics.get("qdrant_elapsed_ms") or 0),
            timeout_phase="semantic_qdrant_timeout",
        )
    except Exception as exc:
        return SemanticRetrievalOutcome(
            limitations=[
                "Semantic memory retrieval failed safely; exact operational facts remain usable."
            ],
            attempted=True,
            error_category=exc.__class__.__name__,
            status="failed",
            degraded=True,
            embedding_backend=diagnostics.get("embedding_backend"),
            embedding_cache_state=diagnostics.get("embedding_cache_state"),
            embedding_elapsed_ms=int(
                diagnostics.get("embedding_elapsed_ms") or 0
            ),
            qdrant_elapsed_ms=int(diagnostics.get("qdrant_elapsed_ms") or 0),
        )

    relevance_started = clock()
    try:
        sources, rejected = _semantic_sources(
            contexts,
            authoritative_sources=authoritative_sources,
            analyst_question=payload.message,
            score_threshold=getattr(kb.config, "score_threshold", None),
            deadline_monotonic=deadline_monotonic,
            clock=clock,
        )
        relevance_elapsed_ms = int((clock() - relevance_started) * 1000)
        if deadline_monotonic is not None and clock() >= deadline_monotonic:
            raise SemanticRetrievalTimeout("relevance")
    except SemanticRetrievalTimeout:
        return SemanticRetrievalOutcome(
            limitations=[
                "Semantic memory was unavailable within its time budget; the answer uses authoritative platform data."
            ],
            attempted=True,
            error_category="SemanticRetrievalTimeout",
            candidates=len(contexts),
            status="timed_out",
            degraded=True,
            embedding_backend=diagnostics.get("embedding_backend"),
            embedding_cache_state=diagnostics.get("embedding_cache_state"),
            embedding_elapsed_ms=int(
                diagnostics.get("embedding_elapsed_ms") or 0
            ),
            qdrant_elapsed_ms=int(diagnostics.get("qdrant_elapsed_ms") or 0),
            relevance_filter_elapsed_ms=int(
                (clock() - relevance_started) * 1000
            ),
            timeout_phase="semantic_retrieval_timeout",
        )
    rejection_reason = ",".join(
        f"{reason}:{count}" for reason, count in sorted(rejected.items())
    ) or None
    return SemanticRetrievalOutcome(
        sources=sources,
        attempted=True,
        available=bool(sources),
        candidates=len(contexts),
        rejected=sum(rejected.values()),
        rejection_reason=rejection_reason,
        status="ok",
        embedding_backend=diagnostics.get("embedding_backend"),
        embedding_cache_state=diagnostics.get("embedding_cache_state"),
        embedding_elapsed_ms=int(diagnostics.get("embedding_elapsed_ms") or 0),
        qdrant_elapsed_ms=int(diagnostics.get("qdrant_elapsed_ms") or 0),
        relevance_filter_elapsed_ms=relevance_elapsed_ms,
    )


def retrieve_assistant_context(
    payload: AssistantQueryRequest,
    *,
    db,
    settings: Any,
    knowledge_base_factory=get_knowledge_base,
    semantic_timeout_seconds: float | None = None,
    deadline_monotonic: float | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> RetrievalResult:
    authoritative_started = clock()
    authoritative_sources: list[SourceRecord] = []
    limitations: list[str] = []
    fact_inventory: dict[str, Any] = {
        "source_type": payload.scope,
        "incident_id": payload.incident_id,
        "case_id": payload.case_id,
    }
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
        linked_case_rows = (
            db.query(CaseIncident)
            .filter(CaseIncident.incident_id == incident.id)
            .limit(5)
            .all()
        )
        linked_case_ids = [
            int(row.case_id)
            for row in linked_case_rows
            if row.case_id is not None
        ]
        fact_inventory = _incident_facts(
            incident,
            audit_rows=audit_rows,
            linked_case_ids=linked_case_ids,
        )
        authoritative_sources.append(
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id=str(incident.id),
                label=f"Incident {incident.id}",
                url=f"/incidents/{incident.id}",
                excerpt=_incident_excerpt(
                    incident,
                    audit_rows,
                    linked_case_ids,
                ),
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
        fact_inventory = _case_facts(
            case,
            incident_count=incident_count,
            latest_analysis=latest_analysis,
            closure=closure,
            audit_rows=audit_rows,
            action_rows=action_rows,
            linked_incidents=linked_incidents,
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

    authoritative_elapsed_ms = int((clock() - authoritative_started) * 1000)
    semantic_started = clock()
    semantic_budget = min(
        2.0,
        max(0.0, float(semantic_timeout_seconds or 2.0)),
    )
    semantic_deadline = (
        semantic_started + semantic_budget
        if semantic_budget is not None
        else deadline_monotonic
    )
    if deadline_monotonic is not None:
        semantic_deadline = (
            min(semantic_deadline, deadline_monotonic)
            if semantic_deadline is not None
            else deadline_monotonic
        )
    semantic = _retrieve_semantic_sources(
        payload,
        authoritative_sources=authoritative_sources,
        settings=settings,
        knowledge_base_factory=knowledge_base_factory,
        deadline_monotonic=semantic_deadline,
        clock=clock,
    )
    semantic_elapsed_ms = int((clock() - semantic_started) * 1000)
    limitations.extend(semantic.limitations)

    return RetrievalResult(
        scope=payload.scope,
        incident_id=incident_id,
        case_id=case_id,
        fact_inventory=fact_inventory,
        sources=[*authoritative_sources, *semantic.sources],
        limitations=limitations,
        semantic_memory_requested=payload.include_semantic_memory,
        semantic_memory_attempted=semantic.attempted,
        semantic_memory_available=semantic.available,
        semantic_error_category=semantic.error_category,
        authoritative_elapsed_ms=authoritative_elapsed_ms,
        semantic_elapsed_ms=semantic_elapsed_ms,
        semantic_candidates=semantic.candidates,
        semantic_sources_accepted=len(semantic.sources),
        semantic_sources_rejected=semantic.rejected,
        semantic_rejection_reason=semantic.rejection_reason,
        semantic_status=semantic.status,
        semantic_degraded=semantic.degraded,
        semantic_budget_ms=max(0, int((semantic_budget or 0) * 1000)),
        embedding_backend=semantic.embedding_backend,
        embedding_cache_state=semantic.embedding_cache_state,
        embedding_elapsed_ms=semantic.embedding_elapsed_ms,
        qdrant_elapsed_ms=semantic.qdrant_elapsed_ms,
        relevance_filter_elapsed_ms=semantic.relevance_filter_elapsed_ms,
        semantic_timeout_phase=semantic.timeout_phase,
    )
