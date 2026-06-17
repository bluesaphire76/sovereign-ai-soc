from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from ai_provider_redaction import RedactionOptions, redact_text
from database import SessionLocal
from investigation_ai.adapters import safe_text
from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseClosureChecklist,
    CaseIncident,
    Incident,
    IncidentCase,
)
from qdrant_knowledge import QdrantKnowledgeBase


router = APIRouter(tags=["Case Closure Semantic Context"])

CASE_CLOSURE_CONTEXT_DECISION_BOUNDARY = (
    "Case closure semantic memory is advisory only. It may support closure "
    "review, residual-risk comparison, precedent lookup and detection-control "
    "awareness, but it must not close cases, approve closure, set final "
    "severity, suppress alerts, apply detection controls or replace RBAC, "
    "audit, deterministic readiness checks and human validation."
)
CASE_CLOSURE_SOURCE_TYPE = "case_closure"
DETECTION_CONTROL_SOURCE_TYPE = "detection_control"
HISTORICAL_INCIDENT_SOURCE_TYPE = "historical_incident"
KNOWLEDGE_BASE_SOURCE_TYPE = "knowledge_base"
OPEN_ACTION_STATUSES = {"OPEN", "IN_PROGRESS"}
CLOSURE_REQUIRED_FIELDS = {
    "root_cause": "Root cause / conclusion",
    "evidence_reviewed": "Evidence reviewed",
    "actions_summary": "Actions summary",
    "closure_reason": "Closure reason",
    "closure_decision": "Closure decision",
    "final_severity": "Final severity",
    "residual_risk": "Residual risk",
}
CASE_CLOSURE_PAYLOAD_FIELDS = [
    "case_id",
    "case_title",
    "case_status",
    "case_severity",
    "closure_decision",
    "final_severity",
    "closure_approved",
    "incident_count",
    "redaction_applied",
    "decision_boundary",
]
DETECTION_CONTROL_PAYLOAD_FIELDS = [
    "rule_id",
    "rule_type",
    "name",
    "status",
    "enabled",
    "scope",
    "matcher_kind",
    "owner",
    "last_validation_status",
    "decision_boundary",
]
HISTORICAL_INCIDENT_PAYLOAD_FIELDS = [
    "incident_id",
    "status",
    "risk_score",
    "level",
    "rule",
    "agent",
    "mitre",
    "correlation_type",
    "recommended_priority",
    "decision_boundary",
]


def _short_text(value: Any, *, max_chars: int = 700) -> str:
    text = " ".join(safe_text(value).split())
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _safe_query_part(value: Any, *, max_chars: int = 700) -> str:
    result = redact_text(
        _short_text(value, max_chars=max_chars),
        RedactionOptions(
            redact_ips=True,
            redact_usernames=True,
            redact_hostnames=True,
            redact_file_paths=True,
        ),
    )
    return safe_text(result.value)


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _case_id_from_context(context: dict[str, Any]) -> int | None:
    case_id = _int_or_none(context.get("case_id"))
    if case_id is not None:
        return case_id

    source = safe_text(context.get("source"))
    if source.startswith("case_closure:"):
        return _int_or_none(source.split(":", 1)[1])

    return None


def _severity_rank(value: Any) -> int:
    severity = safe_text(value).upper()
    return {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(severity, 0)


def _closure_missing_items(
    closure: CaseClosureChecklist | None,
    *,
    open_action_count: int,
) -> list[str]:
    missing: list[str] = []
    if open_action_count > 0:
        missing.append(f"{open_action_count} action(s) are still OPEN or IN_PROGRESS")

    if not closure:
        missing.extend(CLOSURE_REQUIRED_FIELDS.values())
        missing.append("Closure approval")
        return missing

    for field, label in CLOSURE_REQUIRED_FIELDS.items():
        if not safe_text(getattr(closure, field, None)):
            missing.append(label)

    if not bool(closure.closure_approved):
        missing.append("Closure approval")

    return missing


def build_case_closure_semantic_query(
    case: IncidentCase,
    *,
    closure: CaseClosureChecklist | None,
    incidents: list[Incident],
    actions: list[CaseAction],
    latest_analysis: CaseAIAnalysis | None,
) -> str:
    incident_lines = [
        (
            f"Incident {incident.id}: rule={incident.rule}; agent={incident.agent}; "
            f"mitre={incident.mitre}; correlation={incident.correlation_type}; "
            f"risk={incident.risk_score}; priority={incident.recommended_priority}"
        )
        for incident in incidents[:8]
    ]
    action_lines = [
        (
            f"{action.category}: {action.title}; status={action.status}; "
            f"priority={action.priority}; description={action.description}"
        )
        for action in actions[:8]
    ]
    parts = [
        "Case closure semantic decision support request.",
        f"Case ID: {case.id}",
        f"Case Title: {_safe_query_part(case.title, max_chars=260)}",
        f"Case Status: {_safe_query_part(case.status, max_chars=120)}",
        f"Case Severity: {_safe_query_part(case.severity_review or case.severity, max_chars=120)}",
        f"Case Risk Score: {case.risk_score}",
        f"Case Correlation Type: {_safe_query_part(case.correlation_type, max_chars=180)}",
        f"Case Summary: {_safe_query_part(case.summary, max_chars=800)}",
        f"Closure Decision: {_safe_query_part(getattr(closure, 'closure_decision', None), max_chars=160)}",
        f"Final Severity: {_safe_query_part(getattr(closure, 'final_severity', None), max_chars=120)}",
        f"Root Cause: {_safe_query_part(getattr(closure, 'root_cause', None), max_chars=700)}",
        f"Evidence Reviewed: {_safe_query_part(getattr(closure, 'evidence_reviewed', None), max_chars=700)}",
        f"Actions Summary: {_safe_query_part(getattr(closure, 'actions_summary', None), max_chars=700)}",
        f"Residual Risk: {_safe_query_part(getattr(closure, 'residual_risk', None), max_chars=700)}",
        f"Closure Reason: {_safe_query_part(getattr(closure, 'closure_reason', None), max_chars=700)}",
        f"Linked Incident Context: {_safe_query_part(' '.join(incident_lines), max_chars=1200)}",
        f"Case Action Context: {_safe_query_part(' '.join(action_lines), max_chars=1200)}",
        f"Latest AI Analysis: {_safe_query_part(getattr(latest_analysis, 'analysis', None), max_chars=900)}",
    ]
    return _short_text(" ".join(part for part in parts if safe_text(part)), max_chars=3200)


def _semantic_context_item(context: dict[str, Any], *, max_excerpt: int = 560) -> dict[str, Any]:
    item = {
        "source_type": safe_text(context.get("source_type")) or "unknown",
        "source": safe_text(context.get("source")),
        "score": context.get("score"),
        "excerpt": _short_text(context.get("text"), max_chars=max_excerpt),
    }

    for key in [
        "case_id",
        "case_title",
        "case_status",
        "case_severity",
        "closure_decision",
        "final_severity",
        "closure_approved",
        "incident_count",
        "rule_id",
        "rule_type",
        "name",
        "status",
        "enabled",
        "scope",
        "matcher_kind",
        "owner",
        "last_validation_status",
        "incident_id",
        "risk_score",
        "level",
        "rule",
        "agent",
        "mitre",
        "correlation_type",
        "recommended_priority",
    ]:
        if key in context:
            item[key] = context.get(key)

    return item


def _retrieve_source_contexts(
    kb: QdrantKnowledgeBase,
    query: str,
    *,
    source_type: str,
    limit: int,
    payload_fields: list[str],
) -> list[dict[str, Any]]:
    return kb.retrieve_contexts(
        query,
        limit=limit,
        source_type=source_type,
        payload_fields=payload_fields,
    )


def _build_warnings(
    *,
    case: IncidentCase,
    closure: CaseClosureChecklist | None,
    missing_items: list[str],
    similar_closures: list[dict[str, Any]],
    related_detection_controls: list[dict[str, Any]],
) -> list[str]:
    warnings: list[str] = []

    if missing_items:
        warnings.append(
            "Deterministic closure readiness still has blockers; semantic memory must not override them."
        )

    if not similar_closures:
        warnings.append(
            "No similar final/approved case closure was found in semantic memory for this review context."
        )

    current_decision = safe_text(getattr(closure, "closure_decision", None)).upper()
    different_decisions = {
        safe_text(item.get("closure_decision")).upper()
        for item in similar_closures
        if safe_text(item.get("closure_decision"))
        and safe_text(item.get("closure_decision")).upper() != current_decision
    }
    if current_decision and different_decisions:
        warnings.append(
            "Similar closures include different closure decisions: "
            + ", ".join(sorted(different_decisions))
            + "."
        )

    current_severity = safe_text(
        getattr(closure, "final_severity", None) or case.severity_review or case.severity
    ).upper()
    higher_severities = {
        safe_text(item.get("final_severity")).upper()
        for item in similar_closures
        if _severity_rank(item.get("final_severity")) > _severity_rank(current_severity)
    }
    if current_severity and higher_severities:
        warnings.append(
            "Similar closures include higher final severity outcomes: "
            + ", ".join(sorted(higher_severities, key=_severity_rank))
            + "."
        )

    if related_detection_controls:
        warnings.append(
            "Related detection controls or tuning records were found; review them before treating this closure as recurring noise."
        )

    return warnings


def build_case_closure_semantic_context(
    db,
    case_id: int,
    *,
    limit: int = 4,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    case = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()
    if not case:
        raise ValueError(f"Case {case_id} not found")

    closure = (
        db.query(CaseClosureChecklist)
        .filter(CaseClosureChecklist.case_id == case_id)
        .first()
    )
    incidents = (
        db.query(Incident)
        .join(CaseIncident, CaseIncident.incident_id == Incident.id)
        .filter(CaseIncident.case_id == case_id)
        .order_by(Incident.risk_score.desc(), Incident.id.desc())
        .limit(8)
        .all()
    )
    actions = (
        db.query(CaseAction)
        .filter(CaseAction.case_id == case_id)
        .order_by(CaseAction.updated_at.desc(), CaseAction.id.desc())
        .limit(8)
        .all()
    )
    open_action_count = (
        db.query(CaseAction)
        .filter(
            CaseAction.case_id == case_id,
            CaseAction.status.in_(sorted(OPEN_ACTION_STATUSES)),
        )
        .count()
    )
    latest_analysis = (
        db.query(CaseAIAnalysis)
        .filter(CaseAIAnalysis.case_id == case_id)
        .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
        .first()
    )
    missing_items = _closure_missing_items(closure, open_action_count=open_action_count)
    ready_to_close = len(missing_items) == 0
    query = build_case_closure_semantic_query(
        case,
        closure=closure,
        incidents=incidents,
        actions=actions,
        latest_analysis=latest_analysis,
    )
    kb = knowledge_base_factory()
    resolved_limit = max(1, min(limit, 8))

    base_response = {
        "case_id": case_id,
        "enabled": bool(kb.config.enabled),
        "ready_to_close": ready_to_close,
        "missing_items": missing_items,
        "open_action_count": open_action_count,
        "similar_closures": [],
        "related_detection_controls": [],
        "similar_historical_incidents": [],
        "related_playbooks": [],
        "warnings": [],
        "result_count": 0,
        "decision_boundary": CASE_CLOSURE_CONTEXT_DECISION_BOUNDARY,
        "message": (
            "Semantic memory context is analyst guidance only; no case closure, "
            "approval, severity, suppression or detection-control change was made."
        ),
    }

    if not kb.config.enabled:
        return {
            **base_response,
            "status": "DISABLED",
            "message": "Semantic memory is disabled.",
        }

    try:
        closure_contexts = _retrieve_source_contexts(
            kb,
            query,
            source_type=CASE_CLOSURE_SOURCE_TYPE,
            limit=min(resolved_limit + 2, 10),
            payload_fields=CASE_CLOSURE_PAYLOAD_FIELDS,
        )
        detection_contexts = _retrieve_source_contexts(
            kb,
            query,
            source_type=DETECTION_CONTROL_SOURCE_TYPE,
            limit=resolved_limit,
            payload_fields=DETECTION_CONTROL_PAYLOAD_FIELDS,
        )
        historical_contexts = _retrieve_source_contexts(
            kb,
            query,
            source_type=HISTORICAL_INCIDENT_SOURCE_TYPE,
            limit=resolved_limit,
            payload_fields=HISTORICAL_INCIDENT_PAYLOAD_FIELDS,
        )
        playbook_contexts = _retrieve_source_contexts(
            kb,
            query,
            source_type=KNOWLEDGE_BASE_SOURCE_TYPE,
            limit=min(resolved_limit, 3),
            payload_fields=[],
        )
    except Exception as exc:
        return {
            **base_response,
            "status": "WARN",
            "error_type": exc.__class__.__name__,
            "message": (
                "Semantic memory context retrieval failed; no case closure, "
                "approval, severity, suppression or detection-control change was made."
            ),
        }

    similar_closures: list[dict[str, Any]] = []
    for context in closure_contexts:
        if _case_id_from_context(context) == case_id:
            continue
        similar_closures.append(_semantic_context_item(context))
        if len(similar_closures) >= resolved_limit:
            break

    related_detection_controls = [
        _semantic_context_item(context)
        for context in detection_contexts[:resolved_limit]
    ]
    similar_historical_incidents = [
        _semantic_context_item(context)
        for context in historical_contexts[:resolved_limit]
    ]
    related_playbooks = [
        _semantic_context_item(context, max_excerpt=420)
        for context in playbook_contexts[: min(resolved_limit, 3)]
    ]
    warnings = _build_warnings(
        case=case,
        closure=closure,
        missing_items=missing_items,
        similar_closures=similar_closures,
        related_detection_controls=related_detection_controls,
    )
    result_count = (
        len(similar_closures)
        + len(related_detection_controls)
        + len(similar_historical_incidents)
        + len(related_playbooks)
    )

    return {
        **base_response,
        "status": "OK",
        "similar_closures": similar_closures,
        "related_detection_controls": related_detection_controls,
        "similar_historical_incidents": similar_historical_incidents,
        "related_playbooks": related_playbooks,
        "warnings": warnings,
        "result_count": result_count,
    }


@router.get("/cases/{case_id}/closure/semantic-context")
def get_case_closure_semantic_context(
    case_id: int,
    limit: int = Query(default=4, ge=1, le=8),
):
    db = SessionLocal()

    try:
        return build_case_closure_semantic_context(db, case_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Case not found.") from exc
    finally:
        db.close()
