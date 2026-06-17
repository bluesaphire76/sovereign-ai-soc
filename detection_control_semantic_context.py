from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ai_provider_redaction import RedactionOptions, redact_text
from investigation_ai.adapters import safe_text
from qdrant_knowledge import QdrantKnowledgeBase


DETECTION_CONTROL_CONTEXT_DECISION_BOUNDARY = (
    "Detection Control semantic memory is advisory only. It may support tuning "
    "review, duplicate/overlap detection, precedent lookup and playbook lookup, "
    "but it must not create, update, approve, apply, disable or delete detection "
    "controls, suppress alerts, close cases, set severity or replace validation, "
    "RBAC, audit and human review."
)
DETECTION_CONTROL_SOURCE_TYPE = "detection_control"
CASE_CLOSURE_SOURCE_TYPE = "case_closure"
HISTORICAL_INCIDENT_SOURCE_TYPE = "historical_incident"
KNOWLEDGE_BASE_SOURCE_TYPE = "knowledge_base"
DETECTION_CONTROL_PAYLOAD_FIELDS = [
    "source_type",
    "source",
    "rule_id",
    "rule_type",
    "name",
    "status",
    "enabled",
    "scope",
    "matcher_kind",
    "owner",
    "last_validation_status",
    "redaction_applied",
    "decision_boundary",
]
CASE_CLOSURE_PAYLOAD_FIELDS = [
    "source_type",
    "source",
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
HISTORICAL_INCIDENT_PAYLOAD_FIELDS = [
    "source_type",
    "source",
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


class DetectionControlSemanticContextRequest(BaseModel):
    current_rule_id: str | None = Field(default=None, max_length=180)
    name: str | None = Field(default=None, max_length=500)
    type: str | None = Field(default=None, max_length=120)
    status: str | None = Field(default=None, max_length=120)
    scope: str | None = Field(default=None, max_length=500)
    matcher_kind: str | None = Field(default=None, max_length=80)
    matcher_value: str | None = Field(default=None, max_length=5000)
    reason: str | None = Field(default=None, max_length=2500)
    owner: str | None = Field(default=None, max_length=180)
    enabled: bool | None = None
    description: str | None = Field(default=None, max_length=2500)
    metadata: Any = Field(default_factory=dict)


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


def _metadata_query(metadata: Any) -> str:
    if not isinstance(metadata, dict):
        return ""

    parts: list[str] = []
    for key in [
        "inventory_id",
        "inventory_category",
        "inventory_type",
        "inventory_source",
        "inventory_target",
    ]:
        value = metadata.get(key)
        if safe_text(value):
            parts.append(f"{key}={_safe_query_part(value, max_chars=180)}")

    return "; ".join(parts)


def _rule_id_from_context(context: dict[str, Any]) -> str:
    rule_id = safe_text(context.get("rule_id"))
    if rule_id:
        return rule_id

    source = safe_text(context.get("source"))
    if source.startswith("detection_control:"):
        return source.split(":", 1)[1]

    return ""


def _severity_rank(value: Any) -> int:
    severity = safe_text(value).upper()
    return {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }.get(severity, 0)


def _numeric_risk(value: Any) -> float:
    try:
        if value is None or value == "":
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _semantic_context_item(context: dict[str, Any], *, max_excerpt: int = 560) -> dict[str, Any]:
    item = {
        "source_type": safe_text(context.get("source_type")) or "unknown",
        "source": safe_text(context.get("source")),
        "score": context.get("score"),
        "excerpt": _short_text(context.get("text"), max_chars=max_excerpt),
    }

    for key in [
        "rule_id",
        "rule_type",
        "name",
        "status",
        "enabled",
        "scope",
        "matcher_kind",
        "owner",
        "last_validation_status",
        "case_id",
        "case_title",
        "case_status",
        "case_severity",
        "closure_decision",
        "final_severity",
        "closure_approved",
        "incident_count",
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


def _context_contains(context: dict[str, Any], markers: list[str]) -> bool:
    haystack = " ".join(
        safe_text(context.get(key))
        for key in [
            "text",
            "status",
            "case_status",
            "closure_decision",
            "final_severity",
            "rule_type",
            "name",
            "recommended_priority",
        ]
    ).lower()
    return any(marker in haystack for marker in markers)


def _is_global_scope(scope: Any) -> bool:
    normalized = safe_text(scope).strip().lower()
    return normalized in {"global", "all", "any", "*", "default"}


def _is_broad_matcher(value: Any) -> bool:
    normalized = safe_text(value).strip().lower()
    return normalized in {"", "*", ".*", "any", "all", "true"}


def build_detection_control_semantic_query(
    payload: DetectionControlSemanticContextRequest,
) -> str:
    parts = [
        "Detection Control semantic decision support request.",
        f"Current Rule ID: {_safe_query_part(payload.current_rule_id, max_chars=180)}",
        f"Type: {_safe_query_part(payload.type, max_chars=120)}",
        f"Name: {_safe_query_part(payload.name, max_chars=320)}",
        f"Description: {_safe_query_part(payload.description, max_chars=700)}",
        f"Status: {_safe_query_part(payload.status, max_chars=120)}",
        f"Enabled: {payload.enabled}",
        f"Scope: {_safe_query_part(payload.scope, max_chars=500)}",
        f"Matcher Kind: {_safe_query_part(payload.matcher_kind, max_chars=80)}",
        f"Matcher Value: {_safe_query_part(payload.matcher_value, max_chars=900)}",
        f"Reason: {_safe_query_part(payload.reason, max_chars=900)}",
        f"Owner: {_safe_query_part(payload.owner, max_chars=180)}",
        f"Inventory Context: {_metadata_query(payload.metadata)}",
    ]
    return _short_text(" ".join(part for part in parts if safe_text(part)), max_chars=3200)


def _build_warnings(
    *,
    payload: DetectionControlSemanticContextRequest,
    similar_detection_controls: list[dict[str, Any]],
    similar_case_closures: list[dict[str, Any]],
    similar_historical_incidents: list[dict[str, Any]],
    result_count: int,
) -> list[str]:
    warnings: list[str] = []
    rule_type = safe_text(payload.type).upper()

    if result_count == 0:
        warnings.append(
            "No matching semantic memory was found; rely on deterministic validation, change history and human review."
        )

    if similar_detection_controls:
        warnings.append(
            "Similar Detection Control entries were found; review them for duplicate or overlapping scope before saving."
        )

    if (
        payload.enabled is not False
        and rule_type in {"NOISE_SUPPRESSION", "EXCEPTION"}
        and _is_global_scope(payload.scope)
    ):
        warnings.append(
            "Global scope for suppression or exception entries should be used only for narrow, reviewed matchers."
        )

    if _is_broad_matcher(payload.matcher_value):
        warnings.append(
            "Matcher value is empty or broad; deterministic validation and human review remain required before any save/apply."
        )

    if any(
        _context_contains(context, ["false positive", "false_positive", "benign", "noise"])
        for context in similar_case_closures
    ):
        warnings.append(
            "Similar case closures include false-positive or noise outcomes; verify that the proposed control matches the same reviewed conditions."
        )

    closure_high_severities = {
        safe_text(item.get("final_severity")).upper()
        for item in similar_case_closures
        if _severity_rank(item.get("final_severity")) >= _severity_rank("HIGH")
    }
    if closure_high_severities:
        warnings.append(
            "Similar closures include HIGH/CRITICAL final severity outcomes: "
            + ", ".join(sorted(closure_high_severities, key=_severity_rank))
            + "."
        )

    if any(_numeric_risk(item.get("risk_score")) >= 70 for item in similar_historical_incidents):
        warnings.append(
            "Similar historical incidents include high-risk outcomes; avoid broad suppression without additional evidence."
        )

    return warnings


def build_detection_control_semantic_context(
    payload: DetectionControlSemanticContextRequest,
    *,
    limit: int = 4,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    query = build_detection_control_semantic_query(payload)
    kb = knowledge_base_factory()
    resolved_limit = max(1, min(limit, 8))

    base_response = {
        "enabled": bool(kb.config.enabled),
        "status": "OK",
        "similar_detection_controls": [],
        "similar_case_closures": [],
        "similar_historical_incidents": [],
        "related_playbooks": [],
        "warnings": [],
        "result_count": 0,
        "decision_boundary": DETECTION_CONTROL_CONTEXT_DECISION_BOUNDARY,
        "message": (
            "Semantic memory context is analyst guidance only; no Detection Control "
            "entry was created, updated, applied, disabled or deleted."
        ),
    }

    if not kb.config.enabled:
        return {
            **base_response,
            "status": "DISABLED",
            "message": "Semantic memory is disabled.",
        }

    try:
        detection_contexts = _retrieve_source_contexts(
            kb,
            query,
            source_type=DETECTION_CONTROL_SOURCE_TYPE,
            limit=min(resolved_limit + 2, 10),
            payload_fields=DETECTION_CONTROL_PAYLOAD_FIELDS,
        )
        closure_contexts = _retrieve_source_contexts(
            kb,
            query,
            source_type=CASE_CLOSURE_SOURCE_TYPE,
            limit=resolved_limit,
            payload_fields=CASE_CLOSURE_PAYLOAD_FIELDS,
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
                "Semantic memory context retrieval failed; no Detection Control "
                "entry was created, updated, applied, disabled or deleted."
            ),
        }

    current_rule_id = safe_text(payload.current_rule_id)
    similar_detection_controls: list[dict[str, Any]] = []
    for context in detection_contexts:
        if current_rule_id and _rule_id_from_context(context) == current_rule_id:
            continue
        similar_detection_controls.append(_semantic_context_item(context))
        if len(similar_detection_controls) >= resolved_limit:
            break

    similar_case_closures = [
        _semantic_context_item(context)
        for context in closure_contexts[:resolved_limit]
    ]
    similar_historical_incidents = [
        _semantic_context_item(context)
        for context in historical_contexts[:resolved_limit]
    ]
    related_playbooks = [
        _semantic_context_item(context, max_excerpt=420)
        for context in playbook_contexts[: min(resolved_limit, 3)]
    ]
    result_count = (
        len(similar_detection_controls)
        + len(similar_case_closures)
        + len(similar_historical_incidents)
        + len(related_playbooks)
    )
    warnings = _build_warnings(
        payload=payload,
        similar_detection_controls=similar_detection_controls,
        similar_case_closures=similar_case_closures,
        similar_historical_incidents=similar_historical_incidents,
        result_count=result_count,
    )

    return {
        **base_response,
        "similar_detection_controls": similar_detection_controls,
        "similar_case_closures": similar_case_closures,
        "similar_historical_incidents": similar_historical_incidents,
        "related_playbooks": related_playbooks,
        "warnings": warnings,
        "result_count": result_count,
    }
