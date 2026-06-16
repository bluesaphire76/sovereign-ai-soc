from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from ai_provider_redaction import RedactionOptions, redact_text
from detection_quality_guidance import generate_detection_quality_guidance
from investigation_ai.adapters import safe_text
from qdrant_knowledge import QdrantKnowledgeBase


router = APIRouter()

DETECTION_QUALITY_SEMANTIC_DECISION_BOUNDARY = (
    "Semantic memory context is advisory only. It may support detection-quality "
    "review, but it must not create, update, approve or apply detection rules, "
    "exceptions or noise suppression. It must not determine final severity, "
    "deduplication, incident closure or tuning decisions. Human validation and "
    "governed Detection Control approval remain required."
)
DETECTION_QUALITY_PAYLOAD_FIELDS = [
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
]


class DetectionQualityGuidanceRequest(BaseModel):
    summary: str
    recommended_action: str
    quality_score: int
    total_synthetic: int
    scenario_name: str | None = None
    force_refresh: bool = False
    weakest_scenario: dict[str, Any] | None = None
    signals: list[dict[str, Any]] = Field(default_factory=list)
    gaps: dict[str, Any] = Field(default_factory=dict)


class DetectionQualitySemanticContextRequest(BaseModel):
    rule: str = Field(default="", max_length=500)
    recommended_action: str = Field(default="", max_length=800)
    evidence: str = Field(default="", max_length=2000)
    mitre: str | None = Field(default=None, max_length=300)
    agent: str | None = Field(default=None, max_length=300)
    severity: str | None = Field(default=None, max_length=100)


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


def build_detection_quality_semantic_query(
    payload: DetectionQualitySemanticContextRequest,
) -> str:
    parts = [
        "Detection quality semantic context request.",
        f"Rule: {_safe_query_part(payload.rule, max_chars=500)}",
        f"Recommended Action: {_safe_query_part(payload.recommended_action, max_chars=800)}",
        f"Evidence: {_safe_query_part(payload.evidence, max_chars=1200)}",
        f"MITRE: {_safe_query_part(payload.mitre, max_chars=300)}",
        f"Agent: {_safe_query_part(payload.agent, max_chars=300)}",
        f"Severity: {_safe_query_part(payload.severity, max_chars=100)}",
    ]
    return _short_text(" ".join(part for part in parts if safe_text(part)), max_chars=2200)


def _semantic_context_item(context: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_type": safe_text(context.get("source_type")) or "unknown",
        "source": safe_text(context.get("source")),
        "score": context.get("score"),
        "excerpt": _short_text(context.get("text"), max_chars=520),
        "incident_id": context.get("incident_id"),
        "status": safe_text(context.get("status")),
        "risk_score": context.get("risk_score"),
        "level": context.get("level"),
        "rule": safe_text(context.get("rule")),
        "agent": safe_text(context.get("agent")),
        "mitre": safe_text(context.get("mitre")),
        "correlation_type": safe_text(context.get("correlation_type")),
        "recommended_priority": safe_text(context.get("recommended_priority")),
    }


def _is_possible_false_positive_context(context: dict[str, Any]) -> bool:
    haystack = " ".join(
        [
            safe_text(context.get("status")),
            safe_text(context.get("text")),
            safe_text(context.get("rule")),
            safe_text(context.get("recommended_priority")),
        ]
    ).lower()
    return any(
        marker in haystack
        for marker in [
            "false_positive",
            "false positive",
            "benign",
            "noise",
            "suppression",
            "maintenance",
        ]
    )


def build_detection_quality_semantic_context(
    payload: DetectionQualitySemanticContextRequest,
    *,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    query = build_detection_quality_semantic_query(payload)
    kb = knowledge_base_factory()

    base_response = {
        "enabled": bool(kb.config.enabled),
        "related_playbooks": [],
        "similar_false_positives": [],
        "similar_tuning_examples": [],
        "result_count": 0,
        "decision_boundary": DETECTION_QUALITY_SEMANTIC_DECISION_BOUNDARY,
        "message": (
            "Semantic memory context is analyst guidance only; no detection-control "
            "change was created or applied."
        ),
    }

    if not kb.config.enabled:
        return {
            **base_response,
            "status": "DISABLED",
            "message": "Semantic memory is disabled.",
        }

    try:
        contexts = kb.retrieve_contexts(
            query,
            limit=8,
            payload_fields=DETECTION_QUALITY_PAYLOAD_FIELDS,
        )
    except Exception as exc:
        return {
            **base_response,
            "status": "WARN",
            "error_type": exc.__class__.__name__,
            "message": (
                "Semantic memory context retrieval failed; no detection-control "
                "change was created or applied."
            ),
        }

    related_playbooks: list[dict[str, Any]] = []
    similar_false_positives: list[dict[str, Any]] = []
    similar_tuning_examples: list[dict[str, Any]] = []

    for context in contexts:
        item = _semantic_context_item(context)
        source_type = item["source_type"]

        if source_type == "knowledge_base":
            related_playbooks.append(item)
        elif source_type == "historical_incident" and _is_possible_false_positive_context(context):
            item["context_label"] = "possible_historical_false_positive_or_noise_context"
            similar_false_positives.append(item)
        elif source_type == "historical_incident":
            item["context_label"] = "possible_historical_tuning_context"
            similar_tuning_examples.append(item)

    result_count = (
        len(related_playbooks)
        + len(similar_false_positives)
        + len(similar_tuning_examples)
    )

    return {
        **base_response,
        "status": "OK",
        "related_playbooks": related_playbooks,
        "similar_false_positives": similar_false_positives,
        "similar_tuning_examples": similar_tuning_examples,
        "result_count": result_count,
    }


@router.post("/detection-quality/action-guidance")
def create_detection_quality_action_guidance(
    payload: DetectionQualityGuidanceRequest,
):
    return generate_detection_quality_guidance(payload.dict())


@router.post("/detection-quality/semantic-context")
def detection_quality_semantic_context(
    payload: DetectionQualitySemanticContextRequest,
):
    return build_detection_quality_semantic_context(payload)
