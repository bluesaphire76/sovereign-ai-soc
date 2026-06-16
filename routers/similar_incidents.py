from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from ai_provider_redaction import RedactionOptions, redact_text
from database import SessionLocal
from investigation_ai.adapters import safe_text
from models import Incident
from qdrant_knowledge import QdrantKnowledgeBase


router = APIRouter(tags=["Similar Incidents"])

SIMILAR_INCIDENTS_SOURCE_TYPE = "historical_incident"
SIMILAR_INCIDENTS_DECISION_BOUNDARY = (
    "Similar incidents are historical context only. Similarity does not prove "
    "same root cause. Similarity does not mean duplicate. Similarity must not "
    "determine severity. Similarity must not close or suppress an incident. "
    "Human validation remains required."
)
SIMILAR_INCIDENT_PAYLOAD_FIELDS = [
    "incident_id",
    "status",
    "risk_score",
    "level",
    "rule",
    "agent",
    "mitre",
    "correlation_type",
    "recommended_priority",
    "created_at",
    "updated_at",
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


def build_similar_incident_query(incident: Incident) -> str:
    parts = [
        "Find historical incidents with similar SOC pattern.",
        f"Rule: {_safe_query_part(incident.rule, max_chars=220)}",
        f"Agent: {_safe_query_part(incident.agent, max_chars=160)}",
        f"MITRE: {_safe_query_part(incident.mitre, max_chars=160)}",
        f"Correlation Type: {_safe_query_part(incident.correlation_type, max_chars=160)}",
        f"Attack Chain: {_safe_query_part(incident.attack_chain, max_chars=500)}",
        f"Escalation Reason: {_safe_query_part(incident.escalation_reason, max_chars=500)}",
        f"AI Analysis Summary: {_safe_query_part(incident.ai_analysis, max_chars=900)}",
    ]
    return _short_text(" ".join(part for part in parts if safe_text(part)), max_chars=2000)


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _incident_id_from_context(context: dict[str, Any]) -> int | None:
    incident_id = _int_or_none(context.get("incident_id"))
    if incident_id is not None:
        return incident_id

    source = safe_text(context.get("source"))
    if source.startswith("incident:"):
        return _int_or_none(source.split(":", 1)[1])

    return None


def serialize_similar_incident_context(
    context: dict[str, Any],
    *,
    current_incident_id: int,
) -> dict[str, Any] | None:
    incident_id = _incident_id_from_context(context)
    if incident_id is None or incident_id == current_incident_id:
        return None

    return {
        "incident_id": incident_id,
        "score": context.get("score"),
        "status": safe_text(context.get("status")),
        "risk_score": context.get("risk_score"),
        "level": context.get("level"),
        "recommended_priority": safe_text(context.get("recommended_priority")),
        "rule": safe_text(context.get("rule")),
        "agent": safe_text(context.get("agent")),
        "mitre": safe_text(context.get("mitre")),
        "correlation_type": safe_text(context.get("correlation_type")),
        "source": safe_text(context.get("source")),
        "source_type": safe_text(context.get("source_type")) or SIMILAR_INCIDENTS_SOURCE_TYPE,
        "excerpt": _short_text(context.get("text"), max_chars=600),
    }


def build_similar_incidents_response(
    db,
    incident_id: int,
    *,
    limit: int = 5,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    kb = knowledge_base_factory()
    if not kb.config.enabled:
        return {
            "incident_id": incident_id,
            "enabled": False,
            "status": "DISABLED",
            "result_count": 0,
            "results": [],
            "source_type": SIMILAR_INCIDENTS_SOURCE_TYPE,
            "decision_boundary": SIMILAR_INCIDENTS_DECISION_BOUNDARY,
            "message": "Semantic memory is disabled.",
        }

    query = build_similar_incident_query(incident)

    try:
        contexts = kb.retrieve_contexts(
            query,
            limit=min(max(1, limit) + 1, 25),
            source_type=SIMILAR_INCIDENTS_SOURCE_TYPE,
            payload_fields=SIMILAR_INCIDENT_PAYLOAD_FIELDS,
        )
    except Exception as exc:
        return {
            "incident_id": incident_id,
            "enabled": True,
            "status": "WARN",
            "result_count": 0,
            "results": [],
            "source_type": SIMILAR_INCIDENTS_SOURCE_TYPE,
            "decision_boundary": SIMILAR_INCIDENTS_DECISION_BOUNDARY,
            "message": "Semantic memory search failed; no operational decision was made.",
            "error_type": exc.__class__.__name__,
        }

    results = []
    for context in contexts:
        item = serialize_similar_incident_context(
            context,
            current_incident_id=incident_id,
        )
        if item:
            results.append(item)
        if len(results) >= limit:
            break

    return {
        "incident_id": incident_id,
        "enabled": True,
        "status": "OK",
        "result_count": len(results),
        "results": results,
        "source_type": SIMILAR_INCIDENTS_SOURCE_TYPE,
        "decision_boundary": SIMILAR_INCIDENTS_DECISION_BOUNDARY,
        "message": (
            "Similar incidents retrieved as analyst decision-support context only."
        ),
    }


@router.get("/incidents/{incident_id}/similar-incidents")
def get_similar_incidents(
    incident_id: int,
    limit: int = Query(default=5, ge=1, le=10),
):
    db = SessionLocal()

    try:
        return build_similar_incidents_response(db, incident_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Incident not found.") from exc
    finally:
        db.close()
