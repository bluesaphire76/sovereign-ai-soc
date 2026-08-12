from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from schemas.assistant import (
    AssistantCapabilitiesResponse,
    AssistantQueryRequest,
    AssistantQueryResponse,
)
from security.audit import security_audit_actor, write_security_audit
from services.assistant.orchestrator import (
    AssistantError,
    assistant_capabilities,
    run_assistant_query,
)


router = APIRouter(prefix="/assistant", tags=["Assistant"])


def _message_hash(message: str) -> str:
    normalized = " ".join(str(message or "").split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _base_audit_details(payload: AssistantQueryRequest) -> dict[str, Any]:
    return {
        "scope": payload.scope,
        "incident_id": payload.incident_id,
        "case_id": payload.case_id,
        "requested_mode": payload.requested_mode,
        "include_semantic_memory": payload.include_semantic_memory,
        "conversation_id_present": payload.conversation_id is not None,
        "message_length": len(payload.message),
        "message_sha256": _message_hash(payload.message),
    }


def _completed_audit_details(
    payload: AssistantQueryRequest,
    response: AssistantQueryResponse,
) -> dict[str, Any]:
    source_type_counts = Counter(source.source_type for source in response.sources)
    advisory_count = sum(1 for source in response.sources if source.authority == "advisory")
    source_refs = [
        {
            "source_id": source.source_id,
            "source_type": source.source_type,
            "record_id": source.record_id,
            "provenance_class": source.provenance_class,
        }
        for source in response.sources[:12]
    ]
    return {
        **_base_audit_details(payload),
        "status": response.status,
        "generation_kind": response.generation_kind,
        "effective_profile": response.metadata.effective_profile,
        "effective_model": response.metadata.effective_model,
        "queue_wait_ms": response.metadata.queue_wait_ms,
        "generation_ms": response.metadata.generation_ms,
        "total_latency_ms": response.metadata.total_latency_ms,
        "semantic_status": response.metadata.semantic_status,
        "semantic_elapsed_ms": response.metadata.semantic_elapsed_ms,
        "semantic_degraded": response.metadata.semantic_degraded,
        "grounding_validation": response.metadata.grounding_validation,
        "focus_validation": response.metadata.focus_validation,
        "fallback_reason": response.metadata.fallback_reason,
        "response_language": response.metadata.response_language,
        "thinking_disabled": response.metadata.thinking_disabled,
        "source_count": len(response.sources),
        "source_type_counts": dict(sorted(source_type_counts.items())),
        "source_refs": source_refs,
        "semantic_memory_attempted": response.metadata.semantic_status not in {
            "not_requested",
            "disabled",
        },
        "semantic_memory_available": advisory_count > 0,
        "assistant_intent": response.metadata.assistant_intent,
        "analysis_scope": response.metadata.analysis_scope,
        "context_atoms": response.metadata.context_atoms,
        "cross_incident_candidates": response.metadata.cross_incident_candidates,
        "graph_edges": response.metadata.graph_edges,
        "conversation_followup": response.metadata.conversation_followup,
    }


def _write_failed_audit(
    *,
    payload: AssistantQueryRequest,
    request: Request,
    current_user: dict | None,
    category: str,
    status: str = "unavailable",
) -> None:
    write_security_audit(
        event_type="AI_ASSISTANT_QUERY_FAILED",
        outcome="FAILURE",
        current_user=current_user,
        target_type="ASSISTANT",
        target_id=payload.incident_id or payload.case_id,
        request=request,
        details={
            **_base_audit_details(payload),
            "status": status,
            "error_category": category,
            "semantic_memory_attempted": False,
            "semantic_memory_available": False,
        },
    )


@router.get("/capabilities", response_model=AssistantCapabilitiesResponse)
def get_assistant_capabilities() -> AssistantCapabilitiesResponse:
    return assistant_capabilities()


@router.post("/query", response_model=AssistantQueryResponse)
def query_assistant(
    payload: AssistantQueryRequest,
    request: Request,
) -> AssistantQueryResponse:
    current_user = security_audit_actor(request)

    try:
        response = run_assistant_query(payload, current_user=current_user)
    except AssistantError as exc:
        _write_failed_audit(
            payload=payload,
            request=request,
            current_user=current_user,
            category=exc.category,
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "message": exc.message,
                "error_category": exc.category,
            },
        ) from exc
    except Exception as exc:
        _write_failed_audit(
            payload=payload,
            request=request,
            current_user=current_user,
            category="ProviderUnavailable",
        )
        raise HTTPException(
            status_code=503,
            detail={
                "message": "SOC assistant failed safely.",
                "error_category": "ProviderUnavailable",
            },
        ) from exc

    write_security_audit(
        event_type="AI_ASSISTANT_QUERY_COMPLETED",
        outcome="SUCCESS",
        current_user=current_user,
        target_type="ASSISTANT",
        target_id=payload.incident_id or payload.case_id,
        request=request,
        details=_completed_audit_details(payload, response),
    )
    return response
