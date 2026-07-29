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
        "message_length": len(payload.message),
        "message_sha256": _message_hash(payload.message),
    }


def _completed_audit_details(
    payload: AssistantQueryRequest,
    response: AssistantQueryResponse,
) -> dict[str, Any]:
    source_type_counts = Counter(source.source_type for source in response.sources)
    advisory_count = sum(1 for source in response.sources if source.authority == "advisory")
    return {
        **_base_audit_details(payload),
        "status": response.status,
        "provider_key": response.metadata.provider_key,
        "provider_type": response.metadata.provider_type,
        "profile": response.metadata.profile,
        "model": response.metadata.model,
        "fallback_used": response.metadata.fallback_used,
        "latency_ms": response.metadata.latency_ms,
        "source_count": len(response.sources),
        "source_type_counts": dict(sorted(source_type_counts.items())),
        "semantic_memory_attempted": bool(payload.include_semantic_memory),
        "semantic_memory_available": advisory_count > 0,
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
