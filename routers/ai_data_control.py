from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ai_data_control_policy import (
    enforce_ai_data_policy,
    get_feature_policy,
    policy_capabilities,
    policies_payload,
    decisions_payload,
    record_policy_event,
    redact_value,
    update_feature_policy,
)
from ai_provider_registry import load_provider_registry


router = APIRouter(tags=["AI Data Control"])


class PolicyUpdateRequest(BaseModel):
    mode: str | None = None
    allowed_provider_keys: list[str] | None = None
    allowed_roles: list[str] | None = None
    require_confirmation: bool | None = None
    payload_preview_enabled: bool | None = None
    store_payload_hash: bool | None = None
    store_redacted_preview: bool | None = None
    allow_raw_telemetry: bool | None = None
    allow_personal_data: bool | None = None
    audit_level: str | None = None
    reason: str = Field(default="", min_length=1)


class EvaluationPreviewRequest(BaseModel):
    feature_key: str
    provider_key: str = "local_ollama"
    prompt: str | None = None
    messages: list[dict[str, Any]] | None = None
    context: dict[str, Any] | None = None
    confirmed: bool = False


class RedactionPreviewRequest(BaseModel):
    payload: Any
    external_sensitive: bool = True
    allow_raw_telemetry: bool = False
    allow_personal_data: bool = False


def _current_user(request: Request) -> dict[str, Any]:
    return getattr(request.state, "current_user", None) or {}


def _is_admin(request: Request) -> bool:
    return str(_current_user(request).get("role") or "").upper() == "ADMIN"


@router.get("/ai-data-control/capabilities")
def get_ai_data_control_capabilities():
    return policy_capabilities()


@router.get("/ai-data-control/policies")
def get_ai_data_control_policies():
    return policies_payload()


@router.get("/ai-data-control/policies/{feature_key}")
def get_ai_data_control_feature_policy(feature_key: str):
    return get_feature_policy(feature_key)


@router.patch("/ai-data-control/policies/{feature_key}")
def patch_ai_data_control_feature_policy(
    feature_key: str,
    payload: PolicyUpdateRequest,
    request: Request,
):
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="ADMIN role required.")

    updates = payload.dict(exclude_unset=True)
    reason = str(updates.pop("reason", "")).strip()
    try:
        return update_feature_policy(
            feature_key=feature_key,
            updates=updates,
            reason=reason,
            current_user=_current_user(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/ai-data-control/evaluate-preview")
def evaluate_ai_data_control_preview(payload: EvaluationPreviewRequest, request: Request):
    registry = load_provider_registry()
    provider = registry.get(payload.provider_key)
    if provider is None:
        raise HTTPException(status_code=404, detail="Provider not found.")

    decision = enforce_ai_data_policy(
        feature_key=payload.feature_key,
        provider_config=provider,
        registry=registry,
        prompt=payload.prompt,
        messages=payload.messages,
        context=payload.context,
        current_user=_current_user(request),
        confirmed=payload.confirmed,
        audit=False,
    )
    record_policy_event(
        event_type="AI_DATA_POLICY_PREVIEW_RUN",
        outcome="SUCCESS",
        decision=decision,
        current_user=_current_user(request),
    )
    return {
        "decision": {
            "decision_id": decision.decision_id,
            "feature_key": decision.feature_key,
            "provider_key": decision.provider_key,
            "external": decision.external,
            "mode": decision.mode,
            "allowed": decision.allowed,
            "action": decision.action,
            "reason": decision.reason,
            "redaction_applied": decision.redaction_applied,
            "replacements": decision.replacements,
            "payload_hash": decision.payload_hash,
            "input_character_count": decision.input_character_count,
            "output_character_count": decision.output_character_count,
        },
        "transformed_payload": {
            "prompt": decision.transformed_prompt,
            "messages": decision.transformed_messages,
            "context": decision.transformed_context,
        },
    }


@router.post("/ai-data-control/redaction-preview")
def redaction_preview(payload: RedactionPreviewRequest, request: Request):
    result = redact_value(
        payload.payload,
        external_sensitive=payload.external_sensitive,
        allow_raw_telemetry=payload.allow_raw_telemetry,
        allow_personal_data=payload.allow_personal_data,
    )
    record_policy_event(
        event_type="AI_DATA_POLICY_PREVIEW_RUN",
        outcome="SUCCESS",
        current_user=_current_user(request),
        details={
            "preview_type": "redaction",
            "redaction_applied": result.applied,
            "replacements": result.replacements,
            "input_character_count": result.input_character_count,
            "output_character_count": result.output_character_count,
        },
    )
    return {
        "redacted_payload": result.transformed_value,
        "redaction_applied": result.applied,
        "replacements": result.replacements,
        "input_character_count": result.input_character_count,
        "output_character_count": result.output_character_count,
    }


@router.get("/ai-data-control/decisions")
def get_ai_data_control_decisions(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
):
    record_policy_event(
        event_type="AI_DATA_POLICY_DECISION_VIEWED",
        outcome="SUCCESS",
        current_user=_current_user(request),
        details={"limit": limit},
    )
    return {"decisions": decisions_payload(limit=limit)}
