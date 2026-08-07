from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ai_model_config import get_profile
from ai_provider_audit import record_ai_provider_audit
from ai_provider_policy import (
    external_block_reason,
    provider_capabilities,
)
from ai_provider_registry import (
    load_provider_registry,
    provider_public_dict,
    save_provider_settings,
    save_registry_settings,
)
from services.ai_execution.client import AiExecutionClient, generate_ai_response
from services.ai_execution.errors import AiExecutionError


router = APIRouter(tags=["AI Providers"])


class ProviderTestRequest(BaseModel):
    confirm: bool = False


class ProviderRegistrySettingsRequest(BaseModel):
    default_provider: str | None = None
    external_providers_enabled: bool | None = None
    feature_overrides: dict[str, str] | None = None
    reason: str


class ProviderConfigUpdateRequest(BaseModel):
    enabled: bool | None = None
    base_url: str | None = None
    model: str | None = None
    timeout_seconds: float | None = None
    max_tokens: int | None = None
    feature_allowlist: list[str] | None = None
    redaction_mode: str | None = None
    reason: str


def _current_user(request: Request) -> dict[str, Any]:
    return getattr(request.state, "current_user", None) or {}


def _is_admin(request: Request) -> bool:
    return str(_current_user(request).get("role") or "").upper() == "ADMIN"


def _provider_list_response(registry, *, include_api_key_presence: bool) -> dict[str, Any]:
    fallback_provider = _logical_fallback_provider()
    return {
        "default_provider": registry.default_provider,
        "fallback_provider": fallback_provider,
        "external_providers_enabled": registry.external_providers_enabled,
        "feature_overrides": dict(registry.feature_overrides),
        "providers": [
            {
                **provider_public_dict(config, include_api_key_presence=include_api_key_presence),
                "is_default": config.key == registry.default_provider,
                "is_fallback": config.key == fallback_provider,
            }
            for config in registry.providers.values()
        ],
    }


def _logical_fallback_provider() -> str:
    normalized = os.getenv("AI_LLM_FALLBACK_PROVIDER", "ollama").strip().lower()
    mapping = {
        "ollama": "local_ollama",
        "local_ollama": "local_ollama",
        "llama_cpp": "local_llama_cpp",
        "llama.cpp": "local_llama_cpp",
        "local_llama_cpp": "local_llama_cpp",
    }
    return mapping.get(normalized, normalized or "local_ollama")


@router.get("/ai-providers")
def list_ai_providers(request: Request):
    registry = load_provider_registry()
    include_api_key_presence = _is_admin(request)

    return _provider_list_response(registry, include_api_key_presence=include_api_key_presence)


@router.get("/ai-providers/capabilities")
def ai_provider_capabilities():
    return provider_capabilities()


@router.get("/ai-providers/effective-policy")
def ai_provider_effective_policy(request: Request):
    registry = load_provider_registry()
    include_api_key_presence = _is_admin(request)

    return {
        "default_provider": registry.default_provider,
        "external_providers_enabled": registry.external_providers_enabled,
        "feature_overrides": dict(registry.feature_overrides),
        "providers": [
            {
                **provider_public_dict(config, include_api_key_presence=include_api_key_presence),
                "external_block_reason": (
                    None
                    if not config.external
                    else external_block_reason(
                        config=config,
                        feature="provider_test",
                        registry=registry,
                    )
                ),
            }
            for config in registry.providers.values()
        ],
    }


@router.get("/ai-providers/health")
def ai_provider_health():
    registry = load_provider_registry()
    try:
        status = AiExecutionClient().status()
        reachable = True
        safe_error = None
    except AiExecutionError as exc:
        status = None
        reachable = False
        safe_error = exc.safe_error
    return {
        "default_provider": "ai_execution_gateway",
        "fallback_provider": None,
        "active_provider": {
            "provider_key": "ai_execution_gateway",
            "provider_type": "INFERENCE_GATEWAY",
            "model": "ai-soc-standard",
            "external": False,
            "redaction_mode": "LOCAL_ONLY",
        },
        "external_providers_enabled": registry.external_providers_enabled,
        "providers": [{
            "provider_key": "ai_execution_gateway",
            "provider_type": "INFERENCE_GATEWAY",
            "configured_model": "ai-soc-standard",
            "configured": True,
            "enabled": True,
            "reachable": reachable,
            "model_available": bool(status and status.state == "ready"),
            "latency_ms": None,
            "safe_message": (
                status.message
                if status
                else "Inference gateway is unavailable."
            ),
            "safe_error": safe_error,
        }],
    }


def _gateway_status():
    try:
        return AiExecutionClient().status(), None
    except AiExecutionError as exc:
        return None, exc.safe_error


@router.get("/ai-providers/local-profiles")
def local_ai_profiles():
    status, safe_error = _gateway_status()
    standard = get_profile("standard")
    ready = bool(status and status.state == "ready")
    return {
        "mode": "gateway",
        "current_profile": "standard" if ready else None,
        "last_call": {},
        "ollama_ps_error": safe_error,
        "loaded_models": (
            [{"name": "ai-soc-standard", "state": status.state}]
            if status
            else []
        ),
        "profiles": [{
            "name": "standard",
            "model": "ai-soc-standard",
            "num_ctx": standard.num_ctx,
            "temperature": 0,
            "timeout_seconds": standard.timeout_seconds,
            "keep_alive": standard.keep_alive,
            "active": ready,
            "loaded": ready,
            "last_used": ready,
            "routed_features": ["all_generative_tasks"],
        }],
    }


@router.patch("/ai-providers/settings")
def update_ai_provider_registry_settings(payload: ProviderRegistrySettingsRequest, request: Request):
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="ADMIN role required.")
    if not payload.reason.strip():
        raise HTTPException(status_code=400, detail="Change reason is required.")

    try:
        registry = save_registry_settings(
            default_provider=payload.default_provider,
            external_providers_enabled=payload.external_providers_enabled,
            feature_overrides=payload.feature_overrides,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    record_ai_provider_audit(
        event_type="AI_PROVIDER_CONFIG_CHANGED",
        outcome="SUCCESS",
        provider_key=registry.default_provider,
        provider_type="REGISTRY",
        feature="provider_registry",
        model=None,
        external=False,
        redaction_mode="LOCAL_ONLY",
        redaction_applied=False,
        input_character_count_after_redaction=0,
        output_character_count=0,
        latency_ms=None,
        fallback_used=False,
        safe_error=None,
        current_user=_current_user(request),
        request_metadata={
            "reason": payload.reason,
            "external_providers_enabled": registry.external_providers_enabled,
            "feature_overrides": registry.feature_overrides,
        },
    )
    return _provider_list_response(registry, include_api_key_presence=True)


@router.patch("/ai-providers/{provider_key}/config")
def update_ai_provider_config(provider_key: str, payload: ProviderConfigUpdateRequest, request: Request):
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="ADMIN role required.")
    if not payload.reason.strip():
        raise HTTPException(status_code=400, detail="Change reason is required.")

    updates = payload.dict(exclude_unset=True)
    reason = updates.pop("reason", "")
    try:
        registry = save_provider_settings(provider_key, updates)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Provider not found.") from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    config = registry.get(provider_key)
    record_ai_provider_audit(
        event_type="AI_PROVIDER_CONFIG_CHANGED",
        outcome="SUCCESS",
        provider_key=provider_key,
        provider_type=config.provider_type if config else "UNKNOWN",
        feature="provider_config",
        model=config.model if config else None,
        external=bool(config.external) if config else False,
        redaction_mode=config.redaction_mode if config else "UNKNOWN",
        redaction_applied=False,
        input_character_count_after_redaction=0,
        output_character_count=0,
        latency_ms=None,
        fallback_used=False,
        safe_error=None,
        current_user=_current_user(request),
        request_metadata={"reason": reason, "updated_fields": sorted(updates.keys())},
    )
    return _provider_list_response(registry, include_api_key_presence=True)


@router.post("/ai-providers/{provider_key}/test")
def test_ai_provider(provider_key: str, payload: ProviderTestRequest, request: Request):
    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="ADMIN role required.")

    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Provider test requires confirmation.")

    registry = load_provider_registry()
    config = registry.get(provider_key)
    if config is None:
        raise HTTPException(status_code=404, detail="Provider not found.")

    if config.key != "local_llama_cpp":
        block_reason = "GatewayFixedProviderPolicy"
        record_ai_provider_audit(
            event_type="AI_PROVIDER_TEST_BLOCKED",
            outcome="DENIED",
            provider_key=config.key,
            provider_type=config.provider_type,
            feature="provider_test",
            model=config.model,
            external=config.external,
            redaction_mode=config.redaction_mode,
            redaction_applied=False,
            input_character_count_after_redaction=0,
            output_character_count=0,
            latency_ms=None,
            fallback_used=False,
            safe_error=block_reason,
            current_user=_current_user(request),
        )
        return {
            "provider_key": config.key,
            "success": False,
            "safe_message": "Generation is owned by the inference gateway.",
            "latency_ms": None,
            "safe_error": block_reason,
        }

    response = generate_ai_response(
        prompt="Return only the word OK.",
        task="provider_test",
        requested_mode="standard",
        user_triggered=True,
        timeout_seconds=10,
        max_visible_tokens=16,
    )
    success = bool(response.get("text") and not response.get("safe_error"))
    safe_error = response.get("safe_error")
    record_ai_provider_audit(
        event_type="AI_PROVIDER_TEST",
        outcome="SUCCESS" if success else "FAILURE",
        provider_key="ai_execution_gateway",
        provider_type="INFERENCE_GATEWAY",
        feature="provider_test",
        model="ai-soc-standard",
        external=False,
        redaction_mode="LOCAL_ONLY",
        redaction_applied=False,
        input_character_count_after_redaction=24,
        output_character_count=len(str(response.get("text") or "")),
        latency_ms=response.get("latency_ms"),
        fallback_used=False,
        safe_error=safe_error,
        current_user=_current_user(request),
    )
    return {
        "provider_key": config.key,
        "success": success,
        "safe_message": (
            "Gateway test completed."
            if success
            else "Gateway test failed safely."
        ),
        "latency_ms": response.get("latency_ms"),
        "safe_error": safe_error,
    }
