from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from ai_provider_abstraction import build_provider_client
from ai_provider_audit import record_ai_provider_audit
from ai_provider_policy import (
    external_block_reason,
    health_to_dict,
    provider_capabilities,
)
from ai_provider_registry import (
    PROVIDER_LOCAL_OLLAMA,
    load_provider_registry,
    provider_public_dict,
)


router = APIRouter(tags=["AI Providers"])


class ProviderTestRequest(BaseModel):
    confirm: bool = False


def _current_user(request: Request) -> dict[str, Any]:
    return getattr(request.state, "current_user", None) or {}


def _is_admin(request: Request) -> bool:
    return str(_current_user(request).get("role") or "").upper() == "ADMIN"


@router.get("/ai-providers")
def list_ai_providers(request: Request):
    registry = load_provider_registry()
    include_api_key_presence = _is_admin(request)

    return {
        "default_provider": registry.default_provider,
        "external_providers_enabled": registry.external_providers_enabled,
        "feature_overrides": dict(registry.feature_overrides),
        "providers": [
            provider_public_dict(config, include_api_key_presence=include_api_key_presence)
            for config in registry.providers.values()
        ],
    }


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
    return {
        "default_provider": registry.default_provider,
        "external_providers_enabled": registry.external_providers_enabled,
        "providers": [
            health_to_dict(build_provider_client(config).health_check())
            for config in registry.providers.values()
        ],
    }


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

    if config.provider_type == PROVIDER_LOCAL_OLLAMA:
        health = build_provider_client(config).health_check()
        record_ai_provider_audit(
            event_type="AI_PROVIDER_TEST",
            outcome="SUCCESS" if health.reachable else "FAILURE",
            provider_key=config.key,
            provider_type=config.provider_type,
            feature="provider_test",
            model=config.model,
            external=False,
            redaction_mode=config.redaction_mode,
            redaction_applied=False,
            input_character_count_after_redaction=0,
            output_character_count=0,
            latency_ms=health.latency_ms,
            fallback_used=False,
            safe_error=health.safe_error,
            current_user=_current_user(request),
        )
        return {
            "provider_key": config.key,
            "success": bool(health.reachable),
            "safe_message": health.safe_message,
            "latency_ms": health.latency_ms,
        }

    block_reason = None
    if not registry.external_providers_enabled:
        block_reason = "ExternalProvidersGloballyDisabled"
    elif not config.enabled:
        block_reason = "ProviderDisabled"
    elif not config.configured:
        block_reason = "ProviderNotConfigured"

    if block_reason:
        record_ai_provider_audit(
            event_type="AI_PROVIDER_TEST_BLOCKED",
            outcome="DENIED",
            provider_key=config.key,
            provider_type=config.provider_type,
            feature="provider_test",
            model=config.model,
            external=True,
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
            "safe_message": "Provider is disabled or not configured.",
            "latency_ms": None,
            "safe_error": block_reason,
        }

    response = build_provider_client(config).generate(
        feature="provider_test",
        prompt="Return only the word OK. This is a harmless AI SOC provider connectivity test.",
        messages=None,
        context={},
        options={"max_tokens": 8, "temperature": 0},
        data_control={"redaction_mode": config.redaction_mode},
    )
    record_ai_provider_audit(
        event_type="AI_PROVIDER_TEST",
        outcome="SUCCESS" if response.text and not response.safe_error else "FAILURE",
        provider_key=config.key,
        provider_type=config.provider_type,
        feature="provider_test",
        model=config.model,
        external=True,
        redaction_mode=response.redaction_mode,
        redaction_applied=response.redaction_applied,
        input_character_count_after_redaction=response.input_character_count_after_redaction,
        output_character_count=response.output_character_count,
        latency_ms=response.latency_ms,
        fallback_used=response.fallback_used,
        safe_error=response.safe_error,
        current_user=_current_user(request),
    )
    return {
        "provider_key": config.key,
        "success": bool(response.text and not response.safe_error),
        "safe_message": "Provider test completed." if response.text else "Provider test failed safely.",
        "latency_ms": response.latency_ms,
        "safe_error": response.safe_error,
    }
