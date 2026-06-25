from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import requests

from ai_data_control_policy import enforce_ai_data_policy
from ai_model_config import DEFAULT_LLM_MODE, PROFILES
from ai_model_policy import AiTask, select_profile
from ai_provider_abstraction import build_provider_client
from ai_provider_audit import record_ai_provider_audit
from ai_provider_policy import (
    external_block_reason,
    health_to_dict,
    provider_capabilities,
)
from ai_provider_registry import (
    load_provider_registry,
    provider_public_dict,
    save_provider_settings,
    save_registry_settings,
    is_local_provider_type,
)
from ai_triage_hardening import get_last_llm_call_metadata


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
    fallback_provider = _logical_fallback_provider()
    active_config = registry.get(registry.default_provider)
    return {
        "default_provider": registry.default_provider,
        "fallback_provider": fallback_provider,
        "active_provider": (
            {
                "provider_key": active_config.key,
                "provider_type": active_config.provider_type,
                "model": active_config.model,
                "external": active_config.external,
                "redaction_mode": active_config.redaction_mode,
            }
            if active_config
            else None
        ),
        "external_providers_enabled": registry.external_providers_enabled,
        "providers": [
            health_to_dict(build_provider_client(config).health_check())
            for config in registry.providers.values()
        ],
    }


def _loaded_ollama_models() -> tuple[list[dict[str, Any]], str | None]:
    registry = load_provider_registry()
    local = registry.get("local_ollama")
    if local is None or not local.base_url:
        return [], "LocalProviderMissing"

    try:
        response = requests.get(
            f"{str(local.base_url).rstrip('/')}/api/ps",
            timeout=min(float(local.timeout_seconds), 2),
        )
        response.raise_for_status()
        payload = response.json()
        return [
            item
            for item in payload.get("models", [])
            if isinstance(item, dict)
        ], None
    except Exception as exc:
        return [], type(exc).__name__


@router.get("/ai-providers/local-profiles")
def local_ai_profiles():
    loaded_models, safe_error = _loaded_ollama_models()
    loaded_names = {
        str(item.get("name") or item.get("model") or "")
        for item in loaded_models
        if item.get("name") or item.get("model")
    }
    last_metadata = get_last_llm_call_metadata()
    last_profile = str(last_metadata.get("profile") or "")
    routing = {
        AiTask.CLASSIFICATION.value: select_profile(AiTask.CLASSIFICATION),
        AiTask.ROUTING.value: select_profile(AiTask.ROUTING),
        AiTask.INCIDENT_TRIAGE.value: select_profile(AiTask.INCIDENT_TRIAGE),
        AiTask.DETECTION_QUALITY.value: select_profile(AiTask.DETECTION_QUALITY),
        AiTask.ACTION_HOW_TO.value: select_profile(AiTask.ACTION_HOW_TO),
        AiTask.CASE_ANALYSIS.value: select_profile(AiTask.CASE_ANALYSIS),
        AiTask.INCIDENT_ANALYSIS.value: select_profile(AiTask.INCIDENT_ANALYSIS),
        AiTask.REMEDIATION.value: select_profile(AiTask.REMEDIATION),
        AiTask.REPORT.value: select_profile(AiTask.REPORT),
        AiTask.EXECUTIVE_SUMMARY.value: select_profile(AiTask.EXECUTIVE_SUMMARY),
        "incident_analysis_critical_user_triggered": select_profile(
            AiTask.INCIDENT_ANALYSIS,
            severity="CRITICAL",
            user_triggered=True,
        ),
        "report_user_triggered": select_profile(
            AiTask.REPORT,
            user_triggered=True,
        ),
    }
    profile_to_features: dict[str, list[str]] = {name: [] for name in PROFILES}
    for feature_key, profile_name in routing.items():
        profile_to_features.setdefault(profile_name, []).append(feature_key)

    return {
        "mode": DEFAULT_LLM_MODE,
        "current_profile": last_profile or None,
        "last_call": last_metadata,
        "ollama_ps_error": safe_error,
        "loaded_models": loaded_models,
        "profiles": [
            {
                "name": profile.name,
                "model": profile.model,
                "num_ctx": profile.num_ctx,
                "temperature": profile.temperature,
                "timeout_seconds": profile.timeout_seconds,
                "keep_alive": profile.keep_alive,
                "active": profile.name == last_profile or profile.model in loaded_names,
                "loaded": profile.model in loaded_names,
                "last_used": profile.name == last_profile,
                "routed_features": sorted(profile_to_features.get(profile.name, [])),
            }
            for profile in PROFILES.values()
        ],
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

    if is_local_provider_type(config.provider_type):
        decision = enforce_ai_data_policy(
            feature_key="provider_test",
            provider_config=config,
            registry=registry,
            prompt="Local AI SOC provider connectivity test.",
            messages=None,
            context={},
            current_user=_current_user(request),
            confirmed=payload.confirm,
        )
        if not decision.allowed:
            raise HTTPException(status_code=403, detail=decision.reason or "AI data policy denied provider test.")
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
            "safe_error": health.safe_error,
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

    decision = enforce_ai_data_policy(
        feature_key="provider_test",
        provider_config=config,
        registry=registry,
        prompt="Return only the word OK. This is a harmless AI SOC provider connectivity test.",
        messages=None,
        context={},
        current_user=_current_user(request),
        confirmed=payload.confirm,
    )
    if not decision.allowed:
        record_ai_provider_audit(
            event_type="AI_PROVIDER_TEST_BLOCKED",
            outcome="DENIED",
            provider_key=config.key,
            provider_type=config.provider_type,
            feature="provider_test",
            model=config.model,
            external=True,
            redaction_mode=decision.mode,
            redaction_applied=decision.redaction_applied,
            input_character_count_after_redaction=decision.output_character_count,
            output_character_count=0,
            latency_ms=None,
            fallback_used=False,
            safe_error=decision.reason,
            current_user=_current_user(request),
        )
        return {
            "provider_key": config.key,
            "success": False,
            "safe_message": "Provider test was denied by AI data policy.",
            "latency_ms": None,
            "safe_error": decision.reason,
        }

    response = build_provider_client(config).generate(
        feature="provider_test",
        prompt=decision.transformed_prompt,
        messages=decision.transformed_messages,
        context=decision.transformed_context or {},
        options={"max_tokens": 8, "temperature": 0},
        data_control={
            "redaction_mode": decision.mode,
            "policy_preprocessed": True,
            "policy_redaction_applied": decision.redaction_applied,
            "policy_output_character_count": decision.output_character_count,
        },
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
