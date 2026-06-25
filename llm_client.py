from __future__ import annotations

import os
import time
from typing import Any

import requests

from ai_data_control_policy import enforce_ai_data_policy
from ai_model_config import DEFAULT_LLM_MODE, LlmProfile, get_profile
from ai_model_policy import AiTask, select_profile
from ai_provider_abstraction import build_provider_client
from ai_provider_policy import generate_with_provider, normalize_feature, select_provider_config
from ai_provider_registry import PROVIDER_LOCAL_LLAMA_CPP, PROVIDER_LOCAL_OLLAMA, load_provider_registry
from llama_cpp_profiles import get_llama_cpp_profile, select_llama_cpp_profile


def generate_ai_response(
    *,
    prompt: str | None = None,
    messages: list[dict[str, Any]] | None = None,
    task: AiTask | str,
    severity: str | None = None,
    requested_mode: str | None = None,
    user_triggered: bool = False,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    if not prompt and not messages:
        raise ValueError("prompt or messages is required")

    profile_name = select_profile(
        task=task,
        severity=severity,
        requested_mode=requested_mode or DEFAULT_LLM_MODE,
        user_triggered=user_triggered,
    )
    feature = normalize_feature(task)
    registry = load_provider_registry()
    provider = select_provider_config(feature=feature, registry=registry)

    if provider.provider_type == PROVIDER_LOCAL_LLAMA_CPP:
        llama_profile_name = select_llama_cpp_profile(
            task=task,
            severity=severity,
            requested_mode=requested_mode,
            user_triggered=user_triggered,
        )
        profile = get_llama_cpp_profile(llama_profile_name)
        response = generate_with_provider(
            feature=feature,
            prompt=prompt,
            messages=messages,
            options=_profile_options(profile=profile, timeout_seconds=timeout_seconds),
        )
        if response.safe_error and _logical_provider_key(os.getenv("AI_LLM_FALLBACK_PROVIDER", "ollama")) == "local_ollama":
            fallback = _call_ollama_with_fallback(
                feature=feature,
                prompt=prompt,
                messages=messages,
                profile_name=getattr(response, "profile", None) or profile.name,
                timeout_seconds=timeout_seconds,
            )
            fallback["fallback_used"] = True
            fallback["error_type"] = response.safe_error
            fallback["safe_error"] = response.safe_error
            return fallback
        return _provider_result(
            response=response,
            profile=profile,
            fallback_used=False,
            error_type=response.safe_error,
        )

    if provider.provider_type != PROVIDER_LOCAL_OLLAMA:
        profile = get_profile(profile_name)
        response = generate_with_provider(
            feature=feature,
            prompt=prompt,
            messages=messages,
            options=_profile_options(profile=profile, timeout_seconds=timeout_seconds),
        )
        return _provider_result(
            response=response,
            profile=profile,
            fallback_used=False,
            error_type=response.safe_error,
        )

    return _call_ollama_with_fallback(
        feature=feature,
        prompt=prompt,
        messages=messages,
        profile_name=profile_name,
        timeout_seconds=timeout_seconds,
    )


def _call_ollama_with_fallback(
    *,
    feature: str,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    profile_name: str,
    timeout_seconds: float | None,
) -> dict[str, Any]:
    started = time.monotonic()
    profile = get_profile(profile_name)

    try:
        text = _call_ollama(
            feature=feature,
            prompt=prompt,
            messages=messages,
            profile=profile,
            timeout_seconds=timeout_seconds,
        )
        return _result(
            text=text,
            profile=profile,
            fallback_used=False,
            error_type=None,
            started=started,
        )
    except Exception as exc:
        if profile.name == "fast":
            return _result(
                text="",
                profile=profile,
                fallback_used=False,
                error_type=type(exc).__name__,
                started=started,
            )

        fallback = get_profile("fast")

        try:
            text = _call_ollama(
                feature=feature,
                prompt=prompt,
                messages=messages,
                profile=fallback,
                timeout_seconds=timeout_seconds,
            )
            return _result(
                text=text,
                profile=fallback,
                fallback_used=True,
                error_type=type(exc).__name__,
                started=started,
            )
        except Exception as fallback_exc:
            return _result(
                text="",
                profile=fallback,
                fallback_used=True,
                error_type=type(fallback_exc).__name__,
                started=started,
            )


def _call_ollama(
    *,
    feature: str,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    profile: LlmProfile,
    timeout_seconds: float | None,
) -> str:
    registry = load_provider_registry()
    config = registry.get("local_ollama")
    if config is None:
        raise RuntimeError("Local Ollama provider configuration is missing.")

    policy_decision = enforce_ai_data_policy(
        feature_key=feature,
        provider_config=config,
        registry=registry,
        prompt=prompt,
        messages=messages,
        context=None,
        current_user=None,
    )
    if not policy_decision.allowed:
        raise RuntimeError(policy_decision.reason or "AIDataPolicyDenied")

    client = build_provider_client(config)
    response = client.generate(
        feature=feature,
        prompt=policy_decision.transformed_prompt,
        messages=policy_decision.transformed_messages,
        context=None,
        options=_profile_options(profile=profile, timeout_seconds=timeout_seconds),
        data_control={
            "redaction_mode": policy_decision.mode,
            "policy_preprocessed": True,
            "policy_decision_id": policy_decision.decision_id,
            "policy_redaction_applied": policy_decision.redaction_applied,
            "policy_output_character_count": policy_decision.output_character_count,
            "policy_replacements": dict(policy_decision.replacements),
        },
    )

    if response.safe_error:
        if response.safe_error in {
            "ReadTimeout",
            "Timeout",
            "TimeoutError",
            "TimeoutException",
        }:
            raise requests.exceptions.Timeout(response.safe_error)
        raise RuntimeError(response.safe_error)

    return response.text


def _result(
    *,
    text: str,
    profile: LlmProfile,
    fallback_used: bool,
    error_type: str | None,
    started: float,
) -> dict[str, Any]:
    return {
        "text": text,
        "profile": profile.name,
        "model": profile.model,
        "fallback_used": fallback_used,
        "error_type": error_type,
        "latency_ms": int((time.monotonic() - started) * 1000),
        "provider_key": "local_ollama",
        "provider_type": PROVIDER_LOCAL_OLLAMA,
        "used_external_provider": False,
        "redaction_applied": False,
        "redaction_mode": "LOCAL_ONLY",
        "safe_error": error_type,
    }


def _profile_options(*, profile: LlmProfile, timeout_seconds: float | None) -> dict[str, Any]:
    return {
        "model": profile.model,
        "llm_profile": profile.name,
        "num_ctx": profile.num_ctx,
        "temperature": profile.temperature,
        "timeout_seconds": timeout_seconds or profile.timeout_seconds,
        "keep_alive": profile.keep_alive,
    }


def _logical_provider_key(value: str | None) -> str | None:
    normalized = str(value or "").lower().strip()
    mapping = {
        "ollama": "local_ollama",
        "local_ollama": "local_ollama",
        "llama_cpp": "local_llama_cpp",
        "llama.cpp": "local_llama_cpp",
        "local_llama_cpp": "local_llama_cpp",
    }
    return mapping.get(normalized, normalized or None)


def _provider_result(
    *,
    response,
    profile: LlmProfile,
    fallback_used: bool,
    error_type: str | None,
) -> dict[str, Any]:
    return {
        "text": response.text,
        "profile": getattr(response, "profile", None) or profile.name,
        "model": response.model or profile.model,
        "fallback_used": fallback_used or response.fallback_used,
        "error_type": error_type,
        "latency_ms": response.latency_ms or 0,
        "provider_key": response.provider_key,
        "provider_type": response.provider_type,
        "used_external_provider": response.used_external_provider,
        "redaction_applied": response.redaction_applied,
        "redaction_mode": response.redaction_mode,
        "safe_error": response.safe_error,
        "usage": response.usage,
    }
