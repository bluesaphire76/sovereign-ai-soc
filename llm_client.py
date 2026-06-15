from __future__ import annotations

import time
from typing import Any

import requests

from ai_model_config import DEFAULT_LLM_MODE, LlmProfile, get_profile
from ai_model_policy import AiTask, select_profile
from ai_provider_abstraction import build_provider_client
from ai_provider_policy import generate_with_provider, normalize_feature, select_provider_config
from ai_provider_registry import PROVIDER_LOCAL_OLLAMA, load_provider_registry


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
        prompt=prompt,
        messages=messages,
        profile_name=profile_name,
        timeout_seconds=timeout_seconds,
    )


def _call_ollama_with_fallback(
    *,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    profile_name: str,
    timeout_seconds: float | None,
) -> dict[str, Any]:
    started = time.monotonic()
    profile = get_profile(profile_name)

    try:
        text = _call_ollama(
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
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    profile: LlmProfile,
    timeout_seconds: float | None,
) -> str:
    registry = load_provider_registry()
    config = registry.get("local_ollama")
    if config is None:
        raise RuntimeError("Local Ollama provider configuration is missing.")

    client = build_provider_client(config)
    response = client.generate(
        feature="local_ollama",
        prompt=prompt,
        messages=messages,
        context=None,
        options=_profile_options(profile=profile, timeout_seconds=timeout_seconds),
        data_control=None,
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
        "num_ctx": profile.num_ctx,
        "temperature": profile.temperature,
        "timeout_seconds": timeout_seconds or profile.timeout_seconds,
        "keep_alive": profile.keep_alive,
    }


def _provider_result(
    *,
    response,
    profile: LlmProfile,
    fallback_used: bool,
    error_type: str | None,
) -> dict[str, Any]:
    return {
        "text": response.text,
        "profile": profile.name,
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
