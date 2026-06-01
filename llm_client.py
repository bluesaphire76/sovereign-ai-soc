from __future__ import annotations

import time
from typing import Any

import requests

from ai_model_config import DEFAULT_LLM_MODE, OLLAMA_BASE_URL, LlmProfile, get_profile
from ai_model_policy import AiTask, select_profile


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
    timeout = timeout_seconds or profile.timeout_seconds

    if messages:
        payload = {
            "model": profile.model,
            "messages": messages,
            "stream": False,
            "keep_alive": profile.keep_alive,
            "options": {
                "num_ctx": profile.num_ctx,
                "temperature": profile.temperature,
            },
        }
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        message = data.get("message") or {}

        return str(message.get("content") or "")

    payload = {
        "model": profile.model,
        "prompt": prompt,
        "stream": False,
        "keep_alive": profile.keep_alive,
        "options": {
            "num_ctx": profile.num_ctx,
            "temperature": profile.temperature,
        },
    }
    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/generate",
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()

    return str(data.get("response") or "")


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
    }
