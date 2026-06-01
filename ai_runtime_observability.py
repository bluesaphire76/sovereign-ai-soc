from __future__ import annotations

import os
import time
from typing import Any

import requests

from ai_model_config import PROFILES, get_profile
from ai_model_policy import AiTask
from llm_client import generate_ai_response

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = get_profile("standard").model

AI_RUNTIME_HEALTH_TIMEOUT_SECONDS = float(
    os.getenv("AI_RUNTIME_HEALTH_TIMEOUT_SECONDS", "3")
)
AI_RUNTIME_HEALTH_CHAT_ENABLED = (
    os.getenv("AI_RUNTIME_HEALTH_CHAT_ENABLED", "false").strip().lower()
    in {"1", "true", "yes", "on"}
)
AI_RUNTIME_HEALTH_CHAT_TIMEOUT_SECONDS = float(
    os.getenv("AI_RUNTIME_HEALTH_CHAT_TIMEOUT_SECONDS", "20")
)


def _empty_model_details() -> dict[str, Any]:
    return {
        "name": None,
        "family": None,
        "families": [],
        "parameter_size": None,
        "quantization_level": None,
        "format": None,
        "size_bytes": None,
        "modified_at": None,
        "digest": None,
    }


def _normalize_model(item: dict[str, Any]) -> dict[str, Any]:
    details = item.get("details") or {}

    return {
        "name": item.get("name") or item.get("model"),
        "family": details.get("family"),
        "families": details.get("families") or [],
        "parameter_size": details.get("parameter_size"),
        "quantization_level": details.get("quantization_level"),
        "format": details.get("format"),
        "size_bytes": item.get("size"),
        "modified_at": item.get("modified_at"),
        "digest": item.get("digest"),
    }


def _configured_profiles() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "model": profile.model,
            "num_ctx": profile.num_ctx,
            "temperature": profile.temperature,
            "timeout_seconds": profile.timeout_seconds,
            "keep_alive": profile.keep_alive,
        }
        for name, profile in PROFILES.items()
    }


def get_ollama_runtime_snapshot() -> dict[str, Any]:
    started_at = time.perf_counter()

    response = requests.get(
        f"{OLLAMA_BASE_URL}/api/tags",
        timeout=AI_RUNTIME_HEALTH_TIMEOUT_SECONDS,
    )
    response.raise_for_status()

    latency_ms = round((time.perf_counter() - started_at) * 1000, 2)

    payload = response.json()
    raw_models = payload.get("models") or []
    models = [_normalize_model(item) for item in raw_models]

    configured = next(
        (
            item
            for item in models
            if item.get("name") == OLLAMA_MODEL
            or item.get("name", "").split(":")[0] == OLLAMA_MODEL.split(":")[0]
        ),
        None,
    )

    return {
        "provider": "ollama",
        "base_url": OLLAMA_BASE_URL,
        "configured_model": OLLAMA_MODEL,
        "configured_profile": "standard",
        "configured_profiles": _configured_profiles(),
        "model_present": configured is not None,
        "available_model_count": len(models),
        "available_models": [item.get("name") for item in models if item.get("name")],
        "configured_model_details": configured or _empty_model_details(),
        "tags_latency_ms": latency_ms,
        "health_chat_enabled": AI_RUNTIME_HEALTH_CHAT_ENABLED,
        "health_timeout_seconds": AI_RUNTIME_HEALTH_TIMEOUT_SECONDS,
        "health_chat_timeout_seconds": AI_RUNTIME_HEALTH_CHAT_TIMEOUT_SECONDS,
    }


def run_optional_ollama_chat_probe() -> dict[str, Any] | None:
    if not AI_RUNTIME_HEALTH_CHAT_ENABLED:
        return None

    started_at = time.perf_counter()
    result = generate_ai_response(
        messages=[
            {
                "role": "user",
                "content": "Return only the word OK.",
            }
        ],
        task=AiTask.ROUTING,
        requested_mode="fast",
        user_triggered=False,
        timeout_seconds=AI_RUNTIME_HEALTH_CHAT_TIMEOUT_SECONDS,
    )

    latency_ms = round((time.perf_counter() - started_at) * 1000, 2)

    return {
        "latency_ms": latency_ms,
        "profile": result.get("profile"),
        "model": result.get("model"),
        "fallback_used": result.get("fallback_used"),
        "error_type": result.get("error_type"),
        "response_present": bool(result.get("text")),
    }


def get_ai_runtime_health_details() -> dict[str, Any]:
    snapshot = get_ollama_runtime_snapshot()
    chat_probe = run_optional_ollama_chat_probe()

    if chat_probe is not None:
        snapshot["chat_probe"] = chat_probe

    return snapshot
