from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from ai_data_control_policy import enforce_ai_data_policy
from ai_provider_abstraction import (
    build_provider_client,
    is_nonfatal_llama_cpp_unload_error,
    llama_cpp_managed_models,
)
from ai_provider_redaction import REDACTION_LOCAL_ONLY
from ai_provider_registry import load_provider_registry
from llama_cpp_profiles import resolve_llama_cpp_profile


@pytest.fixture(autouse=True)
def isolated_provider_config(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_PROVIDER_CONFIG_PATH", str(tmp_path / "ai_providers.json"))
    monkeypatch.setenv("AI_DATA_POLICY_CONFIG_PATH", str(tmp_path / "ai_data_control_policy.json"))
    monkeypatch.delenv("AI_PROVIDER_DEFAULT", raising=False)
    monkeypatch.delenv("AI_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("LLAMA_CPP_ENABLED", raising=False)
    monkeypatch.delenv("LLAMA_CPP_API_KEY", raising=False)


class _Response:
    def __init__(self, payload, *, error: Exception | None = None, text: str = ""):
        self._payload = payload
        self._error = error
        self.text = text

    def raise_for_status(self):
        if self._error:
            if isinstance(self._error, requests.HTTPError):
                self._error.response = self
            raise self._error

    def json(self):
        return self._payload


def test_llama_cpp_registered_disabled_and_not_default(monkeypatch):
    registry = load_provider_registry()

    assert registry.default_provider == "local_ollama"
    provider = registry.providers["local_llama_cpp"]
    assert provider.enabled is False
    assert provider.external is False
    assert provider.configured is True
    assert provider.api_key_configured is False
    assert provider.redaction_mode == REDACTION_LOCAL_ONLY


def test_llama_cpp_managed_models_ignore_default_and_non_ai_soc_models():
    models = llama_cpp_managed_models(
        {
            "data": [
                {"id": "default", "status": {"value": "loaded"}},
                {"id": "ai-soc-fast", "status": {"value": "loaded"}},
                {"id": "not-ai-soc", "status": {"value": "loaded"}},
                {"name": "ai-soc-standard", "status": "unloaded"},
            ]
        }
    )

    assert [item["id"] for item in models] == ["ai-soc-fast", "ai-soc-standard"]
    assert models[0]["status"] == "loaded"
    assert models[1]["status"] == "unloaded"


def test_llama_cpp_profile_degrades_to_available_ai_soc_model(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_FAST_MODEL", "ai-soc-fast")
    monkeypatch.setenv("LLAMA_CPP_STANDARD_MODEL", "ai-soc-standard")
    monkeypatch.setenv("LLAMA_CPP_QUALITY_MODEL", "ai-soc-quality")

    standard = resolve_llama_cpp_profile("standard", {"ai-soc-fast"})
    quality = resolve_llama_cpp_profile("quality", {"ai-soc-fast", "ai-soc-standard"})

    assert standard.profile == "fast"
    assert standard.model == "ai-soc-fast"
    assert standard.degraded_from == "standard"
    assert quality.profile == "standard"
    assert quality.model == "ai-soc-standard"
    assert quality.degraded_from == "quality"


def test_llama_cpp_unload_model_not_running_is_nonfatal(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    error = requests.HTTPError("409 Client Error")

    with patch(
        "ai_provider_abstraction.requests.post",
        return_value=_Response({"error": {"message": "model is not running"}}, error=error, text="model is not running"),
    ):
        client._post_router_action("unload", "ai-soc-standard", timeout=1)

    assert is_nonfatal_llama_cpp_unload_error("model is not running")


def test_llama_cpp_provider_generates_openai_compatible_request(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_API_KEY", "no-key")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    calls = []

    def fake_get(url, **kwargs):
        calls.append(("GET", url, None, None))
        assert kwargs["timeout"] <= 5
        if url.endswith("/models"):
            return _Response(
                {
                    "data": [
                        {"id": "default", "status": {"value": "loaded"}},
                        {"id": "ai-soc-fast", "status": {"value": "loaded"}},
                    ]
                }
            )
        return _Response({"status": "ok"})

    def fake_post(url, **kwargs):
        calls.append(("POST", url, kwargs.get("json"), kwargs.get("headers")))
        assert url.endswith("/chat/completions")
        return _Response(
            {
                "model": kwargs["json"]["model"],
                "choices": [
                    {
                        "message": {"content": "{\"ok\": true}"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 2},
            }
        )

    with patch("ai_provider_abstraction.requests.get", side_effect=fake_get), patch(
        "ai_provider_abstraction.requests.post",
        side_effect=fake_post,
    ):
        response = client.generate(
            feature="incident_ai_analysis",
            prompt="Return JSON",
            messages=None,
            context=None,
            options={
                "llm_profile": "standard",
                "response_format": {"type": "json_object"},
                "timeout_seconds": 1,
            },
            data_control={
                "redaction_mode": REDACTION_LOCAL_ONLY,
                "policy_redaction_applied": False,
                "policy_output_character_count": 11,
            },
        )

    post_call = next(call for call in calls if call[0] == "POST")
    assert post_call[2]["model"] == "ai-soc-fast"
    assert post_call[2]["response_format"] == {"type": "json_object"}
    assert "Authorization" not in post_call[3]
    assert response.text == "{\"ok\": true}"
    assert response.model == "ai-soc-fast"
    assert response.profile == "fast"
    assert response.fallback_used is True
    assert response.used_external_provider is False


def test_llama_cpp_data_policy_is_local_only(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    provider = registry.providers["local_llama_cpp"]

    decision = enforce_ai_data_policy(
        feature_key="incident_ai_analysis",
        provider_config=provider,
        registry=registry,
        prompt="password=hunter2 host=soc.internal.local",
        messages=None,
        context=None,
        current_user={"role": "ADMIN"},
        audit=False,
    )

    assert decision.allowed is True
    assert decision.external is False
    assert decision.action == "allow_local"
