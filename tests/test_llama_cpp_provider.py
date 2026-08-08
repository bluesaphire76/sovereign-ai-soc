from __future__ import annotations

import threading
from unittest.mock import patch

import pytest
import requests

from ai_data_control_policy import enforce_ai_data_policy
from ai_provider_abstraction import (
    _llama_cpp_timing_diagnostics,
    build_provider_client,
    is_nonfatal_llama_cpp_unload_error,
    llama_cpp_managed_models,
)
from ai_provider_redaction import REDACTION_LOCAL_ONLY
from ai_provider_registry import load_provider_registry, provider_public_dict
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
    def __init__(
        self,
        payload,
        *,
        error: Exception | None = None,
        text: str = "",
        status_code: int = 200,
    ):
        self._payload = payload
        self._error = error
        self.text = text
        self.status_code = status_code

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


def test_llama_cpp_provider_public_payload_has_native_ui_and_profiles(monkeypatch):
    registry = load_provider_registry()
    provider = registry.providers["local_llama_cpp"]

    payload = provider_public_dict(provider, include_api_key_presence=True)

    assert payload["key"] == "local_llama_cpp"
    assert payload["type"] == "LOCAL_LLAMA_CPP"
    assert payload["external"] is False
    assert payload["api_key_configured"] is False
    assert payload["runtime"]["native_ui_url"] == "http://127.0.0.1:8081"
    assert payload["runtime"]["router_base_url"] == "http://127.0.0.1:8081"
    assert payload["runtime"]["api_base_url"] == "http://127.0.0.1:8081/v1"
    assert payload["runtime"]["profile_models"] == [
        {"profile": "fast", "model": "ai-soc-fast"},
        {"profile": "standard", "model": "ai-soc-standard"},
        {"profile": "quality", "model": "ai-soc-quality"},
    ]


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
                "usage": {
                    "prompt_tokens": 100,
                    "completion_tokens": 20,
                    "prompt_tokens_details": {"cached_tokens": 0},
                },
                "timings": {
                    "cache_n": 0,
                    "prompt_n": 100,
                    "prompt_ms": 420.5,
                    "predicted_n": 20,
                    "predicted_ms": 780.25,
                },
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
    assert response.diagnostics["availability_status"] == "profile_configured"
    assert response.diagnostics["model_load_state"] == "already_loaded"
    assert response.diagnostics["model_was_loaded"] is True
    assert response.diagnostics["availability_elapsed_ms"] >= 0
    assert response.diagnostics["profile_resolution_elapsed_ms"] >= 0
    assert response.diagnostics["prompt_tokens"] == 100
    assert response.diagnostics["cached_prompt_tokens"] == 0
    assert response.diagnostics["prompt_cache_state"] == "cold"
    assert response.diagnostics["prompt_eval_ms"] == 420.5
    assert response.diagnostics["generation_ms"] == 780.25
    assert response.diagnostics["completion_tokens"] == 20


def test_llama_cpp_structured_output_rejection_is_distinct(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    error = requests.HTTPError("400 Client Error")

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {
                        "id": "ai-soc-standard",
                        "status": {"value": "loaded"},
                    }
                ]
            }
        ),
    ), patch(
        "ai_provider_abstraction.requests.post",
        return_value=_Response(
            {"error": {"message": "invalid schema"}},
            error=error,
            status_code=400,
        ),
    ) as post:
        response = client.generate(
            feature="soc_assistant",
            prompt="test",
            messages=None,
            context=None,
            options={
                "llm_profile": "standard",
                "timeout_seconds": 1,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "test_schema",
                        "strict": True,
                        "schema": {"type": "object"},
                    },
                },
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    post.assert_called_once()
    assert response.text == ""
    assert response.safe_error == "LlamaCppStructuredOutputRejected"


def test_llama_cpp_waits_for_existing_warmup_without_duplicate_load(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    model_calls = 0
    post_urls = []

    def fake_get(url, **kwargs):
        nonlocal model_calls
        model_calls += 1
        status = "loading" if model_calls == 1 else "loaded"
        return _Response(
            {"data": [{"id": "ai-soc-standard", "status": {"value": status}}]}
        )

    def fake_post(url, **kwargs):
        post_urls.append(url)
        assert url.endswith("/chat/completions")
        return _Response(
            {
                "model": "ai-soc-standard",
                "choices": [
                    {
                        "message": {"content": "Complete answer [S1]."},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    with patch("ai_provider_abstraction.requests.get", side_effect=fake_get), patch(
        "ai_provider_abstraction.requests.post",
        side_effect=fake_post,
    ):
        response = client.generate(
            feature="soc_assistant",
            prompt="test",
            messages=None,
            context=None,
            options={
                "llm_profile": "standard",
                "timeout_seconds": 2,
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert response.text == "Complete answer [S1]."
    assert response.diagnostics["model_load_state"] == "loaded"
    assert response.diagnostics["model_was_loaded"] is False
    assert not any(url.endswith("/models/load") for url in post_urls)


def test_llama_cpp_length_finish_is_marked_truncated(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": "loaded"}}
                ]
            }
        ),
    ), patch(
        "ai_provider_abstraction.requests.post",
        return_value=_Response(
            {
                "model": "ai-soc-standard",
                "choices": [
                    {
                        "message": {"content": "Incomplete answer [S1] but"},
                        "finish_reason": "length",
                    }
                ],
            }
        ),
    ):
        response = client.generate(
            feature="soc_assistant",
            prompt="test",
            messages=None,
            context=None,
            options={"llm_profile": "standard", "timeout_seconds": 2},
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert response.finish_reason == "length"
    assert response.diagnostics["generation_result"] == "visible_content_truncated"


def test_llama_cpp_prewarm_initiates_one_load_and_waits_until_ready(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    model_calls = 0
    load_calls = 0

    def fake_get(url, **kwargs):
        nonlocal model_calls
        model_calls += 1
        status = "loaded" if load_calls else "unloaded"
        return _Response(
            {"data": [{"id": "ai-soc-standard", "status": {"value": status}}]}
        )

    def fake_post(url, **kwargs):
        nonlocal load_calls
        assert url.endswith("/models/load")
        load_calls += 1
        return _Response({"success": True})

    with patch("ai_provider_abstraction.requests.get", side_effect=fake_get), patch(
        "ai_provider_abstraction.requests.post",
        side_effect=fake_post,
    ):
        result = client.prewarm_profile("standard", timeout_seconds=2)

    assert result["state"] == "ready"
    assert result["profile"] == "standard"
    assert result["model"] == "ai-soc-standard"
    assert result["reason"] == "target_ready"
    assert result["retryable"] is False
    assert result["active_profiles"] == ["standard"]
    assert result["diagnostics"]["model_load_state"] == "loaded"
    assert load_calls == 1


def test_gateway_standard_prewarm_loads_once_with_auto_switch_disabled(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    model_calls = 0
    posts = []

    def fake_get(url, **kwargs):
        nonlocal model_calls
        model_calls += 1
        standard_status = (
            "unloaded"
            if model_calls <= 2
            else "loading"
            if model_calls == 3
            else "loaded"
        )
        return _Response(
            {
                "data": [
                    {"id": "ai-soc-fast", "status": {"value": "unloaded"}},
                    {
                        "id": "ai-soc-standard",
                        "status": {"value": standard_status},
                    },
                    {
                        "id": "ai-soc-quality",
                        "status": {"value": "unloaded"},
                    },
                ]
            }
        )

    def fake_post(url, **kwargs):
        posts.append((url, kwargs.get("json")))
        return _Response({"success": True})

    with patch("ai_provider_abstraction.requests.get", side_effect=fake_get), patch(
        "ai_provider_abstraction.requests.post",
        side_effect=fake_post,
    ):
        result = client.prewarm_gateway_standard(timeout_seconds=2)

    assert result["state"] == "ready"
    assert result["profile"] == "standard"
    assert result["model"] == "ai-soc-standard"
    assert result["diagnostics"]["model_load_state"] == "loaded"
    assert result["diagnostics"]["profile_load_count"] == 1
    assert posts == [
        (
            "http://127.0.0.1:8081/models/load",
            {"model": "ai-soc-standard"},
        )
    ]


def test_legacy_prewarm_does_not_load_when_auto_switch_is_disabled(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    payload = {
        "data": [
            {"id": "ai-soc-fast", "status": {"value": "unloaded"}},
            {"id": "ai-soc-standard", "status": {"value": "unloaded"}},
            {"id": "ai-soc-quality", "status": {"value": "unloaded"}},
        ]
    }

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(payload),
    ), patch("ai_provider_abstraction.requests.post") as post:
        result = client.prewarm_profile("standard", timeout_seconds=2)

    assert result["state"] == "failed"
    assert result["diagnostics"]["model_load_state"] == "model_not_loaded"
    post.assert_not_called()


@pytest.mark.parametrize("initial_status", ["loading", "loaded"])
def test_gateway_standard_prewarm_avoids_duplicate_load(
    monkeypatch,
    tmp_path,
    initial_status,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    model_calls = 0

    def fake_get(url, **kwargs):
        nonlocal model_calls
        model_calls += 1
        status = (
            "loaded"
            if initial_status == "loaded" or model_calls >= 3
            else "loading"
        )
        return _Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": status}},
                ]
            }
        )

    with patch(
        "ai_provider_abstraction.requests.get",
        side_effect=fake_get,
    ), patch("ai_provider_abstraction.requests.post") as post:
        result = client.prewarm_gateway_standard(timeout_seconds=2)

    assert result["state"] == "ready"
    assert result["profile"] == "standard"
    assert result["model"] == "ai-soc-standard"
    post.assert_not_called()


@pytest.mark.parametrize("forbidden_profile", ["fast", "quality", "auto", "custom"])
def test_gateway_standard_prewarm_has_no_configurable_profile(
    monkeypatch,
    forbidden_profile,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with pytest.raises(TypeError):
        client.prewarm_gateway_standard(
            forbidden_profile,
            timeout_seconds=2,
        )
    with pytest.raises(TypeError):
        client.prewarm_gateway_standard(
            timeout_seconds=2,
            model=forbidden_profile,
        )


def test_gateway_standard_prewarm_rejects_arbitrary_standard_model(
    monkeypatch,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    monkeypatch.setenv("LLAMA_CPP_STANDARD_MODEL", "ai-soc-custom")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch("ai_provider_abstraction.requests.get") as get, patch(
        "ai_provider_abstraction.requests.post"
    ) as post:
        result = client.prewarm_gateway_standard(timeout_seconds=2)

    assert result["state"] == "failed"
    assert result["model"] == "ai-soc-standard"
    assert result["reason"] == "standard_profile_not_configured"
    assert result["retryable"] is False
    get.assert_not_called()
    post.assert_not_called()


@pytest.mark.parametrize(
    ("router_status", "expected_reason"),
    [
        ("mystery", "model_status_unknown"),
        ("unloaded", "model_load_rejected"),
    ],
)
def test_gateway_standard_prewarm_reports_safe_model_failure_reason(
    monkeypatch,
    tmp_path,
    router_status,
    expected_reason,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    payload = {
        "data": [
            {
                "id": "ai-soc-standard",
                "status": {"value": router_status},
            }
        ]
    }

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(payload),
    ), patch(
        "ai_provider_abstraction.requests.post",
        return_value=_Response(
            {"success": False, "error": "private router detail"}
        ),
    ) as post:
        result = client.prewarm_gateway_standard(timeout_seconds=2)

    assert result["state"] == "failed"
    assert result["reason"] == expected_reason
    assert "private router detail" not in str(result)
    if router_status == "mystery":
        post.assert_not_called()
    else:
        post.assert_called_once()


def test_gateway_standard_prewarm_applies_existing_exclusive_policy(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    monkeypatch.setenv("LLAMA_CPP_EXCLUSIVE_MODEL", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    statuses = {"ai-soc-fast": "loaded", "ai-soc-standard": "unloaded"}
    posts = []

    def fake_get(url, **kwargs):
        return _Response(
            {
                "data": [
                    {"id": model, "status": {"value": status}}
                    for model, status in statuses.items()
                ]
            }
        )

    def fake_post(url, **kwargs):
        model = kwargs["json"]["model"]
        action = url.rsplit("/", 1)[-1]
        posts.append((action, model))
        statuses[model] = "unloaded" if action == "unload" else "loaded"
        return _Response({"success": True})

    with patch("ai_provider_abstraction.requests.get", side_effect=fake_get), patch(
        "ai_provider_abstraction.requests.post",
        side_effect=fake_post,
    ):
        result = client.prewarm_gateway_standard(timeout_seconds=2)

    assert result["state"] == "ready"
    assert posts == [
        ("unload", "ai-soc-fast"),
        ("load", "ai-soc-standard"),
    ]
    assert result["diagnostics"]["profile_unload_count"] == 1
    assert result["diagnostics"]["profile_load_count"] == 1


def test_llama_cpp_prewarm_defers_when_another_profile_is_active(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {"id": "ai-soc-fast", "status": {"value": "loaded"}},
                    {"id": "ai-soc-standard", "status": {"value": "unloaded"}},
                ]
            }
        ),
    ), patch("ai_provider_abstraction.requests.post") as post:
        result = client.prewarm_profile("standard", timeout_seconds=2)

    assert result["state"] == "unloaded"
    assert result["reason"] == "active_profile_conflict"
    assert result["retryable"] is True
    assert result["active_profiles"] == ["fast"]
    assert result["safe_error"] == "PrewarmDeferred"
    assert result["diagnostics"]["model_load_state"] == "prewarm_deferred"
    post.assert_not_called()


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": "loaded"}},
                ]
            },
            ("ready", "loaded", "target_ready", ["standard"]),
        ),
        (
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": "loading"}},
                ]
            },
            ("warming", "loading", "target_loading", ["standard"]),
        ),
        (
            {
                "data": [
                    {"id": "ai-soc-fast", "status": {"value": "loaded"}},
                    {"id": "ai-soc-standard", "status": {"value": "unloaded"}},
                ]
            },
            ("unloaded", "unloaded", "active_profile_conflict", ["fast"]),
        ),
        (
            {
                "data": [
                    {"id": "ai-soc-fast", "status": {"value": "unloaded"}},
                    {"id": "ai-soc-standard", "status": {"value": "unloaded"}},
                ]
            },
            ("unloaded", "unloaded", "target_unloaded", []),
        ),
    ],
)
def test_llama_cpp_live_profile_inspection_is_safe_and_normalized(
    monkeypatch,
    tmp_path,
    payload,
    expected,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(payload),
    ):
        result = client.inspect_profile_state("standard")

    state, target_status, reason, active_profiles = expected
    assert result["router_reachable"] is True
    assert result["profile"] == "standard"
    assert result["model"] == "ai-soc-standard"
    assert result["state"] == state
    assert result["target_status"] == target_status
    assert result["reason"] == reason
    assert result["active_profiles"] == active_profiles


def test_llama_cpp_live_inspection_reports_router_unavailable_as_retryable(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        side_effect=requests.ConnectionError("private endpoint detail"),
    ):
        result = client.inspect_profile_state("standard")

    assert result["state"] == "unknown"
    assert result["router_reachable"] is False
    assert result["reason"] == "router_unavailable"
    assert result["retryable"] is True
    assert "private endpoint detail" not in str(result)


def test_llama_cpp_provider_disabled_prewarm_is_non_retryable() -> None:
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    result = client.prewarm_profile("standard", timeout_seconds=2)

    assert result["state"] == "failed"
    assert result["reason"] == "provider_disabled"
    assert result["retryable"] is False
    assert result["safe_error"] == "ProviderDisabled"


def test_llama_cpp_prewarm_does_not_reload_ready_target(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": "loaded"}},
                ]
            }
        ),
    ), patch("ai_provider_abstraction.requests.post") as post:
        result = client.prewarm_profile("standard", timeout_seconds=2)

    assert result["state"] == "ready"
    assert result["target_status"] == "loaded"
    assert result["active_profiles"] == ["standard"]
    post.assert_not_called()


def test_llama_cpp_prewarm_waits_for_loading_target_without_duplicate_load(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    model_calls = 0

    def fake_get(url, **kwargs):
        nonlocal model_calls
        model_calls += 1
        status = "loaded" if model_calls >= 3 else "loading"
        return _Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": status}},
                ]
            }
        )

    with patch(
        "ai_provider_abstraction.requests.get",
        side_effect=fake_get,
    ), patch("ai_provider_abstraction.requests.post") as post:
        result = client.prewarm_profile("standard", timeout_seconds=2)

    assert result["state"] == "ready"
    assert result["reason"] == "target_ready"
    assert result["diagnostics"]["model_load_state"] == "loaded"
    post.assert_not_called()


def test_query_and_background_prewarm_share_profile_switch_lock(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "true")
    monkeypatch.setenv(
        "LLAMA_CPP_PROFILE_SWITCH_LOCK",
        str(tmp_path / "profile.lock"),
    )
    registry = load_provider_registry()
    provider = registry.providers["local_llama_cpp"]
    query_client = build_provider_client(provider)
    prewarm_client = build_provider_client(provider)
    state_lock = threading.Lock()
    start = threading.Barrier(2)
    model_loaded = False
    load_calls = 0
    results = {}

    def fake_get(url, **kwargs):
        with state_lock:
            status = "loaded" if model_loaded else "unloaded"
        return _Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": status}},
                ]
            }
        )

    def fake_post(url, **kwargs):
        nonlocal model_loaded, load_calls
        if url.endswith("/models/load"):
            with state_lock:
                load_calls += 1
                model_loaded = True
            return _Response({"success": True})
        assert url.endswith("/chat/completions")
        return _Response(
            {
                "model": "ai-soc-standard",
                "choices": [
                    {
                        "message": {"content": "Grounded answer [S1]."},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    def run_query():
        start.wait()
        results["query"] = query_client.generate(
            feature="soc_assistant",
            prompt="test",
            messages=None,
            context=None,
            options={"llm_profile": "standard", "timeout_seconds": 2},
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    def run_prewarm():
        start.wait()
        results["prewarm"] = prewarm_client.prewarm_profile(
            "standard",
            timeout_seconds=2,
        )

    with patch(
        "ai_provider_abstraction.requests.get",
        side_effect=fake_get,
    ), patch(
        "ai_provider_abstraction.requests.post",
        side_effect=fake_post,
    ):
        threads = [
            threading.Thread(target=run_query),
            threading.Thread(target=run_prewarm),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)

    assert all(not thread.is_alive() for thread in threads)
    assert load_calls == 1
    assert results["query"].text == "Grounded answer [S1]."
    assert results["prewarm"]["state"] == "ready"


def test_warm_llama_cpp_response_reports_cached_prompt_tokens() -> None:
    diagnostics = _llama_cpp_timing_diagnostics(
        {
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 20,
                "prompt_tokens_details": {"cached_tokens": 99},
            },
            "timings": {
                "cache_n": 99,
                "prompt_n": 1,
                "prompt_ms": 8.5,
                "predicted_n": 20,
                "predicted_ms": 700.0,
            },
        }
    )

    assert diagnostics == {
        "prompt_n": 1,
        "prompt_ms": 8.5,
        "cached_tokens": 99,
        "predicted_n": 20,
        "predicted_ms": 700.0,
        "prompt_tokens": 100,
        "cached_prompt_tokens": 99,
        "prompt_cache_state": "warm",
        "completion_tokens": 20,
        "prompt_eval_ms": 8.5,
        "generation_ms": 700.0,
    }


def test_llama_cpp_missing_profile_alias_fails_before_model_load(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {"data": [{"id": "default", "status": {"value": "loaded"}}]}
        ),
    ), patch("ai_provider_abstraction.requests.post") as post:
        response = client.generate(
            feature="soc_assistant",
            prompt="test",
            messages=None,
            context=None,
            options={
                "llm_profile": "standard",
                "timeout_seconds": 1,
                "availability_timeout_seconds": 0.5,
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert response.text == ""
    assert response.safe_error == "LlamaCppProfileNotConfigured"
    assert response.diagnostics["availability_status"] == "profile_not_configured"
    assert response.diagnostics["model_load_state"] == "not_applicable"
    post.assert_not_called()


def test_llama_cpp_unreachable_router_fails_fast_without_generation(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        side_effect=requests.ConnectionError("router unavailable"),
    ), patch("ai_provider_abstraction.requests.post") as post:
        response = client.generate(
            feature="soc_assistant",
            prompt="test",
            messages=None,
            context=None,
            options={
                "llm_profile": "standard",
                "timeout_seconds": 30,
                "availability_timeout_seconds": 1,
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert response.text == ""
    assert response.safe_error == "LlamaCppProviderUnavailable"
    assert response.diagnostics["availability_status"] == "provider_unavailable"
    assert response.latency_ms < 1000
    post.assert_not_called()


def test_llama_cpp_model_load_timeout_is_distinct(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": "unloaded"}},
                ]
            }
        ),
    ), patch(
        "ai_provider_abstraction.requests.post",
        side_effect=requests.Timeout("load timed out"),
    ):
        response = client.generate(
            feature="soc_assistant",
            prompt="test",
            messages=None,
            context=None,
            options={
                "llm_profile": "standard",
                "timeout_seconds": 1,
                "availability_timeout_seconds": 0.5,
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert response.safe_error == "LlamaCppModelLoadTimeout"
    assert response.diagnostics["model_load_state"] == "load_timeout"
    assert response.diagnostics["timeout_phase"] == "model_load"


def test_llama_cpp_reasoning_only_response_has_stable_safe_error(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": "loaded"}},
                ]
            }
        ),
    ), patch(
        "ai_provider_abstraction.requests.post",
        return_value=_Response(
            {
                "model": "ai-soc-standard",
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "reasoning_content": "private reasoning must be discarded",
                        },
                        "finish_reason": "length",
                    }
                ],
            }
        ),
    ) as post:
        response = client.generate(
            feature="soc_assistant",
            prompt=None,
            messages=[{"role": "user", "content": "Explain the risk."}],
            context=None,
            options={
                "llm_profile": "standard",
                "timeout_seconds": 2,
                "chat_template_kwargs": {"enable_thinking": False},
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert post.call_count == 1
    assert response.text == ""
    assert response.safe_error == "LlamaCppEmptyVisibleContent"
    assert response.diagnostics["generation_result"] == "empty_visible_content"
    assert response.diagnostics["thinking_disabled"] is True
    assert response.diagnostics["reasoning_retry_performed"] is False
    assert "private reasoning" not in str(response)


def test_llama_cpp_reasoning_only_retries_once_with_thinking_disabled(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_STANDARD_MODEL_FAMILY", "qwen3")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    original_messages = [{"role": "user", "content": "Explain the risk."}]
    payloads = []

    def fake_post(url, **kwargs):
        payloads.append(kwargs["json"])
        if len(payloads) == 1:
            return _Response(
                {
                    "model": "ai-soc-standard",
                    "choices": [
                        {
                            "message": {
                                "content": "",
                                "reasoning_content": "discard this",
                            },
                            "finish_reason": "length",
                        }
                    ],
                }
            )
        return _Response(
            {
                "model": "ai-soc-standard",
                "choices": [
                    {
                        "message": {"content": "Visible grounded answer [S1]."},
                        "finish_reason": "stop",
                    }
                ],
            }
        )

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": "loaded"}},
                ]
            }
        ),
    ), patch("ai_provider_abstraction.requests.post", side_effect=fake_post):
        response = client.generate(
            feature="soc_assistant",
            prompt=None,
            messages=original_messages,
            context=None,
            options={
                "llm_profile": "standard",
                "timeout_seconds": 2,
                "reasoning_retry_allowed": True,
                "caller_kind": "assistant_primary",
                "request_id_hash": "a1b2c3d4e5f60718",
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert len(payloads) == 2
    assert "chat_template_kwargs" not in payloads[0]
    assert payloads[1]["chat_template_kwargs"] == {"enable_thinking": False}
    assert "/no_think" not in payloads[1]["messages"][-1]["content"]
    assert response.text == "Visible grounded answer [S1]."
    assert response.diagnostics["generation_result"] == "visible_content_after_retry"
    assert response.diagnostics["thinking_disabled"] is True
    assert response.diagnostics["reasoning_retry_performed"] is True
    assert response.diagnostics["caller_kind"] == "assistant_primary"
    assert response.diagnostics["request_id_hash"] == "a1b2c3d4e5f60718"
    assert response.diagnostics["requested_profile"] == "standard"
    assert response.diagnostics["effective_profile"] == "standard"
    assert response.diagnostics["profile_switch_count"] == 0
    assert response.diagnostics["profile_load_count"] == 0
    assert response.diagnostics["profile_unload_count"] == 0
    assert original_messages == [{"role": "user", "content": "Explain the risk."}]


def test_qwen3_compatibility_retry_is_once_and_does_not_mutate_input(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_STANDARD_MODEL_FAMILY", "qwen3")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    original_messages = [{"role": "user", "content": "Explain the correlation."}]
    payloads = []

    def fake_post(url, **kwargs):
        payloads.append(kwargs["json"])
        return _Response(
            {
                "model": "ai-soc-standard",
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "reasoning_content": f"discard retry {len(payloads)}",
                        },
                        "finish_reason": "length",
                    }
                ],
            }
        )

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {"id": "ai-soc-standard", "status": {"value": "loaded"}},
                ]
            }
        ),
    ), patch("ai_provider_abstraction.requests.post", side_effect=fake_post):
        response = client.generate(
            feature="soc_assistant",
            prompt=None,
            messages=original_messages,
            context=None,
            options={
                "llm_profile": "standard",
                "timeout_seconds": 2,
                "chat_template_kwargs": {"enable_thinking": False},
                "reasoning_retry_allowed": True,
                "qwen_no_think_compatibility": True,
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert len(payloads) == 2
    assert "/no_think" not in payloads[0]["messages"][-1]["content"]
    assert payloads[1]["messages"][-1]["content"].endswith("/no_think")
    assert original_messages == [
        {"role": "user", "content": "Explain the correlation."}
    ]
    assert response.safe_error == "LlamaCppEmptyVisibleContent"
    assert response.diagnostics["reasoning_retry_performed"] is True
    assert "/no_think" not in str(response)
    assert "discard retry" not in str(response)


def test_non_qwen_profile_never_uses_no_think_compatibility(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    monkeypatch.setenv("LLAMA_CPP_QUALITY_MODEL_FAMILY", "llama")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])
    payloads = []

    def fake_post(url, **kwargs):
        payloads.append(kwargs["json"])
        return _Response(
            {
                "model": "ai-soc-quality",
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "reasoning_content": "discard this",
                        },
                        "finish_reason": "length",
                    }
                ],
            }
        )

    with patch(
        "ai_provider_abstraction.requests.get",
        return_value=_Response(
            {
                "data": [
                    {"id": "ai-soc-quality", "status": {"value": "loaded"}},
                ]
            }
        ),
    ), patch("ai_provider_abstraction.requests.post", side_effect=fake_post):
        response = client.generate(
            feature="soc_assistant",
            prompt=None,
            messages=[{"role": "user", "content": "Explain deeply."}],
            context=None,
            options={
                "llm_profile": "quality",
                "timeout_seconds": 2,
                "chat_template_kwargs": {"enable_thinking": False},
                "reasoning_retry_allowed": True,
                "qwen_no_think_compatibility": True,
            },
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    assert len(payloads) == 1
    assert "/no_think" not in payloads[0]["messages"][-1]["content"]
    assert response.safe_error == "LlamaCppEmptyVisibleContent"
    assert response.diagnostics["reasoning_retry_performed"] is False


def test_llama_cpp_health_filters_default_model(monkeypatch):
    monkeypatch.setenv("LLAMA_CPP_ENABLED", "true")
    registry = load_provider_registry()
    client = build_provider_client(registry.providers["local_llama_cpp"])

    def fake_get(url, **kwargs):
        if url.endswith("/health"):
            return _Response({"status": "ok"})
        return _Response(
            {
                "data": [
                    {"id": "default", "status": {"value": "loaded"}},
                    {"id": "ai-soc-fast", "status": {"value": "loaded"}},
                    {"id": "ai-soc-standard", "status": {"value": "unloaded"}},
                ]
            }
        )

    with patch("ai_provider_abstraction.requests.get", side_effect=fake_get):
        health = client.health_check()

    assert health.reachable is True
    profile_models = [item["model"] for item in health.details["profiles"]]
    assert "ai-soc-fast" in profile_models
    assert "ai-soc-standard" in profile_models
    assert "default" not in profile_models
    assert health.details["loaded_models"] == ["ai-soc-fast"]


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
