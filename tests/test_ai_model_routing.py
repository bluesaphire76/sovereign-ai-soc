import importlib
import logging
import os
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import requests

import ai_triage_hardening
import llm_client
from ai_model_config import LlmProfile
from ai_model_policy import AiTask, select_profile
from ai_provider_abstraction import AIProviderResponse
from ai_provider_registry import PROVIDER_LOCAL_LLAMA_CPP, PROVIDER_LOCAL_OLLAMA


@pytest.fixture(autouse=True)
def isolated_provider_config(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_PROVIDER_CONFIG_PATH", str(tmp_path / "ai_providers.json"))
    monkeypatch.setenv("AI_DATA_POLICY_CONFIG_PATH", str(tmp_path / "ai_data_control_policy.json"))
    monkeypatch.setenv("AI_PROVIDER_DEFAULT", "local_ollama")
    monkeypatch.setenv("AI_LLM_PROVIDER", "ollama")


def _reload_config_with_env(values: dict[str, str]):
    with patch.dict(os.environ, values, clear=False):
        import ai_model_config

        return importlib.reload(ai_model_config)


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_standard_profile_defaults_to_legacy_ollama_model_when_present():
    config = _reload_config_with_env(
        {
            "AI_SOC_LLM_STANDARD": "",
            "OLLAMA_MODEL": "legacy:8b",
        }
    )

    assert config.STANDARD_PROFILE.model == "legacy:8b"


def test_standard_profile_defaults_to_new_operational_model_without_legacy():
    config = _reload_config_with_env(
        {
            "AI_SOC_LLM_STANDARD": "",
            "OLLAMA_MODEL": "",
        }
    )

    assert config.STANDARD_PROFILE.model == "qwen3.5:4b"


def test_invalid_numeric_profile_env_falls_back_to_defaults():
    config = _reload_config_with_env(
        {
            "AI_SOC_LLM_FAST_NUM_CTX": "not-an-int",
            "AI_SOC_LLM_FAST_TEMPERATURE": "not-a-float",
        }
    )

    assert config.FAST_PROFILE.num_ctx == 2048
    assert config.FAST_PROFILE.temperature == 0.1


def test_policy_uses_fast_for_simple_routing_tasks():
    assert select_profile(AiTask.ROUTING) == "fast"
    assert select_profile("classification") == "fast"


def test_policy_keeps_automatic_high_severity_work_off_quality():
    assert (
        select_profile(
            AiTask.INCIDENT_ANALYSIS,
            severity="CRITICAL",
            user_triggered=False,
        )
        == "standard"
    )


def test_policy_allows_quality_for_manual_high_severity_work():
    assert (
        select_profile(
            AiTask.INCIDENT_ANALYSIS,
            severity="HIGH",
            user_triggered=True,
        )
        == "quality"
    )


def test_policy_does_not_honor_quality_override_for_automatic_work():
    assert (
        select_profile(
            AiTask.REMEDIATION,
            requested_mode="quality",
            user_triggered=False,
        )
        == "standard"
    )


def test_llm_client_falls_back_to_fast_when_primary_profile_fails(caplog):
    profiles = {
        "standard": LlmProfile(
            name="standard",
            model="standard:model",
            num_ctx=4096,
            temperature=0.2,
            timeout_seconds=45,
            keep_alive="2m",
        ),
        "fast": LlmProfile(
            name="fast",
            model="fast:model",
            num_ctx=2048,
            temperature=0.1,
            timeout_seconds=20,
            keep_alive="30s",
        ),
    }
    calls = []

    def fake_get_profile(profile_name):
        return profiles[profile_name]

    def fake_call_ollama(*, feature, prompt, messages, profile, timeout_seconds):
        calls.append(profile.name)

        if profile.name == "standard":
            raise requests.exceptions.Timeout("timed out")

        return "fast response"

    with caplog.at_level(logging.INFO, logger="llm_client"):
        with patch("llm_client.get_profile", side_effect=fake_get_profile):
            with patch("llm_client._call_ollama", side_effect=fake_call_ollama):
                result = llm_client.generate_ai_response(
                    prompt="test",
                    task=AiTask.ACTION_HOW_TO,
                    requested_mode="standard",
                    user_triggered=True,
                )

    assert calls == ["standard", "fast"]
    assert "AI provider fallback primary=local_ollama fallback=local_ollama task=detection_quality_how_to_execute reason=Timeout" in caplog.text
    assert "AI provider selected provider=local_ollama type=LOCAL_OLLAMA task=detection_quality_how_to_execute profile=fast resolved_model=fast:model external=false fallback=true redaction_mode=LOCAL_ONLY" in caplog.text
    assert "test" not in caplog.text
    assert result["text"] == "fast response"
    assert result["profile"] == "fast"
    assert result["model"] == "fast:model"
    assert result["fallback_used"] is True
    assert result["error_type"] == "Timeout"
    assert result["generation_kind"] == "model_fallback"
    assert result["provider_status"] == "ok"
    assert result["effective_provider"] == "local_ollama"
    assert result["effective_profile"] == "fast"
    assert isinstance(result["latency_ms"], int)


def test_llm_client_logs_provider_metadata_without_prompt(caplog):
    profile = LlmProfile(
        name="fast",
        model="fast:model",
        num_ctx=2048,
        temperature=0.1,
        timeout_seconds=20,
        keep_alive="30s",
    )

    with caplog.at_level(logging.INFO, logger="llm_client"):
        with patch("llm_client.get_profile", return_value=profile):
            with patch("llm_client._call_ollama", return_value="ok"):
                result = llm_client.generate_ai_response(
                    prompt="secret prompt text",
                    task=AiTask.ROUTING,
                    requested_mode="fast",
                    user_triggered=False,
                )

    assert result["provider_key"] == "local_ollama"
    assert "AI provider selected provider=local_ollama" in caplog.text
    assert "resolved_model=fast:model" in caplog.text
    assert "secret prompt text" not in caplog.text


def test_llama_cpp_failure_with_successful_ollama_fallback_is_model_generated():
    profile = LlmProfile(
        name="standard",
        model="ai-soc-standard",
        num_ctx=4096,
        temperature=0.2,
        timeout_seconds=45,
        keep_alive="2m",
    )
    primary_response = AIProviderResponse(
        provider_key="local_llama_cpp",
        provider_type=PROVIDER_LOCAL_LLAMA_CPP,
        model="ai-soc-standard",
        text="",
        finish_reason=None,
        latency_ms=10,
        used_external_provider=False,
        redaction_applied=False,
        fallback_used=False,
        safe_error="ConnectionError",
        usage=None,
        profile="standard",
    )
    fallback_result = {
        "text": "Grounded fallback answer [S1].",
        "profile": "fast",
        "model": "llama3.2:3b",
        "fallback_used": True,
        "error_type": None,
        "safe_error": None,
        "latency_ms": 41,
        "provider_key": "local_ollama",
        "provider_type": PROVIDER_LOCAL_OLLAMA,
    }

    with (
        patch(
            "llm_client.select_provider_config",
            return_value=SimpleNamespace(
                key="local_llama_cpp",
                provider_type=PROVIDER_LOCAL_LLAMA_CPP,
            ),
        ),
        patch("llm_client.get_llama_cpp_profile", return_value=profile),
        patch("llm_client.generate_with_provider", return_value=primary_response),
        patch("llm_client._call_ollama_with_fallback", return_value=fallback_result),
    ):
        result = llm_client.generate_ai_response(
            prompt="test",
            task=AiTask.SOC_ASSISTANT,
            requested_mode="quality",
            user_triggered=True,
        )

    assert result["generation_kind"] == "model_fallback"
    assert result["primary_provider"] == "local_llama_cpp"
    assert result["effective_provider"] == "local_ollama"
    assert result["fallback_provider"] == "local_ollama"
    assert result["fallback_attempted"] is True
    assert result["provider_status"] == "ok"
    assert result["requested_mode"] == "quality"
    assert result["effective_profile"] == "fast"
    assert result["safe_error"] is None


def test_llama_cpp_and_ollama_failure_has_no_effective_generator():
    profile = LlmProfile(
        name="standard",
        model="ai-soc-standard",
        num_ctx=4096,
        temperature=0.2,
        timeout_seconds=45,
        keep_alive="2m",
    )
    primary_response = AIProviderResponse(
        provider_key="local_llama_cpp",
        provider_type=PROVIDER_LOCAL_LLAMA_CPP,
        model="ai-soc-standard",
        text="",
        finish_reason=None,
        latency_ms=10,
        used_external_provider=False,
        redaction_applied=False,
        fallback_used=False,
        safe_error="ConnectionError",
        usage=None,
        profile="standard",
    )
    fallback_result = {
        "text": "",
        "profile": "fast",
        "model": "llama3.2:3b",
        "fallback_used": True,
        "error_type": "ReadTimeout",
        "safe_error": "ReadTimeout",
        "latency_ms": 41,
        "provider_key": "local_ollama",
        "provider_type": PROVIDER_LOCAL_OLLAMA,
    }

    with (
        patch(
            "llm_client.select_provider_config",
            return_value=SimpleNamespace(
                key="local_llama_cpp",
                provider_type=PROVIDER_LOCAL_LLAMA_CPP,
            ),
        ),
        patch("llm_client.get_llama_cpp_profile", return_value=profile),
        patch("llm_client.generate_with_provider", return_value=primary_response),
        patch("llm_client._call_ollama_with_fallback", return_value=fallback_result),
    ):
        result = llm_client.generate_ai_response(
            prompt="test",
            task=AiTask.SOC_ASSISTANT,
            requested_mode="auto",
            user_triggered=True,
        )

    assert result["generation_kind"] == "unavailable"
    assert result["primary_provider"] == "local_llama_cpp"
    assert result["fallback_provider"] == "local_ollama"
    assert result["fallback_attempted"] is True
    assert result["effective_provider"] is None
    assert result["effective_profile"] is None
    assert result["provider_status"] == "timeout"


def test_assistant_primary_and_fallback_share_one_deadline():
    clock = FakeClock()
    profile = LlmProfile(
        name="standard",
        model="ai-soc-standard",
        num_ctx=4096,
        temperature=0.2,
        timeout_seconds=30,
        keep_alive="2m",
    )
    primary_response = AIProviderResponse(
        provider_key="local_llama_cpp",
        provider_type=PROVIDER_LOCAL_LLAMA_CPP,
        model="ai-soc-standard",
        text="",
        finish_reason=None,
        latency_ms=30000,
        used_external_provider=False,
        redaction_applied=False,
        fallback_used=False,
        safe_error="LlamaCppGenerationTimeout",
        usage=None,
        profile="standard",
    )
    captured = {}

    def primary_call(**kwargs):
        clock.advance(30)
        return primary_response

    def availability_check(**kwargs):
        clock.advance(2)
        return True, 2000, "available"

    def fallback_call(**kwargs):
        captured.update(kwargs)
        clock.advance(kwargs["timeout_seconds"])
        return {
            "text": "",
            "profile": "standard",
            "model": "qwen3.5:4b",
            "fallback_used": False,
            "error_type": "Timeout",
            "safe_error": "Timeout",
            "latency_ms": int(kwargs["timeout_seconds"] * 1000),
            "provider_key": "local_ollama",
            "provider_type": PROVIDER_LOCAL_OLLAMA,
        }

    with (
        patch("llm_client.time.monotonic", side_effect=clock),
        patch(
            "llm_client.select_provider_config",
            return_value=SimpleNamespace(
                key="local_llama_cpp",
                provider_type=PROVIDER_LOCAL_LLAMA_CPP,
            ),
        ),
        patch("llm_client.get_llama_cpp_profile", return_value=profile),
        patch("llm_client.generate_with_provider", side_effect=primary_call),
        patch("llm_client._ollama_fallback_available", side_effect=availability_check),
        patch("llm_client._call_ollama_with_fallback", side_effect=fallback_call),
    ):
        result = llm_client.generate_ai_response(
            prompt="test",
            task=AiTask.SOC_ASSISTANT,
            requested_mode="auto",
            user_triggered=True,
            timeout_seconds=30,
            deadline_monotonic=45,
            fallback_timeout_seconds=10,
            availability_timeout_seconds=2,
        )

    assert captured["timeout_seconds"] == pytest.approx(8)
    assert captured["deadline_monotonic"] == pytest.approx(40)
    assert captured["allow_profile_fallback"] is False
    assert clock.value == pytest.approx(40)
    assert result["generation_kind"] == "unavailable"
    assert result["timeout_reason"] == "fallback_timeout"


def test_assistant_skips_fallback_when_total_budget_is_exhausted():
    clock = FakeClock()
    profile = LlmProfile(
        name="standard",
        model="ai-soc-standard",
        num_ctx=4096,
        temperature=0.2,
        timeout_seconds=30,
        keep_alive="2m",
    )
    primary_response = AIProviderResponse(
        provider_key="local_llama_cpp",
        provider_type=PROVIDER_LOCAL_LLAMA_CPP,
        model="ai-soc-standard",
        text="",
        finish_reason=None,
        latency_ms=44900,
        used_external_provider=False,
        redaction_applied=False,
        fallback_used=False,
        safe_error="Timeout",
        usage=None,
        profile="standard",
    )

    def primary_call(**kwargs):
        clock.advance(44.9)
        return primary_response

    with (
        patch("llm_client.time.monotonic", side_effect=clock),
        patch(
            "llm_client.select_provider_config",
            return_value=SimpleNamespace(
                key="local_llama_cpp",
                provider_type=PROVIDER_LOCAL_LLAMA_CPP,
            ),
        ),
        patch("llm_client.get_llama_cpp_profile", return_value=profile),
        patch("llm_client.generate_with_provider", side_effect=primary_call),
        patch("llm_client._ollama_fallback_available") as availability,
        patch("llm_client._call_ollama_with_fallback") as fallback,
    ):
        result = llm_client.generate_ai_response(
            prompt="test",
            task=AiTask.SOC_ASSISTANT,
            requested_mode="auto",
            user_triggered=True,
            timeout_seconds=30,
            deadline_monotonic=45,
            fallback_timeout_seconds=10,
            availability_timeout_seconds=2,
        )

    availability.assert_not_called()
    fallback.assert_not_called()
    assert result["fallback_attempted"] is False
    assert result["fallback_skipped_reason"] == "total_budget_exhausted"
    assert result["timeout_reason"] == "total_budget_exhausted"


@pytest.mark.parametrize(
    ("requested_mode", "profile_name", "expected_max_tokens"),
    [
        ("auto", "standard", 384),
        ("standard", "standard", 384),
        ("quality", "quality", 512),
    ],
)
def test_soc_assistant_llama_cpp_reserves_visible_tokens_and_disables_thinking(
    requested_mode,
    profile_name,
    expected_max_tokens,
):
    profile = LlmProfile(
        name=profile_name,
        model=f"ai-soc-{profile_name}",
        num_ctx=4096,
        temperature=0.2,
        timeout_seconds=30,
        keep_alive="2m",
    )
    response = AIProviderResponse(
        provider_key="local_llama_cpp",
        provider_type=PROVIDER_LOCAL_LLAMA_CPP,
        model=profile.model,
        text="Visible grounded answer [S1].",
        finish_reason="stop",
        latency_ms=10,
        used_external_provider=False,
        redaction_applied=False,
        fallback_used=False,
        safe_error=None,
        usage={"completion_tokens": 24},
        profile=profile_name,
        diagnostics={
            "generation_result": "visible_content",
            "thinking_disabled": True,
            "reasoning_retry_performed": False,
        },
    )
    captured = {}

    def provider_call(**kwargs):
        captured.update(kwargs)
        return response

    with (
        patch(
            "llm_client.select_provider_config",
            return_value=SimpleNamespace(
                key="local_llama_cpp",
                provider_type=PROVIDER_LOCAL_LLAMA_CPP,
            ),
        ),
        patch("llm_client.get_llama_cpp_profile", return_value=profile),
        patch("llm_client.generate_with_provider", side_effect=provider_call),
    ):
        result = llm_client.generate_ai_response(
            prompt="test",
            task=AiTask.SOC_ASSISTANT,
            requested_mode=requested_mode,
            user_triggered=True,
        )

    options = captured["options"]
    assert options["max_tokens"] == expected_max_tokens
    assert options["chat_template_kwargs"] == {"enable_thinking": False}
    assert options["reasoning_retry_allowed"] is True
    assert options["qwen_no_think_compatibility"] is True
    assert result["generation_kind"] == "model_success"
    assert result["provider_diagnostics"]["generation_result"] == "visible_content"


@pytest.mark.parametrize(
    ("configured", "expected"),
    [("1", 256), ("320", 320), ("999", 384), ("invalid", 384)],
)
def test_soc_assistant_visible_completion_budget_is_clamped(
    monkeypatch,
    configured,
    expected,
):
    monkeypatch.setenv("AI_SOC_ASSISTANT_MAX_VISIBLE_TOKENS", configured)

    assert llm_client._soc_assistant_visible_max_tokens() == expected


def test_soc_assistant_repair_can_override_visible_completion_budget() -> None:
    assert (
        llm_client._soc_assistant_visible_max_tokens(
            requested_mode="quality",
            override=256,
        )
        == 256
    )


def test_reasoning_only_llama_result_skips_ollama_provider_chain():
    profile = LlmProfile(
        name="standard",
        model="ai-soc-standard",
        num_ctx=4096,
        temperature=0.2,
        timeout_seconds=30,
        keep_alive="2m",
    )
    response = AIProviderResponse(
        provider_key="local_llama_cpp",
        provider_type=PROVIDER_LOCAL_LLAMA_CPP,
        model="ai-soc-standard",
        text="",
        finish_reason=None,
        latency_ms=18000,
        used_external_provider=False,
        redaction_applied=False,
        fallback_used=False,
        safe_error="LlamaCppEmptyVisibleContent",
        usage=None,
        profile="standard",
        diagnostics={
            "generation_result": "empty_visible_content",
            "thinking_disabled": True,
            "reasoning_retry_performed": True,
        },
    )

    with (
        patch(
            "llm_client.select_provider_config",
            return_value=SimpleNamespace(
                key="local_llama_cpp",
                provider_type=PROVIDER_LOCAL_LLAMA_CPP,
            ),
        ),
        patch("llm_client.get_llama_cpp_profile", return_value=profile),
        patch("llm_client.generate_with_provider", return_value=response),
        patch("llm_client._ollama_fallback_available") as availability,
        patch("llm_client._call_ollama_with_fallback") as fallback,
    ):
        result = llm_client.generate_ai_response(
            prompt="test",
            task=AiTask.SOC_ASSISTANT,
            requested_mode="auto",
            user_triggered=True,
            fallback_timeout_seconds=10,
        )

    availability.assert_not_called()
    fallback.assert_not_called()
    assert result["provider_status"] == "empty_visible_content"
    assert result["generation_kind"] == "unavailable"
    assert result["fallback_attempted"] is False
    assert result["fallback_skipped_reason"] == "empty_visible_content"
    assert result["provider_diagnostics"]["reasoning_retry_performed"] is True


def test_call_ai_gateway_uses_routed_client_and_records_metadata():
    calls = []

    def fake_generate_ai_response(**kwargs):
        calls.append(kwargs)

        return {
            "text": "routed response",
            "profile": "standard",
            "model": "standard:model",
            "fallback_used": False,
            "error_type": None,
            "latency_ms": 42,
        }

    with patch(
        "ai_triage_hardening.generate_ai_response",
        side_effect=fake_generate_ai_response,
    ):
        text = ai_triage_hardening.call_ai_gateway(
            messages=[{"role": "user", "content": "hello"}],
            timeout_seconds=12,
        )

    metadata = ai_triage_hardening.get_last_llm_call_metadata()

    assert text == "routed response"
    assert calls[0]["task"] == AiTask.INCIDENT_TRIAGE
    assert calls[0]["requested_mode"] == "standard"
    assert calls[0]["user_triggered"] is False
    assert calls[0]["timeout_seconds"] == 12
    assert metadata["profile"] == "standard"
    assert metadata["model"] == "standard:model"
    assert metadata["fallback_used"] is False
    assert metadata["latency_ms"] == 42


def test_call_ai_gateway_raises_timeout_when_gateway_times_out():
    with patch(
        "ai_triage_hardening.generate_ai_response",
        return_value={
            "text": "",
            "profile": "fast",
            "model": "fast:model",
            "fallback_used": True,
            "error_type": "Timeout",
            "latency_ms": 1000,
        },
    ):
        try:
            ai_triage_hardening.call_ai_gateway(
                messages=[{"role": "user", "content": "hello"}],
            )
            raised = None
        except Exception as exc:
            raised = exc

    assert isinstance(raised, requests.exceptions.Timeout)
