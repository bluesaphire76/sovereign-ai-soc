import importlib
import os
from unittest.mock import patch

import requests

import ai_triage_hardening
import llm_client
from ai_model_config import LlmProfile
from ai_model_policy import AiTask, select_profile


def _reload_config_with_env(values: dict[str, str]):
    with patch.dict(os.environ, values, clear=False):
        import ai_model_config

        return importlib.reload(ai_model_config)


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


def test_llm_client_falls_back_to_fast_when_primary_profile_fails():
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

    def fake_call_ollama(*, prompt, messages, profile, timeout_seconds):
        calls.append(profile.name)

        if profile.name == "standard":
            raise requests.exceptions.Timeout("timed out")

        return "fast response"

    with patch("llm_client.get_profile", side_effect=fake_get_profile):
        with patch("llm_client._call_ollama", side_effect=fake_call_ollama):
            result = llm_client.generate_ai_response(
                prompt="test",
                task=AiTask.ACTION_HOW_TO,
                requested_mode="standard",
                user_triggered=True,
            )

    assert calls == ["standard", "fast"]
    assert result["text"] == "fast response"
    assert result["profile"] == "fast"
    assert result["model"] == "fast:model"
    assert result["fallback_used"] is True
    assert result["error_type"] == "Timeout"
    assert isinstance(result["latency_ms"], int)


def test_legacy_call_ollama_chat_uses_routed_client_and_records_metadata():
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
        text = ai_triage_hardening.call_ollama_chat(
            messages=[{"role": "user", "content": "hello"}],
            timeout_seconds=12,
        )

    metadata = ai_triage_hardening.get_last_llm_call_metadata()

    assert text == "routed response"
    assert calls[0]["task"] == AiTask.INCIDENT_TRIAGE
    assert calls[0]["requested_mode"] == "auto"
    assert calls[0]["user_triggered"] is False
    assert calls[0]["timeout_seconds"] == 12
    assert metadata["profile"] == "standard"
    assert metadata["model"] == "standard:model"
    assert metadata["fallback_used"] is False
    assert metadata["latency_ms"] == 42


def test_legacy_call_ollama_chat_raises_timeout_when_all_profiles_timeout():
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
            ai_triage_hardening.call_ollama_chat(
                messages=[{"role": "user", "content": "hello"}],
            )
            raised = None
        except Exception as exc:
            raised = exc

    assert isinstance(raised, requests.exceptions.Timeout)
