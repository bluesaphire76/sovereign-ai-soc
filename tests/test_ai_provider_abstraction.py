from __future__ import annotations

from unittest.mock import patch

import pytest

from ai_model_policy import AiTask
from ai_provider_abstraction import build_provider_client
from ai_provider_policy import external_block_reason, generate_with_provider
from ai_provider_redaction import redact_text
from ai_provider_registry import load_provider_registry, provider_public_dict


@pytest.fixture(autouse=True)
def isolated_runtime_config(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_PROVIDER_CONFIG_PATH", str(tmp_path / "ai_providers.json"))
    monkeypatch.setenv("AI_DATA_POLICY_CONFIG_PATH", str(tmp_path / "ai_data_control_policy.json"))


def test_local_ollama_is_default_and_external_is_disabled(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER_DEFAULT", raising=False)
    monkeypatch.delenv("AI_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("AI_EXTERNAL_PROVIDERS_ENABLED", raising=False)
    monkeypatch.delenv("AI_OPENROUTER_ENABLED", raising=False)
    monkeypatch.delenv("AI_OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("AI_OPENAI_COMPATIBLE_API_KEY", raising=False)

    registry = load_provider_registry()

    assert registry.default_provider == "local_ollama"
    assert registry.external_providers_enabled is False
    assert registry.providers["local_ollama"].enabled is True
    assert registry.providers["local_ollama"].display_name == "Ollama"
    assert registry.providers["openrouter"].display_name == "Openrouter"
    assert registry.providers["openai_compatible"].display_name == "OpenAI"
    assert registry.providers["azure_openai_compatible"].display_name == "MS Azure"
    assert registry.providers["anthropic_compatible"].display_name == "Anthropic"
    assert registry.providers["custom_http_compatible"].display_name == "Custom HTTP"
    assert registry.providers["openrouter"].enabled is False
    assert registry.providers["openrouter"].base_url == "https://openrouter.ai/api/v1"
    assert registry.providers["openai_compatible"].enabled is False
    assert registry.providers["openai_compatible"].feature_allowlist == []
    assert registry.providers["openai_compatible"].redaction_mode == "BLOCK_EXTERNAL"


def test_public_provider_dict_never_returns_raw_api_key(monkeypatch):
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_API_KEY", "secret-key-value")

    config = load_provider_registry().providers["openai_compatible"]
    admin_payload = provider_public_dict(config, include_api_key_presence=True)
    viewer_payload = provider_public_dict(config, include_api_key_presence=False)

    assert "api_key" not in admin_payload
    assert "secret-key-value" not in str(admin_payload)
    assert admin_payload["api_key_configured"] is True
    assert viewer_payload["api_key_configured"] is None


def test_openrouter_health_reports_configured_model_and_availability(monkeypatch):
    monkeypatch.setenv("AI_OPENROUTER_ENABLED", "true")
    monkeypatch.setenv("AI_OPENROUTER_MODEL", "openai/gpt-4o-mini")
    monkeypatch.setenv("AI_OPENROUTER_API_KEY", "test-key")

    response = type(
        "Response",
        (),
        {
            "raise_for_status": lambda self: None,
            "json": lambda self: {"data": [{"id": "openai/gpt-4o-mini"}]},
        },
    )()

    with patch("ai_provider_abstraction.requests.get", return_value=response):
        health = build_provider_client(load_provider_registry().providers["openrouter"]).health_check()

    assert health.configured_model == "openai/gpt-4o-mini"
    assert health.reachable is True
    assert health.model_available is True


def test_external_provider_blocked_when_global_flag_is_false(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER_DEFAULT", "openai_compatible")
    monkeypatch.setenv("AI_EXTERNAL_PROVIDERS_ENABLED", "false")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_ENABLED", "true")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_MODEL", "test-model")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_API_KEY", "test-key")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_FEATURE_ALLOWLIST", "incident_triage")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_REDACTION_MODE", "REDACTED_CONTEXT")

    registry = load_provider_registry()
    config = registry.providers["openai_compatible"]

    assert external_block_reason(config=config, feature="incident_triage", registry=registry) == (
        "ExternalProvidersGloballyDisabled"
    )


def test_external_provider_blocked_when_feature_is_not_allowlisted(monkeypatch):
    monkeypatch.setenv("AI_EXTERNAL_PROVIDERS_ENABLED", "true")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_ENABLED", "true")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_MODEL", "test-model")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_API_KEY", "test-key")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_FEATURE_ALLOWLIST", "")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_REDACTION_MODE", "REDACTED_CONTEXT")

    registry = load_provider_registry()
    config = registry.providers["openai_compatible"]

    assert external_block_reason(config=config, feature="incident_triage", registry=registry) == (
        "FeatureNotAllowlisted"
    )


def test_block_external_redaction_mode_blocks_external_call(monkeypatch):
    monkeypatch.setenv("AI_EXTERNAL_PROVIDERS_ENABLED", "true")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_ENABLED", "true")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_MODEL", "test-model")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_API_KEY", "test-key")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_FEATURE_ALLOWLIST", "incident_triage")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_REDACTION_MODE", "BLOCK_EXTERNAL")

    registry = load_provider_registry()
    config = registry.providers["openai_compatible"]

    assert external_block_reason(config=config, feature="incident_triage", registry=registry) == (
        "ExternalRedactionModeBlocksCall"
    )


def test_redaction_masks_common_sensitive_values():
    text = (
        "Bearer abc.def token=secret password=hunter2 admin@example.com "
        "10.0.0.25 host=soc.internal.local /var/log/secure"
    )

    result = redact_text(text)

    assert result.applied is True
    assert "abc.def" not in result.value
    assert "hunter2" not in result.value
    assert "admin@example.com" not in result.value
    assert "10.0.0.25" not in result.value
    assert "/var/log/secure" not in result.value
    assert "<REDACTED_TOKEN>" in result.value
    assert "<REDACTED_EMAIL>" in result.value
    assert "<REDACTED_IP>" in result.value


def test_generate_with_provider_returns_safe_block_without_external_call(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER_DEFAULT", "openai_compatible")
    monkeypatch.setenv("AI_EXTERNAL_PROVIDERS_ENABLED", "false")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_ENABLED", "true")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_BASE_URL", "https://example.invalid/v1")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_MODEL", "test-model")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_API_KEY", "test-key")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_FEATURE_ALLOWLIST", "incident_triage")
    monkeypatch.setenv("AI_OPENAI_COMPATIBLE_REDACTION_MODE", "REDACTED_CONTEXT")

    with patch("ai_provider_policy.record_ai_provider_audit") as audit:
        response = generate_with_provider(
            feature=AiTask.INCIDENT_TRIAGE,
            prompt="raw alert should not leave",
            messages=None,
        )

    assert response.text == ""
    assert response.used_external_provider is True
    assert response.safe_error == "ExternalProvidersGloballyDisabled"
    audit.assert_not_called()
