from __future__ import annotations

from dataclasses import replace

import pytest

from ai_data_control_policy import (
    POLICY_FULL_CONTEXT_ADMIN_ONLY,
    POLICY_METADATA_ONLY,
    POLICY_REDACTED_CONTEXT,
    default_feature_policies,
    enforce_ai_data_policy,
    load_policy_config,
    redact_value,
    save_policy_config,
    update_feature_policy,
)
from ai_provider_registry import load_provider_registry


def _isolated_policy_config(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_DATA_POLICY_CONFIG_PATH", str(tmp_path / "ai_data_policy.json"))
    monkeypatch.setenv("AI_PROVIDER_CONFIG_PATH", str(tmp_path / "ai_providers.json"))
    monkeypatch.setenv("AI_EXTERNAL_PROVIDERS_ENABLED", "false")
    monkeypatch.delenv("AI_OPENROUTER_API_KEY", raising=False)


def test_default_policy_allows_local_and_denies_external_by_default(monkeypatch, tmp_path):
    _isolated_policy_config(monkeypatch, tmp_path)
    registry = load_provider_registry()

    local_decision = enforce_ai_data_policy(
        feature_key="incident_triage",
        provider_config=registry.providers["local_ollama"],
        registry=registry,
        prompt="password=hunter2",
        messages=None,
        context=None,
        current_user={"role": "ANALYST", "username": "ana"},
        audit=False,
    )

    external_decision = enforce_ai_data_policy(
        feature_key="incident_triage",
        provider_config=registry.providers["openrouter"],
        registry=registry,
        prompt="raw alert",
        messages=None,
        context=None,
        current_user={"role": "ADMIN", "username": "admin"},
        audit=False,
    )

    assert local_decision.allowed is True
    assert "[REDACTED_SECRET]" in str(local_decision.transformed_prompt)
    assert "hunter2" not in str(local_decision.transformed_prompt)
    assert external_decision.allowed is False
    assert external_decision.reason == "ExternalProvidersGloballyDisabled"


def test_redacted_context_masks_soc_sensitive_values(monkeypatch, tmp_path):
    _isolated_policy_config(monkeypatch, tmp_path)
    monkeypatch.setenv("AI_EXTERNAL_PROVIDERS_ENABLED", "true")
    monkeypatch.setenv("AI_OPENROUTER_ENABLED", "true")
    monkeypatch.setenv("AI_OPENROUTER_MODEL", "openrouter/test")
    monkeypatch.setenv("AI_OPENROUTER_API_KEY", "secret-key")
    monkeypatch.setenv("AI_OPENROUTER_FEATURE_ALLOWLIST", "incident_triage")
    monkeypatch.setenv("AI_OPENROUTER_REDACTION_MODE", "REDACTED_CONTEXT")

    defaults, _ = load_policy_config()
    policies = default_feature_policies()
    policies["incident_triage"] = replace(
        policies["incident_triage"],
        mode=POLICY_REDACTED_CONTEXT,
        allowed_provider_keys=["openrouter"],
        allowed_roles=["ADMIN"],
    )
    save_policy_config(defaults, policies)
    registry = load_provider_registry()

    decision = enforce_ai_data_policy(
        feature_key="incident_triage",
        provider_config=registry.providers["openrouter"],
        registry=registry,
        prompt="source 10.0.0.5 user analyst@example.com host app.internal.local token=abc123",
        messages=None,
        context={
            "source_ip": "10.0.0.5",
            "username": "analyst@example.com",
            "hostname": "app.internal.local",
            "raw_alert": {"password": "hunter2"},
        },
        current_user={"role": "ADMIN", "username": "admin"},
        audit=False,
    )

    combined = str(decision.transformed_prompt) + str(decision.transformed_context)
    assert decision.allowed is True
    assert decision.redaction_applied is True
    assert "10.0.0.5" not in combined
    assert "analyst@example.com" not in combined
    assert "hunter2" not in combined
    assert "[REDACTED_IP]" in combined
    assert "[REDACTED_PERSONAL_DATA]" in combined
    assert "[REDACTED_RAW_TELEMETRY]" in combined


def test_metadata_only_does_not_send_raw_prompt(monkeypatch, tmp_path):
    _isolated_policy_config(monkeypatch, tmp_path)
    monkeypatch.setenv("AI_EXTERNAL_PROVIDERS_ENABLED", "true")
    monkeypatch.setenv("AI_OPENROUTER_ENABLED", "true")
    monkeypatch.setenv("AI_OPENROUTER_MODEL", "openrouter/test")
    monkeypatch.setenv("AI_OPENROUTER_API_KEY", "secret-key")
    monkeypatch.setenv("AI_OPENROUTER_FEATURE_ALLOWLIST", "case_ai_analysis")
    monkeypatch.setenv("AI_OPENROUTER_REDACTION_MODE", "METADATA_ONLY")

    defaults, _ = load_policy_config()
    policies = default_feature_policies()
    policies["case_ai_analysis"] = replace(
        policies["case_ai_analysis"],
        mode=POLICY_METADATA_ONLY,
        allowed_provider_keys=["openrouter"],
        allowed_roles=["ADMIN"],
    )
    save_policy_config(defaults, policies)
    registry = load_provider_registry()

    decision = enforce_ai_data_policy(
        feature_key="case_ai_analysis",
        provider_config=registry.providers["openrouter"],
        registry=registry,
        prompt="raw credential token=super-secret should not leave",
        messages=None,
        context={"raw_event": "payload"},
        current_user={"role": "ADMIN", "username": "admin"},
        audit=False,
    )

    assert decision.allowed is True
    assert "super-secret" not in str(decision.transformed_prompt)
    assert "Metadata-only AI request" in str(decision.transformed_context)


def test_full_context_external_requires_admin(monkeypatch, tmp_path):
    _isolated_policy_config(monkeypatch, tmp_path)
    monkeypatch.setenv("AI_EXTERNAL_PROVIDERS_ENABLED", "true")
    monkeypatch.setenv("AI_OPENROUTER_ENABLED", "true")
    monkeypatch.setenv("AI_OPENROUTER_MODEL", "openrouter/test")
    monkeypatch.setenv("AI_OPENROUTER_API_KEY", "secret-key")
    monkeypatch.setenv("AI_OPENROUTER_FEATURE_ALLOWLIST", "report_generation")
    monkeypatch.setenv("AI_OPENROUTER_REDACTION_MODE", "REDACTED_CONTEXT")

    defaults, _ = load_policy_config()
    policies = default_feature_policies()
    policies["report_generation"] = replace(
        policies["report_generation"],
        mode=POLICY_FULL_CONTEXT_ADMIN_ONLY,
        allowed_provider_keys=["openrouter"],
        allowed_roles=["ADMIN"],
    )
    save_policy_config(defaults, policies)
    registry = load_provider_registry()

    decision = enforce_ai_data_policy(
        feature_key="report_generation",
        provider_config=registry.providers["openrouter"],
        registry=registry,
        prompt="full context",
        messages=None,
        context={},
        current_user={"role": "ANALYST", "username": "ana"},
        audit=False,
    )

    assert decision.allowed is False
    assert decision.reason == "RoleNotAllowedByPolicy"


def test_policy_update_requires_reason(monkeypatch, tmp_path):
    _isolated_policy_config(monkeypatch, tmp_path)

    with pytest.raises(ValueError):
        update_feature_policy(
            feature_key="incident_triage",
            updates={"mode": POLICY_REDACTED_CONTEXT},
            reason="",
            current_user={"role": "ADMIN", "username": "admin"},
        )


def test_redaction_tokens_are_deterministic():
    result = redact_value(
        {
            "api_key": "secret",
            "source_ip": "192.168.1.10",
            "hostname": "endpoint.internal.local",
            "email": "user@example.com",
            "raw_event": {"payload": "Bearer abc"},
        },
        external_sensitive=True,
    )

    assert result.transformed_value["api_key"] == "[REDACTED_SECRET]"
    assert result.transformed_value["source_ip"] == "[REDACTED_IP]"
    assert result.transformed_value["hostname"] == "[REDACTED_HOST]"
    assert result.transformed_value["email"] == "[REDACTED_PERSONAL_DATA]"
    assert result.transformed_value["raw_event"] == "[REDACTED_RAW_TELEMETRY]"
