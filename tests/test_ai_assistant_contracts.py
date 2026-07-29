from __future__ import annotations

import pytest
from pydantic import ValidationError

from ai_data_control_policy import (
    POLICY_LOCAL_ONLY,
    default_feature_policies,
    normalize_feature_key,
    policy_capabilities,
)
from ai_model_policy import AiTask, select_profile
from ai_provider_policy import normalize_feature, provider_capabilities
from ai_provider_registry import load_provider_registry
from llama_cpp_profiles import select_llama_cpp_profile
from schemas.assistant import AssistantQueryRequest
from security.rbac import is_request_authorized


@pytest.fixture(autouse=True)
def isolated_ai_config(monkeypatch, tmp_path):
    monkeypatch.setenv("AI_PROVIDER_CONFIG_PATH", str(tmp_path / "ai_providers.json"))
    monkeypatch.setenv("AI_DATA_POLICY_CONFIG_PATH", str(tmp_path / "ai_data_control_policy.json"))
    monkeypatch.setenv("AI_DATA_POLICY_DEFAULT_MODE", "LOCAL_ONLY")
    monkeypatch.delenv("AI_PROVIDER_DEFAULT", raising=False)
    monkeypatch.delenv("AI_LLM_PROVIDER", raising=False)


def test_valid_global_incident_and_case_requests() -> None:
    assert AssistantQueryRequest(message="  hello  ", scope="global").message == "hello"
    assert AssistantQueryRequest(message="Explain", scope="incident", incident_id=245).incident_id == 245
    assert AssistantQueryRequest(message="Explain", scope="case", case_id=12).case_id == 12


@pytest.mark.parametrize(
    "payload",
    [
        {"message": "   ", "scope": "global"},
        {"message": "x" * 2001, "scope": "global"},
        {"message": "x", "scope": "workspace"},
        {"message": "x", "scope": "global", "requested_mode": "fast"},
        {"message": "x", "scope": "incident"},
        {"message": "x", "scope": "incident", "incident_id": 1, "case_id": 2},
        {"message": "x", "scope": "case"},
        {"message": "x", "scope": "case", "case_id": 2, "incident_id": 1},
        {"message": "x", "scope": "global", "incident_id": 1},
        {"message": "x", "scope": "incident", "incident_id": 0},
        {"message": "x", "scope": "global", "unknown": "field"},
    ],
)
def test_invalid_request_contracts_are_rejected(payload: dict) -> None:
    with pytest.raises(ValidationError):
        AssistantQueryRequest(**payload)


def test_assistant_rbac_rules_are_explicit_and_secure_by_default() -> None:
    for role in ("ADMIN", "ANALYST"):
        assert is_request_authorized("GET", "/assistant/capabilities", {"role": role})
        assert is_request_authorized("POST", "/assistant/query", {"role": role})

    assert not is_request_authorized("GET", "/assistant/capabilities", {"role": "VIEWER"})
    assert not is_request_authorized("POST", "/assistant/query", {"role": "VIEWER"})
    assert not is_request_authorized("GET", "/assistant/debug", {"role": "ADMIN"})


def test_soc_assistant_ai_task_feature_and_profile_policy() -> None:
    assert AiTask.SOC_ASSISTANT.value == "soc_assistant"
    assert normalize_feature(AiTask.SOC_ASSISTANT) == "soc_assistant"
    assert normalize_feature_key("assistant") == "soc_assistant"
    assert select_profile(AiTask.SOC_ASSISTANT, requested_mode="auto", user_triggered=True) == "standard"
    assert select_profile(AiTask.SOC_ASSISTANT, requested_mode="standard", user_triggered=True) == "standard"
    assert select_profile(AiTask.SOC_ASSISTANT, requested_mode="quality", user_triggered=True) == "quality"
    assert select_profile(AiTask.SOC_ASSISTANT, requested_mode="quality", user_triggered=False) == "standard"
    assert select_llama_cpp_profile(
        task=AiTask.SOC_ASSISTANT,
        requested_mode="auto",
        user_triggered=True,
    ) == "standard"


def test_soc_assistant_data_control_and_provider_capabilities() -> None:
    policies = default_feature_policies()
    policy = policies["soc_assistant"]

    assert policy.mode == POLICY_LOCAL_ONLY
    assert policy.allowed_roles == ["ADMIN", "ANALYST"]
    assert "VIEWER" not in policy.allowed_roles
    assert policy.allow_raw_telemetry is False
    assert policy.allow_personal_data is False
    assert "soc_assistant" in provider_capabilities()["feature_keys"]
    assert any(item["feature_key"] == "soc_assistant" for item in policy_capabilities()["features"])
    assert "soc_assistant" in load_provider_registry().providers["local_ollama"].feature_allowlist


def test_existing_feature_mapping_remains_unchanged() -> None:
    assert normalize_feature(AiTask.INCIDENT_TRIAGE) == "incident_triage"
    assert normalize_feature(AiTask.CASE_ANALYSIS) == "case_ai_analysis"
    assert normalize_feature(AiTask.REMEDIATION) == "remediation_explanation"
