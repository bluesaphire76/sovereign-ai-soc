from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from schemas.assistant import AssistantQueryRequest
from services.ai_execution.metrics import (
    ASSISTANT_V3_CONTEXT_ITEMS,
    ASSISTANT_V3_STAGE_DURATION,
)
from services.assistant.orchestrator import get_assistant_settings
from services.assistant.v3.authorization import PlatformIncidentAccessPolicy
from services.assistant.v3.contracts import (
    ContextLimits,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_contracts import GroundedAnswerPlanV3
from services.assistant.v3.plan_prompting import build_v3_plan_messages
from tests.assistant_v3_test_support import analytical_package


def test_resource_contracts_reject_values_above_closed_bounds() -> None:
    with pytest.raises(ValidationError):
        ContextLimits(max_candidates_rehydrated=25)
    with pytest.raises(ValidationError):
        ContextLimits(max_operational_atoms=161)
    with pytest.raises(ValidationError):
        AssistantQueryRequest(
            message="compare",
            scope="incident",
            incident_id=1,
            compare_incident_ids=list(range(2, 11)),
        )

    package = analytical_package()
    payload = package.model_dump(mode="json")
    payload["source_registry"] = payload["source_registry"] * 100
    with pytest.raises(ValidationError):
        V3AnalyticalContextPackage.model_validate(payload)

    plan = GroundedAnswerPlanV3.model_json_schema()
    assert plan["additionalProperties"] is False


def test_prompt_budget_fails_closed_before_generation() -> None:
    package = analytical_package().model_copy(update={"question": "x" * 2000})

    with pytest.raises(ValueError, match="prompt budget"):
        build_v3_plan_messages(package, max_context_chars=4000)


def test_timeout_hierarchy_defaults_are_coherent(monkeypatch) -> None:
    monkeypatch.delenv("AI_SOC_ASSISTANT_REQUEST_TIMEOUT_SECONDS", raising=False)
    settings = get_assistant_settings()

    assert settings.semantic_timeout_seconds <= 2
    assert settings.request_timeout_seconds == 45
    assert settings.request_timeout_seconds > 35


def test_cross_incident_access_policy_denies_non_reader_roles() -> None:
    policy = PlatformIncidentAccessPolicy()
    incident = type("IncidentRow", (), {"id": 1})()

    assert policy.can_read_incident(
        incident,
        current_user={"role": "ANALYST"},
    )
    assert not policy.can_read_incident(
        incident,
        current_user={"role": "VIEWER"},
    )


def test_observability_labels_are_closed_and_exclude_record_identifiers() -> None:
    stage_labels = set(ASSISTANT_V3_STAGE_DURATION._labelnames)
    item_labels = set(ASSISTANT_V3_CONTEXT_ITEMS._labelnames)
    forbidden = {"incident_id", "case_id", "user_id", "conversation_id", "host"}

    assert stage_labels == {"stage", "status"}
    assert item_labels == {"item_class"}
    assert not (stage_labels | item_labels) & forbidden


def test_structured_contracts_do_not_expose_free_text_fact_channels() -> None:
    schema = json.dumps(GroundedAnswerPlanV3.model_json_schema()).casefold()

    assert "additionalproperties\": true" not in schema
    assert "factual_prose" not in schema
    assert "reasoning" not in schema
    assert "chain_of_thought" not in schema
