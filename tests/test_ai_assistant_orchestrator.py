from __future__ import annotations

from types import SimpleNamespace

import pytest

from models import Incident
from schemas.assistant import AssistantQueryRequest
from services.assistant.orchestrator import (
    AssistantError,
    AssistantSettings,
    run_assistant_query,
)
from tests.test_ai_assistant_retrieval import FakeDb, FakeKb, incident


def enabled_settings() -> AssistantSettings:
    return AssistantSettings(enabled=True, max_sources=8, semantic_limit=4, timeout_seconds=60)


def db_factory_with_incident() -> FakeDb:
    return FakeDb({Incident: [incident()]})


def test_disabled_feature_short_circuits_before_retrieval_and_provider() -> None:
    def db_factory():
        raise AssertionError("db should not be opened while disabled")

    def generator(**kwargs):
        raise AssertionError("provider should not be called while disabled")

    with pytest.raises(AssistantError) as exc:
        run_assistant_query(
            AssistantQueryRequest(message="Explain", scope="global"),
            settings=AssistantSettings(enabled=False),
            db_factory=db_factory,
            generator=generator,
        )

    assert exc.value.category == "AssistantDisabled"
    assert exc.value.status_code == 503


def test_successful_grounded_answer_uses_backend_sources_and_strips_unknown_citation() -> None:
    def generator(**kwargs):
        return {
            "text": "This incident has authentication evidence [S1] and imaginary evidence [S99].",
            "provider_key": "local_llama_cpp",
            "provider_type": "LOCAL_LLAMA_CPP",
            "profile": "standard",
            "model": "ai-soc-standard",
            "fallback_used": False,
            "latency_ms": 1200,
            "usage": {"prompt_tokens": 4},
        }

    response = run_assistant_query(
        AssistantQueryRequest(message="Explain", scope="incident", incident_id=245, include_semantic_memory=False),
        settings=enabled_settings(),
        db_factory=db_factory_with_incident,
        generator=generator,
    )

    assert response.status == "success"
    assert [source.source_id for source in response.sources] == ["S1"]
    assert "[S99]" not in response.answer
    assert any("Unsupported model citation" in item for item in response.limitations)
    assert response.metadata.provider_key == "local_llama_cpp"
    assert response.metadata.usage == {"prompt_tokens": 4}


def test_provider_timeout_returns_safe_fallback() -> None:
    def generator(**kwargs):
        return {
            "text": "",
            "safe_error": "Timeout",
            "profile": "standard",
            "model": "ai-soc-standard",
            "latency_ms": 60,
        }

    response = run_assistant_query(
        AssistantQueryRequest(message="Explain", scope="incident", incident_id=245, include_semantic_memory=False),
        settings=enabled_settings(),
        db_factory=db_factory_with_incident,
        generator=generator,
    )

    assert response.status == "fallback"
    assert "GenerationTimeout" in response.limitations
    assert "No operational action" in response.answer


def test_provider_error_returns_safe_fallback() -> None:
    def generator(**kwargs):
        return {"text": "", "safe_error": "ConnectionError"}

    response = run_assistant_query(
        AssistantQueryRequest(message="Explain", scope="incident", incident_id=245, include_semantic_memory=False),
        settings=enabled_settings(),
        db_factory=db_factory_with_incident,
        generator=generator,
    )

    assert response.status == "fallback"
    assert "ProviderUnavailable" in response.limitations


def test_no_context_global_query_returns_safe_response_without_provider_call() -> None:
    calls = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {"text": "should not run"}

    response = run_assistant_query(
        AssistantQueryRequest(message="Explain", scope="global", include_semantic_memory=False),
        settings=enabled_settings(),
        db_factory=lambda: FakeDb({}),
        generator=generator,
    )

    assert response.status == "fallback"
    assert response.sources == []
    assert "NoGroundingContext" in response.limitations
    assert calls == []


def test_qdrant_failure_does_not_block_exact_incident_generation() -> None:
    kb = FakeKb(error=RuntimeError("qdrant unavailable"))
    calls = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {"text": "Use exact incident facts [S1]."}

    response = run_assistant_query(
        AssistantQueryRequest(message="Explain", scope="incident", incident_id=245),
        settings=enabled_settings(),
        db_factory=db_factory_with_incident,
        knowledge_base_factory=lambda: kb,
        generator=generator,
    )

    assert response.status == "success"
    assert calls
    assert any("Semantic memory retrieval failed safely" in item for item in response.limitations)


def test_quality_mode_is_user_triggered_and_passed_to_provider_path() -> None:
    captured = {}

    def generator(**kwargs):
        captured.update(kwargs)
        return {"text": "Quality answer [S1]."}

    run_assistant_query(
        AssistantQueryRequest(
            message="Explain deeply",
            scope="incident",
            incident_id=245,
            requested_mode="quality",
            include_semantic_memory=False,
        ),
        settings=enabled_settings(),
        db_factory=db_factory_with_incident,
        generator=generator,
        current_user={"role": "ANALYST", "username": "ana"},
    )

    assert captured["task"].value == "soc_assistant"
    assert captured["requested_mode"] == "quality"
    assert captured["user_triggered"] is True
    assert captured["current_user"]["role"] == "ANALYST"
    assert captured["context"]["incident_id"] == 245
