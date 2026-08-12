from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from schemas.assistant import AssistantQueryRequest
from services.assistant.focus import (
    FocusDimension,
    FocusSelection,
)
from services.assistant.orchestrator import AssistantSettings, run_assistant_query
from services.assistant.retrieval import RetrievalResult
from services.assistant.sources import SourceRecord
from services.assistant.v3.contracts import AnswerIntent
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    AnswerAudience,
    AnswerDetailLevel,
    AnswerSection,
    AnswerSectionType,
    DiscourseOrdering,
    GroundedAnswerPlanV3,
)
from services.assistant.v3.plan_fallback import deterministic_answer_plan_v3
from tests.assistant_v3_test_support import analytical_package


class _Db:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _Router:
    def __init__(self, value: Any) -> None:
        self.value = value

    def route(self, _message: str) -> Any:
        return self.value


class _RequestEmbeddingRouter(_Router):
    def __init__(self, value: Any) -> None:
        super().__init__(value)
        self.request_embeddings: list[Any] = []

    def route(self, _message: str, *, request_embedding=None) -> Any:
        self.request_embeddings.append(request_embedding)
        return self.value


class _Builder:
    def __init__(self, package) -> None:
        self.package = package

    def build(self, **_kwargs):
        return self.package


def _settings(**overrides: Any) -> AssistantSettings:
    values = {
        "enabled": True,
        "response_architecture": "v3",
        "max_context_chars": 16_000,
        "max_sources": 8,
        "request_timeout_seconds": 30,
        "v3_max_output_tokens": 1_536,
    }
    values.update(overrides)
    return AssistantSettings(**values)


def _retrieval() -> RetrievalResult:
    return RetrievalResult(
        scope="incident",
        incident_id=1,
        fact_inventory={
            "source_type": "incident",
            "incident_id": 1,
            "status": "OPEN",
            "severity": None,
            "agent": "endpoint-a",
            "rule": "Registry changed",
            "risk_score": 72,
            "correlated": True,
            "correlation_type": "endpoint_pattern",
        },
        sources=[
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id="1",
                label="Incident 1",
                excerpt="Incident 1 authoritative record.",
                url="/incidents/1",
            )
        ],
    )


def _run(monkeypatch, generator, *, package=None, settings=None):
    selected_package = package or analytical_package()
    retrieval = _retrieval()
    monkeypatch.setattr(
        "services.assistant.orchestrator.retrieve_assistant_context",
        lambda *args, **kwargs: retrieval,
    )
    db = _Db()
    response = run_assistant_query(
        AssistantQueryRequest(
            message="Find related incidents and explain why.",
            scope="incident",
            incident_id=1,
            include_semantic_memory=False,
        ),
        settings=settings or _settings(),
        db_factory=lambda: db,
        generator=generator,
        focus_router=_Router(
            FocusSelection(
                dimensions=(FocusDimension.GENERAL,),
                confidence=1,
            )
        ),
        intent_router=_Router(selected_package.intent_selection),
        v3_context_builder=_Builder(selected_package),
    )
    assert db.closed is True
    return response


def test_v3_success_uses_one_generation_and_exact_plan_refs(monkeypatch) -> None:
    package = analytical_package()
    plan = deterministic_answer_plan_v3(package)
    calls = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {
            "structured_output": plan.model_dump(mode="json"),
            "finish_reason": "stop",
            "generation_ms": 123,
            "queue_wait_ms": 4,
        }

    response = _run(monkeypatch, generator, package=package)

    assert len(calls) == 1
    assert calls[0]["output_schema"] == "assistant_grounded_v3"
    assert calls[0]["max_visible_tokens"] == 1_536
    assert "relationship:shared-host" in str(calls[0]["structured_output_schema"])
    assert response.status == "ok"
    assert response.generation_kind == "model"
    assert response.metadata.response_architecture == "v3"
    assert response.metadata.provider_generation_count == 1
    assert response.metadata.plan_validation_status == "passed"
    assert response.metadata.plan_sections == len(plan.sections)
    assert response.metadata.plan_units == len(plan.analytical_units)
    assert response.metadata.automatic_retries == 0
    assert response.metadata.model_switches == 0
    assert response.metadata.intent_routing_ms >= 0
    assert response.metadata.focus_routing_ms >= 0
    assert response.metadata.scope_resolution_ms >= 0
    assert response.metadata.operational_retrieval_ms >= 0
    assert response.metadata.semantic_candidate_ms >= 0
    assert response.metadata.schema_chars > 0
    assert any(block.kind == "related_incidents" for block in response.blocks)
    assert any(
        "analytical_relationship" in block.provenance_classes
        for block in response.blocks
    )
    assert all(source.provenance_class for source in response.sources)
    assert all(
        source_id in {source.source_id for source in response.sources}
        for block in response.blocks
        for source_id in block.source_ids
    )


def test_default_routers_reuse_one_request_embedding(monkeypatch) -> None:
    package = analytical_package()
    retrieval = _retrieval()
    vector = (0.25, 0.75)

    class _EmbeddingProvider:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def embed(self, text: str):
            self.calls.append(text)
            return vector

    provider = _EmbeddingProvider()
    intent_router = _RequestEmbeddingRouter(package.intent_selection)
    focus_router = _RequestEmbeddingRouter(
        FocusSelection(dimensions=(FocusDimension.GENERAL,), confidence=1)
    )
    monkeypatch.setattr(
        "services.assistant.orchestrator.retrieve_assistant_context",
        lambda *args, **kwargs: retrieval,
    )
    monkeypatch.setattr(
        "services.assistant.orchestrator.get_shared_semantic_embedding_provider",
        lambda: provider,
    )
    monkeypatch.setattr(
        "services.assistant.orchestrator.get_semantic_intent_router",
        lambda: intent_router,
    )
    monkeypatch.setattr(
        "services.assistant.orchestrator.get_semantic_focus_router",
        lambda: focus_router,
    )

    response = run_assistant_query(
        AssistantQueryRequest(
            message="Find related incidents and explain why.",
            scope="incident",
            incident_id=1,
            include_semantic_memory=False,
        ),
        settings=_settings(),
        db_factory=_Db,
        generator=lambda **_kwargs: {
            "structured_output": deterministic_answer_plan_v3(package).model_dump(
                mode="json"
            )
        },
        v3_context_builder=_Builder(package),
    )

    assert response.generation_kind == "model"
    assert len(provider.calls) == 1
    assert intent_router.request_embeddings == [vector]
    assert focus_router.request_embeddings == [vector]


@pytest.mark.parametrize(
    ("structured_output", "reason"),
    [
        ({"answer_intent": "CROSS_INCIDENT_ANALYSIS"}, "v3_invalid_structured_output"),
        (
            GroundedAnswerPlanV3(
                answer_intent=AnswerIntent.CROSS_INCIDENT_ANALYSIS,
                detail_level=AnswerDetailLevel.STANDARD,
                audience=AnswerAudience.SOC_ANALYST,
                ordering=DiscourseOrdering.CONCLUSION_FIRST,
                sections=[
                    AnswerSection(
                        section_type=AnswerSectionType.DIRECT_ANSWER,
                        units=[
                            AnalyticalUnit(
                                unit_type=AnalyticalUnitType.RECORDED_FACT,
                                fact_refs=["incident:missing:status"],
                            )
                        ],
                    )
                ],
            ).model_dump(mode="json"),
            "v3_plan_validation_failed",
        ),
    ],
)
def test_v3_invalid_output_fails_closed_without_retry(
    monkeypatch,
    structured_output,
    reason,
) -> None:
    calls = 0

    def generator(**_kwargs):
        nonlocal calls
        calls += 1
        return {"structured_output": structured_output, "finish_reason": "stop"}

    response = _run(monkeypatch, generator)

    assert calls == 1
    assert response.status == "fallback"
    assert response.metadata.fallback_reason == reason
    assert response.metadata.provider_generation_count == 1
    assert response.metadata.automatic_retries == 0
    assert response.answer


def test_v3_context_failure_skips_provider_and_uses_safe_fallback(monkeypatch) -> None:
    calls = 0

    class _FailingBuilder:
        def build(self, **_kwargs):
            raise ValueError("context unavailable")

    def generator(**_kwargs):
        nonlocal calls
        calls += 1
        return {}

    retrieval = _retrieval()
    retrieval.sources.append(
        SourceRecord(
            source_type="historical_incident",
            authority="advisory",
            record_id="2",
            label="Historical incident 2",
            excerpt="Semantic candidate that did not pass V3 authorization.",
            url="/incidents/2",
        )
    )
    monkeypatch.setattr(
        "services.assistant.orchestrator.retrieve_assistant_context",
        lambda *args, **kwargs: retrieval,
    )
    response = run_assistant_query(
        AssistantQueryRequest(
            message="Explain this incident.",
            scope="incident",
            incident_id=1,
            include_semantic_memory=False,
        ),
        settings=_settings(),
        db_factory=_Db,
        generator=generator,
        focus_router=_Router(
            FocusSelection(dimensions=(FocusDimension.GENERAL,))
        ),
        intent_router=_Router(
            analytical_package(AnswerIntent.EXPLAIN).intent_selection
        ),
        v3_context_builder=_FailingBuilder(),
    )

    assert calls == 0
    assert response.metadata.fallback_reason == "v3_context_build_failed"
    assert response.metadata.provider_generation_count == 0
    assert [(source.source_type, source.record_id) for source in response.sources] == [
        ("incident", "1")
    ]


def test_v3_case_context_failure_does_not_expose_linked_incident_data(monkeypatch) -> None:
    class _FailingBuilder:
        def build(self, **_kwargs):
            raise ValueError("context unavailable")

    retrieval = RetrievalResult(
        scope="case",
        case_id=7,
        fact_inventory={
            "source_type": "case",
            "case_id": 7,
            "status": "OPEN",
            "linked_incident_count": 1,
            "linked_incidents": [
                {"incident_id": 99, "rule": "UNAUTHORIZED_MARKER"}
            ],
        },
        sources=[
            SourceRecord(
                source_type="case",
                authority="authoritative",
                record_id="7",
                label="Case 7",
                excerpt="Authoritative case record.",
                url="/cases/7",
            ),
            SourceRecord(
                source_type="case_linked_incidents",
                authority="authoritative",
                record_id="7",
                label="UNAUTHORIZED_MARKER",
                excerpt="UNAUTHORIZED_MARKER",
                url="/cases/7/incidents",
            ),
        ],
    )
    monkeypatch.setattr(
        "services.assistant.orchestrator.retrieve_assistant_context",
        lambda *args, **kwargs: retrieval,
    )
    response = run_assistant_query(
        AssistantQueryRequest(
            message="Explain this case.",
            scope="case",
            case_id=7,
            include_semantic_memory=False,
        ),
        settings=_settings(),
        db_factory=_Db,
        generator=lambda **_kwargs: pytest.fail("provider must not be called"),
        focus_router=_Router(FocusSelection(dimensions=(FocusDimension.GENERAL,))),
        intent_router=_Router(
            analytical_package(AnswerIntent.EXPLAIN).intent_selection
        ),
        v3_context_builder=_FailingBuilder(),
    )

    assert response.metadata.fallback_reason == "v3_context_build_failed"
    assert [(source.source_type, source.record_id) for source in response.sources] == [
        ("case", "7")
    ]
    assert "UNAUTHORIZED_MARKER" not in response.answer


def test_v3_schema_failure_skips_provider(monkeypatch) -> None:
    package = analytical_package().model_copy(update={"question": "x" * 20_000})
    calls = 0

    def generator(**_kwargs):
        nonlocal calls
        calls += 1
        return {}

    response = _run(monkeypatch, generator, package=package)

    assert calls == 0
    assert response.metadata.fallback_reason == "v3_schema_build_failed"
    assert response.metadata.provider_generation_count == 0


def test_v3_renderer_failure_never_generates_again(monkeypatch) -> None:
    calls = 0

    def generator(**_kwargs):
        nonlocal calls
        calls += 1
        package = analytical_package()
        return {
            "structured_output": deterministic_answer_plan_v3(package).model_dump(
                mode="json"
            )
        }

    monkeypatch.setattr(
        "services.assistant.orchestrator.RichGroundedDiscourseRenderer.render",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("render failed")),
    )
    response = _run(monkeypatch, generator)

    assert calls == 1
    assert response.metadata.fallback_reason == "v3_renderer_failed"
    assert response.metadata.provider_generation_count == 1
    assert response.generation_kind == "deterministic_fallback"


def test_v2_rollout_path_remains_available(monkeypatch) -> None:
    calls = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {
            "structured_output": {
                "claims": [
                    {
                        "claim_type": "RECORDED_FACT",
                        "field": "status",
                        "value": "OPEN",
                        "provenance": "recorded_operational",
                        "source_ids": ["S1"],
                    }
                ],
                "next_check": None,
                "limitations": [],
                "used_advisory_context": False,
            }
        }

    response = _run(
        monkeypatch,
        generator,
        settings=replace(_settings(), response_architecture="v2"),
    )

    assert len(calls) == 1
    assert calls[0]["output_schema"] == "assistant_grounded_v2"
    assert response.metadata.response_architecture == "v2"
    assert response.metadata.provider_generation_count == 1
