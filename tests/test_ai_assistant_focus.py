from __future__ import annotations

import inspect
from collections import Counter

import pytest

import services.assistant.focus as focus_module
import services.assistant.prompting as prompting_module
from services.assistant.focus import (
    FOCUS_REGISTRY,
    FocusDimension,
    FocusEmbeddingUnavailable,
    FocusSelection,
    SemanticFocusRouter,
    SharedSemanticEmbeddingProvider,
    build_focused_fact_view,
)


class _SemanticFixtureEmbedding:
    def __init__(
        self,
        query_dimensions: dict[str, tuple[FocusDimension, ...]],
        *,
        fail: bool = False,
    ) -> None:
        self.query_dimensions = query_dimensions
        self.fail = fail
        self.calls: list[str] = []
        self._descriptor_dimensions = {
            prototype: descriptor.dimension
            for descriptor in FOCUS_REGISTRY
            for prototype in descriptor.prototype_embedding_texts
        }
        self._positions = {
            dimension: index for index, dimension in enumerate(FocusDimension)
        }
        self._width = len(self._positions) + 1

    def _vector(self, dimensions: tuple[FocusDimension, ...]) -> list[float]:
        vector = [0.0] * self._width
        for dimension in dimensions:
            vector[self._positions[dimension]] = 1.0
        return vector

    def embed(self, text: str) -> list[float]:
        self.calls.append(text)
        if self.fail:
            raise RuntimeError("embedding unavailable")
        descriptor_dimension = self._descriptor_dimensions.get(text)
        if descriptor_dimension is not None:
            return self._vector((descriptor_dimension,))
        if text == "orthogonal semantic request":
            vector = [0.0] * self._width
            vector[-1] = 1.0
            return vector
        return self._vector(self.query_dimensions[text])


class _CalibratedSemanticEmbedding:
    def __init__(
        self,
        question_vectors: dict[str, dict[FocusDimension, float]],
    ) -> None:
        self.question_vectors = question_vectors
        self._descriptor_dimensions = {
            prototype: descriptor.dimension
            for descriptor in FOCUS_REGISTRY
            for prototype in descriptor.prototype_embedding_texts
        }
        self._positions = {
            dimension: index for index, dimension in enumerate(FocusDimension)
        }
        self._width = len(self._positions) + 1

    def embed(self, text: str) -> list[float]:
        descriptor_dimension = self._descriptor_dimensions.get(text)
        if descriptor_dimension is not None:
            vector = [0.0] * self._width
            vector[self._positions[descriptor_dimension]] = 1.0
            return vector

        vector = [0.0] * self._width
        dimensions = self.question_vectors[text]
        for dimension, score in dimensions.items():
            vector[self._positions[dimension]] = score
        squared = sum(value * value for value in vector)
        vector[-1] = max(0.0, 1.0 - squared) ** 0.5
        return vector


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        (
            "Explain the risk and correlation without changing the recorded severity.",
            {
                FocusDimension.RISK,
                FocusDimension.CORRELATION,
                FocusDimension.SEVERITY,
            },
        ),
        (
            "What can you tell me about this incident's risk and how it is correlated?",
            {FocusDimension.RISK, FocusDimension.CORRELATION},
        ),
        (
            "Give me the recorded scoring and correlation information while preserving severity.",
            {
                FocusDimension.RISK,
                FocusDimension.CORRELATION,
                FocusDimension.SEVERITY,
            },
        ),
        (
            "How is this incident scored and what correlation was recorded?",
            {FocusDimension.RISK, FocusDimension.CORRELATION},
        ),
        (
            "Spiegami rischio e correlazione senza alterare la severità registrata.",
            {
                FocusDimension.RISK,
                FocusDimension.CORRELATION,
                FocusDimension.SEVERITY,
            },
        ),
        (
            "Quali sono il rischio e le informazioni di correlazione di questo incidente?",
            {FocusDimension.RISK, FocusDimension.CORRELATION},
        ),
        (
            "Riporta punteggio e correlazione mantenendo distinta la severità.",
            {
                FocusDimension.RISK,
                FocusDimension.CORRELATION,
                FocusDimension.SEVERITY,
            },
        ),
    ],
)
def test_semantic_router_supports_multilingual_paraphrases(
    question,
    expected,
) -> None:
    embedder = _SemanticFixtureEmbedding({question: tuple(expected)})
    selection = SemanticFocusRouter(embedding_provider=embedder).route(question)

    assert set(selection.dimensions) == expected
    assert selection.focus_degraded is False
    assert selection.routing_status == "ok"


@pytest.mark.parametrize(
    ("question", "dimension"),
    [
        ("Describe the recorded scoring for this record.", FocusDimension.RISK),
        ("Describe the relationship among the grouped alerts.", FocusDimension.CORRELATION),
        ("Which canonical classification is recorded?", FocusDimension.SEVERITY),
        ("What operational state is currently stored?", FocusDimension.STATUS),
        ("Which endpoint is associated with the record?", FocusDimension.HOST),
        ("Show the supporting timeline material.", FocusDimension.EVIDENCE),
        ("Which response order is recommended?", FocusDimension.PRIORITY),
        ("Was an escalation state explicitly stored?", FocusDimension.ESCALATION),
    ],
)
def test_semantic_router_supports_single_dimensions(question, dimension) -> None:
    embedder = _SemanticFixtureEmbedding({question: (dimension,)})
    selection = SemanticFocusRouter(embedding_provider=embedder).route(question)

    assert selection.dimensions == (dimension,)


def test_semantic_router_excludes_contextual_near_matches() -> None:
    question = "Report the one requested operational field."
    embedder = _CalibratedSemanticEmbedding(
        {
            question: {
                FocusDimension.STATUS: 0.45,
                FocusDimension.HOST: 0.39,
            }
        }
    )

    selection = SemanticFocusRouter(embedding_provider=embedder).route(question)

    assert selection.dimensions == (FocusDimension.STATUS,)


def test_semantic_router_keeps_only_confident_compound_dimensions() -> None:
    question = "Report the two separately requested operational fields."
    embedder = _CalibratedSemanticEmbedding(
        {
            question: {
                FocusDimension.STATUS: 0.54,
                FocusDimension.SEVERITY: 0.43,
                FocusDimension.RISK: 0.39,
            }
        }
    )

    selection = SemanticFocusRouter(embedding_provider=embedder).route(question)

    assert selection.dimensions == (
        FocusDimension.SEVERITY,
        FocusDimension.STATUS,
    )


def test_semantic_router_uses_general_for_unconfident_broad_requests() -> None:
    question = "Provide a broad operational overview."
    embedder = _CalibratedSemanticEmbedding(
        {
            question: {
                FocusDimension.STATUS: 0.41,
                FocusDimension.HOST: 0.39,
                FocusDimension.EVIDENCE: 0.38,
                FocusDimension.GENERAL: 0.22,
            }
        }
    )

    selection = SemanticFocusRouter(embedding_provider=embedder).route(question)

    assert selection.dimensions == (FocusDimension.GENERAL,)
    assert selection.focus_degraded is False
    assert selection.routing_status == "low_confidence"


def test_semantic_router_is_not_activated_by_incidental_substrings() -> None:
    question = "Archive this status report as evidence of project risk ownership."
    embedder = _SemanticFixtureEmbedding({question: (FocusDimension.GENERAL,)})

    selection = SemanticFocusRouter(embedding_provider=embedder).route(question)

    assert selection.dimensions == (FocusDimension.GENERAL,)
    assert selection.routing_status == "low_confidence"


def test_descriptor_vectors_are_cached_once_and_warm_routing_is_fast() -> None:
    question = "How is the incident scored?"
    embedder = _SemanticFixtureEmbedding({question: (FocusDimension.RISK,)})
    router = SemanticFocusRouter(embedding_provider=embedder)

    assert router.warm() is True
    first = router.route(question)
    second = router.route(question)
    call_counts = Counter(embedder.calls)

    assert first.dimensions == second.dimensions == (FocusDimension.RISK,)
    assert router.descriptor_cache_size == len(FOCUS_REGISTRY)
    assert all(
        call_counts[prototype] == 1
        for descriptor in FOCUS_REGISTRY
        for prototype in descriptor.prototype_embedding_texts
    )
    assert call_counts[question] == 2
    assert second.focus_routing_ms < 100


def test_request_scoped_vector_avoids_second_question_embedding() -> None:
    question = "How is the incident scored?"
    embedder = _SemanticFixtureEmbedding({question: (FocusDimension.RISK,)})
    router = SemanticFocusRouter(embedding_provider=embedder)
    vector = embedder.embed(question)

    selection = router.route(question, request_embedding=vector)

    assert selection.dimensions == (FocusDimension.RISK,)
    assert Counter(embedder.calls)[question] == 1


def test_low_confidence_and_embedding_failure_use_safe_general_focus() -> None:
    low_confidence = SemanticFocusRouter(
        embedding_provider=_SemanticFixtureEmbedding({})
    ).route("orthogonal semantic request")
    unavailable = SemanticFocusRouter(
        embedding_provider=_SemanticFixtureEmbedding({}, fail=True)
    ).route("Any analyst request")

    assert low_confidence.dimensions == (FocusDimension.GENERAL,)
    assert low_confidence.focus_degraded is False
    assert low_confidence.routing_status == "low_confidence"
    assert unavailable.dimensions == (FocusDimension.GENERAL,)
    assert unavailable.focus_degraded is True
    assert unavailable.routing_status == "embedding_unavailable"


def test_shared_provider_never_loads_an_embedding_when_cache_is_cold(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        focus_module,
        "embedding_runtime_snapshot",
        lambda: {
            "embedding_ready": False,
            "embedding_cache_state": "loading",
        },
    )
    monkeypatch.setattr(
        focus_module,
        "get_knowledge_base",
        lambda: (_ for _ in ()).throw(
            AssertionError("knowledge base embed must not run while cold")
        ),
    )

    with pytest.raises(FocusEmbeddingUnavailable):
        SharedSemanticEmbeddingProvider().embed("question")


def test_shared_provider_reuses_the_warmed_knowledge_base_encoder(
    monkeypatch,
) -> None:
    class _WarmKnowledgeBase:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def embed(self, text: str) -> list[float]:
            self.calls.append(text)
            return [0.25, 0.75]

    knowledge_base = _WarmKnowledgeBase()
    monkeypatch.setattr(
        focus_module,
        "embedding_runtime_snapshot",
        lambda: {
            "embedding_ready": True,
            "embedding_cache_state": "warm",
        },
    )
    monkeypatch.setattr(
        focus_module,
        "get_knowledge_base",
        lambda: knowledge_base,
    )

    vector = SharedSemanticEmbeddingProvider().embed("semantic question")

    assert vector == (0.25, 0.75)
    assert knowledge_base.calls == ["semantic question"]


def test_registry_separates_canonical_supporting_and_excluded_fields() -> None:
    descriptors = {
        descriptor.dimension: descriptor for descriptor in FOCUS_REGISTRY
    }

    severity = descriptors[FocusDimension.SEVERITY]
    correlation = descriptors[FocusDimension.CORRELATION]
    assert severity.allowed_fact_fields == ("severity",)
    assert severity.supporting_fact_fields == ("risk_normalization_severity",)
    assert "recommended_priority" in severity.excluded_fact_fields
    assert "correlation_summary" in correlation.excluded_fact_fields
    evidence = descriptors[FocusDimension.EVIDENCE]
    assert {"rule", "wazuh_level"}.isdisjoint(evidence.allowed_fact_fields)
    assert "mitre" in evidence.supporting_fact_fields


def test_detection_rule_question_routes_to_evidence_focus() -> None:
    question = "Quale regola di detection ha prodotto l'incidente corrente?"
    embedder = _SemanticFixtureEmbedding(
        {question: (FocusDimension.EVIDENCE,)}
    )

    selection = SemanticFocusRouter(embedding_provider=embedder).route(question)

    assert selection.dimensions == (FocusDimension.EVIDENCE,)


def test_focused_fact_view_for_test_c_excludes_unrelated_inventory() -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 5299,
        "status": "NEW",
        "severity": None,
        "risk_score": 35,
        "risk_normalization_severity": "LOW",
        "correlated": True,
        "correlation_score": 35,
        "correlation_type": "SINGLE_HOST_PATTERN_CORRELATION",
        "recommended_priority": "LOW",
        "rule": "Registry Key Integrity Checksum Changed",
        "agent": "darkstar-windows",
        "latest_timeline_event": "ALERT_CREATED",
        "correlation_summary": {"event_count": 4},
        "ai_analysis": "Long-form model text",
    }
    focus = FocusSelection(
        dimensions=(
            FocusDimension.RISK,
            FocusDimension.CORRELATION,
            FocusDimension.SEVERITY,
        )
    )

    view = build_focused_fact_view(fact_inventory=facts, focus=focus)

    assert view == {
        "source_type": "incident",
        "incident_id": 5299,
        "risk_score": 35,
        "correlated": True,
        "correlation_type": "SINGLE_HOST_PATTERN_CORRELATION",
        "correlation_score": 35,
        "severity": None,
        "risk_normalization_severity": "LOW",
    }


@pytest.mark.parametrize(
    ("facts", "expected"),
    [
        (
            {
                "source_type": "incident",
                "incident_id": 11,
                "risk_score": 12,
                "severity": "LOW",
                "risk_normalization_severity": "MEDIUM",
            },
            (11, 12, "LOW", "MEDIUM"),
        ),
        (
            {
                "source_type": "incident",
                "incident_id": 22,
                "risk_score": 72,
                "severity": "HIGH",
                "risk_normalization_severity": "LOW",
            },
            (22, 72, "HIGH", "LOW"),
        ),
    ],
)
def test_focused_fact_view_uses_dynamic_inventory_values(facts, expected) -> None:
    view = build_focused_fact_view(
        fact_inventory=facts,
        focus=FocusSelection(
            dimensions=(FocusDimension.RISK, FocusDimension.SEVERITY)
        ),
    )

    assert (
        view["incident_id"],
        view["risk_score"],
        view["severity"],
        view["risk_normalization_severity"],
    ) == expected


def test_general_focus_uses_only_safe_minimal_fact_view() -> None:
    view = build_focused_fact_view(
        fact_inventory={
            "source_type": "incident",
            "incident_id": 31,
            "status": "NEW",
            "severity": "LOW",
            "risk_score": 18,
            "correlated": False,
            "rule": "UNRELATED_RULE",
            "agent": "unrelated-host",
            "correlation_summary": {"events": [1, 2, 3]},
        },
        focus=FocusSelection(dimensions=(FocusDimension.GENERAL,)),
    )

    assert view == {
        "source_type": "incident",
        "incident_id": 31,
        "status": "NEW",
        "severity": "LOW",
        "risk_score": 18,
        "correlated": False,
    }


def test_focus_routing_and_prompting_have_no_lexical_router() -> None:
    focus_source = inspect.getsource(focus_module)
    prompting_source = inspect.getsource(prompting_module)

    for source in (focus_source, prompting_source):
        assert "import re" not in source
        assert "re.compile" not in source
        assert "re.search" not in source
        assert "re.match" not in source
    route_source = inspect.getsource(SemanticFocusRouter.route)
    assert ".lower(" not in route_source
    assert " in question" not in route_source
    assert "analyst_question" not in inspect.signature(
        prompting_module.build_response_contract
    ).parameters
