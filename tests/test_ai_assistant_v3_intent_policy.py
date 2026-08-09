from __future__ import annotations

import inspect

import pytest
from pydantic import ValidationError

from services.assistant.focus import FocusDimension, FocusSelection, normalize_embedding_text
from services.assistant.v3.contracts import (
    AnalysisScope,
    AnswerIntent,
    AuthorityClass,
    ContextRequirement,
    IntentSelection,
    Provenance,
    StatusAtom,
)
from services.assistant.v3.intent import (
    INTENT_REGISTRY,
    IntentRoutingConfig,
    SemanticIntentRouter,
)
from services.assistant.v3.policy import ContextPolicyEngine, resolve_analysis_scope


class RegistryVectorProvider:
    def __init__(self, question_intents: dict[str, tuple[AnswerIntent, ...]]) -> None:
        self.calls: list[str] = []
        self._descriptor_vectors = {
            normalize_embedding_text(item.embedding_text): self._vector((item.intent,))
            for item in INTENT_REGISTRY
        }
        self._question_vectors = {
            normalize_embedding_text(question): self._vector(intents)
            for question, intents in question_intents.items()
        }

    @staticmethod
    def _vector(intents: tuple[AnswerIntent, ...]) -> tuple[float, ...]:
        selected = set(intents)
        return tuple(1.0 if item.intent in selected else 0.0 for item in INTENT_REGISTRY) + (
            0.0,
        )

    def embed(self, text: str) -> tuple[float, ...]:
        normalized = normalize_embedding_text(text)
        self.calls.append(normalized)
        if normalized in self._descriptor_vectors:
            return self._descriptor_vectors[normalized]
        return self._question_vectors.get(normalized, (0.0,) * 10 + (1.0,))


SEMANTIC_CASES = (
    ("Which state is currently recorded?", AnswerIntent.FACT_LOOKUP),
    ("Quale valore di stato risulta nel sistema?", AnswerIntent.FACT_LOOKUP),
    ("Walk me through what this detection means.", AnswerIntent.EXPLAIN),
    ("Aiutami a capire il significato del record.", AnswerIntent.EXPLAIN),
    ("Give me a concise operational recap.", AnswerIntent.SUMMARY),
    ("Fammi un riepilogo dei dati operativi.", AnswerIntent.SUMMARY),
    ("Analyze the evidence and reconstruct what happened.", AnswerIntent.INVESTIGATE),
    ("Ricostruisci l'accaduto usando le evidenze.", AnswerIntent.INVESTIGATE),
    ("Contrast the selected security records.", AnswerIntent.COMPARE),
    ("Metti a confronto i due incidenti selezionati.", AnswerIntent.COMPARE),
    ("Look beyond this alert for possible incident connections.", AnswerIntent.CROSS_INCIDENT_ANALYSIS),
    ("Verifica possibili relazioni con altri incidenti.", AnswerIntent.CROSS_INCIDENT_ANALYSIS),
    ("Identify repeated behavior across the incident set.", AnswerIntent.PATTERN_ANALYSIS),
    ("Trova comportamenti ricorrenti nell'insieme.", AnswerIntent.PATTERN_ANALYSIS),
    ("Name the next verification steps for the analyst.", AnswerIntent.NEXT_ACTION),
    ("Indica i prossimi controlli per l'analista.", AnswerIntent.NEXT_ACTION),
    ("Prepare the factual context for the next shift.", AnswerIntent.HANDOVER),
    ("Prepara il contesto per il turno successivo.", AnswerIntent.HANDOVER),
    ("Summarize the operational situation for leadership.", AnswerIntent.EXECUTIVE_SUMMARY),
    ("Crea una sintesi operativa per la direzione.", AnswerIntent.EXECUTIVE_SUMMARY),
)


@pytest.mark.parametrize(("question", "expected"), SEMANTIC_CASES)
def test_semantic_intent_pack_routes_en_it_paraphrases(question, expected) -> None:
    provider = RegistryVectorProvider({question: (expected,)})
    result = SemanticIntentRouter(embedding_provider=provider).route(question)

    assert result.primary_intent is expected
    assert result.routing_status == "ok"
    assert result.degraded is False


def test_intent_descriptors_are_cached_and_multi_intent_is_bounded() -> None:
    question = "Analyze the evidence and tell me what to verify next."
    provider = RegistryVectorProvider(
        {question: (AnswerIntent.INVESTIGATE, AnswerIntent.NEXT_ACTION)}
    )
    router = SemanticIntentRouter(
        embedding_provider=provider,
        config=IntentRoutingConfig(secondary_intent_margin=0.01),
    )

    first = router.route(question)
    second = router.route(question)

    assert first.primary_intent in {AnswerIntent.INVESTIGATE, AnswerIntent.NEXT_ACTION}
    assert len(first.secondary_intents) == 1
    assert router.descriptor_cache_size == len(INTENT_REGISTRY)
    assert len(provider.calls) == len(INTENT_REGISTRY) + 2
    assert second.primary_intent == first.primary_intent


def test_low_confidence_and_embedding_failure_choose_neutral_summary() -> None:
    low = SemanticIntentRouter(
        embedding_provider=RegistryVectorProvider({}),
    ).route("Unmapped ambiguous request")

    class FailingProvider:
        def embed(self, text: str):
            raise RuntimeError("not ready")

    failed = SemanticIntentRouter(embedding_provider=FailingProvider()).route("Anything")

    assert low.primary_intent is AnswerIntent.SUMMARY
    assert low.routing_status == "low_confidence"
    assert failed.primary_intent is AnswerIntent.SUMMARY
    assert failed.degraded is True


def _selection(intent: AnswerIntent) -> IntentSelection:
    return IntentSelection(
        primary_intent=intent,
        confidence=1.0,
        routing_status="ok",
        routing_ms=0.0,
    )


def _focus(*values: FocusDimension) -> FocusSelection:
    return FocusSelection(dimensions=values, confidence=1.0)


FACTS = {
    "source_type": "incident",
    "incident_id": 10,
    "status": "OPEN",
    "severity": None,
    "agent": "endpoint-1",
    "rule": "Registry changed",
    "wazuh_level": 10,
    "risk_score": 70,
    "risk_normalization_severity": "HIGH",
    "recommended_priority": "HIGH",
    "correlated": True,
    "correlation_type": "host_pattern",
    "correlation_score": 80,
    "mitre": [{"id": "T1112", "name": "Modify Registry"}],
    "latest_timeline_event": {"event_type": "STATUS_CHANGED"},
    "compromise_confirmed": None,
    "linked_case_ids": [2],
    "raw_alert": "must never enter a policy plan",
    "ai_analysis": "must never enter a policy plan",
}


def test_context_policy_keeps_fact_lookup_narrow() -> None:
    intent = _selection(AnswerIntent.FACT_LOOKUP)
    scope = resolve_analysis_scope(
        request_scope="incident",
        incident_id=10,
        case_id=None,
        intent=intent,
        conversation_state=None,
    )
    plan = ContextPolicyEngine().plan(
        intent=intent,
        focus=_focus(FocusDimension.STATUS),
        resolved_scope=scope,
        available_facts=FACTS,
        conversation_state=None,
    )

    assert {field.value for field in plan.fact_fields} == {
        "source_type",
        "incident_id",
        "case_id",
        "title",
        "status",
    }
    assert plan.include_cross_incident is False
    assert plan.include_advisory is False


def test_context_policy_makes_open_explanation_rich_but_excludes_raw_fields() -> None:
    intent = _selection(AnswerIntent.EXPLAIN)
    scope = resolve_analysis_scope(
        request_scope="incident",
        incident_id=10,
        case_id=None,
        intent=intent,
        conversation_state=None,
    )
    plan = ContextPolicyEngine().plan(
        intent=intent,
        focus=_focus(FocusDimension.GENERAL),
        resolved_scope=scope,
        available_facts=FACTS,
        conversation_state=None,
    )
    fields = {field.value for field in plan.fact_fields}

    assert {"agent", "rule", "risk_score", "mitre", "latest_timeline_event"} <= fields
    assert "raw_alert" not in fields
    assert "ai_analysis" not in fields
    assert plan.include_reference is True
    assert plan.include_advisory is False


def test_executive_context_includes_material_handling_and_detection_facts() -> None:
    intent = _selection(AnswerIntent.EXECUTIVE_SUMMARY)
    scope = resolve_analysis_scope(
        request_scope="incident",
        incident_id=10,
        case_id=None,
        intent=intent,
        conversation_state=None,
    )
    plan = ContextPolicyEngine().plan(
        intent=intent,
        focus=_focus(FocusDimension.GENERAL),
        resolved_scope=scope,
        available_facts=FACTS,
        conversation_state=None,
    )
    fields = {field.value for field in plan.fact_fields}

    assert {
        "status",
        "rule",
        "risk_score",
        "recommended_priority",
        "correlated",
        "linked_case_ids",
    } <= fields
    assert "mitre" not in fields
    assert "latest_timeline_event" not in fields


def test_cross_incident_intent_expands_scope_and_context_policy() -> None:
    intent = _selection(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    scope = resolve_analysis_scope(
        request_scope="incident",
        incident_id=10,
        case_id=None,
        intent=intent,
        conversation_state=None,
    )
    plan = ContextPolicyEngine().plan(
        intent=intent,
        focus=_focus(FocusDimension.CORRELATION),
        resolved_scope=scope,
        available_facts=FACTS,
        conversation_state=None,
    )

    assert scope.analysis_scope is AnalysisScope.RELATED_INCIDENTS
    assert plan.include_cross_incident is True
    assert plan.include_advisory is True
    assert ContextRequirement.CROSS_INCIDENT in plan.requirements


def test_v3_contracts_are_closed_and_authority_is_explicit() -> None:
    provenance = Provenance(
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        source_type="incident",
        source_record_id="10",
        retrieval_method="operational_query",
    )
    with pytest.raises(ValidationError):
        StatusAtom(
            atom_id="incident:10:status",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=provenance,
            incident_id=10,
            status="OPEN",
            uncontrolled={"claim": "value"},
        )


def test_production_intent_router_has_no_lexical_or_regex_routing() -> None:
    source = inspect.getsource(SemanticIntentRouter)

    assert "import re" not in source
    assert "re." not in source
    assert "analyst_question.lower" not in source
    assert " in analyst_question" not in source
