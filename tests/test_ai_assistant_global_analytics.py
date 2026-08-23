from __future__ import annotations

import json
from datetime import datetime, timezone
from collections.abc import Sequence
from typing import Any

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, Incident, IncidentCase
from schemas.assistant import AssistantQueryRequest
from services.assistant.analytics.builder import (
    GlobalAnalyticsContextBuilder,
    GlobalAnalyticsResolutionError,
)
from services.assistant.analytics.contracts import (
    AnalyticsQueryPlan,
    AnalyticsRouteDecision,
)
from services.assistant.analytics.execution import (
    AuthoritativeAnalyticsExecutor,
    PlatformAnalyticsAccessPolicy,
)
from services.assistant.analytics.interpreter import GlobalAnalyticsInterpreter
from services.assistant.analytics.fallback import render_global_analytics_fallback
from services.assistant.analytics.normalization import normalize_mitre_facts
from services.assistant.analytics.registry import DEFAULT_ANALYTICS_REGISTRY
from services.assistant.analytics.temporal import ZurichTemporalResolver
from services.assistant.orchestrator import (
    AssistantSettings,
    _response_language,
    run_assistant_query,
)
from services.assistant.v3.contracts import (
    AnalyticalEntity,
    AnalyticalFilterDescriptor,
    AnalyticalFilterField,
    AnalyticalMeasure,
    AnalyticalOperation,
    AuthorityClass,
    RelationshipClass,
)
from services.assistant.v3.conversation import ConversationStateStore
from services.assistant.v3.response_v32 import (
    GroundedResponseV32Validator,
    compile_v32_proof_units,
    grounded_response_v32_schema,
    v32_proposition_budget,
)
from services.assistant.v3.semantic_index import (
    IncidentSemanticHit,
    IncidentSemanticQueryResult,
    incident_source_fingerprint,
)
from services.assistant.v3.semantic_proof.contracts import (
    EntailmentDecision,
    EntailmentDecisionReason,
    EntailmentLabel,
    EntailmentPair,
    EntailmentProviderInfo,
    EvidenceKind,
    ProofPredicate,
    ProofScopeKind,
)
from services.assistant.v3.semantic_proof.guards import (
    TypedGuardReason,
    TypedSemanticGuard,
)
from services.assistant.v3.semantic_proof.response_contracts import (
    GroundedResponseDraftV32,
    V32Proposition,
    V32SectionKind,
)


NOW = datetime(2026, 8, 23, 10, 0, tzinfo=timezone.utc)


class StaticAnalyticsRouter:
    def __init__(self, definition_id: str | None, *, status: str = "ok") -> None:
        self.definition_id = definition_id
        self.status = status

    def route(self, question: str, **kwargs: Any) -> AnalyticsRouteDecision:
        del question, kwargs
        return AnalyticsRouteDecision(
            accepted=self.definition_id is not None,
            definition_id=self.definition_id,
            confidence=0.93 if self.definition_id else 0.0,
            routing_status=self.status,
            routing_ms=0.1,
        )


class StaticSemanticIndex:
    def __init__(self, hits: tuple[IncidentSemanticHit, ...]) -> None:
        self.hits = hits
        self.calls = 0

    def query(self, text: str, **kwargs: Any) -> IncidentSemanticQueryResult:
        del text, kwargs
        self.calls += 1
        return IncidentSemanticQueryResult(
            hits=self.hits,
            status="ready",
            query_ms=0.2,
            raw_candidate_count=len(self.hits),
        )


class ExcludeRestrictedPolicy(PlatformAnalyticsAccessPolicy):
    def apply_incident_scope(self, query, *, current_user):
        del current_user
        return query.filter(Incident.agent != "restricted-host")


class EntailingProvider:
    @property
    def info(self) -> EntailmentProviderInfo:
        return EntailmentProviderInfo(
            backend="test",
            model="test-entailment",
            precision="none",
            quantization="none",
            device="cpu",
        )

    def evaluate(
        self,
        pairs: Sequence[EntailmentPair],
        *,
        batch_size: int,
    ) -> Sequence[EntailmentDecision]:
        del batch_size
        return [
            EntailmentDecision(
                pair_id=pair.pair_id,
                proof_unit_id=pair.proof_unit_id,
                hypothesis_id=pair.hypothesis_id,
                label=EntailmentLabel.ENTAILMENT,
                entailment_score=1.0,
                accepted=True,
                reason=EntailmentDecisionReason.ENTAILED,
            )
            for pair in pairs
        ]


@pytest.fixture()
def analytics_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine)
    db = factory()
    incidents = [
        Incident(
            wazuh_doc_id="global-1",
            status="NEW",
            timestamp="2026-08-20T10:00:00Z",
            agent="darkstar-windows",
            rule="Registry changed",
            level=10,
            mitre=json.dumps([{"id": "T1112", "name": "Modify Registry"}]),
            risk_score=72,
            correlated=True,
            correlation_type="endpoint_pattern",
            correlation_score=88,
            correlation_summary=json.dumps(
                {"related_event_details": [{"id": 2}]}
            ),
            recommended_priority="HIGH",
        ),
        Incident(
            wazuh_doc_id="global-2",
            status="RESOLVED",
            timestamp="2026-08-19T10:00:00Z",
            agent="darkstar-windows",
            rule="PowerShell execution",
            level=9,
            mitre=json.dumps([{"id": "T1059.001", "name": "PowerShell"}]),
            risk_score=55,
            correlated=False,
            correlation_score=0,
            recommended_priority="MEDIUM",
        ),
        Incident(
            wazuh_doc_id="global-3",
            status="NEW",
            timestamp="2026-08-23T09:00:00Z",
            agent="host-b",
            rule="Registry changed",
            level=11,
            mitre=json.dumps([{"id": "T1112", "name": "Modify Registry"}]),
            risk_score=80,
            correlated=False,
            correlation_score=0,
            recommended_priority="HIGH",
        ),
        Incident(
            wazuh_doc_id="global-4",
            status="NEW",
            timestamp="2026-08-13T10:00:00Z",
            agent="host-c",
            rule="Credential access",
            level=12,
            mitre=json.dumps([{"id": "T1003", "name": "OS Credential Dumping"}]),
            risk_score=90,
            correlated=False,
            correlation_score=0,
            recommended_priority="HIGH",
        ),
        Incident(
            wazuh_doc_id="global-5",
            status="NEW",
            timestamp="2026-08-21T10:00:00Z",
            agent="restricted-host",
            rule="Restricted detection",
            level=12,
            mitre=json.dumps([{"id": "T1021", "name": "Remote Services"}]),
            risk_score=90,
            correlated=False,
            correlation_score=0,
            recommended_priority="HIGH",
        ),
        Incident(
            wazuh_doc_id="global-6",
            status="CLOSED",
            timestamp="2026-07-15T10:00:00Z",
            agent="host-july",
            rule="July detection",
            level=6,
            mitre=json.dumps([{"id": "T1112", "name": "Modify Registry"}]),
            risk_score=20,
            correlated=False,
            correlation_score=0,
            recommended_priority="LOW",
        ),
    ]
    db.add_all(incidents)
    db.add_all(
        [
            IncidentCase(
                group_key="case-overdue",
                title="Overdue investigation",
                status="OPEN",
                severity="HIGH",
                agent="darkstar-windows",
                sla_due_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
            ),
            IncidentCase(
                group_key="case-closed",
                title="Closed investigation",
                status="CLOSED",
                severity="LOW",
                agent="host-b",
                sla_due_at=datetime(2026, 8, 20, tzinfo=timezone.utc),
            ),
            IncidentCase(
                group_key="case-future",
                title="Within SLA",
                status="OPEN",
                severity="MEDIUM",
                agent="host-c",
                sla_due_at=datetime(2026, 8, 25, tzinfo=timezone.utc),
            ),
        ]
    )
    db.commit()
    try:
        yield db, factory, incidents
    finally:
        db.close()
        engine.dispose()


def _builder(
    definition_id: str,
    *,
    store: ConversationStateStore | None = None,
    semantic_index: StaticSemanticIndex | None = None,
    access_policy: PlatformAnalyticsAccessPolicy | None = None,
) -> GlobalAnalyticsContextBuilder:
    access = access_policy or PlatformAnalyticsAccessPolicy()
    return GlobalAnalyticsContextBuilder(
        interpreter=GlobalAnalyticsInterpreter(
            router=StaticAnalyticsRouter(definition_id)
        ),
        executor=AuthoritativeAnalyticsExecutor(
            access_policy=access,
            incident_semantic_index=semantic_index,
        ),
        access_policy=access,
        conversation_store=store,
    )


def _build(
    db,
    definition_id: str,
    question: str,
    *,
    conversation_id: str | None = None,
    store: ConversationStateStore | None = None,
    semantic_index: StaticSemanticIndex | None = None,
    access_policy: PlatformAnalyticsAccessPolicy | None = None,
):
    return _builder(
        definition_id,
        store=store,
        semantic_index=semantic_index,
        access_policy=access_policy,
    ).build(
        payload=AssistantQueryRequest(
            message=question,
            scope="global",
            conversation_id=conversation_id,
        ),
        response_language="it",
        db=db,
        current_user={"id": "analyst-a", "role": "ANALYST"},
        now=NOW,
        wall_clock=lambda: NOW.timestamp(),
    )


def test_temporal_resolver_uses_zurich_and_absolute_utc_windows() -> None:
    resolver = ZurichTemporalResolver()
    last_day = resolver.resolve("ultime 24 ore", now=NOW).current
    last_thirty_days = resolver.resolve("ultimi 30 giorni", now=NOW).current
    today = resolver.resolve("oggi", now=NOW).current
    this_week = resolver.resolve("questa settimana", now=NOW).current
    this_month = resolver.resolve("questo mese", now=NOW).current
    previous_month = resolver.resolve("mese scorso", now=NOW).current
    ambiguous_month = resolver.resolve("ultimo mese", now=NOW)
    comparison = resolver.resolve(
        "ultimi 7 giorni e i 7 giorni precedenti",
        now=NOW,
        compare_periods=True,
    )

    assert last_day is not None
    assert (last_day.start_utc, last_day.end_utc) == (
        "2026-08-22T10:00:00Z",
        "2026-08-23T10:00:00Z",
    )
    assert this_week is not None
    assert this_week.start_utc == "2026-08-16T22:00:00Z"
    assert last_thirty_days is not None
    assert last_thirty_days.resolution == "LAST_30_DAYS"
    assert today is not None and today.start_utc == "2026-08-22T22:00:00Z"
    assert this_month is not None
    assert this_month.start_utc == "2026-07-31T22:00:00Z"
    assert previous_month is not None
    assert (previous_month.start_utc, previous_month.end_utc) == (
        "2026-06-30T22:00:00Z",
        "2026-07-31T22:00:00Z",
    )
    assert comparison.current is not None and comparison.previous is not None
    assert comparison.previous.end_utc == comparison.current.start_utc
    assert ambiguous_month.current is None
    assert ambiguous_month.routing_status == "ambiguous_time_window"


def test_global_followups_preserve_italian_language() -> None:
    assert _response_language("Di questi, quanti risultano ancora NEW?") == "it"
    assert (
        _response_language(
            "I risultati simili al 5333 fanno parte dello stesso attacco?"
        )
        == "it"
    )


def test_legacy_mitre_mapping_is_normalized_for_distribution(analytics_db) -> None:
    db, _factory, incidents = analytics_db
    value = (
        "{'technique': ['Stored Data Manipulation', 'Modify Registry'], "
        "'id': ['T1565.001', 'T1112'], "
        "'tactic': ['Impact', 'Defense Evasion']}"
    )
    assert normalize_mitre_facts(value) == [
        {"id": "T1565.001", "name": "Stored Data Manipulation"},
        {"id": "T1112", "name": "Modify Registry"},
    ]
    incidents[5].mitre = value
    db.commit()

    result = _build(
        db,
        "incident_mitre_distribution",
        "Quali tecniche MITRE sono più frequenti negli incidenti del mese scorso?",
    )
    rendered = render_global_analytics_fallback(result.package)
    text = rendered.blocks[0].text

    assert [row.dimensions[0].value for row in result.build_result.result_atom.rows] == [
        "T1112",
        "T1565.001",
    ]
    assert "MITRE T1112 (1)" in text
    assert "MITRE T1565.001 (1)" in text
    assert "{'technique'" not in text


def test_registry_and_query_fingerprint_reject_unregistered_or_tampered_plans() -> None:
    plan = AnalyticsQueryPlan.create(
        definition_id="incident_count",
        operation=AnalyticalOperation.COUNT,
        entity=AnalyticalEntity.INCIDENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        filters=[],
        dimensions=[],
        limit=1,
    )
    assert DEFAULT_ANALYTICS_REGISTRY.validate_plan(plan).definition_id == "incident_count"

    with pytest.raises(ValidationError, match="fingerprint"):
        AnalyticsQueryPlan.model_validate(
            {**plan.model_dump(mode="json"), "query_plan_fingerprint": "0" * 64}
        )
    with pytest.raises(ValueError, match="unknown registry"):
        DEFAULT_ANALYTICS_REGISTRY.validate_plan(
            AnalyticsQueryPlan.create(
                definition_id="arbitrary_sql",
                operation=AnalyticalOperation.COUNT,
                entity=AnalyticalEntity.INCIDENT,
                measure=AnalyticalMeasure.INCIDENT_COUNT,
                filters=[],
                dimensions=[],
                limit=1,
            )
        )
    unsupported_filter = AnalyticalFilterDescriptor(
        field=AnalyticalFilterField.SLA_STATE,
        operator="EQ",
        values=["BREACHED"],
    )
    with pytest.raises(ValueError, match="unregistered filter"):
        DEFAULT_ANALYTICS_REGISTRY.validate_plan(
            AnalyticsQueryPlan.create(
                definition_id="incident_count",
                operation=AnalyticalOperation.COUNT,
                entity=AnalyticalEntity.INCIDENT,
                measure=AnalyticalMeasure.INCIDENT_COUNT,
                filters=[unsupported_filter],
                dimensions=[],
                limit=1,
            )
        )


@pytest.mark.parametrize(
    ("definition_id", "question", "expected_scalar", "expected_rows"),
    [
        (
            "incident_count",
            "Quanti incidenti HIGH abbiamo avuto questa settimana?",
            3,
            0,
        ),
        (
            "incident_count",
            "Quanti incidenti NEW ci sono stati nelle ultime 24 ore?",
            1,
            0,
        ),
        (
            "incident_top_agents",
            "Quali host hanno generato più incidenti negli ultimi 7 giorni?",
            None,
            3,
        ),
        (
            "incident_top_detection_rules",
            "Quali regole di detection hanno generato più incidenti negli ultimi 30 giorni?",
            None,
            4,
        ),
        (
            "incident_mitre_distribution",
            "Quali tecniche MITRE sono più frequenti negli incidenti del mese scorso?",
            None,
            1,
        ),
        (
            "incident_compare_periods",
            "Confronta il numero di incidenti degli ultimi 7 giorni con i 7 giorni precedenti.",
            None,
            2,
        ),
        (
            "case_sla_breached_list",
            "Quali casi hanno superato lo SLA?",
            None,
            1,
        ),
    ],
)
def test_acceptance_analytics_are_exact_sql_or_typed_derivations(
    analytics_db,
    definition_id,
    question,
    expected_scalar,
    expected_rows,
) -> None:
    db, _factory, _incidents = analytics_db
    result = _build(db, definition_id, question)
    atom = result.build_result.result_atom

    assert atom.scalar_value == expected_scalar
    assert len(atom.rows) == expected_rows
    assert atom.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
    assert atom.provenance.retrieval_method == "deterministic_derivation"
    assert result.build_result.plan.query_plan_fingerprint == atom.query_plan_fingerprint


def test_typed_followup_uses_previous_result_ids_and_handles_empty_sets(
    analytics_db,
) -> None:
    db, _factory, _incidents = analytics_db
    store = ConversationStateStore(clock=lambda: NOW.timestamp())
    first = _build(
        db,
        "incident_list",
        "Mostrami gli incidenti di darkstar-windows degli ultimi 7 giorni.",
        conversation_id="global-followup",
        store=store,
    )
    followup = _build(
        db,
        "incident_count_previous_result",
        "Di questi, quanti risultano ancora NEW?",
        conversation_id="global-followup",
        store=store,
    )

    assert first.build_result.result_atom.result_ids == [1, 2]
    assert followup.build_result.result_atom.scalar_value == 1
    assert followup.build_result.plan.previous_result_ref == (
        first.build_result.plan.query_plan_fingerprint
    )
    assert followup.package.resolved_scope.conversation_followup is True

    empty_first = _build(
        db,
        "incident_list",
        "Mostrami gli incidenti di darkstar-windows nelle ultime 24 ore.",
        conversation_id="empty-followup",
        store=store,
    )
    empty_followup = _build(
        db,
        "incident_count_previous_result",
        "Di questi, quanti risultano ancora NEW?",
        conversation_id="empty-followup",
        store=store,
    )
    assert empty_first.build_result.result_atom.result_ids == []
    assert empty_followup.build_result.plan.previous_result_empty is True
    assert empty_followup.build_result.result_atom.scalar_value == 0


def test_recorded_relationship_and_semantic_similarity_remain_distinct(
    analytics_db,
) -> None:
    db, _factory, incidents = analytics_db
    recorded = _build(
        db,
        "recorded_related_incidents",
        "Quali incidenti risultano correlati al 1?",
    )
    semantic_index = StaticSemanticIndex(
        (
            IncidentSemanticHit(
                incident_id=2,
                score=0.87,
                source_fingerprint=incident_source_fingerprint(incidents[1]),
            ),
        )
    )
    semantic = _build(
        db,
        "semantic_similar_incidents",
        "Quali incidenti sono semanticamente simili al 1?",
        semantic_index=semantic_index,
    )

    recorded_edge = recorded.package.cross_incident_graph.relationships[0]
    semantic_edge = semantic.package.cross_incident_graph.relationships[0]
    assert recorded_edge.relationship_class is RelationshipClass.RECORDED_CORRELATION
    assert recorded_edge.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
    assert semantic_edge.relationship_class is RelationshipClass.SEMANTIC_SIMILARITY
    assert semantic_edge.authority_class is AuthorityClass.SEMANTIC_CANDIDATE
    assert semantic.package.cross_incident_candidates[0].authoritative_rehydrated
    assert semantic_index.calls == 1

    semantic_units = compile_v32_proof_units(semantic.package)
    semantic_proof = next(
        item
        for item in semantic_units
        if item.predicate is ProofPredicate.SEMANTIC_SIMILARITY
    )
    promoted = TypedSemanticGuard().evaluate(
        semantic_proof,
        "Gli incidenti 1 e 2 hanno una correlazione registrata dalla piattaforma.",
    )
    assert not promoted.accepted
    assert promoted.reason is TypedGuardReason.INCOMPATIBLE_SEMANTIC_CONCEPT

    recorded_units = compile_v32_proof_units(recorded.package)
    assert recorded_units[0].evidence_kind is EvidenceKind.ANALYTICAL_RESULT_SET
    assert recorded_units[0].scope.scope_kind is ProofScopeKind.GLOBAL
    assert len(recorded_units) <= 3
    recorded_proof = next(
        item
        for item in recorded_units
        if item.predicate is ProofPredicate.RECORDED_RELATIONSHIP
    )
    caused = TypedSemanticGuard().evaluate(
        recorded_proof,
        "La correlazione registrata tra gli incidenti 1 e 2 prova la stessa causa.",
    )
    assert not caused.accepted
    assert caused.reason is TypedGuardReason.INCOMPATIBLE_SEMANTIC_CONCEPT
    assert semantic_units[0].evidence_kind is EvidenceKind.ANALYTICAL_RESULT_SET
    assert semantic_units[0].scope.scope_kind is ProofScopeKind.GLOBAL
    assert len(semantic_units) <= 3


def test_global_proposition_budget_is_typed_by_analytical_operation(
    analytics_db,
) -> None:
    db, _factory, incidents = analytics_db
    count = _build(
        db,
        "incident_count",
        "Quanti incidenti NEW ci sono stati nelle ultime 24 ore?",
    )
    recorded = _build(
        db,
        "recorded_related_incidents",
        "Quali incidenti risultano correlati al 1?",
    )
    semantic = _build(
        db,
        "semantic_similar_incidents",
        "Quali incidenti sono semanticamente simili al 1?",
        semantic_index=StaticSemanticIndex(
            (
                IncidentSemanticHit(
                    incident_id=2,
                    score=0.87,
                    source_fingerprint=incident_source_fingerprint(incidents[1]),
                ),
            )
        ),
    )

    assert v32_proposition_budget(count.package) == 1
    assert v32_proposition_budget(recorded.package) == 1
    assert v32_proposition_budget(semantic.package) == 3
    count_schema = grounded_response_v32_schema(
        compile_v32_proof_units(count.package),
        max_propositions=v32_proposition_budget(count.package),
    )
    assert count_schema["properties"]["propositions"]["maxItems"] == 1


def test_typed_relationship_result_can_satisfy_cross_incident_contract(
    analytics_db,
) -> None:
    db, _factory, incidents = analytics_db
    recorded = _build(
        db,
        "recorded_related_incidents",
        "Quali incidenti risultano correlati al 1?",
    )
    recorded_units = compile_v32_proof_units(recorded.package)
    recorded_result = recorded_units[0]
    recorded_draft = GroundedResponseDraftV32(
        response_language="it",
        propositions=[
            V32Proposition(
                proposition_id="p1",
                text="L'analisi ha restituito 1 incidente correlato al 1: il 2.",
                proof_unit_refs=[recorded_result.proof_unit_id],
                section_kind=V32SectionKind.DIRECT_ANSWER,
            )
        ],
    )

    assert GroundedResponseV32Validator(EntailingProvider()).validate(
        recorded_draft,
        package=recorded.package,
        proof_units=recorded_units,
    ).accepted

    semantic = _build(
        db,
        "semantic_similar_incidents",
        "Quali incidenti sono semanticamente simili al 1?",
        semantic_index=StaticSemanticIndex(
            (
                IncidentSemanticHit(
                    incident_id=2,
                    score=0.87,
                    source_fingerprint=incident_source_fingerprint(incidents[1]),
                ),
            )
        ),
    )
    semantic_units = compile_v32_proof_units(semantic.package)
    aggregate = semantic_units[0]
    boundary = next(
        item
        for item in semantic_units
        if item.predicate is ProofPredicate.NON_IMPLICATION
    )
    semantic_draft = GroundedResponseDraftV32(
        response_language="it",
        propositions=[
            V32Proposition(
                proposition_id="p1",
                text="L'incidente 2 è un candidato semanticamente simile all'1.",
                proof_unit_refs=[aggregate.proof_unit_id],
                section_kind=V32SectionKind.DIRECT_ANSWER,
            ),
            V32Proposition(
                proposition_id="p2",
                text="Un risultato semanticamente simile non prova lo stesso attacco.",
                proof_unit_refs=[boundary.proof_unit_id],
                section_kind=V32SectionKind.UNCERTAINTY,
            ),
        ],
    )

    assert GroundedResponseV32Validator(EntailingProvider()).validate(
        semantic_draft,
        package=semantic.package,
        proof_units=semantic_units,
    ).accepted


def test_analytical_proof_rejects_wrong_count_window_and_security_promotion(
    analytics_db,
) -> None:
    db, _factory, _incidents = analytics_db
    count = _build(
        db,
        "incident_count",
        "Quanti incidenti HIGH abbiamo avuto questa settimana?",
    )
    unit = next(
        item
        for item in compile_v32_proof_units(count.package)
        if item.evidence_kind is EvidenceKind.ANALYTICAL_COUNT
    )
    guard = TypedSemanticGuard()

    wrong_count = guard.evaluate(
        unit,
        "Il conteggio è 99 incidenti HIGH dal 2026-08-16T22:00:00Z al 2026-08-23T10:00:00Z.",
    )
    wrong_window = guard.evaluate(
        unit,
        "Il conteggio è 3 incidenti HIGH dal 2026-08-01T00:00:00Z al 2026-08-23T10:00:00Z.",
    )
    promoted = guard.evaluate(
        unit,
        "Il conteggio è 3 incidenti HIGH e prova una minaccia critica dal 2026-08-16T22:00:00Z al 2026-08-23T10:00:00Z.",
    )

    assert wrong_count.reason is TypedGuardReason.CONFLICTING_NUMERIC_VALUE
    assert wrong_window.reason is TypedGuardReason.CONFLICTING_TEMPORAL_VALUE
    assert promoted.reason is TypedGuardReason.INCOMPATIBLE_SEMANTIC_CONCEPT


def test_valid_analytical_answer_must_traverse_v32_proof_gate(analytics_db) -> None:
    db, _factory, _incidents = analytics_db
    count = _build(
        db,
        "incident_count",
        "Quanti incidenti HIGH abbiamo avuto questa settimana?",
    )
    proof_units = compile_v32_proof_units(count.package)
    unit = next(
        item
        for item in proof_units
        if item.evidence_kind is EvidenceKind.ANALYTICAL_COUNT
    )
    draft = GroundedResponseDraftV32(
        response_language="it",
        propositions=[
            V32Proposition(
                proposition_id="p1",
                text=(
                    "Il conteggio analitico è 3 incidenti HIGH tra "
                    "2026-08-16T22:00:00Z e 2026-08-23T10:00:00Z."
                ),
                proof_unit_refs=[unit.proof_unit_id],
                section_kind=V32SectionKind.DIRECT_ANSWER,
            )
        ],
    )

    validation = GroundedResponseV32Validator(EntailingProvider()).validate(
        draft,
        package=count.package,
        proof_units=proof_units,
    )

    assert validation.accepted
    assert validation.proof_result is not None
    assert validation.proof_result.pair_count == 1


def test_natural_analytical_paraphrases_reach_hybrid_proof(analytics_db) -> None:
    db, _factory, _incidents = analytics_db
    scenarios = (
        (
            "incident_count",
            "Quanti incidenti NEW ci sono stati nelle ultime 24 ore?",
            EvidenceKind.ANALYTICAL_COUNT,
            "Nelle ultime 24 ore risulta 1 incidente in stato NEW.",
        ),
        (
            "incident_top_agents",
            "Quali host hanno generato più incidenti negli ultimi 7 giorni?",
            EvidenceKind.ANALYTICAL_TOP_K,
            "Negli ultimi 7 giorni, darkstar è l'host con più incidenti: 2.",
        ),
        (
            "incident_mitre_distribution",
            "Quali tecniche MITRE sono più frequenti negli incidenti del mese scorso?",
            EvidenceKind.ANALYTICAL_DISTRIBUTION,
            "Nel mese scorso, MITRE T1112 risulta in 1 incidente.",
        ),
        (
            "incident_compare_periods",
            "Confronta il numero di incidenti degli ultimi 7 giorni con i 7 giorni precedenti.",
            EvidenceKind.ANALYTICAL_COMPARISON,
            "Il periodo corrente registra 4 incidenti e quello precedente 1.",
        ),
        (
            "incident_list",
            "Mostrami gli incidenti di darkstar-windows nelle ultime 24 ore.",
            EvidenceKind.ANALYTICAL_RESULT_SET,
            "Nelle ultime 24 ore non risultano incidenti per darkstar-windows.",
        ),
    )
    guard = TypedSemanticGuard()
    for definition_id, question, kind, proposition in scenarios:
        result = _build(db, definition_id, question)
        unit = next(
            item
            for item in compile_v32_proof_units(result.package)
            if item.evidence_kind is kind
        )
        decision = guard.evaluate(unit, proposition)
        assert decision.accepted, (definition_id, decision)


def test_analytical_temporal_guard_rejects_wrong_rolling_interval(
    analytics_db,
) -> None:
    db, _factory, _incidents = analytics_db
    result = _build(
        db,
        "incident_count",
        "Quanti incidenti NEW ci sono stati nelle ultime 24 ore?",
    )
    unit = compile_v32_proof_units(result.package)[0]

    decision = TypedSemanticGuard().evaluate(
        unit,
        "Negli ultimi 30 giorni risulta 1 incidente NEW.",
    )
    constraint = unit.value.temporal_constraints[0]
    interval = TypedSemanticGuard().evaluate(
        unit,
        f"L'intervallo analizzato va da {constraint.start_utc} a {constraint.end_utc}.",
    )
    investigation_state = TypedSemanticGuard().evaluate(
        unit,
        "Risultano incidenti analizzati.",
    )

    assert decision.reason is TypedGuardReason.CONFLICTING_TEMPORAL_VALUE
    assert interval.accepted
    assert (
        investigation_state.reason
        is TypedGuardReason.INCOMPATIBLE_SEMANTIC_CONCEPT
    )


def test_missing_or_malformed_followup_context_fails_closed(analytics_db) -> None:
    db, _factory, _incidents = analytics_db
    with pytest.raises(GlobalAnalyticsResolutionError) as captured:
        _build(
            db,
            "incident_count_previous_result",
            "Di questi, quanti risultano ancora NEW?",
            conversation_id="missing-state",
            store=ConversationStateStore(clock=lambda: NOW.timestamp()),
        )

    assert getattr(captured.value, "routing_status", None) == "missing_typed_context"


def test_rbac_scope_is_applied_before_count_and_identity_resolution(
    analytics_db,
) -> None:
    db, _factory, _incidents = analytics_db
    result = _build(
        db,
        "incident_count",
        "Quanti incidenti HIGH abbiamo avuto questa settimana?",
        access_policy=ExcludeRestrictedPolicy(),
    )
    identity_probe = _build(
        db,
        "incident_count",
        "Quanti incidenti restricted-host abbiamo?",
        access_policy=ExcludeRestrictedPolicy(),
    )

    assert result.build_result.result_atom.scalar_value == 2
    assert not any(
        item.field is AnalyticalFilterField.AGENT
        and item.values == ["restricted-host"]
        for item in identity_probe.build_result.plan.filters
    )


def test_global_orchestrator_uses_one_generation_and_deterministic_fallback(
    analytics_db,
) -> None:
    _db, factory, _incidents = analytics_db
    calls: list[dict[str, Any]] = []

    def invalid_generator(**kwargs):
        calls.append(kwargs)
        return {
            "safe_error": "invalid_structured_output",
            "error_type": "invalid_structured_output",
        }

    response = run_assistant_query(
        AssistantQueryRequest(
            message="Quanti incidenti NEW ci sono stati nelle ultime 24 ore?",
            scope="global",
            conversation_id="orchestrator-global",
        ),
        current_user={"id": "analyst-a", "role": "ANALYST"},
        settings=AssistantSettings(enabled=True, response_architecture="v3_2"),
        db_factory=factory,
        global_context_builder=_builder("incident_count"),
        generator=invalid_generator,
    )

    assert len(calls) == 1
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.provider_generation_count == 1
    assert response.metadata.automatic_retries == 0
    assert response.metadata.model_switches == 0
    assert response.metadata.analytics_operation == "COUNT"
    assert response.metadata.fallback_reason == "v32_invalid_structured_output"
    assert response.blocks[0].provenance_classes == ["analytical_relationship"]


@pytest.mark.parametrize(
    ("definition_id", "question", "semantic"),
    [
        (
            "recorded_related_incidents",
            "Quali incidenti risultano correlati al 1?",
            False,
        ),
        (
            "semantic_similar_incidents",
            "Quali incidenti sono semanticamente simili al 1?",
            True,
        ),
    ],
)
def test_relationship_fallback_stays_within_attribution_budget(
    analytics_db,
    definition_id,
    question,
    semantic,
) -> None:
    db, factory, incidents = analytics_db
    related = [
        Incident(
            wazuh_doc_id=f"related-{index}",
            status="NEW",
            timestamp="2026-08-23T09:00:00Z",
            agent=f"related-host-{index}",
            rule="Related detection",
            level=8,
            mitre="[]",
            risk_score=40,
            correlated=False,
            correlation_score=0,
            recommended_priority="MEDIUM",
        )
        for index in range(10)
    ]
    db.add_all(related)
    db.commit()
    incidents[0].correlation_summary = json.dumps(
        {"related_event_details": [{"id": item.id} for item in related]}
    )
    db.commit()
    semantic_index = (
        StaticSemanticIndex(
            tuple(
                IncidentSemanticHit(
                    incident_id=item.id,
                    score=0.9 - index / 100,
                    source_fingerprint=incident_source_fingerprint(item),
                )
                for index, item in enumerate(related)
            )
        )
        if semantic
        else None
    )
    calls = 0

    def invalid_generator(**kwargs):
        nonlocal calls
        del kwargs
        calls += 1
        return {
            "safe_error": "invalid_structured_output",
            "error_type": "invalid_structured_output",
        }

    response = run_assistant_query(
        AssistantQueryRequest(message=question, scope="global"),
        current_user={"id": "analyst-a", "role": "ANALYST"},
        settings=AssistantSettings(
            enabled=True,
            response_architecture="v3_2",
            max_sources=8,
        ),
        db_factory=factory,
        global_context_builder=_builder(
            definition_id,
            semantic_index=semantic_index,
        ),
        generator=invalid_generator,
    )

    assert calls == 1
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.fallback_reason == "v32_invalid_structured_output"
    assert response.metadata.analytics_definition_id == definition_id
    assert response.metadata.provider_generation_count == 1
    assert len(response.sources) <= 8
    assert response.blocks[0].provenance_classes


def test_ambiguous_global_query_fails_closed_before_generation(analytics_db) -> None:
    _db, factory, _incidents = analytics_db
    calls = 0

    def generator(**kwargs):
        nonlocal calls
        calls += 1
        return {}

    builder = GlobalAnalyticsContextBuilder(
        interpreter=GlobalAnalyticsInterpreter(
            router=StaticAnalyticsRouter(None, status="ambiguous")
        )
    )
    response = run_assistant_query(
        AssistantQueryRequest(message="Analizza la situazione", scope="global"),
        current_user={"id": "analyst-a", "role": "ANALYST"},
        settings=AssistantSettings(enabled=True, response_architecture="v3_2"),
        db_factory=factory,
        global_context_builder=builder,
        generator=generator,
    )

    assert calls == 0
    assert response.metadata.provider_generation_count == 0
    assert response.metadata.fallback_reason == "global_query_ambiguous"
    assert response.metadata.semantic_proof_status == "not_run"


def test_ambiguous_last_month_clarifies_without_generation(analytics_db) -> None:
    _db, factory, _incidents = analytics_db
    calls = 0

    def generator(**kwargs):
        nonlocal calls
        del kwargs
        calls += 1
        return {}

    response = run_assistant_query(
        AssistantQueryRequest(
            message=(
                "Quali tecniche MITRE sono più frequenti negli incidenti "
                "dell'ultimo mese?"
            ),
            scope="global",
        ),
        current_user={"id": "analyst-a", "role": "ANALYST"},
        settings=AssistantSettings(enabled=True, response_architecture="v3_2"),
        db_factory=factory,
        global_context_builder=_builder("incident_mitre_distribution"),
        generator=generator,
    )

    assert calls == 0
    assert response.metadata.provider_generation_count == 0
    assert response.metadata.fallback_reason == "global_time_window_ambiguous"
    assert "ultimi 30 giorni" in response.answer
    assert "calendario precedente" in response.answer


def test_high_incident_filter_is_canonical_recorded_risk(analytics_db) -> None:
    db, _factory, _incidents = analytics_db
    result = _build(
        db,
        "incident_count",
        "Quanti incidenti HIGH abbiamo avuto questa settimana?",
    )

    assert result.build_result.plan.filters == [
        AnalyticalFilterDescriptor(
            field=AnalyticalFilterField.RECORDED_RISK,
            operator="EQ",
            values=["HIGH"],
        )
    ]
    assert "rischio registrato HIGH" in compile_v32_proof_units(
        result.package
    )[0].canonical_premise
