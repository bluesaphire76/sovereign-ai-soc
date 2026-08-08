from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, CaseIncident, Incident, IncidentCase
from services.assistant.focus import FocusDimension, FocusSelection
from services.assistant.v3.atoms import OperationalAtomNormalizer
from services.assistant.v3.contracts import (
    AnalyticalRelationship,
    AnswerIntent,
    AuthorityClass,
    ContextLimits,
    DiscoverySignal,
    IntentSelection,
    Provenance,
    RelationshipClass,
    RelationshipRegistry,
    RelationshipType,
)
from services.assistant.v3.cross_incident import (
    CrossIncidentCandidateRetriever,
    SemanticIncidentHit,
)
from services.assistant.v3.graph import (
    CrossIncidentGraphBuilder,
    RecordedCorrelationLink,
)
from services.assistant.v3.policy import ContextPolicyEngine, resolve_analysis_scope


def _db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def _incident(
    doc_id: str,
    *,
    agent: str,
    rule: str,
    mitre: str,
    correlation_type: str,
    timestamp: str,
) -> Incident:
    return Incident(
        wazuh_doc_id=doc_id,
        status="OPEN",
        timestamp=timestamp,
        agent=agent,
        rule=rule,
        level=10,
        mitre=json.dumps([mitre]),
        risk_score=70,
        correlated=True,
        correlation_type=correlation_type,
        correlation_score=75,
        recommended_priority="HIGH",
    )


def _fixture(db):
    anchor = _incident(
        "anchor",
        agent="endpoint-a",
        rule="Registry changed",
        mitre="T1112",
        correlation_type="endpoint_pattern",
        timestamp="2026-08-08T10:00:00Z",
    )
    shared_agent_rule = _incident(
        "shared-agent-rule",
        agent="endpoint-a",
        rule="Registry changed",
        mitre="T1059.001",
        correlation_type="other_pattern",
        timestamp="2026-08-08T12:00:00Z",
    )
    shared_mitre_correlation = _incident(
        "shared-mitre-correlation",
        agent="endpoint-b",
        rule="Different rule",
        mitre="T1112",
        correlation_type="endpoint_pattern",
        timestamp="2026-08-09T09:00:00Z",
    )
    semantic_only = _incident(
        "semantic-only",
        agent="endpoint-c",
        rule="Unrelated rule",
        mitre="T1110",
        correlation_type="authentication",
        timestamp="2026-09-10T10:00:00Z",
    )
    unrelated = _incident(
        "unrelated",
        agent="endpoint-d",
        rule="File deleted",
        mitre="T1070.004",
        correlation_type="file_activity",
        timestamp="2026-10-10T10:00:00Z",
    )
    db.add_all([anchor, shared_agent_rule, shared_mitre_correlation, semantic_only, unrelated])
    db.flush()
    case = IncidentCase(group_key="v3-case", title="V3 test case", status="OPEN")
    db.add(case)
    db.flush()
    db.add_all(
        [
            CaseIncident(case_id=case.id, incident_id=anchor.id),
            CaseIncident(case_id=case.id, incident_id=shared_mitre_correlation.id),
        ]
    )
    db.commit()
    return anchor, shared_agent_rule, shared_mitre_correlation, semantic_only, unrelated, case


def _anchor_facts(anchor: Incident, case_id: int):
    return {
        "source_type": "incident",
        "incident_id": anchor.id,
        "status": anchor.status,
        "severity": None,
        "timestamp": anchor.timestamp,
        "agent": anchor.agent,
        "rule": anchor.rule,
        "wazuh_level": anchor.level,
        "risk_score": anchor.risk_score,
        "mitre": [{"id": "T1112", "name": "Modify Registry"}],
        "correlated": anchor.correlated,
        "correlation_type": anchor.correlation_type,
        "correlation_score": anchor.correlation_score,
        "recommended_priority": anchor.recommended_priority,
        "linked_case_ids": [case_id],
        "compromise_confirmed": None,
    }


def _cross_plan(facts):
    selection = IntentSelection(
        primary_intent=AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        confidence=1.0,
        routing_status="ok",
        routing_ms=0.0,
    )
    scope = resolve_analysis_scope(
        request_scope="incident",
        incident_id=facts["incident_id"],
        case_id=None,
        intent=selection,
        conversation_state=None,
    )
    return ContextPolicyEngine().plan(
        intent=selection,
        focus=FocusSelection(dimensions=(FocusDimension.CORRELATION,), confidence=1.0),
        resolved_scope=scope,
        available_facts=facts,
        conversation_state=None,
    )


def test_candidate_retrieval_combines_signals_rehydrates_and_filters() -> None:
    db = _db()
    try:
        anchor, shared_agent, shared_mitre, semantic_only, unrelated, case = _fixture(db)
        result = CrossIncidentCandidateRetriever().retrieve(
            db=db,
            anchor_facts=_anchor_facts(anchor, case.id),
            semantic_hits=[
                SemanticIncidentHit(incident_id=semantic_only.id, score=0.84),
                SemanticIncidentHit(incident_id=999999, score=0.99),
                SemanticIncidentHit(incident_id=semantic_only.id, score=0.82),
            ],
            limits=ContextLimits(max_candidates_rehydrated=8),
        )
        by_id = {item.candidate_incident_id: item for item in result.candidates}

        assert DiscoverySignal.SHARED_AGENT in by_id[shared_agent.id].discovery_signals
        assert DiscoverySignal.SHARED_RULE in by_id[shared_agent.id].discovery_signals
        assert DiscoverySignal.SHARED_MITRE in by_id[shared_mitre.id].discovery_signals
        assert DiscoverySignal.SHARED_CORRELATION_TYPE in by_id[shared_mitre.id].discovery_signals
        assert DiscoverySignal.SAME_CASE in by_id[shared_mitre.id].discovery_signals
        assert by_id[semantic_only.id].discovery_source == "semantic"
        assert by_id[semantic_only.id].authoritative_rehydrated is True
        assert unrelated.id not in by_id
        assert 999999 not in by_id
        assert len(by_id) == len(result.candidates)
        assert {item.incident_id for item in result.incidents} == set(by_id)
    finally:
        db.close()


def test_candidate_retrieval_is_deterministic_and_bounded() -> None:
    db = _db()
    try:
        anchor, _, _, semantic_only, _, case = _fixture(db)
        retriever = CrossIncidentCandidateRetriever()
        limits = ContextLimits(max_candidates_rehydrated=2, max_candidates_discovered=4)
        first = retriever.retrieve(
            db=db,
            anchor_facts=_anchor_facts(anchor, case.id),
            semantic_hits=[SemanticIncidentHit(semantic_only.id, 0.8)],
            limits=limits,
        )
        second = retriever.retrieve(
            db=db,
            anchor_facts=_anchor_facts(anchor, case.id),
            semantic_hits=[SemanticIncidentHit(semantic_only.id, 0.8)],
            limits=limits,
        )

        assert len(first.candidates) <= 2
        assert [item.candidate_id for item in first.candidates] == [
            item.candidate_id for item in second.candidates
        ]
    finally:
        db.close()


def test_graph_preserves_relationship_classes_and_evidence_refs() -> None:
    db = _db()
    try:
        anchor, _, _, semantic_only, _, case = _fixture(db)
        facts = _anchor_facts(anchor, case.id)
        plan = _cross_plan(facts)
        result = CrossIncidentCandidateRetriever().retrieve(
            db=db,
            anchor_facts=facts,
            semantic_hits=[SemanticIncidentHit(semantic_only.id, 0.84)],
            limits=plan.limits,
        )
        normalizer = OperationalAtomNormalizer()
        atoms = normalizer.normalize(facts=facts, plan=plan)
        for incident in result.incidents:
            atoms.extend(normalizer.normalize(facts=incident.facts, plan=plan))
        graph = CrossIncidentGraphBuilder().build(
            anchor_incident_id=anchor.id,
            candidates=result.candidates,
            operational_atoms=atoms,
        )

        assert graph.relationships
        assert all(edge.evidence_atom_refs for edge in graph.relationships)
        assert all(
            set(edge.evidence_atom_refs) <= set(graph.available_evidence_refs)
            for edge in graph.relationships
        )
        analytical_edges = [
            edge
            for edge in graph.relationships
            if edge.relationship_class is RelationshipClass.ANALYTICAL_RELATIONSHIP
        ]
        atoms_by_id = {atom.atom_id: atom for atom in atoms}
        assert analytical_edges
        assert all(
            edge.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
            and edge.provenance.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
            for edge in analytical_edges
        )
        assert all(
            atoms_by_id[ref].authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
            for edge in analytical_edges
            for ref in edge.evidence_atom_refs
        )
        semantic_edges = [
            edge
            for edge in graph.relationships
            if edge.relationship_class is RelationshipClass.SEMANTIC_SIMILARITY
        ]
        assert semantic_edges
        assert all(
            edge.relationship_type is RelationshipType.SEMANTIC_SIMILARITY
            and edge.authority_class is AuthorityClass.SEMANTIC_CANDIDATE
            for edge in semantic_edges
        )
        assert all(
            edge.relationship_class is not RelationshipClass.RECORDED_CORRELATION
            for edge in semantic_edges
        )
        assert "CAUSALITY" not in {item.value for item in RelationshipType}
        assert "COMPROMISE" not in {item.value for item in RelationshipType}
        assert "SAME_ATTACKER" not in {item.value for item in RelationshipType}
        assert "SAME_CAMPAIGN" not in {item.value for item in RelationshipType}
    finally:
        db.close()


def test_recorded_correlation_requires_explicit_supported_link() -> None:
    db = _db()
    try:
        anchor, shared_agent, _, _, _, case = _fixture(db)
        facts = _anchor_facts(anchor, case.id)
        plan = _cross_plan(facts)
        normalizer = OperationalAtomNormalizer()
        anchor_atoms = normalizer.normalize(facts=facts, plan=plan)
        other_facts = _anchor_facts(shared_agent, case.id)
        other_atoms = normalizer.normalize(facts=other_facts, plan=plan)
        refs = (anchor_atoms[0].atom_id, other_atoms[0].atom_id)
        graph = CrossIncidentGraphBuilder().build(
            anchor_incident_id=anchor.id,
            candidates=[],
            operational_atoms=[*anchor_atoms, *other_atoms],
            recorded_links=[
                RecordedCorrelationLink(
                    left_incident_id=anchor.id,
                    right_incident_id=shared_agent.id,
                    evidence_atom_refs=refs,
                    source_record_id="platform-correlation-1",
                )
            ],
        )

        assert len(graph.relationships) == 1
        relationship = graph.relationships[0]
        assert relationship.relationship_class is RelationshipClass.RECORDED_CORRELATION
        assert relationship.relationship_type is RelationshipType.PLATFORM_RECORDED_CORRELATION
        assert relationship.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
        assert (
            relationship.provenance.authority_class
            is AuthorityClass.OPERATIONAL_AUTHORITATIVE
        )
    finally:
        db.close()


def test_analytical_relationship_cannot_claim_operational_or_recorded_authority() -> None:
    operational_provenance = Provenance(
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        source_type="cross_incident_discovery",
        source_record_id="candidate:2",
        retrieval_method="operational_query",
    )
    with pytest.raises(ValidationError):
        AnalyticalRelationship(
            relationship_id="relationship:invalid-authority",
            relationship_class=RelationshipClass.ANALYTICAL_RELATIONSHIP,
            relationship_type=RelationshipType.SHARED_HOST,
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            left_incident_id=1,
            right_incident_id=2,
            evidence_atom_refs=["incident:1:host", "incident:2:host"],
            provenance=operational_provenance,
        )

    analytical_provenance = operational_provenance.model_copy(
        update={
            "authority_class": AuthorityClass.ANALYTICAL_DERIVATION,
            "retrieval_method": "deterministic_derivation",
        }
    )
    with pytest.raises(ValidationError):
        AnalyticalRelationship(
            relationship_id="relationship:invalid-recorded-type",
            relationship_class=RelationshipClass.ANALYTICAL_RELATIONSHIP,
            relationship_type=RelationshipType.PLATFORM_RECORDED_CORRELATION,
            authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
            left_incident_id=1,
            right_incident_id=2,
            evidence_atom_refs=["incident:1:host", "incident:2:host"],
            provenance=analytical_provenance,
        )


def test_relationship_registry_resolves_exact_typed_refs_and_authority() -> None:
    relationship = AnalyticalRelationship(
        relationship_id="relationship:shared-host",
        relationship_class=RelationshipClass.ANALYTICAL_RELATIONSHIP,
        relationship_type=RelationshipType.SHARED_HOST,
        authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
        left_incident_id=1,
        right_incident_id=2,
        evidence_atom_refs=["incident:1:host", "incident:2:host"],
        provenance=Provenance(
            authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
            source_type="cross_incident_discovery",
            source_record_id="candidate:2",
            retrieval_method="deterministic_derivation",
        ),
    )
    registry = RelationshipRegistry(relationships=[relationship])

    resolved = registry.resolve(
        relationship.relationship_id,
        expected_authority=AuthorityClass.ANALYTICAL_DERIVATION,
    )
    assert resolved == relationship
    assert resolved.relationship_class is RelationshipClass.ANALYTICAL_RELATIONSHIP
    assert resolved.relationship_type is RelationshipType.SHARED_HOST
    assert (resolved.left_incident_id, resolved.right_incident_id) == (1, 2)
    assert resolved.evidence_atom_refs == ["incident:1:host", "incident:2:host"]
    assert resolved.provenance.source_record_id == "candidate:2"
    assert registry.resolve("relationship:missing") is None
    assert (
        registry.resolve(
            relationship.relationship_id,
            expected_authority=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        )
        is None
    )
