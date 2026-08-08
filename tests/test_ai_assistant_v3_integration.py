from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, CaseIncident, Incident, IncidentCase
from schemas.assistant import AssistantQueryRequest
from services.assistant.focus import FocusDimension, FocusSelection
from services.assistant.orchestrator import AssistantSettings, run_assistant_query
from services.assistant.retrieval import RetrievalResult
from services.assistant.sources import SourceRecord
from services.assistant.v3.builder import V3AnalyticalContextBuilder
from services.assistant.v3.contracts import (
    AnswerIntent,
    DiscoverySignal,
    IntentSelection,
    RelationshipClass,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.conversation import ConversationStateStore
from services.assistant.v3.discourse import RichGroundedDiscourseRenderer
from services.assistant.v3.plan_contracts import (
    AnalyticalUnitType,
    AnswerSectionType,
)
from services.assistant.v3.plan_fallback import deterministic_answer_plan_v3
from services.assistant.v3.plan_validation import GroundedAnswerPlanV3Validator


class StaticIntentRouter:
    def __init__(self, intent: AnswerIntent) -> None:
        self.intent = intent
        self.calls = 0

    def route(self, question: str) -> IntentSelection:
        self.calls += 1
        return IntentSelection(
            primary_intent=self.intent,
            confidence=1.0,
            routing_status="ok",
            routing_ms=0.1,
        )


class StaticFocusRouter:
    def __init__(self, *dimensions: FocusDimension) -> None:
        self.selection = FocusSelection(
            dimensions=dimensions,
            confidence=1.0,
            focus_routing_ms=0.1,
        )

    def route(self, question: str) -> FocusSelection:
        return self.selection


def _settings() -> AssistantSettings:
    return AssistantSettings(
        enabled=True,
        max_message_chars=2000,
        max_context_chars=16000,
        max_sources=8,
        semantic_limit=4,
        semantic_timeout_seconds=2.0,
        request_timeout_seconds=30.0,
        max_output_tokens=384,
    )


def _facts(incident_id: int) -> dict:
    return {
        "source_type": "incident",
        "incident_id": incident_id,
        "status": "OPEN",
        "severity": None,
        "timestamp": "2026-08-08T10:00:00Z",
        "agent": "endpoint-v3",
        "rule": "Registry changed",
        "wazuh_level": 10,
        "risk_score": 72,
        "risk_normalization_severity": "HIGH",
        "mitre": [{"id": "T1112", "name": "Modify Registry"}],
        "correlated": True,
        "correlation_type": "endpoint_pattern",
        "correlation_score": 75,
        "recommended_priority": "HIGH",
        "linked_case_ids": [],
        "latest_timeline_event": {"event_type": "INCIDENT_CREATED"},
        "compromise_confirmed": None,
    }


def _session_with_incidents():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    anchor = Incident(
        wazuh_doc_id="v3-anchor",
        status="OPEN",
        timestamp="2026-08-08T10:00:00Z",
        agent="endpoint-v3",
        rule="Registry changed",
        level=10,
        mitre=json.dumps(["T1112"]),
        risk_score=72,
        correlated=True,
        correlation_type="endpoint_pattern",
        correlation_score=75,
        recommended_priority="HIGH",
    )
    candidate = Incident(
        wazuh_doc_id="v3-candidate",
        status="INVESTIGATING",
        timestamp="2026-08-08T11:00:00Z",
        agent="endpoint-v3",
        rule="Registry changed",
        level=11,
        mitre=json.dumps(["T1112"]),
        risk_score=80,
        correlated=False,
        correlation_type="endpoint_pattern",
        correlation_score=0,
        recommended_priority="HIGH",
    )
    db.add_all([anchor, candidate])
    db.commit()
    return db, anchor, candidate


def test_non_generative_pipeline_builds_closed_context_package_and_followup_state() -> None:
    db, anchor, candidate = _session_with_incidents()
    try:
        retrieval = SimpleNamespace(
            fact_inventory=_facts(anchor.id),
            sources=[
                SourceRecord(
                    source_type="incident",
                    authority="authoritative",
                    record_id=str(anchor.id),
                    label=f"Incident {anchor.id}",
                    excerpt="Authoritative incident facts.",
                ),
                SourceRecord(
                    source_type="historical_incident",
                    authority="advisory",
                    record_id=str(candidate.id),
                    label=f"Historical incident {candidate.id}",
                    excerpt="Retrieved historical candidate requiring SQL rehydration.",
                    score=0.86,
                ),
                SourceRecord(
                    source_type="knowledge_base",
                    authority="advisory",
                    record_id="registry-playbook",
                    label="Registry review playbook",
                    excerpt="Review registry and adjacent process telemetry.",
                ),
            ],
        )
        payload = AssistantQueryRequest(
            message="Analyze possible connections with other incidents.",
            scope="incident",
            incident_id=anchor.id,
            conversation_id="integration-thread",
        )
        intent = StaticIntentRouter(AnswerIntent.CROSS_INCIDENT_ANALYSIS).route(
            payload.message
        )
        focus = StaticFocusRouter(
            FocusDimension.CORRELATION,
            FocusDimension.EVIDENCE,
        ).route(payload.message)
        store = ConversationStateStore(clock=lambda: 100.0)
        builder = V3AnalyticalContextBuilder(conversation_store=store)

        package = builder.build(
            payload=payload,
            response_language="en",
            intent_selection=intent,
            focus_selection=focus,
            retrieval=retrieval,
            db=db,
            current_user={"username": "analyst-a", "role": "ANALYST"},
            wall_clock=lambda: 100.0,
        )
        followup = builder.build(
            payload=payload.model_copy(update={"message": "Continue the analysis."}),
            response_language="en",
            intent_selection=intent,
            focus_selection=focus,
            retrieval=retrieval,
            db=db,
            current_user={"username": "analyst-a", "role": "ANALYST"},
            wall_clock=lambda: 101.0,
        )

        assert package.operational_atoms
        assert package.reference_atoms
        assert package.advisory_atoms
        assert package.cross_incident_candidates[0].candidate_incident_id == candidate.id
        assert package.cross_incident_candidates[0].authoritative_rehydrated is True
        assert any(
            edge.relationship_class is RelationshipClass.SEMANTIC_SIMILARITY
            for edge in package.cross_incident_graph.relationships
        )
        assert followup.resolved_scope.conversation_followup is True
        assert followup.resolved_scope.analysis_scope.value == "EXPLICIT_RECORD_SET"
        assert followup.conversation_state_refs.related_incident_ids == [candidate.id]
        assert DiscoverySignal.EXPLICIT_SELECTION in (
            followup.cross_incident_candidates[0].discovery_signals
        )
        assert V3AnalyticalContextPackage.model_validate(package.model_dump()) == package
        invalid_package = package.model_dump()
        invalid_package["relationship_registry"] = {"relationships": []}
        with pytest.raises(ValidationError):
            V3AnalyticalContextPackage.model_validate(invalid_package)
    finally:
        db.close()


def test_case_scope_builds_multi_incident_graph_and_visible_pattern() -> None:
    db, first, second = _session_with_incidents()
    try:
        third = Incident(
            wazuh_doc_id="v3-case-third",
            status="OPEN",
            timestamp="2026-08-08T13:00:00Z",
            agent="endpoint-v3",
            rule="Different registry rule",
            level=9,
            mitre=json.dumps(["T1112"]),
            risk_score=60,
            correlated=False,
            correlation_type="other_pattern",
            correlation_score=0,
            recommended_priority="MEDIUM",
        )
        case = IncidentCase(
            group_key="v3-pattern-case",
            title="V3 pattern case",
            status="OPEN",
        )
        db.add_all([third, case])
        db.flush()
        db.add_all(
            [
                CaseIncident(case_id=case.id, incident_id=first.id),
                CaseIncident(case_id=case.id, incident_id=second.id),
                CaseIncident(case_id=case.id, incident_id=third.id),
            ]
        )
        db.commit()
        linked = [_facts(first.id), _facts(second.id), _facts(third.id)]
        linked[1]["status"] = "INVESTIGATING"
        linked[2]["rule"] = "Different registry rule"
        retrieval = SimpleNamespace(
            fact_inventory={
                "source_type": "case",
                "case_id": case.id,
                "title": case.title,
                "status": case.status,
                "severity": None,
                "linked_incident_count": 3,
                "linked_incidents": linked,
            },
            sources=[
                SourceRecord(
                    source_type="case",
                    authority="authoritative",
                    record_id=str(case.id),
                    label=f"Case {case.id}",
                    excerpt="Authoritative case and linked incident records.",
                )
            ],
        )
        payload = AssistantQueryRequest(
            message="Find the recurring pattern in this case.",
            scope="case",
            case_id=case.id,
            conversation_id="case-pattern-thread",
        )
        intent = StaticIntentRouter(AnswerIntent.PATTERN_ANALYSIS).route(
            payload.message
        )
        focus = StaticFocusRouter(FocusDimension.EVIDENCE).route(payload.message)
        package = V3AnalyticalContextBuilder(
            conversation_store=ConversationStateStore(clock=lambda: 100.0)
        ).build(
            payload=payload,
            response_language="en",
            intent_selection=intent,
            focus_selection=focus,
            retrieval=retrieval,
            db=db,
            current_user={"username": "analyst-a", "role": "ANALYST"},
            wall_clock=lambda: 100.0,
        )
        plan = deterministic_answer_plan_v3(package)
        validation = GroundedAnswerPlanV3Validator().validate(
            plan,
            package=package,
        )
        rendered = RichGroundedDiscourseRenderer().render(
            plan,
            package=package,
        )
        answer = "\n\n".join(block.text for block in rendered.blocks)

        assert set(package.resolved_scope.active_incident_ids) == {
            first.id,
            second.id,
            third.id,
        }
        assert package.resolved_scope.active_case_ids == [case.id]
        assert len(package.cross_incident_candidates) == 2
        assert any(
            relationship.relationship_type.value == "SAME_CASE"
            for relationship in package.cross_incident_graph.relationships
        )
        assert validation.accepted is True
        pattern_section = next(
            section
            for section in plan.sections
            if section.section_type is AnswerSectionType.PATTERN
        )
        assert all(
            unit.unit_type is AnalyticalUnitType.SHARED_PATTERN
            for unit in pattern_section.units
        )
        assert "3 incidents" in answer
        assert "explicit record set includes" in answer.casefold()
        assert "ranking indicates comparison utility, not risk or compromise" in answer
        assert "does not establish causality" in answer
        assert "share the same attacker" not in answer.casefold()
        assert "form the same campaign" not in answer.casefold()
    finally:
        db.close()


def test_orchestrator_builds_v3_metadata_but_calls_provider_once(monkeypatch) -> None:
    captured_retrieval_payloads = []
    retrieval = RetrievalResult(
        scope="incident",
        incident_id=1,
        fact_inventory=_facts(1),
        sources=[
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id="1",
                label="Incident 1",
                excerpt="Incident 1 status OPEN.",
            )
        ],
    )

    def retrieve(payload, **kwargs):
        captured_retrieval_payloads.append(payload)
        return retrieval

    monkeypatch.setattr("services.assistant.orchestrator.retrieve_assistant_context", retrieve)
    provider_calls = []

    def generator(**kwargs):
        provider_calls.append(kwargs)
        return {"safe_error": "gateway_unavailable"}

    class Db:
        def close(self):
            pass

    intent_router = StaticIntentRouter(AnswerIntent.FACT_LOOKUP)
    response = run_assistant_query(
        AssistantQueryRequest(
            message="Which status is recorded?",
            scope="incident",
            incident_id=1,
            include_semantic_memory=True,
        ),
        current_user={"username": "analyst-a", "role": "ANALYST"},
        settings=_settings(),
        db_factory=Db,
        generator=generator,
        intent_router=intent_router,
        focus_router=StaticFocusRouter(FocusDimension.STATUS),
    )

    assert len(provider_calls) == 1
    assert intent_router.calls == 1
    assert captured_retrieval_payloads[0].include_semantic_memory is False
    assert response.metadata.assistant_intent == "FACT_LOOKUP"
    assert response.metadata.analysis_scope == "CURRENT_RECORD"
    assert response.metadata.operational_atoms >= 2
    assert response.metadata.reference_atoms == 0
    assert response.metadata.advisory_atoms == 0
