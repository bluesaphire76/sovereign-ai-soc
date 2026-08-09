from __future__ import annotations

import pytest

from services.assistant.focus import FocusDimension, FocusSelection
from services.assistant.sources import SourceRecord
from services.assistant.v3.atoms import OperationalAtomNormalizer
from services.assistant.v3.contracts import (
    AnswerIntent,
    AuthorityClass,
    CompromiseStateAtom,
    ContextRequirement,
    EscalationReasonAtom,
    EscalationStateAtom,
    FactField,
    IncidentIdentityAtom,
    IntentSelection,
    MitreTechniqueAtom,
    RecordedCorrelationAtom,
    TimelineEventAtom,
)
from services.assistant.v3.knowledge import ReferenceKnowledgeProvider, normalize_advisory_sources
from services.assistant.v3.policy import ContextPolicyEngine, resolve_analysis_scope


def _plan(intent_value: AnswerIntent):
    intent = IntentSelection(
        primary_intent=intent_value,
        confidence=1.0,
        routing_status="ok",
        routing_ms=0.0,
    )
    scope = resolve_analysis_scope(
        request_scope="incident",
        incident_id=42,
        case_id=None,
        intent=intent,
        conversation_state=None,
    )
    facts = {
        "source_type": "incident",
        "incident_id": 42,
        "status": "NEW",
        "severity": None,
        "timestamp": "2026-08-08T10:00:00Z",
        "agent": "soc-endpoint-4",
        "rule": "Registry value modified",
        "wazuh_level": 11,
        "risk_score": 76,
        "risk_normalization_severity": "HIGH",
        "recommended_priority": "HIGH",
        "mitre": [
            {"id": "T1112", "name": "Modify Registry"},
            {"unexpected": "ignored"},
        ],
        "correlated": True,
        "correlation_type": "endpoint_pattern",
        "correlation_score": 75,
        "latest_timeline_event": {
            "event_type": "INCIDENT_CREATED",
            "created_at": "2026-08-08T10:01:00Z",
            "unbounded": {"ignored": True},
        },
        "compromise_confirmed": None,
        "linked_case_ids": [7],
    }
    return facts, ContextPolicyEngine().plan(
        intent=intent,
        focus=FocusSelection(dimensions=(FocusDimension.GENERAL,), confidence=1.0),
        resolved_scope=scope,
        available_facts=facts,
        conversation_state=None,
    )


def test_structured_operational_evidence_becomes_typed_atoms_with_provenance() -> None:
    facts, plan = _plan(AnswerIntent.EXPLAIN)
    atoms = OperationalAtomNormalizer().normalize(facts=facts, plan=plan)

    assert any(isinstance(atom, IncidentIdentityAtom) for atom in atoms)
    mitre = next(atom for atom in atoms if isinstance(atom, MitreTechniqueAtom))
    timeline = next(atom for atom in atoms if isinstance(atom, TimelineEventAtom))
    compromise = next(atom for atom in atoms if isinstance(atom, CompromiseStateAtom))
    assert mitre.technique_id == "T1112"
    assert mitre.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
    assert mitre.provenance.source_record_id == "42"
    assert timeline.event_type == "INCIDENT_CREATED"
    assert compromise.compromise_confirmed is None
    assert all(not hasattr(atom, "unbounded") for atom in atoms)


def test_missing_structured_fields_do_not_create_fabricated_atoms() -> None:
    facts, plan = _plan(AnswerIntent.EXPLAIN)
    facts["mitre"] = [{"unexpected": "value"}]
    facts["latest_timeline_event"] = {}
    facts.pop("correlated")
    atoms = OperationalAtomNormalizer().normalize(facts=facts, plan=plan)

    assert not any(isinstance(atom, MitreTechniqueAtom) for atom in atoms)
    assert not any(isinstance(atom, TimelineEventAtom) for atom in atoms)
    correlation = next(atom for atom in atoms if isinstance(atom, RecordedCorrelationAtom))
    assert correlation.correlated is None


def test_structured_values_are_not_coerced_into_visible_atom_text() -> None:
    facts, plan = _plan(AnswerIntent.EXPLAIN)
    facts["mitre"] = [
        {
            "id": "T1112",
            "name": (
                "{'technique': ['Modify Registry'], "
                "'tactic': ['Defense Evasion']}"
            ),
        }
    ]

    atoms = OperationalAtomNormalizer().normalize(facts=facts, plan=plan)
    mitre = next(atom for atom in atoms if isinstance(atom, MitreTechniqueAtom))

    assert mitre.technique_id == "T1112"
    assert mitre.technique_name is None
    assert "Modify Registry" not in str(mitre.technique_name)


def _escalation_plan(facts: dict):
    intent = IntentSelection(
        primary_intent=AnswerIntent.FACT_LOOKUP,
        confidence=1.0,
        routing_status="ok",
        routing_ms=0.0,
    )
    scope = resolve_analysis_scope(
        request_scope="incident",
        incident_id=facts["incident_id"],
        case_id=None,
        intent=intent,
        conversation_state=None,
    )
    return ContextPolicyEngine().plan(
        intent=intent,
        focus=FocusSelection(dimensions=(FocusDimension.ESCALATION,), confidence=1.0),
        resolved_scope=scope,
        available_facts=facts,
        conversation_state=None,
    )


def test_escalation_reason_or_non_boolean_value_never_infers_state() -> None:
    missing_facts = {"source_type": "incident", "incident_id": 42}
    missing_plan = _escalation_plan(missing_facts)
    missing_atoms = OperationalAtomNormalizer().normalize(
        facts=missing_facts,
        plan=missing_plan,
    )
    assert not any(isinstance(atom, EscalationStateAtom) for atom in missing_atoms)

    facts = {
        "source_type": "incident",
        "incident_id": 42,
        "escalation_reason": "Repeated failures",
    }
    plan = _escalation_plan(facts)
    atoms = OperationalAtomNormalizer().normalize(facts=facts, plan=plan)

    assert ContextRequirement.ESCALATION in plan.requirements
    assert FactField.ESCALATION_REASON in plan.fact_fields
    assert FactField.ESCALATED not in plan.fact_fields
    assert any(isinstance(atom, EscalationReasonAtom) for atom in atoms)
    assert not any(isinstance(atom, EscalationStateAtom) for atom in atoms)

    facts["escalated"] = "false"
    plan = _escalation_plan(facts)
    atoms = OperationalAtomNormalizer().normalize(facts=facts, plan=plan)
    assert FactField.ESCALATED in plan.fact_fields
    assert not any(isinstance(atom, EscalationStateAtom) for atom in atoms)


@pytest.mark.parametrize("explicit_state", [False, True])
def test_only_explicit_authoritative_boolean_creates_escalation_state(
    explicit_state: bool,
) -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 42,
        "escalated": explicit_state,
    }
    plan = _escalation_plan(facts)
    atoms = OperationalAtomNormalizer().normalize(facts=facts, plan=plan)

    state = next(atom for atom in atoms if isinstance(atom, EscalationStateAtom))
    assert state.escalated is explicit_state
    assert state.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
    assert not any(isinstance(atom, EscalationReasonAtom) for atom in atoms)


def test_reference_and_advisory_knowledge_remain_separate_authority_classes() -> None:
    _, explain_plan = _plan(AnswerIntent.EXPLAIN)
    facts, investigate_plan = _plan(AnswerIntent.INVESTIGATE)
    operational = OperationalAtomNormalizer().normalize(facts=facts, plan=investigate_plan)
    references = ReferenceKnowledgeProvider().retrieve(
        plan=explain_plan,
        operational_atoms=operational,
    )
    advisories = normalize_advisory_sources(
        [
            SourceRecord(
                source_type="knowledge_base",
                authority="advisory",
                record_id="registry-review",
                label="Registry investigation playbook",
                excerpt="Review the affected registry path and adjacent process telemetry.",
                section="Investigation",
                source_id="S2",
            )
        ],
        plan=investigate_plan,
    )

    assert references
    mitre_reference = next(
        item for item in references if item.knowledge_id == "reference:mitre:T1112"
    )
    assert mitre_reference.bounded_content == "T1112 = Modify Registry."
    assert all(item.authority_class is AuthorityClass.REFERENCE_KNOWLEDGE for item in references)
    assert advisories[0].authority_class is AuthorityClass.ADVISORY_KNOWLEDGE
    assert advisories[0].retrieved is True
    assert advisories[0].used is False
    assert all(item.authority_class is not AuthorityClass.OPERATIONAL_AUTHORITATIVE for item in advisories)


def test_reference_and_advisory_absence_does_not_create_substitutes() -> None:
    _, fact_plan = _plan(AnswerIntent.FACT_LOOKUP)

    assert ReferenceKnowledgeProvider().retrieve(plan=fact_plan, operational_atoms=[]) == []
    assert normalize_advisory_sources([], plan=fact_plan) == []
    assert ContextRequirement.REFERENCE not in fact_plan.requirements
