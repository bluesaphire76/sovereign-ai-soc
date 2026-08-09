from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from services.assistant.v3.contracts import (
    AnalyticalFocus,
    AnswerIntent,
    EvidenceAtom,
    FactField,
    PriorityAtom,
    RecordedCorrelationAtom,
    ReferenceKnowledgeAtom,
    RiskAtom,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    AnswerSectionType,
    EvidencePriority,
    PropositionImportance,
    PropositionType,
    RhetoricalRole,
    SurfaceVariant,
    UNIT_PROPOSITION_TYPES,
)


@dataclass(frozen=True)
class IntentUsefulnessContract:
    min_sections: int
    max_sections: int
    min_units: int
    max_units: int


INTENT_USEFULNESS_CONTRACTS: dict[AnswerIntent, IntentUsefulnessContract] = {
    AnswerIntent.FACT_LOOKUP: IntentUsefulnessContract(1, 2, 1, 3),
    AnswerIntent.EXPLAIN: IntentUsefulnessContract(2, 5, 2, 8),
    AnswerIntent.INVESTIGATE: IntentUsefulnessContract(2, 5, 3, 8),
    AnswerIntent.SUMMARY: IntentUsefulnessContract(2, 4, 2, 6),
    AnswerIntent.COMPARE: IntentUsefulnessContract(3, 5, 3, 8),
    AnswerIntent.CROSS_INCIDENT_ANALYSIS: IntentUsefulnessContract(3, 5, 3, 9),
    AnswerIntent.PATTERN_ANALYSIS: IntentUsefulnessContract(2, 5, 3, 5),
    AnswerIntent.NEXT_ACTION: IntentUsefulnessContract(2, 4, 2, 6),
    AnswerIntent.HANDOVER: IntentUsefulnessContract(3, 5, 3, 8),
    AnswerIntent.EXECUTIVE_SUMMARY: IntentUsefulnessContract(1, 3, 2, 5),
}


_ATOM_ORDER: dict[AnswerIntent, tuple[str, ...]] = {
    AnswerIntent.FACT_LOOKUP: (
        "status",
        "risk",
        "priority",
        "host",
        "detection",
        "recorded_correlation",
        "escalation_state",
        "incident_identity",
    ),
    AnswerIntent.EXPLAIN: (
        "detection",
        "status",
        "host",
        "mitre_technique",
        "recorded_correlation",
        "risk",
        "priority",
        "timeline_event",
        "incident_identity",
    ),
    AnswerIntent.INVESTIGATE: (
        "detection",
        "evidence",
        "observable",
        "process",
        "timeline_event",
        "status",
        "host",
        "user",
        "mitre_technique",
        "recorded_correlation",
        "incident_identity",
    ),
    AnswerIntent.SUMMARY: (
        "status",
        "detection",
        "priority",
        "risk",
        "recorded_correlation",
        "case_relationship",
        "host",
        "incident_identity",
    ),
    AnswerIntent.COMPARE: (
        "status",
        "host",
        "detection",
        "mitre_technique",
        "risk",
        "priority",
        "recorded_correlation",
        "timeline_event",
        "incident_identity",
    ),
    AnswerIntent.CROSS_INCIDENT_ANALYSIS: (
        "detection",
        "host",
        "mitre_technique",
        "recorded_correlation",
        "status",
        "timeline_event",
        "case_relationship",
        "incident_identity",
    ),
    AnswerIntent.PATTERN_ANALYSIS: (
        "detection",
        "host",
        "mitre_technique",
        "recorded_correlation",
        "timeline_event",
        "status",
        "incident_identity",
    ),
    AnswerIntent.NEXT_ACTION: (
        "detection",
        "evidence",
        "observable",
        "process",
        "timeline_event",
        "host",
        "status",
        "incident_identity",
    ),
    AnswerIntent.HANDOVER: (
        "status",
        "detection",
        "priority",
        "risk",
        "recorded_correlation",
        "timeline_event",
        "host",
        "case_relationship",
        "incident_identity",
    ),
    AnswerIntent.EXECUTIVE_SUMMARY: (
        "status",
        "priority",
        "risk",
        "case_relationship",
        "recorded_correlation",
        "detection",
        "host",
        "incident_identity",
        "timeline_event",
    ),
}

_FOCUS_ATOM_TYPES: dict[AnalyticalFocus, frozenset[str]] = {
    AnalyticalFocus.RISK: frozenset({"risk"}),
    AnalyticalFocus.CORRELATION: frozenset({"recorded_correlation"}),
    AnalyticalFocus.SEVERITY: frozenset({"status"}),
    AnalyticalFocus.STATUS: frozenset({"status"}),
    AnalyticalFocus.HOST: frozenset({"host"}),
    AnalyticalFocus.EVIDENCE: frozenset(
        {"detection", "evidence", "observable", "process", "timeline_event"}
    ),
    AnalyticalFocus.PRIORITY: frozenset({"priority"}),
    AnalyticalFocus.ESCALATION: frozenset(
        {"escalation_state", "escalation_reason"}
    ),
    AnalyticalFocus.GENERAL: frozenset(),
}

_OPTIONAL_ATOM_TYPES: dict[AnswerIntent, frozenset[str]] = {
    AnswerIntent.EXECUTIVE_SUMMARY: frozenset(
        {"incident_identity", "timeline_event", "mitre_technique"}
    ),
}

_PRIORITY_RANK = {
    EvidencePriority.PRIMARY: 0,
    EvidencePriority.SUPPORTING: 1,
    EvidencePriority.CONTEXTUAL: 2,
    EvidencePriority.OPTIONAL: 3,
}


def evidence_priority_for_atom(
    package: V3AnalyticalContextPackage,
    atom: EvidenceAtom,
) -> EvidencePriority:
    order = _ATOM_ORDER[package.intent_selection.primary_intent]
    try:
        position = order.index(atom.atom_type)
    except ValueError:
        position = len(order)
    focused_types = {
        atom_type
        for focus in package.focus_selection
        for atom_type in _FOCUS_ATOM_TYPES[focus]
    }
    if (
        atom.atom_type
        in _OPTIONAL_ATOM_TYPES.get(
            package.intent_selection.primary_intent,
            frozenset(),
        )
        and atom.atom_type not in focused_types
    ):
        return EvidencePriority.OPTIONAL
    if atom.atom_type in focused_types:
        position = max(0, position - 2)
    if position <= 2:
        priority = EvidencePriority.PRIMARY
    elif position <= 5:
        priority = EvidencePriority.SUPPORTING
    elif position < len(order):
        priority = EvidencePriority.CONTEXTUAL
    else:
        priority = EvidencePriority.OPTIONAL
    if (
        package.intent_selection.primary_intent
        in {
            AnswerIntent.CROSS_INCIDENT_ANALYSIS,
            AnswerIntent.PATTERN_ANALYSIS,
        }
        and priority is EvidencePriority.PRIMARY
    ):
        return EvidencePriority.SUPPORTING
    return priority


def rank_operational_atoms(
    package: V3AnalyticalContextPackage,
    atoms: Iterable[EvidenceAtom],
) -> list[EvidenceAtom]:
    explicit = package.resolved_scope.explicit_compare_incident_ids
    active = explicit or package.resolved_scope.active_incident_ids
    scope_rank = {incident_id: index for index, incident_id in enumerate(active)}
    order = _ATOM_ORDER[package.intent_selection.primary_intent]
    atom_type_rank = {atom_type: index for index, atom_type in enumerate(order)}
    return sorted(
        atoms,
        key=lambda atom: (
            _PRIORITY_RANK[evidence_priority_for_atom(package, atom)],
            scope_rank.get(atom.incident_id, len(scope_rank) + 1),
            atom_type_rank.get(atom.atom_type, len(atom_type_rank) + 1),
            atom.incident_id or 0,
            atom.case_id or 0,
            atom.atom_id,
        ),
    )


def reference_is_relevant(
    package: V3AnalyticalContextPackage,
    atom: ReferenceKnowledgeAtom,
) -> bool:
    intent = package.intent_selection.primary_intent
    focus = set(package.focus_selection)
    if atom.knowledge_type == "mitre_definition":
        return intent in {AnswerIntent.EXPLAIN, AnswerIntent.INVESTIGATE}
    if atom.knowledge_type == "correlation_semantics":
        return (
            intent
            in {
                AnswerIntent.COMPARE,
                AnswerIntent.CROSS_INCIDENT_ANALYSIS,
                AnswerIntent.PATTERN_ANALYSIS,
            }
            or AnalyticalFocus.CORRELATION in focus
            or (
                intent in {AnswerIntent.EXPLAIN, AnswerIntent.INVESTIGATE}
                and any(
                    isinstance(item, RecordedCorrelationAtom)
                    for item in package.operational_atoms
                )
            )
        )
    if atom.knowledge_type == "risk_methodology":
        return bool(
            focus.intersection(
                {
                    AnalyticalFocus.RISK,
                    AnalyticalFocus.SEVERITY,
                    AnalyticalFocus.PRIORITY,
                }
            )
            or (
                intent in {AnswerIntent.EXPLAIN, AnswerIntent.INVESTIGATE}
                and any(
                    isinstance(item, (RiskAtom, PriorityAtom))
                    for item in package.operational_atoms
                )
            )
        )
    return intent in {AnswerIntent.EXPLAIN, AnswerIntent.INVESTIGATE}


def absence_is_material(
    package: V3AnalyticalContextPackage,
    field: FactField,
) -> bool:
    focus = set(package.focus_selection)
    if field is FactField.SEVERITY:
        return AnalyticalFocus.SEVERITY in focus
    if field is FactField.ESCALATED:
        return AnalyticalFocus.ESCALATION in focus
    return package.intent_selection.primary_intent is AnswerIntent.FACT_LOOKUP


SECTION_PROPOSITION_TYPES: dict[
    AnswerSectionType,
    frozenset[PropositionType],
] = {
    AnswerSectionType.DIRECT_ANSWER: frozenset(
        {
            PropositionType.PRIMARY_FINDING,
            PropositionType.HANDOVER_POINT,
            PropositionType.EXECUTIVE_POINT,
            PropositionType.UNCERTAINTY,
        }
    ),
    AnswerSectionType.KEY_FINDINGS: frozenset(
        {
            PropositionType.PRIMARY_FINDING,
            PropositionType.SUPPORTING_EVIDENCE,
            PropositionType.EVIDENCE_STRENGTH,
            PropositionType.EXECUTIVE_POINT,
        }
    ),
    AnswerSectionType.INCIDENT_OVERVIEW: frozenset(
        {
            PropositionType.PRIMARY_FINDING,
            PropositionType.HANDOVER_POINT,
            PropositionType.SUPPORTING_EVIDENCE,
        }
    ),
    AnswerSectionType.EVIDENCE: frozenset(
        {PropositionType.SUPPORTING_EVIDENCE, PropositionType.EVIDENCE_STRENGTH}
    ),
    AnswerSectionType.TIMELINE: frozenset({PropositionType.SUPPORTING_EVIDENCE}),
    AnswerSectionType.RELATED_INCIDENTS: frozenset(
        {
            PropositionType.RELATIONSHIP_SUMMARY,
            PropositionType.COMPARATIVE_FINDING,
            PropositionType.EVIDENCE_STRENGTH,
            PropositionType.SIMILARITY,
        }
    ),
    AnswerSectionType.COMPARISON: frozenset(
        {
            PropositionType.COMPARATIVE_FINDING,
            PropositionType.SIMILARITY,
            PropositionType.DIFFERENCE,
        }
    ),
    AnswerSectionType.PATTERN: frozenset({PropositionType.PATTERN_SUMMARY}),
    AnswerSectionType.TECHNICAL_CONTEXT: frozenset(
        {PropositionType.TECHNICAL_SIGNIFICANCE}
    ),
    AnswerSectionType.WHAT_WE_CAN_CONCLUDE: frozenset(
        {PropositionType.PRIMARY_FINDING, PropositionType.EVIDENCE_STRENGTH}
    ),
    AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE: frozenset(
        {PropositionType.CAVEAT, PropositionType.UNCERTAINTY}
    ),
    AnswerSectionType.NEXT_STEPS: frozenset(
        {
            PropositionType.INVESTIGATIVE_STEP,
            PropositionType.EXPECTED_VERIFICATION_TARGET,
        }
    ),
    AnswerSectionType.LIMITATIONS: frozenset(
        {PropositionType.CAVEAT, PropositionType.UNCERTAINTY}
    ),
}

PROPOSITION_ROLES: dict[PropositionType, frozenset[RhetoricalRole]] = {
    PropositionType.PRIMARY_FINDING: frozenset(
        {RhetoricalRole.LEAD, RhetoricalRole.EXPLAIN}
    ),
    PropositionType.SUPPORTING_EVIDENCE: frozenset(
        {RhetoricalRole.SUPPORT, RhetoricalRole.EXPLANATION}
    ),
    PropositionType.TECHNICAL_SIGNIFICANCE: frozenset(
        {RhetoricalRole.EXPLAIN, RhetoricalRole.EXPLANATION}
    ),
    PropositionType.COMPARATIVE_FINDING: frozenset(
        {RhetoricalRole.COMPARE, RhetoricalRole.CONTRAST}
    ),
    PropositionType.SIMILARITY: frozenset({RhetoricalRole.COMPARE}),
    PropositionType.DIFFERENCE: frozenset({RhetoricalRole.CONTRAST}),
    PropositionType.RELATIONSHIP_SUMMARY: frozenset(
        {RhetoricalRole.COMPARE, RhetoricalRole.EXPLAIN}
    ),
    PropositionType.PATTERN_SUMMARY: frozenset(
        {RhetoricalRole.COMPARE, RhetoricalRole.EXPLAIN}
    ),
    PropositionType.EVIDENCE_STRENGTH: frozenset(
        {RhetoricalRole.SUPPORT, RhetoricalRole.EXPLAIN}
    ),
    PropositionType.UNCERTAINTY: frozenset({RhetoricalRole.CAVEAT}),
    PropositionType.CAVEAT: frozenset({RhetoricalRole.CAVEAT}),
    PropositionType.INVESTIGATIVE_STEP: frozenset({RhetoricalRole.FOLLOW_UP}),
    PropositionType.EXPECTED_VERIFICATION_TARGET: frozenset(
        {RhetoricalRole.FOLLOW_UP, RhetoricalRole.EXPLANATION}
    ),
    PropositionType.HANDOVER_POINT: frozenset(
        {RhetoricalRole.LEAD, RhetoricalRole.SUPPORT}
    ),
    PropositionType.EXECUTIVE_POINT: frozenset(
        {RhetoricalRole.LEAD, RhetoricalRole.SUPPORT}
    ),
}


def proposition_types_for(
    section_type: AnswerSectionType,
    unit_type: AnalyticalUnitType,
    *,
    intent: AnswerIntent | None = None,
) -> tuple[PropositionType, ...]:
    selected = set(
        SECTION_PROPOSITION_TYPES[section_type].intersection(
            UNIT_PROPOSITION_TYPES[unit_type]
        )
    )
    if intent is not AnswerIntent.EXECUTIVE_SUMMARY:
        selected.discard(PropositionType.EXECUTIVE_POINT)
    if intent is not AnswerIntent.HANDOVER:
        selected.discard(PropositionType.HANDOVER_POINT)
    if intent is AnswerIntent.EXECUTIVE_SUMMARY and section_type is AnswerSectionType.DIRECT_ANSWER:
        selected.intersection_update(
            {PropositionType.EXECUTIVE_POINT, PropositionType.UNCERTAINTY}
        )
    if intent is AnswerIntent.HANDOVER and section_type in {
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.INCIDENT_OVERVIEW,
    }:
        selected.intersection_update(
            {PropositionType.HANDOVER_POINT, PropositionType.UNCERTAINTY}
        )
    return tuple(sorted(selected, key=lambda item: item.value))


def rhetorical_roles_for(
    proposition_types: Iterable[PropositionType],
) -> tuple[RhetoricalRole, ...]:
    roles = {
        role
        for proposition_type in proposition_types
        for role in PROPOSITION_ROLES[proposition_type]
    }
    return tuple(sorted(roles, key=lambda item: item.value))


def default_proposition_type(
    *,
    intent: AnswerIntent,
    section_type: AnswerSectionType,
    unit_type: AnalyticalUnitType,
) -> PropositionType:
    if section_type is AnswerSectionType.DIRECT_ANSWER:
        if intent is AnswerIntent.EXECUTIVE_SUMMARY:
            return PropositionType.EXECUTIVE_POINT
        if intent is AnswerIntent.HANDOVER:
            return PropositionType.HANDOVER_POINT
        if unit_type in {AnalyticalUnitType.ABSENCE, AnalyticalUnitType.LIMITATION}:
            return PropositionType.UNCERTAINTY
        return PropositionType.PRIMARY_FINDING
    if section_type is AnswerSectionType.COMPARISON:
        return (
            PropositionType.DIFFERENCE
            if unit_type is AnalyticalUnitType.DIFFERENCE
            else PropositionType.COMPARATIVE_FINDING
        )
    if section_type is AnswerSectionType.RELATED_INCIDENTS:
        return PropositionType.RELATIONSHIP_SUMMARY
    if section_type is AnswerSectionType.PATTERN:
        return PropositionType.PATTERN_SUMMARY
    if section_type is AnswerSectionType.TECHNICAL_CONTEXT:
        return PropositionType.TECHNICAL_SIGNIFICANCE
    if section_type in {
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.LIMITATIONS,
    }:
        return PropositionType.CAVEAT
    if section_type is AnswerSectionType.NEXT_STEPS:
        return PropositionType.INVESTIGATIVE_STEP
    if section_type is AnswerSectionType.INCIDENT_OVERVIEW and intent is AnswerIntent.HANDOVER:
        return PropositionType.HANDOVER_POINT
    if section_type is AnswerSectionType.KEY_FINDINGS and intent is AnswerIntent.EXECUTIVE_SUMMARY:
        return PropositionType.EXECUTIVE_POINT
    return PropositionType.SUPPORTING_EVIDENCE


def default_importance(section_type: AnswerSectionType) -> PropositionImportance:
    if section_type in {
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.KEY_FINDINGS,
        AnswerSectionType.COMPARISON,
        AnswerSectionType.RELATED_INCIDENTS,
        AnswerSectionType.PATTERN,
    }:
        return PropositionImportance.PRIMARY
    if section_type in {
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.LIMITATIONS,
    }:
        return PropositionImportance.SECONDARY
    return PropositionImportance.SUPPORTING


def default_rhetorical_role(proposition_type: PropositionType) -> RhetoricalRole:
    if proposition_type in {
        PropositionType.PRIMARY_FINDING,
        PropositionType.HANDOVER_POINT,
        PropositionType.EXECUTIVE_POINT,
    }:
        return RhetoricalRole.LEAD
    if proposition_type in {
        PropositionType.COMPARATIVE_FINDING,
        PropositionType.SIMILARITY,
        PropositionType.RELATIONSHIP_SUMMARY,
        PropositionType.PATTERN_SUMMARY,
    }:
        return RhetoricalRole.COMPARE
    if proposition_type is PropositionType.DIFFERENCE:
        return RhetoricalRole.CONTRAST
    if proposition_type in {PropositionType.CAVEAT, PropositionType.UNCERTAINTY}:
        return RhetoricalRole.CAVEAT
    if proposition_type in {
        PropositionType.INVESTIGATIVE_STEP,
        PropositionType.EXPECTED_VERIFICATION_TARGET,
    }:
        return RhetoricalRole.FOLLOW_UP
    if proposition_type is PropositionType.TECHNICAL_SIGNIFICANCE:
        return RhetoricalRole.EXPLAIN
    return RhetoricalRole.SUPPORT


def subject_record_ids_for_unit(
    unit: AnalyticalUnit,
    *,
    package: V3AnalyticalContextPackage,
) -> list[int]:
    atoms = {item.atom_id: item for item in package.operational_atoms}
    relationships = {
        item.relationship_id: item
        for item in package.relationship_registry.relationships
    }
    candidates = {
        item.candidate_id: item for item in package.cross_incident_candidates
    }
    result: list[int] = []
    for ref in unit.fact_refs:
        atom = atoms.get(ref)
        if atom is not None:
            result.extend(
                value
                for value in (atom.incident_id, atom.case_id)
                if value is not None
            )
    for ref in unit.relationship_refs:
        relationship = relationships.get(ref)
        if relationship is not None:
            result.extend(
                [relationship.left_incident_id, relationship.right_incident_id]
            )
    for ref in unit.candidate_refs:
        candidate = candidates.get(ref)
        if candidate is not None:
            result.append(candidate.candidate_incident_id)
    if unit.reference_refs or unit.advisory_refs:
        result.extend(package.resolved_scope.active_incident_ids)
        result.extend(package.resolved_scope.active_case_ids)
    return list(dict.fromkeys(result))[:12]


def evidence_priority_for_unit(
    unit: AnalyticalUnit,
    *,
    package: V3AnalyticalContextPackage,
) -> EvidencePriority:
    atoms = {item.atom_id: item for item in package.operational_atoms}
    priorities = [
        evidence_priority_for_atom(package, atoms[ref])
        for ref in unit.fact_refs
        if ref in atoms
    ]
    if unit.relationship_refs or unit.candidate_refs:
        return EvidencePriority.PRIMARY
    if unit.advisory_refs:
        return (
            EvidencePriority.PRIMARY
            if package.intent_selection.primary_intent is AnswerIntent.NEXT_ACTION
            else EvidencePriority.SUPPORTING
        )
    if unit.reference_refs:
        return EvidencePriority.CONTEXTUAL
    if not priorities:
        return EvidencePriority.CONTEXTUAL
    return min(priorities, key=lambda item: _PRIORITY_RANK[item])


def enrich_unit(
    unit: AnalyticalUnit,
    *,
    package: V3AnalyticalContextPackage,
    section_type: AnswerSectionType,
    proposition_type: PropositionType | None = None,
    importance: PropositionImportance | None = None,
    rhetorical_role: RhetoricalRole | None = None,
) -> AnalyticalUnit:
    selected_proposition = proposition_type or default_proposition_type(
        intent=package.intent_selection.primary_intent,
        section_type=section_type,
        unit_type=unit.unit_type,
    )
    selected_role = rhetorical_role or default_rhetorical_role(selected_proposition)
    surface = (
        SurfaceVariant.CONTRASTIVE
        if selected_role is RhetoricalRole.CONTRAST
        else SurfaceVariant.COMPARISON_LED
        if selected_role is RhetoricalRole.COMPARE
        else SurfaceVariant.EVIDENCE_LED
        if selected_role is RhetoricalRole.SUPPORT
        else SurfaceVariant.SUMMARY_LED
    )
    prepared = unit.model_copy(
        update={
            "proposition_type": selected_proposition,
            "importance": importance or default_importance(section_type),
            "rhetorical_role": selected_role,
            "surface_variant": surface,
        }
    )
    return prepared.model_copy(
        update={
            "evidence_priority": evidence_priority_for_unit(
                prepared,
                package=package,
            ),
            "subject_record_ids": subject_record_ids_for_unit(
                prepared,
                package=package,
            ),
        }
    )


def limitation_may_lead(package: V3AnalyticalContextPackage) -> bool:
    if not package.operational_atoms:
        return True
    if package.intent_selection.primary_intent is not AnswerIntent.FACT_LOOKUP:
        return False
    return bool(
        set(package.focus_selection).intersection(
            {AnalyticalFocus.SEVERITY, AnalyticalFocus.ESCALATION}
        )
    )


def plan_contract(intent: AnswerIntent) -> IntentUsefulnessContract:
    return INTENT_USEFULNESS_CONTRACTS[intent]
