from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from services.assistant.v3.contracts import (
    AnswerIntent,
    AuthorityClass,
    FactField,
    RecordedCorrelationAtom,
    RelationshipType,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_contracts import (
    AnalyticalUnitType,
    AnswerSectionType,
    DiscourseOrdering,
    PropositionImportance,
    PropositionType,
    RhetoricalRole,
    INTENT_SECTION_TYPES,
    NonImplicationCode,
    PlanLimitationCode,
    SECTION_UNIT_TYPES,
)
from services.assistant.v3.quality_policy import (
    PROPOSITION_ROLES,
    absence_is_material,
    evidence_priority_for_atom,
    plan_contract,
    proposition_types_for,
    rank_operational_atoms,
    reference_is_relevant,
)


SECTION_WIRE_CODES = {
    AnswerSectionType.DIRECT_ANSWER: "answer",
    AnswerSectionType.KEY_FINDINGS: "findings",
    AnswerSectionType.INCIDENT_OVERVIEW: "overview",
    AnswerSectionType.EVIDENCE: "evidence",
    AnswerSectionType.TIMELINE: "timeline",
    AnswerSectionType.RELATED_INCIDENTS: "related",
    AnswerSectionType.COMPARISON: "compare",
    AnswerSectionType.PATTERN: "pattern",
    AnswerSectionType.TECHNICAL_CONTEXT: "technical",
    AnswerSectionType.WHAT_WE_CAN_CONCLUDE: "conclusions",
    AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE: "caveats",
    AnswerSectionType.NEXT_STEPS: "next",
    AnswerSectionType.LIMITATIONS: "limits",
}

UNIT_WIRE_CODES = {
    AnalyticalUnitType.RECORDED_FACT: "fact",
    AnalyticalUnitType.ABSENCE: "absence",
    AnalyticalUnitType.COMPARISON: "compare",
    AnalyticalUnitType.DIFFERENCE: "difference",
    AnalyticalUnitType.SHARED_PATTERN: "pattern",
    AnalyticalUnitType.RECORDED_CORRELATION: "recorded",
    AnalyticalUnitType.ANALYTICAL_RELATIONSHIP: "relationship",
    AnalyticalUnitType.SEMANTIC_SIMILARITY: "semantic",
    AnalyticalUnitType.TEMPORAL_SEQUENCE: "temporal",
    AnalyticalUnitType.REFERENCE_EXPLANATION: "reference",
    AnalyticalUnitType.NON_IMPLICATION: "non_implication",
    AnalyticalUnitType.LIMITATION: "limitation",
    AnalyticalUnitType.ADVISORY_GUIDANCE: "advisory",
    AnalyticalUnitType.NEXT_CHECK: "next_check",
    AnalyticalUnitType.CANDIDATE_RELEVANCE: "candidate",
}

PROPOSITION_WIRE_CODES = {
    PropositionType.PRIMARY_FINDING: "primary",
    PropositionType.SUPPORTING_EVIDENCE: "support",
    PropositionType.TECHNICAL_SIGNIFICANCE: "meaning",
    PropositionType.COMPARATIVE_FINDING: "comparison",
    PropositionType.SIMILARITY: "similarity",
    PropositionType.DIFFERENCE: "difference",
    PropositionType.RELATIONSHIP_SUMMARY: "relationship",
    PropositionType.PATTERN_SUMMARY: "pattern",
    PropositionType.EVIDENCE_STRENGTH: "strength",
    PropositionType.UNCERTAINTY: "uncertainty",
    PropositionType.CAVEAT: "caveat",
    PropositionType.INVESTIGATIVE_STEP: "step",
    PropositionType.EXPECTED_VERIFICATION_TARGET: "target",
    PropositionType.HANDOVER_POINT: "handover",
    PropositionType.EXECUTIVE_POINT: "executive",
}

IMPORTANCE_WIRE_CODES = {
    PropositionImportance.PRIMARY: "primary",
    PropositionImportance.SECONDARY: "secondary",
    PropositionImportance.SUPPORTING: "supporting",
}

ROLE_WIRE_CODES = {
    RhetoricalRole.LEAD: "lead",
    RhetoricalRole.SUPPORT: "support",
    RhetoricalRole.EXPLAIN: "explain",
    RhetoricalRole.COMPARE: "compare",
    RhetoricalRole.CONTRAST: "contrast",
    RhetoricalRole.CAVEAT: "caveat",
    RhetoricalRole.EXPLANATION: "explanation",
    RhetoricalRole.TRANSITION: "transition",
    RhetoricalRole.FOLLOW_UP: "follow_up",
}

DISCOURSE_WIRE_CODES = {
    (proposition_type, role): (
        f"{PROPOSITION_WIRE_CODES[proposition_type]}:{ROLE_WIRE_CODES[role]}"
    )
    for proposition_type, roles in PROPOSITION_ROLES.items()
    for role in roles
}

ORDER_WIRE_CODES = {
    DiscourseOrdering.CONCLUSION_FIRST: "conclusion",
    DiscourseOrdering.EVIDENCE_FIRST: "evidence",
    DiscourseOrdering.CHRONOLOGY_FIRST: "chronology",
    DiscourseOrdering.COMPARISON_FIRST: "comparison",
}


@dataclass(frozen=True)
class ModelFacingEvidence:
    operational_atoms: tuple[Any, ...]
    relationships: tuple[Any, ...]
    candidates: tuple[Any, ...]
    reference_atoms: tuple[Any, ...]
    advisory_atoms: tuple[Any, ...]


def model_facing_evidence(
    package: V3AnalyticalContextPackage,
) -> ModelFacingEvidence:
    explicit_compare = set(
        package.resolved_scope.explicit_compare_incident_ids
    )
    candidate_pool = package.cross_incident_candidates
    if explicit_compare:
        candidate_pool = [
            item
            for item in candidate_pool
            if item.candidate_incident_id in explicit_compare
        ]
    candidates = tuple(candidate_pool[:4])
    selected_incident_ids = set(
        package.resolved_scope.explicit_compare_incident_ids
        or package.resolved_scope.active_incident_ids
    )
    selected_case_ids = set(package.resolved_scope.active_case_ids)
    selected_incident_ids.update(
        item.candidate_incident_id for item in candidates
    )
    anchor_ids = set(package.resolved_scope.active_incident_ids[:1])
    relationships = tuple(
        item
        for item in package.cross_incident_graph.relationships
        if (
            item.left_incident_id in selected_incident_ids
            and item.right_incident_id in selected_incident_ids
            and (
                explicit_compare
                or
                not anchor_ids
                or item.left_incident_id in anchor_ids
                or item.right_incident_id in anchor_ids
            )
        )
    )[:8]
    evidence_refs = {
        ref for item in relationships for ref in item.evidence_atom_refs
    }
    selected_atoms: list[Any] = []
    ranked_atoms = rank_operational_atoms(package, package.operational_atoms)
    for atom in ranked_atoms:
        if (
            atom.atom_id in evidence_refs
            or atom.incident_id in selected_incident_ids
            or atom.case_id in selected_case_ids
        ):
            selected_atoms.append(atom)
        if len(selected_atoms) >= 32:
            break
    return ModelFacingEvidence(
        operational_atoms=tuple(selected_atoms),
        relationships=relationships,
        candidates=candidates,
        reference_atoms=tuple(
            item
            for item in package.reference_atoms
            if reference_is_relevant(package, item)
        )[:4],
        advisory_atoms=tuple(package.advisory_atoms[:2]),
    )


def available_absence_fields(package: V3AnalyticalContextPackage) -> list[FactField]:
    selected = set(package.context_plan.fact_fields)
    result: list[FactField] = []
    status_atoms = [atom for atom in package.operational_atoms if atom.atom_type == "status"]
    if FactField.SEVERITY in selected and status_atoms and all(
        atom.canonical_severity is None for atom in status_atoms
    ):
        result.append(FactField.SEVERITY)
    if FactField.ESCALATED in selected and not any(
        atom.atom_type == "escalation_state" for atom in package.operational_atoms
    ):
        result.append(FactField.ESCALATED)
    return result


def available_section_types(
    package: V3AnalyticalContextPackage,
) -> list[AnswerSectionType]:
    allowed = list(INTENT_SECTION_TYPES[package.intent_selection.primary_intent])
    if not package.cross_incident_graph.relationships:
        allowed = [
            item
            for item in allowed
            if item
            not in {
                AnswerSectionType.RELATED_INCIDENTS,
                AnswerSectionType.COMPARISON,
                AnswerSectionType.PATTERN,
            }
        ]
    if not package.reference_atoms:
        allowed = [
            item for item in allowed if item is not AnswerSectionType.TECHNICAL_CONTEXT
        ]
    if not package.advisory_atoms:
        allowed = [item for item in allowed if item is not AnswerSectionType.NEXT_STEPS]
    if not any(atom.atom_type == "timeline_event" for atom in package.operational_atoms):
        allowed = [item for item in allowed if item is not AnswerSectionType.TIMELINE]
    if not (
        available_limitation_codes(package)
        or available_non_implication_codes(package)
    ):
        allowed = [
            item for item in allowed if item is not AnswerSectionType.LIMITATIONS
        ]
    if not available_non_implication_codes(package):
        allowed = [
            item
            for item in allowed
            if item is not AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE
        ]
    return allowed or [AnswerSectionType.DIRECT_ANSWER]


def non_implication_for_relationship_type(
    relationship_type: RelationshipType,
) -> NonImplicationCode:
    if relationship_type is RelationshipType.SHARED_MITRE:
        return NonImplicationCode.SHARED_MITRE_NOT_SAME_ATTACKER
    if relationship_type in {
        RelationshipType.SHARED_HOST,
        RelationshipType.SHARED_AGENT,
    }:
        return NonImplicationCode.SHARED_HOST_NOT_COMMON_ROOT_CAUSE
    if relationship_type is RelationshipType.SAME_CASE:
        return NonImplicationCode.SAME_CASE_NOT_CAUSALITY
    if relationship_type is RelationshipType.SEMANTIC_SIMILARITY:
        return NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
    return NonImplicationCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY


def available_non_implication_codes(
    package: V3AnalyticalContextPackage,
) -> list[NonImplicationCode]:
    result: list[NonImplicationCode] = []
    relationships = package.relationship_registry.relationships
    if any(
        item.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
        for item in relationships
    ) or any(
        isinstance(atom, RecordedCorrelationAtom) for atom in package.operational_atoms
    ):
        result.append(NonImplicationCode.CORRELATION_NOT_COMPROMISE)
    for relationship in relationships:
        code = non_implication_for_relationship_type(relationship.relationship_type)
        if code not in result:
            result.append(code)
    if any(
        item.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
        for item in relationships
    ):
        result.append(NonImplicationCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY)
    if package.cross_incident_candidates:
        result.append(NonImplicationCode.CANDIDATE_RANK_NOT_RISK)
    return list(dict.fromkeys(result))


def available_limitation_codes(
    package: V3AnalyticalContextPackage,
) -> list[PlanLimitationCode]:
    result: list[PlanLimitationCode] = []
    absence_fields = available_absence_fields(package)
    if FactField.SEVERITY in absence_fields and absence_is_material(
        package,
        FactField.SEVERITY,
    ):
        result.append(PlanLimitationCode.CANONICAL_SEVERITY_NOT_RECORDED)
    if FactField.ESCALATED in absence_fields and absence_is_material(
        package,
        FactField.ESCALATED,
    ):
        result.append(PlanLimitationCode.NO_AUTHORITATIVE_ESCALATION_BOOLEAN)
    if package.context_plan.include_cross_incident and not (
        package.cross_incident_candidates
    ):
        result.append(PlanLimitationCode.NO_RELATED_INCIDENT_CANDIDATES)
    if package.semantic_index_status in {"degraded", "unavailable"}:
        result.append(PlanLimitationCode.SEMANTIC_INDEX_DEGRADED)
    if (
        package.intent_selection.primary_intent
        in {AnswerIntent.NEXT_ACTION, AnswerIntent.HANDOVER}
        and package.context_plan.include_advisory
        and not package.advisory_atoms
    ):
        result.append(PlanLimitationCode.ADVISORY_KNOWLEDGE_UNAVAILABLE)
    if any(
        item.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
        for item in package.relationship_registry.relationships
    ):
        result.append(PlanLimitationCode.EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY)
    if not package.operational_atoms:
        result.append(PlanLimitationCode.REQUESTED_DATA_NOT_RECORDED)
    return list(dict.fromkeys(result))


def available_unit_types(package: V3AnalyticalContextPackage) -> list[AnalyticalUnitType]:
    result = {AnalyticalUnitType.RECORDED_FACT}
    if available_non_implication_codes(package):
        result.add(AnalyticalUnitType.NON_IMPLICATION)
    if available_limitation_codes(package):
        result.add(AnalyticalUnitType.LIMITATION)
    if available_absence_fields(package):
        result.add(AnalyticalUnitType.ABSENCE)
    incidents = {
        atom.incident_id
        for atom in package.operational_atoms
        if atom.incident_id is not None
    }
    if len(incidents) >= 2:
        result.update({AnalyticalUnitType.COMPARISON, AnalyticalUnitType.DIFFERENCE})
    relationships = package.cross_incident_graph.relationships
    if any(
        item.relationship_class.value == "RECORDED_CORRELATION"
        and item.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
        for item in relationships
    ) or any(isinstance(atom, RecordedCorrelationAtom) for atom in package.operational_atoms):
        result.add(AnalyticalUnitType.RECORDED_CORRELATION)
    if any(
        item.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
        for item in relationships
    ):
        result.add(AnalyticalUnitType.ANALYTICAL_RELATIONSHIP)
    if any(
        item.authority_class is AuthorityClass.SEMANTIC_CANDIDATE
        for item in relationships
    ):
        result.add(AnalyticalUnitType.SEMANTIC_SIMILARITY)
    if any(item.relationship_type.value == "TEMPORAL_PROXIMITY" for item in relationships):
        result.add(AnalyticalUnitType.TEMPORAL_SEQUENCE)
    analytical_types = Counter(
        item.relationship_type
        for item in relationships
        if item.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
    )
    if any(count >= 2 for count in analytical_types.values()):
        result.add(AnalyticalUnitType.SHARED_PATTERN)
    if package.reference_atoms:
        result.add(AnalyticalUnitType.REFERENCE_EXPLANATION)
    if package.advisory_atoms:
        result.update(
            {AnalyticalUnitType.ADVISORY_GUIDANCE, AnalyticalUnitType.NEXT_CHECK}
        )
    if package.cross_incident_candidates:
        result.add(AnalyticalUnitType.CANDIDATE_RELEVANCE)
    return sorted(result, key=lambda item: item.value)


def _ref_array(
    values: list[str],
    maximum: int,
    *,
    minimum: int = 1,
    prefer_grouped: bool = False,
) -> dict[str, Any]:
    limit = min(maximum, len(values))
    options: list[list[str]] = []
    if prefer_grouped:
        for size in range(limit, max(2, minimum) - 1, -1):
            options.append(values[:size])
    if minimum <= 1:
        options.extend([[value] for value in values])
    if not prefer_grouped:
        for size in range(max(2, minimum), limit + 1):
            options.append(values[:size])
    return {
        "type": "array",
        "enum": options,
    }


def _fixed_ref_array(values: list[str]) -> dict[str, Any]:
    return {
        "type": "array",
        "const": values,
    }


_INTENT_SECTION_PRIORITY: dict[AnswerIntent, tuple[AnswerSectionType, ...]] = {
    AnswerIntent.FACT_LOOKUP: (),
    AnswerIntent.EXPLAIN: (
        AnswerSectionType.TECHNICAL_CONTEXT,
        AnswerSectionType.KEY_FINDINGS,
        AnswerSectionType.EVIDENCE,
    ),
    AnswerIntent.SUMMARY: (
        AnswerSectionType.INCIDENT_OVERVIEW,
        AnswerSectionType.KEY_FINDINGS,
    ),
    AnswerIntent.INVESTIGATE: (
        AnswerSectionType.EVIDENCE,
        AnswerSectionType.TECHNICAL_CONTEXT,
        AnswerSectionType.TIMELINE,
        AnswerSectionType.NEXT_STEPS,
    ),
    AnswerIntent.COMPARE: (
        AnswerSectionType.COMPARISON,
        AnswerSectionType.RELATED_INCIDENTS,
        AnswerSectionType.EVIDENCE,
    ),
    AnswerIntent.CROSS_INCIDENT_ANALYSIS: (
        AnswerSectionType.RELATED_INCIDENTS,
        AnswerSectionType.COMPARISON,
        AnswerSectionType.PATTERN,
    ),
    AnswerIntent.PATTERN_ANALYSIS: (
        AnswerSectionType.PATTERN,
        AnswerSectionType.RELATED_INCIDENTS,
    ),
    AnswerIntent.NEXT_ACTION: (
        AnswerSectionType.NEXT_STEPS,
        AnswerSectionType.EVIDENCE,
    ),
    AnswerIntent.HANDOVER: (
        AnswerSectionType.INCIDENT_OVERVIEW,
        AnswerSectionType.NEXT_STEPS,
        AnswerSectionType.EVIDENCE,
    ),
    AnswerIntent.EXECUTIVE_SUMMARY: (
        AnswerSectionType.KEY_FINDINGS,
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
    ),
}

def _schema_definitions(
    package: V3AnalyticalContextPackage,
    *,
    view: ModelFacingEvidence,
) -> dict[str, Any]:
    fact_refs = [atom.atom_id for atom in view.operational_atoms]
    relationships = view.relationships
    definitions: dict[str, Any] = {}
    if fact_refs:
        definitions["fact_refs"] = _ref_array(fact_refs, 4)
    priority_groups: dict[str, list[str]] = {
        "PRIMARY": [],
        "SUPPORTING": [],
        "CONTEXTUAL": [],
        "OPTIONAL": [],
    }
    for atom in view.operational_atoms:
        priority_groups[evidence_priority_for_atom(package, atom).value].append(
            atom.atom_id
        )
    primary_refs = priority_groups["PRIMARY"]
    remaining_refs = [
        *primary_refs[3:],
        *priority_groups["SUPPORTING"],
        *priority_groups["CONTEXTUAL"],
        *priority_groups["OPTIONAL"],
    ]
    timeline_refs = [
        atom.atom_id
        for atom in view.operational_atoms
        if atom.atom_type == "timeline_event"
    ]
    non_timeline_remaining_refs = [
        ref for ref in remaining_refs if ref not in set(timeline_refs)
    ]
    direct_refs = primary_refs[:3] or fact_refs[:3]
    overview_refs = primary_refs[:4] or fact_refs[:4]
    findings_refs = non_timeline_remaining_refs[:6] or fact_refs[3:7]
    supporting_refs = non_timeline_remaining_refs[:10] or fact_refs[3:]
    for name, values, maximum, prefer_grouped in (
        ("direct_fact_refs", direct_refs, 3, False),
        ("overview_fact_refs", overview_refs, 4, True),
        ("findings_fact_refs", findings_refs, 4, True),
        ("supporting_fact_refs", supporting_refs, 4, True),
        ("timeline_fact_refs", timeline_refs, 2, True),
    ):
        if values:
            minimum = (
                2
                if name == "findings_fact_refs"
                and package.intent_selection.primary_intent
                is AnswerIntent.EXECUTIVE_SUMMARY
                and len(values) >= 2
                else 1
            )
            definitions[name] = _ref_array(
                values,
                maximum,
                minimum=minimum,
                prefer_grouped=prefer_grouped,
            )
    comparison_groups: dict[str, list[Any]] = {}
    for atom in view.operational_atoms:
        if atom.incident_id is not None:
            comparison_groups.setdefault(atom.atom_type, []).append(atom)
    comparison_ref_sets: dict[str, list[list[str]]] = {
        "comparison_same_refs": [],
        "comparison_difference_refs": [],
    }
    explicit_compare = package.resolved_scope.explicit_compare_incident_ids
    comparison_scope = explicit_compare or package.resolved_scope.active_incident_ids
    for atom_type in (
        "status",
        "host",
        "detection",
        "risk",
        "mitre_technique",
        "recorded_correlation",
        "incident_identity",
    ):
        grouped = comparison_groups.get(atom_type, [])
        if len({item.incident_id for item in grouped}) < 2:
            continue
        comparison_by_incident: dict[int, str] = {}
        for atom in grouped:
            if atom.incident_id is not None:
                comparison_by_incident.setdefault(atom.incident_id, atom.atom_id)
        incident_order = [
            incident_id
            for incident_id in comparison_scope
            if incident_id in comparison_by_incident
        ]
        incident_order.extend(
            incident_id
            for incident_id in sorted(comparison_by_incident)
            if incident_id not in incident_order
        )
        comparison_refs = [
            comparison_by_incident[incident_id] for incident_id in incident_order[:2]
        ]
        selected_atoms = {
            atom.incident_id: atom
            for atom in grouped
            if atom.incident_id in incident_order[:2]
        }
        payloads = [
            selected_atoms[incident_id].model_dump(
                mode="json",
                exclude={
                    "atom_id",
                    "authority_class",
                    "provenance",
                    "incident_id",
                    "case_id",
                },
            )
            for incident_id in incident_order[:2]
        ]
        definition_name = (
            "comparison_same_refs"
            if len(payloads) == 2 and payloads[0] == payloads[1]
            else "comparison_difference_refs"
        )
        if (
            len(comparison_refs) == 2
            and comparison_refs not in comparison_ref_sets[definition_name]
        ):
            comparison_ref_sets[definition_name].append(comparison_refs)
        if sum(len(values) for values in comparison_ref_sets.values()) >= 4:
            break
    for name, ref_sets in comparison_ref_sets.items():
        if ref_sets:
            definitions[name] = {"type": "array", "enum": ref_sets}
    recorded_fact_refs = [
        atom.atom_id
        for atom in view.operational_atoms
        if isinstance(atom, RecordedCorrelationAtom)
    ]
    if recorded_fact_refs:
        definitions["recorded_correlation_refs"] = _ref_array(
            recorded_fact_refs,
            2,
        )
    analytical_by_type: dict[RelationshipType, list[str]] = {}
    for relationship in relationships:
        if relationship.authority_class is AuthorityClass.ANALYTICAL_DERIVATION:
            analytical_by_type.setdefault(relationship.relationship_type, []).append(
                relationship.relationship_id
            )
    pattern_refs = max(
        (refs for refs in analytical_by_type.values() if len(refs) >= 2),
        key=lambda refs: (len(refs), refs),
        default=[],
    )
    relationship_groups = {
        "relationship_refs": [item.relationship_id for item in relationships],
        "recorded_relationship_refs": [
            item.relationship_id
            for item in relationships
            if item.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
        ],
        "analytical_relationship_refs": [
            item.relationship_id
            for item in relationships
            if item.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
        ],
        "analytical_pattern_refs": pattern_refs,
        "semantic_relationship_refs": [
            item.relationship_id
            for item in relationships
            if item.authority_class is AuthorityClass.SEMANTIC_CANDIDATE
        ],
        "temporal_relationship_refs": [
            item.relationship_id
            for item in relationships
            if item.relationship_type.value == "TEMPORAL_PROXIMITY"
            and item.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
        ],
    }
    for name, values in relationship_groups.items():
        if values:
            definitions[name] = (
                _fixed_ref_array(values[:2])
                if name == "analytical_pattern_refs"
                else _ref_array(values, 2, prefer_grouped=True)
            )
    candidate_refs = [item.candidate_id for item in view.candidates]
    reference_refs = [item.knowledge_id for item in view.reference_atoms]
    advisory_refs = [item.knowledge_id for item in view.advisory_atoms]
    for name, values, maximum in (
        ("candidate_refs", candidate_refs, 2),
        ("reference_refs", reference_refs, 2),
        ("advisory_refs", advisory_refs, 2),
    ):
        if values:
            definitions[name] = _ref_array(
                values,
                maximum,
                prefer_grouped=True,
            )
    return definitions


def _unit_schema(
    unit_type: AnalyticalUnitType,
    *,
    package: V3AnalyticalContextPackage,
    definitions: dict[str, Any],
    section_type: AnswerSectionType,
    fact_definition: str = "fact_refs",
    non_implication_codes: list[NonImplicationCode] | None = None,
) -> dict[str, Any]:
    discourse_modes = [
        DISCOURSE_WIRE_CODES[(proposition_type, role)]
        for proposition_type in proposition_types_for(
            section_type,
            unit_type,
            intent=package.intent_selection.primary_intent,
        )
        for role in sorted(
            PROPOSITION_ROLES[proposition_type],
            key=lambda item: item.value,
        )
    ]
    properties: dict[str, Any] = {
        "kind": {"type": "string", "const": UNIT_WIRE_CODES[unit_type]},
        "mode": {"type": "string", "enum": discourse_modes},
        "importance": {
            "type": "string",
            "enum": list(IMPORTANCE_WIRE_CODES.values()),
        },
    }
    required = ["kind", "mode", "importance"]

    if unit_type is AnalyticalUnitType.RECORDED_FACT:
        properties["refs"] = {"$ref": f"#/$defs/{fact_definition}"}
        required.append("refs")
    elif unit_type in {
        AnalyticalUnitType.COMPARISON,
        AnalyticalUnitType.DIFFERENCE,
    }:
        definition_name = (
            "comparison_same_refs"
            if unit_type is AnalyticalUnitType.COMPARISON
            else "comparison_difference_refs"
        )
        properties["refs"] = {"$ref": f"#/$defs/{definition_name}"}
        required.append("refs")
    elif unit_type is AnalyticalUnitType.ABSENCE:
        properties["code"] = {
            "type": "string",
            "enum": [item.value for item in available_absence_fields(package)],
        }
        required.append("code")
    elif unit_type is AnalyticalUnitType.RECORDED_CORRELATION:
        name = (
            "recorded_correlation_refs"
            if "recorded_correlation_refs" in definitions
            else "recorded_relationship_refs"
        )
        properties["refs"] = {"$ref": f"#/$defs/{name}"}
        required.append("refs")
    elif unit_type is AnalyticalUnitType.SHARED_PATTERN:
        properties["refs"] = {
            "$ref": "#/$defs/analytical_pattern_refs"
        }
        required.append("refs")
    elif unit_type is AnalyticalUnitType.ANALYTICAL_RELATIONSHIP:
        properties["refs"] = {
            "$ref": "#/$defs/analytical_relationship_refs"
        }
        required.append("refs")
    elif unit_type is AnalyticalUnitType.SEMANTIC_SIMILARITY:
        properties["refs"] = {
            "$ref": "#/$defs/semantic_relationship_refs"
        }
        required.append("refs")
    elif unit_type is AnalyticalUnitType.TEMPORAL_SEQUENCE:
        properties["refs"] = {
            "$ref": "#/$defs/temporal_relationship_refs"
        }
        required.append("refs")
    elif unit_type is AnalyticalUnitType.REFERENCE_EXPLANATION:
        properties["refs"] = {"$ref": "#/$defs/reference_refs"}
        required.append("refs")
    elif unit_type is AnalyticalUnitType.NON_IMPLICATION:
        properties["code"] = {
            "type": "string",
            "enum": [
                item.value
                for item in (
                    non_implication_codes
                    if non_implication_codes is not None
                    else available_non_implication_codes(package)
                )
            ],
        }
        required.append("code")
    elif unit_type is AnalyticalUnitType.LIMITATION:
        properties["code"] = {
            "type": "string",
            "enum": [item.value for item in available_limitation_codes(package)],
        }
        required.append("code")
    elif unit_type in {
        AnalyticalUnitType.ADVISORY_GUIDANCE,
        AnalyticalUnitType.NEXT_CHECK,
    }:
        properties["refs"] = {"$ref": "#/$defs/advisory_refs"}
        required.append("refs")
    elif unit_type is AnalyticalUnitType.CANDIDATE_RELEVANCE:
        properties["refs"] = {"$ref": "#/$defs/candidate_refs"}
        required.append("refs")

    return {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
    }


def _section_unit_bounds(
    section_type: AnswerSectionType,
    *,
    intent: AnswerIntent,
) -> tuple[int, int]:
    if section_type is AnswerSectionType.DIRECT_ANSWER:
        return (1, 1)
    if section_type is AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE:
        return (1, 1)
    if section_type is AnswerSectionType.LIMITATIONS:
        return (1, 2)
    if section_type is AnswerSectionType.COMPARISON:
        return (1, 2)
    if section_type is AnswerSectionType.EVIDENCE:
        return (1, 1)
    if section_type is AnswerSectionType.RELATED_INCIDENTS:
        return (
            (1, 1)
            if intent in {AnswerIntent.HANDOVER, AnswerIntent.PATTERN_ANALYSIS}
            else (1, 2)
        )
    if section_type is AnswerSectionType.NEXT_STEPS:
        return (1, 2)
    if section_type in {
        AnswerSectionType.PATTERN,
        AnswerSectionType.TECHNICAL_CONTEXT,
        AnswerSectionType.TIMELINE,
        AnswerSectionType.INCIDENT_OVERVIEW,
    }:
        return (1, 1)
    return (1, 2)


def _required_sections_for_intent(
    intent: AnswerIntent,
) -> tuple[AnswerSectionType, ...]:
    return {
        AnswerIntent.FACT_LOOKUP: (AnswerSectionType.DIRECT_ANSWER,),
        AnswerIntent.EXPLAIN: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.TECHNICAL_CONTEXT,
        ),
        AnswerIntent.INVESTIGATE: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.EVIDENCE,
            AnswerSectionType.TIMELINE,
        ),
        AnswerIntent.SUMMARY: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.KEY_FINDINGS,
        ),
        AnswerIntent.COMPARE: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.COMPARISON,
            AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        ),
        AnswerIntent.CROSS_INCIDENT_ANALYSIS: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.RELATED_INCIDENTS,
            AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        ),
        AnswerIntent.PATTERN_ANALYSIS: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.PATTERN,
            AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        ),
        AnswerIntent.NEXT_ACTION: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.NEXT_STEPS,
        ),
        AnswerIntent.HANDOVER: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.INCIDENT_OVERVIEW,
            AnswerSectionType.NEXT_STEPS,
        ),
        AnswerIntent.EXECUTIVE_SUMMARY: (
            AnswerSectionType.DIRECT_ANSWER,
            AnswerSectionType.KEY_FINDINGS,
        ),
    }[intent]


def _section_variants(
    *,
    intent: AnswerIntent,
    available: set[AnswerSectionType],
) -> list[list[AnswerSectionType]]:
    contract = plan_contract(intent)
    required = [
        item for item in _required_sections_for_intent(intent) if item in available
    ]
    if AnswerSectionType.DIRECT_ANSWER in available and (
        AnswerSectionType.DIRECT_ANSWER not in required
    ):
        required.insert(0, AnswerSectionType.DIRECT_ANSWER)
    if (
        intent in {AnswerIntent.NEXT_ACTION, AnswerIntent.HANDOVER}
        and AnswerSectionType.NEXT_STEPS not in available
        and AnswerSectionType.LIMITATIONS in available
    ):
        required.append(AnswerSectionType.LIMITATIONS)
    if (
        intent is AnswerIntent.INVESTIGATE
        and AnswerSectionType.TECHNICAL_CONTEXT in available
        and AnswerSectionType.TECHNICAL_CONTEXT not in required
    ):
        required.append(AnswerSectionType.TECHNICAL_CONTEXT)
    priority = [
        item
        for item in _INTENT_SECTION_PRIORITY[intent]
        if item in available and item not in required
    ]
    caveat = AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE
    if intent in {
        AnswerIntent.COMPARE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.PATTERN_ANALYSIS,
    } and caveat in available and caveat not in required:
        required.append(caveat)
    while len(required) < contract.min_sections and priority:
        required.append(priority.pop(0))
    required = list(dict.fromkeys(required))[: contract.max_sections]
    if not required:
        return []
    variants = [required.copy()]
    for section_type in priority:
        if len(variants[-1]) >= contract.max_sections:
            break
        selected = variants[-1].copy()
        insertion = len(selected)
        for terminal in (
            AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
            AnswerSectionType.LIMITATIONS,
        ):
            if terminal in selected:
                insertion = min(insertion, selected.index(terminal))
        selected.insert(insertion, section_type)
        selected = list(dict.fromkeys(selected))
        if selected not in variants:
            variants.append(selected)
    return variants[:4]


def _ordering_values(intent: AnswerIntent) -> list[str]:
    if intent in {
        AnswerIntent.COMPARE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.PATTERN_ANALYSIS,
    }:
        orderings = (
            DiscourseOrdering.COMPARISON_FIRST,
            DiscourseOrdering.CONCLUSION_FIRST,
            DiscourseOrdering.EVIDENCE_FIRST,
        )
    elif intent is AnswerIntent.INVESTIGATE:
        orderings = (
            DiscourseOrdering.EVIDENCE_FIRST,
            DiscourseOrdering.CHRONOLOGY_FIRST,
            DiscourseOrdering.CONCLUSION_FIRST,
        )
    else:
        orderings = (
            DiscourseOrdering.CONCLUSION_FIRST,
            DiscourseOrdering.EVIDENCE_FIRST,
        )
    return [ORDER_WIRE_CODES[item] for item in orderings]


def grounded_answer_plan_v3_schema(
    package: V3AnalyticalContextPackage,
) -> dict[str, Any]:
    section_types = available_section_types(package)
    view = model_facing_evidence(package)
    available_units = set(available_unit_types(package))
    definitions = _schema_definitions(package, view=view)
    definition_requirements = {
        AnalyticalUnitType.RECORDED_FACT: "fact_refs",
        AnalyticalUnitType.COMPARISON: "comparison_same_refs",
        AnalyticalUnitType.DIFFERENCE: "comparison_difference_refs",
        AnalyticalUnitType.SHARED_PATTERN: "analytical_pattern_refs",
        AnalyticalUnitType.RECORDED_CORRELATION: (
            "recorded_correlation_refs"
            if "recorded_correlation_refs" in definitions
            else "recorded_relationship_refs"
        ),
        AnalyticalUnitType.ANALYTICAL_RELATIONSHIP: "analytical_relationship_refs",
        AnalyticalUnitType.SEMANTIC_SIMILARITY: "semantic_relationship_refs",
        AnalyticalUnitType.TEMPORAL_SEQUENCE: "temporal_relationship_refs",
        AnalyticalUnitType.REFERENCE_EXPLANATION: "reference_refs",
        AnalyticalUnitType.ADVISORY_GUIDANCE: "advisory_refs",
        AnalyticalUnitType.NEXT_CHECK: "advisory_refs",
        AnalyticalUnitType.CANDIDATE_RELEVANCE: "candidate_refs",
    }
    available_units = {
        item
        for item in available_units
        if definition_requirements.get(item) in definitions
        or item not in definition_requirements
    }
    analytical_types = Counter(
        item.relationship_type
        for item in view.relationships
        if item.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
    )
    if not any(count >= 2 for count in analytical_types.values()):
        available_units.discard(AnalyticalUnitType.SHARED_PATTERN)
    primary_non_implication = (
        NonImplicationCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY
        if "analytical_relationship_refs" in definitions
        else NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
        if "semantic_relationship_refs" in definitions
        else NonImplicationCode.CANDIDATE_RANK_NOT_RISK
        if "candidate_refs" in definitions
        else NonImplicationCode.CORRELATION_NOT_COMPROMISE
    )

    section_definitions: dict[AnswerSectionType, str] = {}
    for section_type in section_types:
        eligible_units = available_units.intersection(
            SECTION_UNIT_TYPES[section_type]
        )
        fact_definition = "supporting_fact_refs"
        if section_type is AnswerSectionType.DIRECT_ANSWER:
            eligible_units.intersection_update(
                {AnalyticalUnitType.RECORDED_FACT, AnalyticalUnitType.ABSENCE}
            )
            if package.intent_selection.primary_intent is not AnswerIntent.FACT_LOOKUP:
                eligible_units.discard(AnalyticalUnitType.ABSENCE)
            fact_definition = "direct_fact_refs"
        elif section_type in {
            AnswerSectionType.KEY_FINDINGS,
            AnswerSectionType.INCIDENT_OVERVIEW,
        }:
            eligible_units.intersection_update({AnalyticalUnitType.RECORDED_FACT})
            fact_definition = (
                "findings_fact_refs"
                if section_type is AnswerSectionType.KEY_FINDINGS
                else "overview_fact_refs"
            )
        elif section_type is AnswerSectionType.RELATED_INCIDENTS:
            eligible_units.intersection_update(
                {
                    AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                    AnalyticalUnitType.SEMANTIC_SIMILARITY,
                    AnalyticalUnitType.CANDIDATE_RELEVANCE,
                }
            )
            if package.intent_selection.primary_intent is AnswerIntent.PATTERN_ANALYSIS:
                eligible_units.intersection_update(
                    {AnalyticalUnitType.ANALYTICAL_RELATIONSHIP}
                )
            elif "analytical_relationship_refs" in definitions:
                eligible_units.discard(AnalyticalUnitType.SEMANTIC_SIMILARITY)
        elif section_type is AnswerSectionType.COMPARISON:
            eligible_units.intersection_update(
                {AnalyticalUnitType.COMPARISON, AnalyticalUnitType.DIFFERENCE}
            )
        elif section_type is AnswerSectionType.EVIDENCE:
            eligible_units.intersection_update({AnalyticalUnitType.RECORDED_FACT})
        elif section_type is AnswerSectionType.TIMELINE:
            eligible_units.intersection_update({AnalyticalUnitType.RECORDED_FACT})
            fact_definition = "timeline_fact_refs"
        elif section_type is AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE:
            eligible_units.intersection_update({AnalyticalUnitType.NON_IMPLICATION})
        elif section_type is AnswerSectionType.LIMITATIONS:
            eligible_units.intersection_update({AnalyticalUnitType.LIMITATION})
        if (
            AnalyticalUnitType.RECORDED_FACT in eligible_units
            and fact_definition not in definitions
        ):
            eligible_units.remove(AnalyticalUnitType.RECORDED_FACT)
        unit_types = [
            item
            for item in sorted(eligible_units, key=lambda item: item.value)
            if proposition_types_for(
                section_type,
                item,
                intent=package.intent_selection.primary_intent,
            )
        ]
        if not unit_types:
            continue
        minimum, maximum = _section_unit_bounds(
            section_type,
            intent=package.intent_selection.primary_intent,
        )
        definition_name = f"section_{SECTION_WIRE_CODES[section_type]}"
        unit_schemas = [
            _unit_schema(
                item,
                package=package,
                definitions=definitions,
                section_type=section_type,
                fact_definition=fact_definition,
                non_implication_codes=(
                    [primary_non_implication]
                    if item is AnalyticalUnitType.NON_IMPLICATION
                    and section_type
                    is AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE
                    else None
                ),
            )
            for item in unit_types
        ]
        definitions[definition_name] = {
            "type": "array",
            "minItems": minimum,
            "maxItems": maximum,
        }
        if section_type in {
            AnswerSectionType.COMPARISON,
            AnswerSectionType.RELATED_INCIDENTS,
        } and len(unit_schemas) > 1:
            definitions[definition_name].update(
                {
                    "prefixItems": unit_schemas,
                    "minItems": len(unit_schemas),
                    "maxItems": len(unit_schemas),
                }
            )
        else:
            definitions[definition_name]["items"] = {"oneOf": unit_schemas}
        section_definitions[section_type] = definition_name

    intent = package.intent_selection.primary_intent
    variants = _section_variants(
        intent=intent,
        available=set(section_definitions),
    )
    if not variants:
        raise ValueError("no useful V3 plan shape is available")
    section_schemas = []
    for variant in variants:
        properties = {
            SECTION_WIRE_CODES[section_type]: {
                "$ref": f"#/$defs/{section_definitions[section_type]}"
            }
            for section_type in variant
        }
        section_schemas.append(
            {
                "type": "object",
                "additionalProperties": False,
                "properties": properties,
                "required": list(properties),
                "minProperties": len(properties),
                "maxProperties": len(properties),
            }
        )
    return {
        "$defs": definitions,
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "order": {
                "type": "string",
                "enum": _ordering_values(intent),
            },
            "sections": {"oneOf": section_schemas},
        },
        "required": ["order", "sections"],
    }
