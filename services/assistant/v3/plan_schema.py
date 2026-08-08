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
    INTENT_SECTION_TYPES,
    NonImplicationCode,
    PlanLimitationCode,
    SECTION_UNIT_TYPES,
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
    candidates = tuple(package.cross_incident_candidates[:4])
    selected_incident_ids = set(package.resolved_scope.active_incident_ids)
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
    for atom in package.operational_atoms:
        if atom.atom_id in evidence_refs or atom.incident_id in selected_incident_ids:
            selected_atoms.append(atom)
        if len(selected_atoms) >= 32:
            break
    return ModelFacingEvidence(
        operational_atoms=tuple(selected_atoms),
        relationships=relationships,
        candidates=candidates,
        reference_atoms=tuple(package.reference_atoms[:4]),
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
    if FactField.SEVERITY in absence_fields:
        result.append(PlanLimitationCode.CANONICAL_SEVERITY_NOT_RECORDED)
    if FactField.ESCALATED in absence_fields:
        result.append(PlanLimitationCode.NO_AUTHORITATIVE_ESCALATION_BOOLEAN)
    if package.context_plan.include_cross_incident and not (
        package.cross_incident_candidates
    ):
        result.append(PlanLimitationCode.NO_RELATED_INCIDENT_CANDIDATES)
    if package.semantic_index_status in {"degraded", "unavailable"}:
        result.append(PlanLimitationCode.SEMANTIC_INDEX_DEGRADED)
    if package.context_plan.include_reference and not package.reference_atoms:
        result.append(PlanLimitationCode.REFERENCE_KNOWLEDGE_UNAVAILABLE)
    if package.context_plan.include_advisory and not package.advisory_atoms:
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


def _ref_array(values: list[str], maximum: int, *, minimum: int = 1) -> dict[str, Any]:
    limit = min(maximum, len(values))
    options: list[list[str]] = []
    if minimum <= 1:
        options.extend([[value] for value in values])
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


_INTENT_PLAN_BOUNDS: dict[AnswerIntent, tuple[int, int]] = {
    AnswerIntent.FACT_LOOKUP: (1, 1),
    AnswerIntent.EXPLAIN: (3, 1),
    AnswerIntent.SUMMARY: (3, 1),
    AnswerIntent.INVESTIGATE: (3, 1),
    AnswerIntent.COMPARE: (4, 1),
    AnswerIntent.CROSS_INCIDENT_ANALYSIS: (3, 1),
    AnswerIntent.PATTERN_ANALYSIS: (3, 1),
    AnswerIntent.NEXT_ACTION: (3, 1),
    AnswerIntent.HANDOVER: (3, 1),
    AnswerIntent.EXECUTIVE_SUMMARY: (3, 1),
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
        AnswerSectionType.EVIDENCE,
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

_AMBIGUOUS_UNIT_TYPES = {
    AnalyticalUnitType.RECORDED_CORRELATION,
    AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
    AnalyticalUnitType.SEMANTIC_SIMILARITY,
    AnalyticalUnitType.SHARED_PATTERN,
    AnalyticalUnitType.TEMPORAL_SEQUENCE,
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
        definitions["direct_fact_refs"] = _ref_array(fact_refs[:2], 2)
    if len(fact_refs) > 2:
        definitions["supporting_fact_refs"] = _ref_array(fact_refs[2:], 4)
        definitions["overview_fact_refs"] = _ref_array(fact_refs[2:5], 3)
    if len(fact_refs) > 5:
        definitions["findings_fact_refs"] = _ref_array(fact_refs[5:8], 3)
    comparison_groups: dict[str, list[Any]] = {}
    for atom in view.operational_atoms:
        if atom.incident_id is not None:
            comparison_groups.setdefault(atom.atom_type, []).append(atom)
    comparison_atoms: list[Any] = []
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
        if len({item.incident_id for item in grouped}) >= 2:
            comparison_atoms = grouped
            break
    if comparison_atoms:
        comparison_by_incident: dict[int, str] = {}
        for atom in comparison_atoms:
            if atom.incident_id is not None:
                comparison_by_incident.setdefault(atom.incident_id, atom.atom_id)
        incident_order = [
            incident_id
            for incident_id in package.resolved_scope.active_incident_ids
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
        definitions["comparison_fact_refs"] = _fixed_ref_array(comparison_refs)
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
                else _ref_array(values, 2)
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
            definitions[name] = _ref_array(values, maximum)
    return definitions


def _unit_schema(
    unit_type: AnalyticalUnitType,
    *,
    package: V3AnalyticalContextPackage,
    definitions: dict[str, Any],
    fact_definition: str = "fact_refs",
    non_implication_codes: list[NonImplicationCode] | None = None,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "kind": {"type": "string", "const": UNIT_WIRE_CODES[unit_type]},
    }
    required = ["kind"]

    if unit_type is AnalyticalUnitType.RECORDED_FACT:
        properties["refs"] = {"$ref": f"#/$defs/{fact_definition}"}
        required.append("refs")
    elif unit_type in {
        AnalyticalUnitType.COMPARISON,
        AnalyticalUnitType.DIFFERENCE,
    }:
        properties["refs"] = {"$ref": "#/$defs/comparison_fact_refs"}
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


def grounded_answer_plan_v3_schema(
    package: V3AnalyticalContextPackage,
) -> dict[str, Any]:
    section_types = available_section_types(package)
    view = model_facing_evidence(package)
    available_units = set(available_unit_types(package))
    definitions = _schema_definitions(package, view=view)
    definition_requirements = {
        AnalyticalUnitType.RECORDED_FACT: "fact_refs",
        AnalyticalUnitType.COMPARISON: "comparison_fact_refs",
        AnalyticalUnitType.DIFFERENCE: "comparison_fact_refs",
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
    max_sections, _ = _INTENT_PLAN_BOUNDS[
        package.intent_selection.primary_intent
    ]
    section_properties: dict[AnswerSectionType, dict[str, Any]] = {}
    section_unit_types: dict[AnswerSectionType, set[AnalyticalUnitType]] = {}
    for section_type in section_types:
        eligible_units = available_units.intersection(
            SECTION_UNIT_TYPES[section_type]
        )
        if section_type is AnswerSectionType.DIRECT_ANSWER:
            eligible_units.intersection_update(
                {AnalyticalUnitType.RECORDED_FACT, AnalyticalUnitType.ABSENCE}
            )
            fact_definition = "direct_fact_refs"
        elif section_type in {
            AnswerSectionType.KEY_FINDINGS,
            AnswerSectionType.INCIDENT_OVERVIEW,
        }:
            eligible_units.intersection_update(
                {AnalyticalUnitType.RECORDED_FACT, AnalyticalUnitType.ABSENCE}
            )
            fact_definition = (
                "findings_fact_refs"
                if section_type is AnswerSectionType.KEY_FINDINGS
                else "overview_fact_refs"
            )
        elif section_type is AnswerSectionType.RELATED_INCIDENTS:
            for preferred in (
                AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                AnalyticalUnitType.SEMANTIC_SIMILARITY,
                AnalyticalUnitType.CANDIDATE_RELEVANCE,
            ):
                if preferred in eligible_units:
                    eligible_units.intersection_update({preferred})
                    break
            fact_definition = "supporting_fact_refs"
        elif section_type is AnswerSectionType.COMPARISON:
            comparison_units = eligible_units.intersection(
                {AnalyticalUnitType.COMPARISON, AnalyticalUnitType.DIFFERENCE}
            )
            if comparison_units:
                eligible_units = comparison_units
            fact_definition = "supporting_fact_refs"
        elif section_type is AnswerSectionType.EVIDENCE:
            evidence_units = eligible_units.intersection(
                {
                    AnalyticalUnitType.RECORDED_FACT,
                    AnalyticalUnitType.RECORDED_CORRELATION,
                }
            )
            if evidence_units:
                eligible_units = evidence_units
            fact_definition = "supporting_fact_refs"
        elif section_type is AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE:
            eligible_units.intersection_update({AnalyticalUnitType.NON_IMPLICATION})
            fact_definition = "supporting_fact_refs"
        elif section_type is AnswerSectionType.LIMITATIONS:
            eligible_units.intersection_update({AnalyticalUnitType.LIMITATION})
            fact_definition = "supporting_fact_refs"
        else:
            fact_definition = "supporting_fact_refs"
        if (
            AnalyticalUnitType.RECORDED_FACT in eligible_units
            and fact_definition not in definitions
        ):
            eligible_units.remove(AnalyticalUnitType.RECORDED_FACT)
        unit_types = sorted(
            eligible_units,
            key=lambda item: item.value,
        )
        if not unit_types:
            continue
        section_unit_types[section_type] = set(unit_types)
        section_properties[section_type] = {
            "oneOf": [
                _unit_schema(
                    item,
                    package=package,
                    definitions=definitions,
                    fact_definition=fact_definition,
                )
                for item in unit_types
            ]
        }
    intent = package.intent_selection.primary_intent
    selected_sections = [AnswerSectionType.DIRECT_ANSWER]
    selected_ambiguous_units: set[AnalyticalUnitType] = set()
    for section_type in _INTENT_SECTION_PRIORITY[intent]:
        if section_type not in section_properties:
            continue
        candidate_ambiguity = section_unit_types.get(
            section_type,
            set(),
        ).intersection(_AMBIGUOUS_UNIT_TYPES)
        requires_caveat = bool(selected_ambiguous_units or candidate_ambiguity)
        reserved_slots = 1 if requires_caveat else 0
        if len(selected_sections) + 1 + reserved_slots > max_sections:
            continue
        selected_sections.append(section_type)
        selected_ambiguous_units.update(candidate_ambiguity)
    caveat = AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE
    if selected_ambiguous_units and caveat in section_properties:
        non_implication_codes: list[NonImplicationCode] = []
        if AnalyticalUnitType.RECORDED_CORRELATION in selected_ambiguous_units:
            non_implication_codes.append(
                NonImplicationCode.CORRELATION_NOT_COMPROMISE
            )
        if selected_ambiguous_units.intersection(
            {
                AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                AnalyticalUnitType.SHARED_PATTERN,
                AnalyticalUnitType.TEMPORAL_SEQUENCE,
            }
        ):
            non_implication_codes.append(
                NonImplicationCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY
            )
        if AnalyticalUnitType.SEMANTIC_SIMILARITY in selected_ambiguous_units:
            non_implication_codes.append(
                NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
            )
        section_properties[caveat] = {
            "oneOf": [
                _unit_schema(
                    AnalyticalUnitType.NON_IMPLICATION,
                    package=package,
                    definitions=definitions,
                    non_implication_codes=non_implication_codes,
                )
            ]
        }
        selected_sections.append(caveat)
    selected_sections = list(dict.fromkeys(selected_sections))
    selected_properties = {
        SECTION_WIRE_CODES[section_type]: section_properties[section_type]
        for section_type in selected_sections
        if section_type in section_properties
    }
    required_sections = list(selected_properties)
    return {
        "$defs": definitions,
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "sections": {
                "type": "object",
                "additionalProperties": False,
                "properties": selected_properties,
                "required": required_sections,
                "minProperties": 1,
                "maxProperties": len(selected_properties),
            },
        },
        "required": ["sections"],
    }
