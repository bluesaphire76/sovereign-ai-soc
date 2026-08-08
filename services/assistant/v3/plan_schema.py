from __future__ import annotations

from collections import Counter
from typing import Any

from services.assistant.v3.contracts import (
    AuthorityClass,
    FactField,
    RecordedCorrelationAtom,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_contracts import (
    AnalyticalUnitType,
    AnswerAudience,
    AnswerDetailLevel,
    AnswerSectionType,
    DiscourseOrdering,
    INTENT_SECTION_TYPES,
    NonImplicationCode,
    PlanLimitationCode,
    RhetoricalRole,
    SurfaceVariant,
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


def available_unit_types(package: V3AnalyticalContextPackage) -> list[AnalyticalUnitType]:
    result = {
        AnalyticalUnitType.RECORDED_FACT,
        AnalyticalUnitType.NON_IMPLICATION,
        AnalyticalUnitType.LIMITATION,
    }
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


def _enum_or_null(values: list[str]) -> dict[str, Any]:
    if not values:
        return {"type": "null"}
    return {"anyOf": [{"type": "string", "enum": values}, {"type": "null"}]}


def _ref_array(values: list[str], maximum: int) -> dict[str, Any]:
    return {
        "type": "array",
        "items": {"type": "string", "enum": values},
        "maxItems": min(maximum, len(values)),
        "uniqueItems": True,
    }


def grounded_answer_plan_v3_schema(
    package: V3AnalyticalContextPackage,
) -> dict[str, Any]:
    fact_refs = [atom.atom_id for atom in package.operational_atoms]
    relationship_refs = [
        item.relationship_id for item in package.relationship_registry.relationships
    ]
    candidate_refs = [item.candidate_id for item in package.cross_incident_candidates]
    reference_refs = [item.knowledge_id for item in package.reference_atoms]
    advisory_refs = [item.knowledge_id for item in package.advisory_atoms]
    section_types = available_section_types(package)
    unit_types = available_unit_types(package)
    unit_schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "unit_type": {
                "type": "string",
                "enum": [item.value for item in unit_types],
            },
            "fact_refs": _ref_array(fact_refs, 8),
            "relationship_refs": _ref_array(relationship_refs, 8),
            "candidate_refs": _ref_array(candidate_refs, 6),
            "reference_refs": _ref_array(reference_refs, 4),
            "advisory_refs": _ref_array(advisory_refs, 4),
            "absence_field": _enum_or_null(
                [item.value for item in available_absence_fields(package)]
            ),
            "non_implication": _enum_or_null(
                [item.value for item in NonImplicationCode]
            ),
            "limitation": _enum_or_null([item.value for item in PlanLimitationCode]),
            "rhetorical_role": {
                "type": "string",
                "enum": [item.value for item in RhetoricalRole],
            },
            "surface_variant": {
                "type": "string",
                "enum": [item.value for item in SurfaceVariant],
            },
        },
        "required": [
            "unit_type",
            "fact_refs",
            "relationship_refs",
            "candidate_refs",
            "reference_refs",
            "advisory_refs",
            "absence_field",
            "non_implication",
            "limitation",
            "rhetorical_role",
            "surface_variant",
        ],
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "answer_intent": {
                "type": "string",
                "const": package.intent_selection.primary_intent.value,
            },
            "detail_level": {
                "type": "string",
                "enum": [item.value for item in AnswerDetailLevel],
            },
            "audience": {
                "type": "string",
                "enum": [item.value for item in AnswerAudience],
            },
            "ordering": {
                "type": "string",
                "enum": [item.value for item in DiscourseOrdering],
            },
            "sections": {
                "type": "array",
                "minItems": 1,
                "maxItems": min(10, len(section_types)),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "section_type": {
                            "type": "string",
                            "enum": [item.value for item in section_types],
                        },
                        "units": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 8,
                            "items": unit_schema,
                        },
                    },
                    "required": ["section_type", "units"],
                },
            },
        },
        "required": [
            "answer_intent",
            "detail_level",
            "audience",
            "ordering",
            "sections",
        ],
    }
