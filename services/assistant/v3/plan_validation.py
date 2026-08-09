from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from services.assistant.v3.contracts import (
    AnswerIntent,
    AuthorityClass,
    RecordedCorrelationAtom,
    RelationshipClass,
    RelationshipType,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    AnswerAudience,
    AnswerDetailLevel,
    AnswerSectionType,
    DiscourseOrdering,
    GroundedAnswerPlanV3,
    INTENT_SECTION_TYPES,
    NonImplicationCode,
    SECTION_UNIT_TYPES,
)
from services.assistant.v3.plan_schema import (
    DISCOURSE_WIRE_CODES,
    IMPORTANCE_WIRE_CODES,
    ORDER_WIRE_CODES,
    SECTION_WIRE_CODES,
    UNIT_WIRE_CODES,
    available_absence_fields,
    available_limitation_codes,
    available_non_implication_codes,
    available_section_types,
    available_unit_types,
    non_implication_for_relationship_type,
)
from services.assistant.v3.quality_policy import (
    PROPOSITION_ROLES,
    evidence_priority_for_unit,
    enrich_unit,
    limitation_may_lead,
    plan_contract,
    proposition_types_for,
    subject_record_ids_for_unit,
)


@dataclass(frozen=True)
class PlanValidationResult:
    accepted: bool
    reason: str | None = None


_SECTION_TYPES_BY_WIRE = {value: key for key, value in SECTION_WIRE_CODES.items()}
_UNIT_TYPES_BY_WIRE = {value: key for key, value in UNIT_WIRE_CODES.items()}
_IMPORTANCE_BY_WIRE = {value: key for key, value in IMPORTANCE_WIRE_CODES.items()}
_DISCOURSE_BY_WIRE = {value: key for key, value in DISCOURSE_WIRE_CODES.items()}
_ORDER_BY_WIRE = {value: key for key, value in ORDER_WIRE_CODES.items()}
_REF_FIELD_BY_UNIT = {
    AnalyticalUnitType.RECORDED_FACT: "fact_refs",
    AnalyticalUnitType.COMPARISON: "fact_refs",
    AnalyticalUnitType.DIFFERENCE: "fact_refs",
    AnalyticalUnitType.SHARED_PATTERN: "relationship_refs",
    AnalyticalUnitType.ANALYTICAL_RELATIONSHIP: "relationship_refs",
    AnalyticalUnitType.SEMANTIC_SIMILARITY: "relationship_refs",
    AnalyticalUnitType.TEMPORAL_SEQUENCE: "relationship_refs",
    AnalyticalUnitType.REFERENCE_EXPLANATION: "reference_refs",
    AnalyticalUnitType.ADVISORY_GUIDANCE: "advisory_refs",
    AnalyticalUnitType.NEXT_CHECK: "advisory_refs",
    AnalyticalUnitType.CANDIDATE_RELEVANCE: "candidate_refs",
}
_CODE_FIELD_BY_UNIT = {
    AnalyticalUnitType.ABSENCE: "absence_field",
    AnalyticalUnitType.NON_IMPLICATION: "non_implication",
    AnalyticalUnitType.LIMITATION: "limitation",
}


def _compact_plan_defaults(
    package: V3AnalyticalContextPackage,
    *,
    ordering: DiscourseOrdering,
) -> dict[str, Any]:
    intent = package.intent_selection.primary_intent
    return {
        "answer_intent": intent,
        "detail_level": (
            AnswerDetailLevel.CONCISE
            if intent in {AnswerIntent.FACT_LOOKUP, AnswerIntent.EXECUTIVE_SUMMARY}
            else AnswerDetailLevel.STANDARD
        ),
        "audience": (
            AnswerAudience.EXECUTIVE
            if intent is AnswerIntent.EXECUTIVE_SUMMARY
            else AnswerAudience.SOC_ANALYST
        ),
        "ordering": ordering,
    }


def _canonicalize_compact_plan(
    payload: dict[str, Any],
    *,
    package: V3AnalyticalContextPackage,
) -> dict[str, Any] | None:
    if set(payload) != {"order", "sections"} or not isinstance(
        payload["sections"],
        dict,
    ):
        return None
    ordering = _ORDER_BY_WIRE.get(payload["order"])
    if ordering is None:
        return None
    atom_refs = {item.atom_id for item in package.operational_atoms}
    relationship_refs = {
        item.relationship_id for item in package.relationship_registry.relationships
    }
    sections: list[dict[str, Any]] = []
    for section_code, units in payload["sections"].items():
        section_type = _SECTION_TYPES_BY_WIRE.get(section_code)
        if section_type is None or not isinstance(units, list) or not units:
            return None
        canonical_units: list[dict[str, Any]] = []
        for unit in units:
            if not isinstance(unit, dict):
                return None
            unit_type = _UNIT_TYPES_BY_WIRE.get(unit.get("kind"))
            discourse = _DISCOURSE_BY_WIRE.get(unit.get("mode"))
            importance = _IMPORTANCE_BY_WIRE.get(unit.get("importance"))
            if (
                unit_type is None
                or discourse is None
                or importance is None
            ):
                return None
            proposition_type, rhetorical_role = discourse
            canonical: dict[str, Any] = {
                "unit_type": unit_type,
                "proposition_type": proposition_type,
                "importance": importance,
                "rhetorical_role": rhetorical_role,
            }
            if unit_type in _CODE_FIELD_BY_UNIT:
                if set(unit) != {
                    "kind",
                    "mode",
                    "importance",
                    "code",
                }:
                    return None
                canonical[_CODE_FIELD_BY_UNIT[unit_type]] = unit["code"]
            else:
                if set(unit) != {
                    "kind",
                    "mode",
                    "importance",
                    "refs",
                }:
                    return None
                refs = unit["refs"]
                if not isinstance(refs, list) or not all(
                    isinstance(ref, str) for ref in refs
                ):
                    return None
                if unit_type is AnalyticalUnitType.RECORDED_CORRELATION:
                    ref_set = set(refs)
                    if ref_set and ref_set.issubset(atom_refs):
                        canonical["fact_refs"] = refs
                    elif ref_set and ref_set.issubset(relationship_refs):
                        canonical["relationship_refs"] = refs
                    else:
                        return None
                else:
                    ref_field = _REF_FIELD_BY_UNIT.get(unit_type)
                    if ref_field is None:
                        return None
                    canonical[ref_field] = refs
            try:
                prepared = AnalyticalUnit.model_validate(canonical)
            except ValidationError:
                return None
            canonical_units.append(
                enrich_unit(
                    prepared,
                    package=package,
                    section_type=section_type,
                    proposition_type=proposition_type,
                    importance=importance,
                    rhetorical_role=rhetorical_role,
                ).model_dump(mode="json")
            )
        sections.append(
            {"section_type": section_type, "units": canonical_units}
        )
    return {
        **_compact_plan_defaults(package, ordering=ordering),
        "sections": sections,
    }


def parse_grounded_answer_plan_v3(
    value: Any,
    *,
    package: V3AnalyticalContextPackage | None = None,
) -> GroundedAnswerPlanV3 | None:
    if isinstance(value, GroundedAnswerPlanV3):
        return value
    payload = value
    if isinstance(value, str):
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(payload, dict):
        return None
    sections = payload.get("sections")
    if isinstance(sections, dict):
        if set(payload) == {"order", "sections"}:
            if package is None:
                return None
            payload = _canonicalize_compact_plan(payload, package=package)
            if payload is None:
                return None
        else:
            payload = {
                **payload,
                "sections": [
                    {"section_type": section_type, "units": units}
                    for section_type, units in sections.items()
                ],
            }
    try:
        return GroundedAnswerPlanV3.model_validate(payload)
    except ValidationError:
        return None


class GroundedAnswerPlanV3Validator:
    def validate(
        self,
        plan: GroundedAnswerPlanV3,
        *,
        package: V3AnalyticalContextPackage,
    ) -> PlanValidationResult:
        if plan.answer_intent is not package.intent_selection.primary_intent:
            return PlanValidationResult(False, "intent_mismatch")
        allowed_sections = set(available_section_types(package))
        if any(section.section_type not in allowed_sections for section in plan.sections):
            return PlanValidationResult(False, "section_unavailable")
        if any(
            section.section_type not in INTENT_SECTION_TYPES[plan.answer_intent]
            for section in plan.sections
        ):
            return PlanValidationResult(False, "section_intent_mismatch")
        allowed_units = set(available_unit_types(package))
        seen: set[tuple[object, ...]] = set()
        for section in plan.sections:
            for unit in section.units:
                if unit.unit_type not in SECTION_UNIT_TYPES[section.section_type]:
                    return PlanValidationResult(False, "section_unit_mismatch")
                if unit.unit_type not in allowed_units:
                    return PlanValidationResult(False, "unit_unavailable")
                key = unit.semantic_key()
                if key in seen:
                    return PlanValidationResult(False, "duplicate_semantic_unit")
                seen.add(key)
                result = self._validate_unit(
                    unit,
                    package=package,
                    section_type=section.section_type,
                )
                if not result.accepted:
                    return result
                if unit.proposition_type not in proposition_types_for(
                    section.section_type,
                    unit.unit_type,
                    intent=plan.answer_intent,
                ):
                    return PlanValidationResult(False, "proposition_section_mismatch")
                if unit.rhetorical_role not in PROPOSITION_ROLES[unit.proposition_type]:
                    return PlanValidationResult(False, "proposition_role_mismatch")
                if unit.subject_record_ids != subject_record_ids_for_unit(
                    unit,
                    package=package,
                ):
                    return PlanValidationResult(False, "proposition_subject_mismatch")
                if unit.evidence_priority is not evidence_priority_for_unit(
                    unit,
                    package=package,
                ):
                    return PlanValidationResult(False, "evidence_priority_mismatch")
        required_non_implications = self._required_non_implications(
            plan,
            package=package,
        )
        provided_non_implications = {
            unit.non_implication
            for unit in plan.analytical_units
            if unit.non_implication is not None
        }
        if not required_non_implications.issubset(provided_non_implications):
            return PlanValidationResult(False, "required_non_implication_missing")
        analytical_codes: set[NonImplicationCode] = set()
        for unit in plan.analytical_units:
            if unit.unit_type not in {
                AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                AnalyticalUnitType.SHARED_PATTERN,
            }:
                continue
            for ref in unit.relationship_refs:
                relationship = package.relationship_registry.resolve(ref)
                if relationship is not None:
                    analytical_codes.add(
                        non_implication_for_relationship_type(
                            relationship.relationship_type
                        )
                    )
        if analytical_codes and (
            NonImplicationCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY
            not in provided_non_implications
            and not analytical_codes.issubset(provided_non_implications)
        ):
            return PlanValidationResult(False, "required_non_implication_missing")
        usefulness = self._validate_usefulness(plan, package=package)
        if not usefulness.accepted:
            return usefulness
        return PlanValidationResult(True)

    @staticmethod
    def _validate_unit(
        unit: AnalyticalUnit,
        *,
        package: V3AnalyticalContextPackage,
        section_type: AnswerSectionType,
    ) -> PlanValidationResult:
        atoms = {item.atom_id: item for item in package.operational_atoms}
        candidates = {
            item.candidate_id: item for item in package.cross_incident_candidates
        }
        references = {item.knowledge_id: item for item in package.reference_atoms}
        advisories = {item.knowledge_id: item for item in package.advisory_atoms}
        if not set(unit.fact_refs).issubset(atoms):
            return PlanValidationResult(False, "unknown_fact_ref")
        if not set(unit.candidate_refs).issubset(candidates):
            return PlanValidationResult(False, "unknown_candidate_ref")
        if not set(unit.reference_refs).issubset(references):
            return PlanValidationResult(False, "unknown_reference_ref")
        if not set(unit.advisory_refs).issubset(advisories):
            return PlanValidationResult(False, "unknown_advisory_ref")
        relationships = []
        for ref in unit.relationship_refs:
            relationship = package.relationship_registry.resolve(ref)
            if relationship is None:
                return PlanValidationResult(False, "unknown_relationship_ref")
            relationships.append(relationship)
        if any(
            atom.authority_class is not AuthorityClass.OPERATIONAL_AUTHORITATIVE
            for atom in (atoms[ref] for ref in unit.fact_refs)
        ):
            return PlanValidationResult(False, "fact_authority_mismatch")
        if unit.unit_type is AnalyticalUnitType.RECORDED_CORRELATION:
            if any(
                not isinstance(atoms[ref], RecordedCorrelationAtom)
                for ref in unit.fact_refs
            ):
                return PlanValidationResult(False, "recorded_correlation_fact_mismatch")
            if any(
                item.relationship_class is not RelationshipClass.RECORDED_CORRELATION
                or item.authority_class is not AuthorityClass.OPERATIONAL_AUTHORITATIVE
                or item.relationship_type
                is not RelationshipType.PLATFORM_RECORDED_CORRELATION
                for item in relationships
            ):
                return PlanValidationResult(False, "recorded_correlation_authority_mismatch")
        if unit.unit_type is AnalyticalUnitType.ANALYTICAL_RELATIONSHIP and any(
            item.relationship_class is not RelationshipClass.ANALYTICAL_RELATIONSHIP
            or item.authority_class is not AuthorityClass.ANALYTICAL_DERIVATION
            for item in relationships
        ):
            return PlanValidationResult(False, "analytical_relationship_authority_mismatch")
        if unit.unit_type is AnalyticalUnitType.SEMANTIC_SIMILARITY and any(
            item.relationship_class is not RelationshipClass.SEMANTIC_SIMILARITY
            or item.authority_class is not AuthorityClass.SEMANTIC_CANDIDATE
            for item in relationships
        ):
            return PlanValidationResult(False, "semantic_similarity_authority_mismatch")
        if unit.unit_type is AnalyticalUnitType.TEMPORAL_SEQUENCE and any(
            item.relationship_type is not RelationshipType.TEMPORAL_PROXIMITY
            for item in relationships
        ):
            return PlanValidationResult(False, "temporal_relationship_mismatch")
        if unit.unit_type is AnalyticalUnitType.SHARED_PATTERN:
            relationship_types = {item.relationship_type for item in relationships}
            if len(relationships) < 2 or len(relationship_types) != 1:
                return PlanValidationResult(False, "unsupported_shared_pattern")
            if any(
                item.authority_class is not AuthorityClass.ANALYTICAL_DERIVATION
                for item in relationships
            ):
                return PlanValidationResult(False, "shared_pattern_authority_mismatch")
        if unit.unit_type is AnalyticalUnitType.CANDIDATE_RELEVANCE:
            candidate_incident_ids = {
                candidates[ref].candidate_incident_id for ref in unit.candidate_refs
            }
            if any(
                not candidate_incident_ids.intersection(
                    {item.left_incident_id, item.right_incident_id}
                )
                for item in relationships
            ):
                return PlanValidationResult(False, "candidate_relationship_mismatch")
        explicit_compare = set(
            package.resolved_scope.explicit_compare_incident_ids
        )
        if (
            package.intent_selection.primary_intent is AnswerIntent.COMPARE
            and explicit_compare
        ):
            if any(
                not {item.left_incident_id, item.right_incident_id}.issubset(
                    explicit_compare
                )
                for item in relationships
            ):
                return PlanValidationResult(False, "explicit_compare_scope_drift")
            if any(
                candidates[ref].candidate_incident_id not in explicit_compare
                for ref in unit.candidate_refs
            ):
                return PlanValidationResult(False, "explicit_compare_scope_drift")
        if unit.unit_type in {
            AnalyticalUnitType.COMPARISON,
            AnalyticalUnitType.DIFFERENCE,
        }:
            selected_atoms = [atoms[ref] for ref in unit.fact_refs]
            incident_ids = {atom.incident_id for atom in selected_atoms}
            if None in incident_ids or len(incident_ids) < 2:
                return PlanValidationResult(False, "comparison_scope_mismatch")
            if explicit_compare and incident_ids != explicit_compare:
                return PlanValidationResult(False, "explicit_compare_scope_drift")
            if len({atom.atom_type for atom in selected_atoms}) != 1:
                return PlanValidationResult(False, "comparison_type_mismatch")
            payloads = [
                atom.model_dump(
                    mode="json",
                    exclude={
                        "atom_id",
                        "authority_class",
                        "provenance",
                        "incident_id",
                        "case_id",
                    },
                )
                for atom in selected_atoms
            ]
            same = all(payload == payloads[0] for payload in payloads[1:])
            if unit.unit_type is AnalyticalUnitType.COMPARISON and not same:
                return PlanValidationResult(False, "comparison_semantics_mismatch")
            if unit.unit_type is AnalyticalUnitType.DIFFERENCE and same:
                return PlanValidationResult(False, "difference_semantics_mismatch")
        if unit.unit_type is AnalyticalUnitType.ABSENCE and (
            unit.absence_field not in available_absence_fields(package)
        ):
            return PlanValidationResult(False, "unsupported_absence")
        if unit.unit_type is AnalyticalUnitType.NON_IMPLICATION and (
            unit.non_implication not in available_non_implication_codes(package)
        ):
            return PlanValidationResult(False, "unsupported_non_implication")
        if unit.unit_type is AnalyticalUnitType.LIMITATION and (
            unit.limitation not in available_limitation_codes(package)
        ):
            return PlanValidationResult(False, "unsupported_limitation")
        if unit.unit_type is AnalyticalUnitType.REFERENCE_EXPLANATION and any(
            references[ref].authority_class is not AuthorityClass.REFERENCE_KNOWLEDGE
            for ref in unit.reference_refs
        ):
            return PlanValidationResult(False, "reference_authority_mismatch")
        if unit.unit_type in {
            AnalyticalUnitType.ADVISORY_GUIDANCE,
            AnalyticalUnitType.NEXT_CHECK,
        } and any(
            advisories[ref].authority_class is not AuthorityClass.ADVISORY_KNOWLEDGE
            for ref in unit.advisory_refs
        ):
            return PlanValidationResult(False, "advisory_authority_mismatch")
        return PlanValidationResult(True)

    @staticmethod
    def _validate_usefulness(
        plan: GroundedAnswerPlanV3,
        *,
        package: V3AnalyticalContextPackage,
    ) -> PlanValidationResult:
        contract = plan_contract(plan.answer_intent)
        section_count = len(plan.sections)
        unit_count = len(plan.analytical_units)
        if not contract.min_sections <= section_count <= contract.max_sections:
            return PlanValidationResult(False, "intent_section_bounds")
        if not contract.min_units <= unit_count <= contract.max_units:
            return PlanValidationResult(False, "intent_unit_bounds")
        terminal = {
            AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
            AnswerSectionType.LIMITATIONS,
        }
        seen_terminal = False
        for section in plan.sections:
            if section.section_type in terminal:
                seen_terminal = True
            elif seen_terminal:
                return PlanValidationResult(False, "limitation_placement")
        first = plan.sections[0]
        first_is_limitation = first.section_type in terminal or all(
            unit.unit_type
            in {
                AnalyticalUnitType.ABSENCE,
                AnalyticalUnitType.LIMITATION,
                AnalyticalUnitType.NON_IMPLICATION,
            }
            for unit in first.units
        )
        if first_is_limitation and not limitation_may_lead(package):
            return PlanValidationResult(False, "limitation_first")

        unit_types = {unit.unit_type for unit in plan.analytical_units}
        relationship_evidence = {
            AnalyticalUnitType.RECORDED_CORRELATION,
            AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
            AnalyticalUnitType.SEMANTIC_SIMILARITY,
            AnalyticalUnitType.CANDIDATE_RELEVANCE,
        }
        available_units = set(available_unit_types(package))
        comparison_evidence = {
            AnalyticalUnitType.COMPARISON,
            AnalyticalUnitType.DIFFERENCE,
        }
        if not comparison_evidence.intersection(available_units):
            comparison_evidence = relationship_evidence
        pattern_evidence = {AnalyticalUnitType.SHARED_PATTERN}
        if AnalyticalUnitType.SHARED_PATTERN not in available_units:
            pattern_evidence = relationship_evidence
        operational_or_absence = {
            AnalyticalUnitType.RECORDED_FACT,
            AnalyticalUnitType.ABSENCE,
            AnalyticalUnitType.LIMITATION,
        }
        if not comparison_evidence.intersection(available_units):
            comparison_evidence = operational_or_absence
        if not pattern_evidence.intersection(available_units):
            pattern_evidence = operational_or_absence
        cross_evidence = {
            AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
            AnalyticalUnitType.SEMANTIC_SIMILARITY,
            AnalyticalUnitType.CANDIDATE_RELEVANCE,
        }
        if not cross_evidence.intersection(available_units):
            cross_evidence = operational_or_absence
        next_action_evidence = {
            AnalyticalUnitType.NEXT_CHECK,
            AnalyticalUnitType.ADVISORY_GUIDANCE,
        }
        if not next_action_evidence.intersection(available_units):
            next_action_evidence = operational_or_absence
        requirements: dict[AnswerIntent, tuple[set[AnalyticalUnitType], ...]] = {
            AnswerIntent.FACT_LOOKUP: (
                operational_or_absence,
            ),
            AnswerIntent.EXPLAIN: (
                operational_or_absence,
                {
                    AnalyticalUnitType.REFERENCE_EXPLANATION,
                    AnalyticalUnitType.RECORDED_CORRELATION,
                    AnalyticalUnitType.RECORDED_FACT,
                },
            ),
            AnswerIntent.INVESTIGATE: (
                operational_or_absence,
                {
                    AnalyticalUnitType.RECORDED_CORRELATION,
                    AnalyticalUnitType.REFERENCE_EXPLANATION,
                    AnalyticalUnitType.NEXT_CHECK,
                    AnalyticalUnitType.RECORDED_FACT,
                },
            ),
            AnswerIntent.SUMMARY: (operational_or_absence,),
            AnswerIntent.COMPARE: (comparison_evidence,),
            AnswerIntent.CROSS_INCIDENT_ANALYSIS: (cross_evidence,),
            AnswerIntent.PATTERN_ANALYSIS: (pattern_evidence,),
            AnswerIntent.NEXT_ACTION: (next_action_evidence,),
            AnswerIntent.HANDOVER: (operational_or_absence,),
            AnswerIntent.EXECUTIVE_SUMMARY: (
                operational_or_absence,
            ),
        }
        if any(not unit_types.intersection(group) for group in requirements[plan.answer_intent]):
            return PlanValidationResult(False, "intent_usefulness_contract")
        return PlanValidationResult(True)

    @staticmethod
    def _required_non_implications(
        plan: GroundedAnswerPlanV3,
        *,
        package: V3AnalyticalContextPackage,
    ) -> set[NonImplicationCode]:
        result: set[NonImplicationCode] = set()
        for unit in plan.analytical_units:
            if unit.unit_type is AnalyticalUnitType.RECORDED_CORRELATION:
                result.add(NonImplicationCode.CORRELATION_NOT_COMPROMISE)
            if unit.unit_type is AnalyticalUnitType.SEMANTIC_SIMILARITY:
                result.add(
                    NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
                )
        return result
