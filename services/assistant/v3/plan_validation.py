from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from services.assistant.v3.contracts import (
    AuthorityClass,
    RecordedCorrelationAtom,
    RelationshipClass,
    RelationshipType,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    GroundedAnswerPlanV3,
    INTENT_SECTION_TYPES,
    NonImplicationCode,
    SECTION_UNIT_TYPES,
)
from services.assistant.v3.plan_schema import (
    available_absence_fields,
    available_section_types,
    available_unit_types,
)


@dataclass(frozen=True)
class PlanValidationResult:
    accepted: bool
    reason: str | None = None


def parse_grounded_answer_plan_v3(value: Any) -> GroundedAnswerPlanV3 | None:
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
                result = self._validate_unit(unit, package=package)
                if not result.accepted:
                    return result
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
        return PlanValidationResult(True)

    @staticmethod
    def _validate_unit(
        unit: AnalyticalUnit,
        *,
        package: V3AnalyticalContextPackage,
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
        if unit.unit_type in {
            AnalyticalUnitType.COMPARISON,
            AnalyticalUnitType.DIFFERENCE,
        }:
            selected_atoms = [atoms[ref] for ref in unit.fact_refs]
            incident_ids = {atom.incident_id for atom in selected_atoms}
            if None in incident_ids or len(incident_ids) < 2:
                return PlanValidationResult(False, "comparison_scope_mismatch")
            if len({atom.atom_type for atom in selected_atoms}) != 1:
                return PlanValidationResult(False, "comparison_type_mismatch")
        if unit.unit_type is AnalyticalUnitType.ABSENCE and (
            unit.absence_field not in available_absence_fields(package)
        ):
            return PlanValidationResult(False, "unsupported_absence")
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
    def _required_non_implications(
        plan: GroundedAnswerPlanV3,
        *,
        package: V3AnalyticalContextPackage,
    ) -> set[NonImplicationCode]:
        result: set[NonImplicationCode] = set()
        for unit in plan.analytical_units:
            if unit.unit_type is AnalyticalUnitType.CANDIDATE_RELEVANCE:
                result.add(NonImplicationCode.CANDIDATE_RANK_NOT_RISK)
            if unit.unit_type is AnalyticalUnitType.SEMANTIC_SIMILARITY:
                result.add(
                    NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
                )
            if unit.unit_type in {
                AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                AnalyticalUnitType.SHARED_PATTERN,
            }:
                for ref in unit.relationship_refs:
                    relationship = package.relationship_registry.resolve(ref)
                    if relationship is not None:
                        result.add(
                            non_implication_for_relationship_type(
                                relationship.relationship_type
                            )
                        )
        return result


def non_implication_for_relationship_type(
    relationship_type: RelationshipType,
) -> NonImplicationCode:
    if relationship_type is RelationshipType.SHARED_MITRE:
        return NonImplicationCode.SHARED_MITRE_NOT_SAME_ATTACKER
    if relationship_type in {RelationshipType.SHARED_HOST, RelationshipType.SHARED_AGENT}:
        return NonImplicationCode.SHARED_HOST_NOT_COMMON_ROOT_CAUSE
    if relationship_type is RelationshipType.SAME_CASE:
        return NonImplicationCode.SAME_CASE_NOT_CAUSALITY
    if relationship_type is RelationshipType.SEMANTIC_SIMILARITY:
        return NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
    return NonImplicationCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY
