from __future__ import annotations

from collections import defaultdict

from services.assistant.v3.contracts import (
    AnswerIntent,
    AuthorityClass,
    RecordedCorrelationAtom,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    AnswerAudience,
    AnswerDetailLevel,
    AnswerSection,
    AnswerSectionType,
    DiscourseOrdering,
    GroundedAnswerPlanV3,
    NonImplicationCode,
    PlanLimitationCode,
    RhetoricalRole,
    SurfaceVariant,
)
from services.assistant.v3.plan_schema import available_absence_fields
from services.assistant.v3.plan_validation import (
    non_implication_for_relationship_type,
)


def _fact_refs(package: V3AnalyticalContextPackage, *, maximum: int) -> list[str]:
    anchor_ids = set(package.resolved_scope.active_incident_ids)
    anchor_cases = set(package.resolved_scope.active_case_ids)
    preferred = [
        atom.atom_id
        for atom in package.operational_atoms
        if atom.incident_id in anchor_ids or atom.case_id in anchor_cases
    ]
    remaining = [
        atom.atom_id
        for atom in package.operational_atoms
        if atom.atom_id not in preferred
    ]
    return [*preferred, *remaining][:maximum]


def _relationship_sections(
    package: V3AnalyticalContextPackage,
) -> list[AnswerSection]:
    grouped: dict[AuthorityClass, list] = defaultdict(list)
    for relationship in package.cross_incident_graph.relationships:
        grouped[relationship.authority_class].append(relationship)
    units: list[AnalyticalUnit] = []
    for authority, unit_type in (
        (AuthorityClass.OPERATIONAL_AUTHORITATIVE, AnalyticalUnitType.RECORDED_CORRELATION),
        (AuthorityClass.ANALYTICAL_DERIVATION, AnalyticalUnitType.ANALYTICAL_RELATIONSHIP),
        (AuthorityClass.SEMANTIC_CANDIDATE, AnalyticalUnitType.SEMANTIC_SIMILARITY),
    ):
        for relationship in grouped[authority][:6]:
            units.append(
                AnalyticalUnit(
                    unit_type=unit_type,
                    relationship_refs=[relationship.relationship_id],
                    rhetorical_role=RhetoricalRole.SUPPORT,
                    surface_variant=SurfaceVariant.COMPARISON_LED,
                )
            )
    for candidate in package.cross_incident_candidates[:4]:
        relationship_refs = [
            item.relationship_id
            for item in package.cross_incident_graph.relationships
            if candidate.candidate_incident_id
            in {item.left_incident_id, item.right_incident_id}
        ][:4]
        units.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.CANDIDATE_RELEVANCE,
                candidate_refs=[candidate.candidate_id],
                relationship_refs=relationship_refs,
                rhetorical_role=RhetoricalRole.EXPLANATION,
                surface_variant=SurfaceVariant.COMPARISON_LED,
            )
        )
    if not units:
        return [
            AnswerSection(
                section_type=AnswerSectionType.LIMITATIONS,
                units=[
                    AnalyticalUnit(
                        unit_type=AnalyticalUnitType.LIMITATION,
                        limitation=PlanLimitationCode.NO_RELATED_INCIDENT_CANDIDATES,
                        rhetorical_role=RhetoricalRole.CAVEAT,
                    )
                ],
            )
        ]
    caveats: list[AnalyticalUnit] = []
    seen_codes: set[NonImplicationCode] = set()
    for relationship in package.cross_incident_graph.relationships:
        code = non_implication_for_relationship_type(relationship.relationship_type)
        if code in seen_codes:
            continue
        seen_codes.add(code)
        caveats.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.NON_IMPLICATION,
                relationship_refs=[relationship.relationship_id],
                non_implication=code,
                rhetorical_role=RhetoricalRole.CAVEAT,
            )
        )
    if package.cross_incident_candidates:
        caveats.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.NON_IMPLICATION,
                non_implication=NonImplicationCode.CANDIDATE_RANK_NOT_RISK,
                rhetorical_role=RhetoricalRole.CAVEAT,
            )
        )
    caveat_section = (
        AnswerSectionType.LIMITATIONS
        if package.intent_selection.primary_intent is AnswerIntent.HANDOVER
        else AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE
    )
    return [
        AnswerSection(
            section_type=AnswerSectionType.RELATED_INCIDENTS,
            units=units[:8],
        ),
        AnswerSection(
            section_type=caveat_section,
            units=caveats[:8],
        ),
    ]


def deterministic_answer_plan_v3(
    package: V3AnalyticalContextPackage,
) -> GroundedAnswerPlanV3:
    intent = package.intent_selection.primary_intent
    concise = intent in {AnswerIntent.FACT_LOOKUP, AnswerIntent.EXECUTIVE_SUMMARY}
    fact_refs = _fact_refs(package, maximum=2 if concise else 6)
    direct_units: list[AnalyticalUnit] = []
    if fact_refs:
        direct_units.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.RECORDED_FACT,
                fact_refs=fact_refs,
                rhetorical_role=RhetoricalRole.LEAD,
                surface_variant=SurfaceVariant.SUMMARY_LED,
            )
        )
    correlation_refs = [
        atom.atom_id
        for atom in package.operational_atoms
        if isinstance(atom, RecordedCorrelationAtom)
    ][:1]
    if correlation_refs and not concise:
        direct_units.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.RECORDED_CORRELATION,
                fact_refs=correlation_refs,
                rhetorical_role=RhetoricalRole.SUPPORT,
            )
        )
    if not direct_units:
        absence = available_absence_fields(package)
        if absence:
            direct_units.append(
                AnalyticalUnit(
                    unit_type=AnalyticalUnitType.ABSENCE,
                    absence_field=absence[0],
                    rhetorical_role=RhetoricalRole.LEAD,
                )
            )
        else:
            direct_units.append(
                AnalyticalUnit(
                    unit_type=AnalyticalUnitType.LIMITATION,
                    limitation=PlanLimitationCode.REQUESTED_DATA_NOT_RECORDED,
                    rhetorical_role=RhetoricalRole.LEAD,
                )
            )
    sections = [
        AnswerSection(
            section_type=AnswerSectionType.DIRECT_ANSWER,
            units=direct_units,
        )
    ]
    if intent in {
        AnswerIntent.COMPARE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.PATTERN_ANALYSIS,
        AnswerIntent.HANDOVER,
    }:
        sections.extend(_relationship_sections(package))
    if package.reference_atoms and intent in {AnswerIntent.EXPLAIN, AnswerIntent.INVESTIGATE}:
        sections.append(
            AnswerSection(
                section_type=AnswerSectionType.TECHNICAL_CONTEXT,
                units=[
                    AnalyticalUnit(
                        unit_type=AnalyticalUnitType.REFERENCE_EXPLANATION,
                        reference_refs=[item.knowledge_id for item in package.reference_atoms[:2]],
                        rhetorical_role=RhetoricalRole.EXPLANATION,
                    )
                ],
            )
        )
    if package.advisory_atoms and intent in {
        AnswerIntent.INVESTIGATE,
        AnswerIntent.NEXT_ACTION,
        AnswerIntent.HANDOVER,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
    }:
        sections.append(
            AnswerSection(
                section_type=AnswerSectionType.NEXT_STEPS,
                units=[
                    AnalyticalUnit(
                        unit_type=AnalyticalUnitType.NEXT_CHECK,
                        advisory_refs=[package.advisory_atoms[0].knowledge_id],
                        rhetorical_role=RhetoricalRole.FOLLOW_UP,
                    )
                ],
            )
        )
    return GroundedAnswerPlanV3(
        answer_intent=intent,
        detail_level=(
            AnswerDetailLevel.CONCISE if concise else AnswerDetailLevel.STANDARD
        ),
        audience=(
            AnswerAudience.EXECUTIVE
            if intent is AnswerIntent.EXECUTIVE_SUMMARY
            else AnswerAudience.SOC_ANALYST
        ),
        ordering=(
            DiscourseOrdering.COMPARISON_FIRST
            if intent in {
                AnswerIntent.COMPARE,
                AnswerIntent.CROSS_INCIDENT_ANALYSIS,
                AnswerIntent.PATTERN_ANALYSIS,
            }
            else DiscourseOrdering.CONCLUSION_FIRST
        ),
        sections=sections,
    )
