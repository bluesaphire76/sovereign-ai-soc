from __future__ import annotations

from collections import defaultdict
from typing import Any

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
    INTENT_SECTION_TYPES,
    NonImplicationCode,
    PlanLimitationCode,
    RhetoricalRole,
    SurfaceVariant,
)
from services.assistant.v3.plan_schema import available_absence_fields
from services.assistant.v3.quality_policy import enrich_unit, rank_operational_atoms


def _fact_refs(package: V3AnalyticalContextPackage, *, maximum: int) -> list[str]:
    anchor_ids = set(package.resolved_scope.active_incident_ids)
    anchor_cases = set(package.resolved_scope.active_case_ids)
    ranked_atoms = rank_operational_atoms(package, package.operational_atoms)
    preferred = [
        atom.atom_id
        for atom in ranked_atoms
        if atom.incident_id in anchor_ids or atom.case_id in anchor_cases
    ]
    remaining = [
        atom.atom_id
        for atom in ranked_atoms
        if atom.atom_id not in preferred
    ]
    return [*preferred, *remaining][:maximum]


def _relationship_sections(
    package: V3AnalyticalContextPackage,
) -> list[AnswerSection]:
    grouped: dict[AuthorityClass, list] = defaultdict(list)
    explicit_compare = set(package.resolved_scope.explicit_compare_incident_ids)
    selected_relationships = [
        relationship
        for relationship in package.cross_incident_graph.relationships
        if not explicit_compare
        or {relationship.left_incident_id, relationship.right_incident_id}.issubset(
            explicit_compare
        )
    ]
    for relationship in selected_relationships:
        grouped[relationship.authority_class].append(relationship)
    relationship_units: list[AnalyticalUnit] = []
    for authority, unit_type in (
        (AuthorityClass.OPERATIONAL_AUTHORITATIVE, AnalyticalUnitType.RECORDED_CORRELATION),
        (AuthorityClass.ANALYTICAL_DERIVATION, AnalyticalUnitType.ANALYTICAL_RELATIONSHIP),
        (AuthorityClass.SEMANTIC_CANDIDATE, AnalyticalUnitType.SEMANTIC_SIMILARITY),
    ):
        selected = grouped[authority][:3]
        if selected:
            relationship_units.append(
                AnalyticalUnit(
                    unit_type=unit_type,
                    relationship_refs=[
                        relationship.relationship_id for relationship in selected
                    ],
                    rhetorical_role=RhetoricalRole.SUPPORT,
                    surface_variant=SurfaceVariant.COMPARISON_LED,
                )
            )
    candidate_units: list[AnalyticalUnit] = []
    for candidate in package.cross_incident_candidates[:3]:
        if explicit_compare and candidate.candidate_incident_id not in explicit_compare:
            continue
        relationship_refs = [
            item.relationship_id
            for item in package.cross_incident_graph.relationships
            if candidate.candidate_incident_id
            in {item.left_incident_id, item.right_incident_id}
        ][:4]
        candidate_units.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.CANDIDATE_RELEVANCE,
                candidate_refs=[candidate.candidate_id],
                relationship_refs=relationship_refs,
                rhetorical_role=RhetoricalRole.EXPLANATION,
                surface_variant=SurfaceVariant.COMPARISON_LED,
            )
        )
    units = [
        *relationship_units[:2],
        *(
            candidate_units[:1]
            if not explicit_compare
            else []
        ),
    ] or candidate_units[:2]
    if package.intent_selection.primary_intent is AnswerIntent.HANDOVER:
        units = units[:1]
    elif package.intent_selection.primary_intent is AnswerIntent.PATTERN_ANALYSIS:
        units = units[:1]
    elif package.intent_selection.primary_intent is AnswerIntent.COMPARE:
        units = units[:2]
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
    used_relationship_refs = {
        ref for unit in units for ref in unit.relationship_refs
    }
    used_relationships = [
        relationship
        for relationship in selected_relationships
        if relationship.relationship_id in used_relationship_refs
    ]
    caveats: list[AnalyticalUnit] = []
    analytical_refs = [
        relationship.relationship_id
        for relationship in used_relationships
        if relationship.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
    ]
    if analytical_refs:
        caveats.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.NON_IMPLICATION,
                relationship_refs=analytical_refs[:8],
                non_implication=(
                    NonImplicationCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY
                ),
                rhetorical_role=RhetoricalRole.CAVEAT,
            )
        )
    semantic_refs = [
        relationship.relationship_id
        for relationship in used_relationships
        if relationship.authority_class is AuthorityClass.SEMANTIC_CANDIDATE
    ]
    if semantic_refs:
        caveats.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.NON_IMPLICATION,
                relationship_refs=semantic_refs[:8],
                non_implication=(
                    NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
                ),
                rhetorical_role=RhetoricalRole.CAVEAT,
            )
        )
    recorded_refs = [
        relationship.relationship_id
        for relationship in used_relationships
        if relationship.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
    ]
    if recorded_refs:
        caveats.append(
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.NON_IMPLICATION,
                relationship_refs=recorded_refs[:8],
                non_implication=NonImplicationCode.CORRELATION_NOT_COMPROMISE,
                rhetorical_role=RhetoricalRole.CAVEAT,
            )
        )
    if any(
        unit.unit_type is AnalyticalUnitType.CANDIDATE_RELEVANCE
        for unit in units
    ) and not explicit_compare:
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
    sections = [
        AnswerSection(
            section_type=AnswerSectionType.RELATED_INCIDENTS,
            units=units[:8],
        ),
    ]
    pattern = _pattern_section(package)
    comparison = _comparison_section(package)
    intent = package.intent_selection.primary_intent
    if intent is AnswerIntent.COMPARE and comparison is not None:
        sections.append(
            comparison.model_copy(update={"units": comparison.units[:2]})
        )
    elif intent is AnswerIntent.CROSS_INCIDENT_ANALYSIS:
        if pattern is not None:
            sections.append(pattern.model_copy(update={"units": pattern.units[:1]}))
        elif comparison is not None:
            sections.append(
                comparison.model_copy(update={"units": comparison.units[:1]})
            )
    elif intent is AnswerIntent.PATTERN_ANALYSIS and pattern is not None:
        pattern = pattern.model_copy(update={"units": pattern.units[:1]})
        sections.append(pattern)
    if caveats:
        sections.append(
            AnswerSection(
                section_type=caveat_section,
                units=caveats[:8],
            )
        )
    return sections


def _comparison_payload(atom: Any) -> dict[str, Any]:
    payload = atom.model_dump(
        mode="json",
        exclude={
            "atom_id",
            "authority_class",
            "provenance",
            "incident_id",
            "case_id",
        },
    )
    return payload


def _comparison_section(
    package: V3AnalyticalContextPackage,
) -> AnswerSection | None:
    by_type: dict[str, dict[int, Any]] = defaultdict(dict)
    for atom in package.operational_atoms:
        if atom.incident_id is None:
            continue
        by_type[atom.atom_type].setdefault(atom.incident_id, atom)
    units: list[AnalyticalUnit] = []
    preferred_types = (
        "status",
        "host",
        "detection",
        "risk",
        "mitre_technique",
        "recorded_correlation",
        "incident_identity",
    )
    comparison_scope = (
        package.resolved_scope.explicit_compare_incident_ids
        or package.resolved_scope.active_incident_ids
    )
    if len(comparison_scope) < 2:
        comparison_scope = list(by_type.get("incident_identity", {}))[:2]
    for atom_type in preferred_types:
        selected_by_incident = by_type.get(atom_type, {})
        selected = [
            selected_by_incident[incident_id]
            for incident_id in comparison_scope[:2]
            if incident_id in selected_by_incident
        ]
        if len(selected) < 2:
            continue
        unit_type = (
            AnalyticalUnitType.COMPARISON
            if _comparison_payload(selected[0]) == _comparison_payload(selected[1])
            else AnalyticalUnitType.DIFFERENCE
        )
        units.append(
            AnalyticalUnit(
                unit_type=unit_type,
                fact_refs=[item.atom_id for item in selected],
                rhetorical_role=(
                    RhetoricalRole.SUPPORT
                    if unit_type is AnalyticalUnitType.COMPARISON
                    else RhetoricalRole.CONTRAST
                ),
                surface_variant=SurfaceVariant.CONTRASTIVE,
            )
        )
        if len(units) >= 3:
            break
    if not units:
        return None
    return AnswerSection(section_type=AnswerSectionType.COMPARISON, units=units)


def _pattern_section(
    package: V3AnalyticalContextPackage,
) -> AnswerSection | None:
    grouped: dict[Any, list[str]] = defaultdict(list)
    for relationship in package.cross_incident_graph.relationships:
        if relationship.authority_class is AuthorityClass.ANALYTICAL_DERIVATION:
            grouped[relationship.relationship_type].append(
                relationship.relationship_id
            )
    units = [
        AnalyticalUnit(
            unit_type=AnalyticalUnitType.SHARED_PATTERN,
            relationship_refs=refs[:8],
            rhetorical_role=RhetoricalRole.EXPLANATION,
            surface_variant=SurfaceVariant.COMPARISON_LED,
        )
        for refs in grouped.values()
        if len(refs) >= 2
    ][:3]
    if not units:
        return None
    return AnswerSection(section_type=AnswerSectionType.PATTERN, units=units)


def deterministic_answer_plan_v3(
    package: V3AnalyticalContextPackage,
) -> GroundedAnswerPlanV3:
    intent = package.intent_selection.primary_intent
    concise = intent in {AnswerIntent.FACT_LOOKUP, AnswerIntent.EXECUTIVE_SUMMARY}
    ranked_fact_refs = _fact_refs(package, maximum=8)
    direct_ref_limit = 1 if intent is AnswerIntent.INVESTIGATE else 2
    fact_refs = ranked_fact_refs[:direct_ref_limit]
    supporting_fact_refs = ranked_fact_refs[direct_ref_limit:]
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
    if supporting_fact_refs and intent in {
        AnswerIntent.EXPLAIN,
        AnswerIntent.INVESTIGATE,
        AnswerIntent.NEXT_ACTION,
    } or (
        intent is AnswerIntent.CROSS_INCIDENT_ANALYSIS
        and not (
            package.cross_incident_graph.relationships
            or package.cross_incident_candidates
        )
    ):
        selected = supporting_fact_refs[:6]
        chunks = [selected]
        if intent is AnswerIntent.INVESTIGATE and len(selected) >= 2:
            midpoint = max(1, len(selected) // 2)
            chunks = [selected[:midpoint], selected[midpoint:]]
        sections.append(
            AnswerSection(
                section_type=AnswerSectionType.EVIDENCE,
                units=[
                    AnalyticalUnit(
                        unit_type=AnalyticalUnitType.RECORDED_FACT,
                        fact_refs=chunk,
                        rhetorical_role=RhetoricalRole.SUPPORT,
                    )
                    for chunk in chunks
                    if chunk
                ],
            )
        )
    if supporting_fact_refs and intent is AnswerIntent.HANDOVER:
        overview_refs = supporting_fact_refs[:2]
        evidence_refs = (
            []
            if package.cross_incident_graph.relationships
            or package.cross_incident_candidates
            or package.advisory_atoms
            else supporting_fact_refs[2:6]
        )
        sections.append(
            AnswerSection(
                section_type=AnswerSectionType.INCIDENT_OVERVIEW,
                units=[
                    AnalyticalUnit(
                        unit_type=AnalyticalUnitType.RECORDED_FACT,
                        fact_refs=overview_refs,
                    )
                ],
            )
        )
        if evidence_refs:
            sections.append(
                AnswerSection(
                    section_type=AnswerSectionType.EVIDENCE,
                    units=[
                        AnalyticalUnit(
                            unit_type=AnalyticalUnitType.RECORDED_FACT,
                            fact_refs=evidence_refs,
                        )
                    ],
                )
            )
    if intent in {AnswerIntent.SUMMARY, AnswerIntent.EXECUTIVE_SUMMARY}:
        finding_refs = supporting_fact_refs[:3]
        if not finding_refs and len(fact_refs) > 1:
            finding_refs = fact_refs[1:]
        if finding_refs:
            sections.append(
                AnswerSection(
                    section_type=AnswerSectionType.KEY_FINDINGS,
                    units=[
                        AnalyticalUnit(
                            unit_type=AnalyticalUnitType.RECORDED_FACT,
                            fact_refs=finding_refs,
                        )
                    ],
                )
            )
    if intent in {
        AnswerIntent.COMPARE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.PATTERN_ANALYSIS,
    } or (
        intent is AnswerIntent.HANDOVER
        and (
            package.cross_incident_graph.relationships
            or package.cross_incident_candidates
        )
    ):
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
    if package.semantic_index_status in {"degraded", "unavailable"}:
        limitation = AnalyticalUnit(
            unit_type=AnalyticalUnitType.LIMITATION,
            limitation=PlanLimitationCode.SEMANTIC_INDEX_DEGRADED,
            rhetorical_role=RhetoricalRole.CAVEAT,
        )
        for index, section in enumerate(sections):
            if section.section_type is AnswerSectionType.LIMITATIONS:
                sections[index] = section.model_copy(
                    update={"units": [*section.units, limitation][:8]}
                )
                break
        else:
            sections.append(
                AnswerSection(
                    section_type=AnswerSectionType.LIMITATIONS,
                    units=[limitation],
                )
            )
    if (
        intent in {AnswerIntent.NEXT_ACTION, AnswerIntent.HANDOVER}
        and package.context_plan.include_advisory
        and not package.advisory_atoms
    ):
        advisory_limitation = AnalyticalUnit(
            unit_type=AnalyticalUnitType.LIMITATION,
            limitation=PlanLimitationCode.ADVISORY_KNOWLEDGE_UNAVAILABLE,
            rhetorical_role=RhetoricalRole.CAVEAT,
        )
        for index, section in enumerate(sections):
            if section.section_type is AnswerSectionType.LIMITATIONS:
                sections[index] = section.model_copy(
                    update={"units": [*section.units, advisory_limitation][:8]}
                )
                break
        else:
            sections.append(
                AnswerSection(
                    section_type=AnswerSectionType.LIMITATIONS,
                    units=[advisory_limitation],
                )
            )
    selected_fact_refs = {
        ref
        for section in sections
        for unit in section.units
        for ref in unit.fact_refs
    }
    if set(correlation_refs).intersection(selected_fact_refs) and not concise:
        correlation_caveat = AnalyticalUnit(
            unit_type=AnalyticalUnitType.NON_IMPLICATION,
            non_implication=NonImplicationCode.CORRELATION_NOT_COMPROMISE,
            rhetorical_role=RhetoricalRole.CAVEAT,
        )
        for index, section in enumerate(sections):
            if section.section_type in {
                AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
                AnswerSectionType.LIMITATIONS,
            }:
                if correlation_caveat.semantic_key() not in {
                    unit.semantic_key() for unit in section.units
                }:
                    sections[index] = section.model_copy(
                        update={"units": [*section.units, correlation_caveat][:8]}
                    )
                break
        else:
            caveat_section = (
                AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE
                if AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE
                in INTENT_SECTION_TYPES[intent]
                else AnswerSectionType.LIMITATIONS
            )
            sections.append(
                AnswerSection(
                    section_type=caveat_section,
                    units=[correlation_caveat],
                )
            )
    terminal_types = {
        AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        AnswerSectionType.LIMITATIONS,
    }
    sections = [
        *[section for section in sections if section.section_type not in terminal_types],
        *[section for section in sections if section.section_type in terminal_types],
    ]
    enriched_sections = [
        section.model_copy(
            update={
                "units": [
                    enrich_unit(
                        unit,
                        package=package,
                        section_type=section.section_type,
                    )
                    for unit in section.units
                ]
            }
        )
        for section in sections
    ]
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
        sections=enriched_sections,
    )
