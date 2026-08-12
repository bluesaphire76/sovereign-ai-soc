from __future__ import annotations

from types import SimpleNamespace

from services.assistant.orchestrator import (
    _response_language,
    get_assistant_settings,
)
from services.assistant.v3.contracts import (
    AdvisoryActionCode,
    AdvisoryContextCode,
    AdvisoryReasonCode,
    AdvisoryTargetType,
    AnalyticalFocus,
    AnalyticalRelationship,
    AnswerIntent,
    AuthorityClass,
    DiscoverySignal,
    EscalationReasonAtom,
    FactField,
    IncidentCandidate,
    PriorityAtom,
    Provenance,
    RelationshipClass,
    RelationshipType,
)
from services.assistant.v3.discourse import RichGroundedDiscourseRenderer
from services.assistant.v3.knowledge import normalize_advisory_sources
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    AnswerSection,
    AnswerSectionType,
    EvidencePriority,
    NonImplicationCode,
    PropositionType,
)
from services.assistant.v3.plan_fallback import deterministic_answer_plan_v3
from services.assistant.v3.plan_prompting import build_v3_plan_messages
from services.assistant.v3.plan_schema import (
    available_unit_types,
    grounded_answer_plan_v3_schema,
    model_facing_available_unit_types,
    model_facing_evidence,
)
from services.assistant.v3.plan_validation import GroundedAnswerPlanV3Validator
from services.assistant.v3.quality_policy import (
    INTENT_USEFULNESS_CONTRACTS,
    evidence_priority_for_atom,
    evidence_priority_for_unit,
    enrich_unit,
    subject_record_ids_for_unit,
)
from tests.assistant_v3_test_support import analytical_package
from tests.evals.assistant_v3.catalog import adversarial_items, quality_items


def _analytical_relationship(
    relationship_id: str,
    relationship_type: RelationshipType,
    *,
    strength: float,
) -> AnalyticalRelationship:
    return AnalyticalRelationship(
        relationship_id=relationship_id,
        relationship_class=RelationshipClass.ANALYTICAL_RELATIONSHIP,
        relationship_type=relationship_type,
        authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
        left_incident_id=1,
        right_incident_id=2,
        evidence_atom_refs=["incident:1:identity", "incident:2:identity"],
        provenance=Provenance(
            authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
            source_type="cross_incident_discovery",
            source_record_id=relationship_id,
            retrieval_method="deterministic_derivation",
        ),
        strength=strength,
    )


def _explicit_compare_package():
    package = analytical_package(AnswerIntent.COMPARE)
    extra_candidate = IncidentCandidate(
        candidate_id="candidate:incident:3",
        candidate_incident_id=3,
        discovery_signals=[DiscoverySignal.SEMANTIC_SIMILARITY],
        semantic_score=0.76,
        deterministic_signal_count=0,
        discovery_source="semantic",
        ranking_score=2.3,
    )
    extra_relationship = AnalyticalRelationship(
        relationship_id="relationship:semantic:3",
        relationship_class=RelationshipClass.SEMANTIC_SIMILARITY,
        relationship_type=RelationshipType.SEMANTIC_SIMILARITY,
        authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
        left_incident_id=1,
        right_incident_id=3,
        evidence_atom_refs=[extra_candidate.candidate_id],
        provenance=Provenance(
            authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
            source_type="incident_semantic_index",
            source_record_id=extra_candidate.candidate_id,
            retrieval_method="semantic_retrieval",
        ),
        strength=0.76,
    )
    relationships = [
        *package.relationship_registry.relationships,
        extra_relationship,
    ]
    return package.model_copy(
        update={
            "resolved_scope": package.resolved_scope.model_copy(
                update={
                    "active_incident_ids": [1, 2],
                    "explicit_compare_incident_ids": [1, 2],
                }
            ),
            "cross_incident_candidates": [
                *package.cross_incident_candidates,
                extra_candidate,
            ],
            "cross_incident_graph": package.cross_incident_graph.model_copy(
                update={
                    "incident_ids": [1, 2, 3],
                    "relationships": relationships,
                    "available_evidence_refs": [
                        *package.cross_incident_graph.available_evidence_refs,
                        extra_candidate.candidate_id,
                    ],
                }
            ),
            "relationship_registry": package.relationship_registry.model_copy(
                update={"relationships": relationships}
            ),
        }
    )


def _all_identical_compare_package():
    package = analytical_package(AnswerIntent.COMPARE, include_semantic=False)
    first_identity = next(
        atom
        for atom in package.operational_atoms
        if atom.atom_id == "incident:1:identity"
    )
    atoms = [
        atom.model_copy(update={"status": "OPEN"})
        if atom.atom_id == "incident:2:status"
        else atom.model_copy(update={"timestamp": first_identity.timestamp})
        if atom.atom_id == "incident:2:identity"
        else atom
        for atom in package.operational_atoms
    ]
    return package.model_copy(
        update={
            "operational_atoms": atoms,
            "resolved_scope": package.resolved_scope.model_copy(
                update={
                    "active_incident_ids": [1, 2],
                    "explicit_compare_incident_ids": [1, 2],
                }
            ),
        }
    )


def test_typed_propositions_are_structurally_grounded_and_reproducible() -> None:
    package = analytical_package()
    plan = deterministic_answer_plan_v3(package)

    assert {item.value for item in PropositionType} >= {
        "PRIMARY_FINDING",
        "SUPPORTING_EVIDENCE",
        "TECHNICAL_SIGNIFICANCE",
        "COMPARATIVE_FINDING",
        "SIMILARITY",
        "DIFFERENCE",
        "RELATIONSHIP_SUMMARY",
        "PATTERN_SUMMARY",
        "EVIDENCE_STRENGTH",
        "UNCERTAINTY",
        "CAVEAT",
        "INVESTIGATIVE_STEP",
        "EXPECTED_VERIFICATION_TARGET",
        "HANDOVER_POINT",
        "EXECUTIVE_POINT",
    }
    proposition_ids = [unit.proposition_id for unit in plan.analytical_units]
    assert len(proposition_ids) == len(set(proposition_ids))
    for unit in plan.analytical_units:
        assert unit.source_refs or unit.non_implication or unit.limitation
        assert unit.subject_record_ids == subject_record_ids_for_unit(
            unit,
            package=package,
        )
        assert unit.evidence_priority is evidence_priority_for_unit(
            unit,
            package=package,
        )


def test_evidence_priority_is_intent_and_focus_aware() -> None:
    cross = analytical_package(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    detection = next(atom for atom in cross.operational_atoms if atom.atom_type == "detection")
    assert evidence_priority_for_atom(cross, detection) is EvidencePriority.SUPPORTING

    executive = analytical_package(AnswerIntent.EXECUTIVE_SUMMARY).model_copy(
        update={"focus_selection": [AnalyticalFocus.STATUS]}
    )
    status = next(atom for atom in executive.operational_atoms if atom.atom_type == "status")
    timeline = next(
        atom for atom in executive.operational_atoms if atom.atom_type == "timeline_event"
    )
    assert evidence_priority_for_atom(executive, status) is EvidencePriority.PRIMARY
    assert evidence_priority_for_atom(executive, timeline) is EvidencePriority.OPTIONAL


def test_short_italian_analytical_requests_preserve_language() -> None:
    questions = (
        "Confronta i record selezionati.",
        "Cerca possibili collegamenti con altri incidenti.",
        "Prepara una sintesi per il management.",
    )

    assert all(_response_language(question) == "it" for question in questions)


def test_milestone_c_catalog_language_is_preserved_without_phrase_routing() -> None:
    assert all(
        _response_language(item.question) == item.language
        for item in (*quality_items(), *adversarial_items())
    )


def test_dynamic_schema_uses_bounded_adaptive_section_variants() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    schema = grounded_answer_plan_v3_schema(package)
    sections = schema["properties"]["sections"]
    contract = INTENT_USEFULNESS_CONTRACTS[AnswerIntent.EXPLAIN]

    assert len(sections["properties"]) > len(sections["required"])
    assert sections["minProperties"] >= contract.min_sections
    assert sections["maxProperties"] <= contract.max_sections
    assert all(
        definition["type"] == "array"
        and 1 <= definition["minItems"] <= definition["maxItems"] <= 3
        for name, definition in schema["$defs"].items()
        if name.startswith("section_")
    )


def test_rich_sections_prefer_grouped_grounded_evidence() -> None:
    explain = grounded_answer_plan_v3_schema(
        analytical_package(AnswerIntent.EXPLAIN)
    )
    investigate = grounded_answer_plan_v3_schema(
        analytical_package(AnswerIntent.INVESTIGATE)
    )

    assert len(explain["$defs"]["findings_fact_refs"]["enum"][0]) > 1
    assert len(investigate["$defs"]["supporting_fact_refs"]["enum"][0]) > 1
    assert "technical" in investigate["properties"]["sections"]["required"]


def test_executive_findings_require_multiple_facts_when_available() -> None:
    schema = grounded_answer_plan_v3_schema(
        analytical_package(AnswerIntent.EXECUTIVE_SUMMARY)
    )

    options = schema["$defs"]["findings_fact_refs"]["enum"]

    assert options
    assert all(len(option) >= 2 for option in options)


def test_missing_requested_priority_can_only_produce_typed_absence() -> None:
    base_package = analytical_package(AnswerIntent.FACT_LOOKUP)
    linked_priority = PriorityAtom(
        atom_id="incident:2:priority",
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        provenance=next(
            atom.provenance
            for atom in base_package.operational_atoms
            if atom.atom_id == "incident:2:status"
        ),
        incident_id=2,
        recommended_priority="LOW",
    )
    package = base_package.model_copy(
        update={
            "focus_selection": [AnalyticalFocus.PRIORITY],
            "resolved_scope": base_package.resolved_scope.model_copy(
                update={
                    "active_incident_ids": [],
                    "active_case_ids": [1],
                }
            ),
            "context_plan": base_package.context_plan.model_copy(
                update={
                    "fact_fields": [
                        FactField.SOURCE_TYPE,
                        FactField.CASE_ID,
                        FactField.TITLE,
                        FactField.RECOMMENDED_PRIORITY,
                    ]
                }
            ),
            "operational_atoms": [
                *base_package.operational_atoms,
                linked_priority,
            ],
        }
    )
    schema = grounded_answer_plan_v3_schema(package)
    direct_definition = schema["$defs"]["section_answer"]
    direct_variants = direct_definition["items"]["oneOf"]

    assert {
        variant["properties"]["kind"]["const"] for variant in direct_variants
    } == {"absence"}
    assert direct_variants[0]["properties"]["code"]["enum"] == [
        "recommended_priority"
    ]

    plan = deterministic_answer_plan_v3(package)
    assert plan.sections[0].units[0].absence_field is FactField.RECOMMENDED_PRIORITY
    rendered = RichGroundedDiscourseRenderer().render(plan, package=package)
    assert "Recommended priority is not recorded" in rendered.blocks[0].text

    wrong_plan = plan.model_copy(
        update={
            "sections": [
                AnswerSection(
                    section_type=AnswerSectionType.DIRECT_ANSWER,
                    units=[
                        enrich_unit(
                            AnalyticalUnit(
                                unit_type=AnalyticalUnitType.RECORDED_FACT,
                                fact_refs=["incident:1:identity"],
                            ),
                            package=package,
                            section_type=AnswerSectionType.DIRECT_ANSWER,
                        )
                    ],
                )
            ]
        }
    )
    validation = GroundedAnswerPlanV3Validator().validate(
        wrong_plan,
        package=package,
    )
    assert validation.accepted is False
    assert validation.reason == "required_absence_missing"


def test_escalation_reason_cannot_replace_missing_authoritative_state() -> None:
    base_package = analytical_package(AnswerIntent.FACT_LOOKUP)
    reason = EscalationReasonAtom(
        atom_id="incident:1:escalation-reason",
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        provenance=next(
            atom.provenance
            for atom in base_package.operational_atoms
            if atom.atom_id == "incident:1:identity"
        ),
        incident_id=1,
        reason="Repeated failures",
    )
    package = base_package.model_copy(
        update={
            "question": "Is an escalation state explicitly recorded?",
            "focus_selection": [AnalyticalFocus.ESCALATION],
            "context_plan": base_package.context_plan.model_copy(
                update={
                    "fact_fields": [
                        FactField.SOURCE_TYPE,
                        FactField.INCIDENT_ID,
                        FactField.ESCALATED,
                        FactField.ESCALATION_REASON,
                    ]
                }
            ),
            "operational_atoms": [*base_package.operational_atoms, reason],
        }
    )

    schema = grounded_answer_plan_v3_schema(package)
    direct_variants = schema["$defs"]["section_answer"]["items"]["oneOf"]
    assert {
        variant["properties"]["kind"]["const"] for variant in direct_variants
    } == {"absence"}
    assert direct_variants[0]["properties"]["code"]["enum"] == ["escalated"]

    plan = deterministic_answer_plan_v3(package)
    assert plan.sections[0].units[0].absence_field is FactField.ESCALATED
    assert GroundedAnswerPlanV3Validator().validate(plan, package=package).accepted
    rendered = RichGroundedDiscourseRenderer().render(plan, package=package)
    assert rendered.blocks[0].text == (
        "No authoritative escalation boolean is available; a reason does not prove state."
    )


def test_explain_direct_answer_requires_detection_host_and_risk_when_available() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    schema = grounded_answer_plan_v3_schema(package)

    assert schema["$defs"]["direct_fact_refs"]["enum"] == [
        ["incident:1:detection", "incident:1:host", "incident:1:risk"]
    ]
    plan = deterministic_answer_plan_v3(package)
    assert plan.sections[0].units[0].fact_refs == [
        "incident:1:detection",
        "incident:1:host",
        "incident:1:risk",
    ]


def test_identical_compare_fields_require_an_explicit_no_difference_result() -> None:
    package = _all_identical_compare_package()
    schema = grounded_answer_plan_v3_schema(package)

    assert "comparison_difference_refs" not in schema["$defs"]
    same_ref_sets = schema["$defs"]["comparison_same_refs"]["enum"]
    assert len(same_ref_sets) == 2
    assert all(
        len(refs) == 2 and all(isinstance(ref, str) for ref in refs)
        for refs in same_ref_sets
    )
    caveat_variants = schema["$defs"]["section_caveats"]["items"]["oneOf"]
    assert {
        code
        for variant in caveat_variants
        for code in variant["properties"]["code"]["enum"]
    } == {"NO_RECORDED_DIFFERENCE_IN_COMPARED_FIELDS"}
    assert schema["$defs"]["section_compare"]["minItems"] == 2
    assert schema["$defs"]["section_compare"]["maxItems"] == 2

    plan = deterministic_answer_plan_v3(package)
    assert GroundedAnswerPlanV3Validator().validate(plan, package=package).accepted
    assert NonImplicationCode.NO_RECORDED_DIFFERENCE_IN_COMPARED_FIELDS in {
        unit.non_implication for unit in plan.analytical_units
    }
    rendered = RichGroundedDiscourseRenderer().render(plan, package=package)
    assert "No differing values are recorded" in " ".join(
        block.text for block in rendered.blocks
    )

    sections_without_result = []
    for section in plan.sections:
        units = [
            unit
            for unit in section.units
            if unit.non_implication
            is not NonImplicationCode.NO_RECORDED_DIFFERENCE_IN_COMPARED_FIELDS
        ]
        if units:
            sections_without_result.append(section.model_copy(update={"units": units}))
    invalid = plan.model_copy(update={"sections": sections_without_result})
    validation = GroundedAnswerPlanV3Validator().validate(invalid, package=package)
    assert validation.accepted is False
    assert validation.reason == "required_non_implication_missing"


def test_mixed_compare_schema_requires_three_distinct_available_dimensions() -> None:
    package = _explicit_compare_package()
    first_detection = next(
        atom
        for atom in package.operational_atoms
        if atom.atom_id == "incident:1:detection"
    )
    second_detection = first_detection.model_copy(
        update={
            "atom_id": "incident:2:detection",
            "incident_id": 2,
            "provenance": next(
                atom.provenance
                for atom in package.operational_atoms
                if atom.atom_id == "incident:2:identity"
            ),
            "rule": "Different detection",
        }
    )
    package = package.model_copy(
        update={
            "operational_atoms": [
                *package.operational_atoms,
                second_detection,
            ]
        }
    )

    schema = grounded_answer_plan_v3_schema(package)
    comparison = schema["$defs"]["section_compare"]

    assert comparison["minItems"] == 3
    assert comparison["maxItems"] == 3
    assert [
        item["properties"]["refs"]["const"]
        for item in comparison["prefixItems"]
    ] == [
        ["incident:1:status", "incident:2:status"],
        ["incident:1:host", "incident:2:host"],
        ["incident:1:detection", "incident:2:detection"],
    ]
    plan = deterministic_answer_plan_v3(package)
    assert GroundedAnswerPlanV3Validator().validate(plan, package=package).accepted
    comparison_section = next(
        section
        for section in plan.sections
        if section.section_type is AnswerSectionType.COMPARISON
    )
    assert len(comparison_section.units) == 3


def test_cross_relationship_evidence_does_not_add_an_unrelated_candidate_unit() -> None:
    package = analytical_package(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    schema = grounded_answer_plan_v3_schema(package)
    related = schema["$defs"]["section_related"]

    assert [
        item["properties"]["kind"]["const"]
        for item in related["prefixItems"]
    ] == ["relationship", "candidate"]
    assert schema["$defs"]["analytical_relationship_refs"]["const"] == [
        "relationship:shared-host"
    ]
    assert schema["$defs"]["candidate_refs"]["enum"] == [
        ["candidate:incident:2"]
    ]

    plan = deterministic_answer_plan_v3(package)
    assert GroundedAnswerPlanV3Validator().validate(plan, package=package).accepted
    related_units = next(
        section.units
        for section in plan.sections
        if section.section_type is AnswerSectionType.RELATED_INCIDENTS
    )
    candidate_unit = next(
        unit
        for unit in related_units
        if unit.unit_type is AnalyticalUnitType.CANDIDATE_RELEVANCE
    )
    assert candidate_unit.candidate_refs == ["candidate:incident:2"]
    assert "relationship:shared-host" in candidate_unit.relationship_refs
    assert all(
        2
        in {
            package.relationship_registry.resolve(ref).left_incident_id,
            package.relationship_registry.resolve(ref).right_incident_id,
        }
        for ref in candidate_unit.relationship_refs
    )


def test_homogeneous_section_slots_cannot_duplicate_semantic_units() -> None:
    schema = grounded_answer_plan_v3_schema(
        analytical_package(AnswerIntent.EXECUTIVE_SUMMARY)
    )
    findings = schema["$defs"]["section_findings"]

    assert findings["minItems"] == findings["maxItems"] == 1
    assert findings["uniqueItems"] is True


def test_handover_direct_and_overview_fact_pools_are_disjoint() -> None:
    schema = grounded_answer_plan_v3_schema(
        analytical_package(AnswerIntent.HANDOVER)
    )
    direct_refs = {
        ref for option in schema["$defs"]["direct_fact_refs"]["enum"] for ref in option
    }
    overview_refs = {
        ref
        for option in schema["$defs"]["overview_fact_refs"]["enum"]
        for ref in option
    }

    assert direct_refs.isdisjoint(overview_refs)


def test_pattern_schema_requires_the_matching_analytical_caveat() -> None:
    package = analytical_package(AnswerIntent.PATTERN_ANALYSIS)
    schema = grounded_answer_plan_v3_schema(package)
    caveat_definition = schema["$defs"]["section_caveats"]
    related_definition = schema["$defs"]["section_related"]

    caveat_codes = {
        code
        for variant in caveat_definition["items"]["oneOf"]
        for code in variant["properties"]["code"]["enum"]
    }
    related_kinds = {
        variant["properties"]["kind"]["const"]
        for variant in related_definition["items"]["oneOf"]
    }

    assert caveat_codes == {"ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY"}
    assert related_kinds == {"relationship"}
    assert caveat_definition["minItems"] == 1
    assert caveat_definition["maxItems"] == 1


def test_pattern_schema_variants_meet_the_validator_minimum_unit_contract() -> None:
    package = analytical_package(AnswerIntent.PATTERN_ANALYSIS)
    repeated_relationship = _analytical_relationship(
        "relationship:shared-host-repeat",
        RelationshipType.SHARED_AGENT,
        strength=0.7,
    )
    relationships = [
        *package.relationship_registry.relationships,
        repeated_relationship,
    ]
    package = package.model_copy(
        update={
            "cross_incident_graph": package.cross_incident_graph.model_copy(
                update={"relationships": relationships}
            ),
            "relationship_registry": package.relationship_registry.model_copy(
                update={"relationships": relationships}
            ),
        }
    )
    schema = grounded_answer_plan_v3_schema(package)
    minimum = INTENT_USEFULNESS_CONTRACTS[AnswerIntent.PATTERN_ANALYSIS].min_units
    sections = schema["properties"]["sections"]

    assert set(sections["required"]) == {"answer", "pattern", "caveats"}

    prompt = build_v3_plan_messages(
        package,
        max_context_chars=16_000,
        required_section_codes=tuple(sections["required"]),
    )
    prompt_payload = prompt.messages[-1]["content"]
    assert '"required_sections":["answer","caveats","pattern"]' in prompt_payload

    minimum_units = sum(
        schema["$defs"][
            sections["properties"][section_code]["$ref"].rsplit("/", 1)[-1]
        ]["minItems"]
        for section_code in sections["required"]
    )
    assert minimum_units >= minimum
    assert list(sections["properties"])[-1] in {"caveats", "limitations"}


def test_pattern_usefulness_is_bounded_by_model_facing_relationships() -> None:
    package = analytical_package(AnswerIntent.PATTERN_ANALYSIS)
    hidden_relationship = _analytical_relationship(
        "relationship:hidden-shared-host",
        RelationshipType.SHARED_AGENT,
        strength=0.6,
    ).model_copy(update={"left_incident_id": 3, "right_incident_id": 4})
    relationships = [
        *package.relationship_registry.relationships,
        hidden_relationship,
    ]
    package = package.model_copy(
        update={
            "resolved_scope": package.resolved_scope.model_copy(
                update={
                    "active_incident_ids": [1, 2],
                    "explicit_compare_incident_ids": [1, 2],
                }
            ),
            "cross_incident_graph": package.cross_incident_graph.model_copy(
                update={"incident_ids": [1, 2, 3, 4], "relationships": relationships}
            ),
            "relationship_registry": package.relationship_registry.model_copy(
                update={"relationships": relationships}
            ),
        }
    )

    assert AnalyticalUnitType.SHARED_PATTERN in available_unit_types(package)
    assert (
        AnalyticalUnitType.SHARED_PATTERN
        not in model_facing_available_unit_types(package)
    )

    fallback = deterministic_answer_plan_v3(package)
    model_facing_plan = fallback.model_copy(
        update={
            "sections": [
                section
                for section in fallback.sections
                if section.section_type is not AnswerSectionType.PATTERN
            ]
        }
    )
    result = GroundedAnswerPlanV3Validator().validate(
        model_facing_plan,
        package=package,
    )

    assert result.accepted, result.reason


def test_investigation_schema_keeps_timeline_refs_out_of_evidence() -> None:
    package = analytical_package(AnswerIntent.INVESTIGATE)
    schema = grounded_answer_plan_v3_schema(package)

    timeline_refs = {
        ref
        for option in schema["$defs"]["timeline_fact_refs"]["enum"]
        for ref in option
    }
    evidence_refs = {
        ref
        for option in schema["$defs"]["supporting_fact_refs"]["enum"]
        for ref in option
    }

    assert timeline_refs
    assert timeline_refs.isdisjoint(evidence_refs)
    evidence = schema["$defs"]["section_evidence"]
    assert evidence["maxItems"] == 1
    assert {
        item["properties"]["kind"]["const"]
        for item in evidence["items"]["oneOf"]
    } == {"fact"}


def test_cross_schema_uses_distinct_typed_related_slots() -> None:
    package = analytical_package(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    schema = grounded_answer_plan_v3_schema(package)
    related = schema["$defs"]["section_related"]

    kinds = [
        item["properties"]["kind"]["const"]
        for item in related["prefixItems"]
    ]

    assert len(kinds) == len(set(kinds))
    assert related["minItems"] == related["maxItems"] == len(kinds)


def test_model_facing_evidence_includes_authorized_case_scope_atoms() -> None:
    package = analytical_package(AnswerIntent.SUMMARY)
    case_atoms = [
        atom.model_copy(update={"case_id": 9})
        for atom in package.operational_atoms
    ]
    package = package.model_copy(
        update={
            "resolved_scope": package.resolved_scope.model_copy(
                update={"active_incident_ids": [], "active_case_ids": [9]}
            ),
            "operational_atoms": case_atoms,
        }
    )

    view = model_facing_evidence(package)
    schema = grounded_answer_plan_v3_schema(package)

    assert view.operational_atoms
    assert {atom.atom_id for atom in view.operational_atoms}.issubset(
        {atom.atom_id for atom in case_atoms}
    )
    assert schema["properties"]["sections"]["properties"]


def test_limitations_cannot_precede_a_supported_answer() -> None:
    package = analytical_package().model_copy(
        update={"semantic_index_status": "degraded"}
    )
    plan = deterministic_answer_plan_v3(package)
    terminal = plan.sections[-1]
    reordered = plan.model_copy(
        update={"sections": [terminal, *plan.sections[:-1]]}
    )

    result = GroundedAnswerPlanV3Validator().validate(reordered, package=package)
    assert result.accepted is False
    assert result.reason == "limitation_placement"


def test_explicit_compare_pair_excludes_unrelated_candidate_and_rejects_drift() -> None:
    package = _explicit_compare_package()
    view = model_facing_evidence(package)
    schema = grounded_answer_plan_v3_schema(package)
    plan = deterministic_answer_plan_v3(package)
    rendered = RichGroundedDiscourseRenderer().render(plan, package=package)

    assert {item.candidate_incident_id for item in view.candidates} == {2}
    assert all(
        {item.left_incident_id, item.right_incident_id}.issubset({1, 2})
        for item in view.relationships
    )
    assert "candidate:incident:3" not in str(schema)
    assert all(
        set(unit.subject_record_ids).issubset({1, 2})
        for unit in plan.analytical_units
    )
    assert "incident 3" not in " ".join(
        block.text.casefold() for block in rendered.blocks
    )

    drift = enrich_unit(
        AnalyticalUnit(
            unit_type=AnalyticalUnitType.CANDIDATE_RELEVANCE,
            candidate_refs=["candidate:incident:3"],
            relationship_refs=["relationship:semantic:3"],
        ),
        package=package,
        section_type=AnswerSectionType.RELATED_INCIDENTS,
    )
    related_index = next(
        index
        for index, section in enumerate(plan.sections)
        if section.section_type is AnswerSectionType.RELATED_INCIDENTS
    )
    sections = list(plan.sections)
    sections[related_index] = sections[related_index].model_copy(
        update={"units": [drift]}
    )
    result = GroundedAnswerPlanV3Validator().validate(
        plan.model_copy(update={"sections": sections}),
        package=package,
    )
    assert result.reason == "explicit_compare_scope_drift"


def test_cross_incident_renderer_synthesizes_multiple_relationship_signals() -> None:
    package = analytical_package(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    temporal = _analytical_relationship(
        "relationship:temporal",
        RelationshipType.TEMPORAL_PROXIMITY,
        strength=0.45,
    )
    relationships = [
        *package.relationship_registry.relationships,
        temporal,
    ]
    package = package.model_copy(
        update={
            "cross_incident_graph": package.cross_incident_graph.model_copy(
                update={"relationships": relationships}
            ),
            "relationship_registry": package.relationship_registry.model_copy(
                update={"relationships": relationships}
            ),
        }
    )
    plan = deterministic_answer_plan_v3(package)
    answer = " ".join(
        block.text
        for block in RichGroundedDiscourseRenderer().render(
            plan,
            package=package,
        ).blocks
    )

    assert "The leading comparison is that" in answer
    assert "additional context indicates that" in answer
    assert "temporal proximity" in answer
    assert "analytical relationships derived from records" in answer


def test_raw_advisory_payload_has_no_prompt_or_renderer_path() -> None:
    package = analytical_package(AnswerIntent.NEXT_ACTION, include_advisory=False)
    package = package.model_copy(
        update={
            "context_plan": package.context_plan.model_copy(
                update={"include_advisory": True}
            )
        }
    )
    raw_marker = "RAW_PRIVATE_PAYLOAD_SHOULD_NOT_RENDER"
    advisories = normalize_advisory_sources(
        [
            SimpleNamespace(
                authority="advisory",
                source_type="historical_incident",
                record_id="historical-44",
                section="incident",
                label="Historical comparison",
                excerpt=f"{{'raw': '{raw_marker}', 'risk': 99}}",
                source_id="S44",
            )
        ],
        plan=package.context_plan,
    )
    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory.action_code is AdvisoryActionCode.COMPARE_RELATED_EVIDENCE
    assert advisory.reason_code is AdvisoryReasonCode.HISTORICAL_SIMILARITY_RETRIEVED
    assert advisory.target_type is AdvisoryTargetType.DETECTION_AND_TIMELINE
    assert advisory.context_code is AdvisoryContextCode.HISTORICAL_INCIDENT

    package = package.model_copy(update={"advisory_atoms": advisories})
    prompt = build_v3_plan_messages(package, max_context_chars=24_000)
    plan = deterministic_answer_plan_v3(package)
    answer = " ".join(
        block.text
        for block in RichGroundedDiscourseRenderer().render(
            plan,
            package=package,
        ).blocks
    )

    assert raw_marker not in prompt.messages[1]["content"]
    assert raw_marker not in answer
    assert "historical incident was retrieved as a similarity lead" in answer
    assert "events are the same" in answer


def test_v3_structured_output_budget_is_bounded_but_not_truncation_prone(
    monkeypatch,
) -> None:
    monkeypatch.delenv("AI_SOC_ASSISTANT_V3_MAX_OUTPUT_TOKENS", raising=False)
    settings = get_assistant_settings()

    assert settings.v3_max_output_tokens == 768
    assert settings.v3_max_output_tokens < 2048


def test_v3_is_default_response_architecture_with_explicit_v2_rollback(
    monkeypatch,
) -> None:
    monkeypatch.delenv("AI_ASSISTANT_RESPONSE_ARCHITECTURE", raising=False)
    assert get_assistant_settings().response_architecture == "v3"

    monkeypatch.setenv("AI_ASSISTANT_RESPONSE_ARCHITECTURE", "v2")
    assert get_assistant_settings().response_architecture == "v2"


def test_investigate_fallback_meets_richness_bounds_without_timeline() -> None:
    package = analytical_package(AnswerIntent.INVESTIGATE).model_copy(
        update={
            "operational_atoms": [
                atom
                for atom in analytical_package(
                    AnswerIntent.INVESTIGATE
                ).operational_atoms
                if atom.atom_type != "timeline_event"
            ],
            "reference_atoms": [],
            "advisory_atoms": [],
        }
    )

    plan = deterministic_answer_plan_v3(package)
    result = GroundedAnswerPlanV3Validator().validate(plan, package=package)

    assert result.accepted, result.reason
    assert len(plan.sections) >= 2
    assert len(plan.analytical_units) >= 3
    evidence = next(
        section
        for section in plan.sections
        if section.section_type is AnswerSectionType.EVIDENCE
    )
    assert len(evidence.units) >= 2


def test_next_action_without_advisory_uses_typed_limitation_not_fake_guidance() -> None:
    package = analytical_package(AnswerIntent.NEXT_ACTION).model_copy(
        update={
            "context_plan": analytical_package(
                AnswerIntent.NEXT_ACTION
            ).context_plan.model_copy(update={"include_advisory": True}),
            "advisory_atoms": [],
        }
    )

    schema = grounded_answer_plan_v3_schema(package)
    plan = deterministic_answer_plan_v3(package)
    result = GroundedAnswerPlanV3Validator().validate(plan, package=package)

    assert result.accepted, result.reason
    assert not any(unit.advisory_refs for unit in plan.analytical_units)
    assert any(
        unit.limitation.value == "ADVISORY_KNOWLEDGE_UNAVAILABLE"
        for unit in plan.analytical_units
        if unit.limitation is not None
    )
    assert "limits" in schema["properties"]["sections"]["required"]


def test_cross_fallback_without_candidates_still_meets_usefulness_contract() -> None:
    package = analytical_package(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    package = package.model_copy(
        update={
            "cross_incident_candidates": [],
            "cross_incident_graph": package.cross_incident_graph.model_copy(
                update={"relationships": []}
            ),
            "relationship_registry": package.relationship_registry.model_copy(
                update={"relationships": []}
            ),
        }
    )

    plan = deterministic_answer_plan_v3(package)
    result = GroundedAnswerPlanV3Validator().validate(plan, package=package)

    assert result.accepted, result.reason
    assert len(plan.sections) >= 3
    assert len(plan.analytical_units) >= 3
    assert any(
        unit.limitation.value == "NO_RELATED_INCIDENT_CANDIDATES"
        for unit in plan.analytical_units
        if unit.limitation is not None
    )


def test_cross_fallback_caps_rich_relationship_plan_within_intent_budget() -> None:
    package = analytical_package(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    extra_relationships = [
        _analytical_relationship(
            f"relationship:shared-mitre:{index}",
            RelationshipType.SHARED_MITRE,
            strength=0.7,
        )
        for index in range(4)
    ] + [
        _analytical_relationship(
            f"relationship:temporal:{index}",
            RelationshipType.TEMPORAL_PROXIMITY,
            strength=0.5,
        )
        for index in range(4)
    ]
    relationships = [
        *package.relationship_registry.relationships,
        *extra_relationships,
    ]
    package = package.model_copy(
        update={
            "cross_incident_graph": package.cross_incident_graph.model_copy(
                update={"relationships": relationships}
            ),
            "relationship_registry": package.relationship_registry.model_copy(
                update={"relationships": relationships}
            ),
        }
    )

    plan = deterministic_answer_plan_v3(package)
    result = GroundedAnswerPlanV3Validator().validate(plan, package=package)

    assert result.accepted, result.reason
    assert len(plan.analytical_units) <= 12


def test_handover_fallback_does_not_invent_unrequested_cross_limitation() -> None:
    package = analytical_package(AnswerIntent.HANDOVER)
    package = package.model_copy(
        update={
            "context_plan": package.context_plan.model_copy(
                update={"include_cross_incident": False}
            ),
            "cross_incident_candidates": [],
            "cross_incident_graph": package.cross_incident_graph.model_copy(
                update={"relationships": []}
            ),
            "relationship_registry": package.relationship_registry.model_copy(
                update={"relationships": []}
            ),
        }
    )

    plan = deterministic_answer_plan_v3(package)
    result = GroundedAnswerPlanV3Validator().validate(plan, package=package)

    assert result.accepted, result.reason
    assert all(
        unit.limitation is None
        or unit.limitation.value != "NO_RELATED_INCIDENT_CANDIDATES"
        for unit in plan.analytical_units
    )
