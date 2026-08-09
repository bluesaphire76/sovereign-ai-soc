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
    IncidentCandidate,
    Provenance,
    RelationshipClass,
    RelationshipType,
)
from services.assistant.v3.discourse import RichGroundedDiscourseRenderer
from services.assistant.v3.knowledge import normalize_advisory_sources
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    AnswerSectionType,
    EvidencePriority,
    PropositionType,
)
from services.assistant.v3.plan_fallback import deterministic_answer_plan_v3
from services.assistant.v3.plan_prompting import build_v3_plan_messages
from services.assistant.v3.plan_schema import (
    grounded_answer_plan_v3_schema,
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


def test_dynamic_schema_uses_bounded_adaptive_section_variants() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    schema = grounded_answer_plan_v3_schema(package)
    variants = schema["properties"]["sections"]["oneOf"]
    contract = INTENT_USEFULNESS_CONTRACTS[AnswerIntent.EXPLAIN]

    counts = {item["minProperties"] for item in variants}
    assert len(counts) > 1
    assert min(counts) >= contract.min_sections
    assert max(counts) <= contract.max_sections
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
    assert all(
        "technical" in variant["required"]
        for variant in investigate["properties"]["sections"]["oneOf"]
    )


def test_executive_findings_require_multiple_facts_when_available() -> None:
    schema = grounded_answer_plan_v3_schema(
        analytical_package(AnswerIntent.EXECUTIVE_SUMMARY)
    )

    options = schema["$defs"]["findings_fact_refs"]["enum"]

    assert options
    assert all(len(option) >= 2 for option in options)


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
    assert schema["properties"]["sections"]["oneOf"]


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
    first_variant = schema["properties"]["sections"]["oneOf"][0]
    assert "limits" in first_variant["required"]


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
