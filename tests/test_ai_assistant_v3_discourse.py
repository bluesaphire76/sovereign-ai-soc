from __future__ import annotations

from services.assistant.v3.attribution import build_v3_attribution
from services.assistant.v3.contracts import AnswerIntent
from services.assistant.v3.discourse import RichGroundedDiscourseRenderer
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    AnswerAudience,
    AnswerDetailLevel,
    AnswerSection,
    AnswerSectionType,
    DiscourseOrdering,
    GroundedAnswerPlanV3,
    PlanLimitationCode,
)
from services.assistant.v3.plan_fallback import deterministic_answer_plan_v3
from services.assistant.v3.plan_validation import GroundedAnswerPlanV3Validator
from tests.assistant_v3_test_support import analytical_package


def _render(intent: AnswerIntent, *, language: str = "en"):
    package = analytical_package(intent).model_copy(
        update={"response_language": language}
    )
    plan = deterministic_answer_plan_v3(package)
    assert GroundedAnswerPlanV3Validator().validate(plan, package=package).accepted
    return package, plan, RichGroundedDiscourseRenderer().render(
        plan,
        package=package,
    )


def test_renderer_combines_facts_into_a_grounded_paragraph() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    plan = GroundedAnswerPlanV3(
        answer_intent=AnswerIntent.EXPLAIN,
        detail_level=AnswerDetailLevel.STANDARD,
        audience=AnswerAudience.SOC_ANALYST,
        ordering=DiscourseOrdering.CONCLUSION_FIRST,
        sections=[
            AnswerSection(
                section_type=AnswerSectionType.DIRECT_ANSWER,
                units=[
                    AnalyticalUnit(
                        unit_type=AnalyticalUnitType.RECORDED_FACT,
                        fact_refs=[
                            "incident:1:status",
                            "incident:1:host",
                            "incident:1:detection",
                        ],
                    )
                ],
            )
        ],
    )

    rendered = RichGroundedDiscourseRenderer().render(plan, package=package)

    assert len(rendered.blocks) == 1
    assert rendered.blocks[0].text.count("Incident 1") == 1
    assert "endpoint-a" in rendered.blocks[0].text
    assert "Registry changed" in rendered.blocks[0].text
    assert rendered.blocks[0].source_refs == (
        "incident:1:status",
        "incident:1:host",
        "incident:1:detection",
    )


def test_renderer_supports_natural_italian_and_preserves_identifiers() -> None:
    package, _, rendered = _render(AnswerIntent.EXPLAIN, language="it")
    answer = "\n\n".join(block.text for block in rendered.blocks)

    assert package.response_language == "it"
    assert "L'incidente 1" in answer
    assert "endpoint-a" in answer
    assert "T1112" in answer
    assert "guida investigativa" not in answer


def test_cross_incident_rendering_keeps_authority_classes_distinct() -> None:
    _, _, rendered = _render(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    answer = "\n\n".join(block.text for block in rendered.blocks)

    assert "recorded correlation" in answer
    assert "analytical relationship derived from records" in answer
    assert "comparison candidate based on semantic similarity" in answer
    assert "Semantic similarity is not a recorded correlation" in answer
    assert "ranking indicates comparison utility, not risk or compromise" in answer
    assert "common root cause" in answer


def test_reference_and_advisory_content_are_separate_blocks() -> None:
    _, _, explain = _render(AnswerIntent.EXPLAIN)
    _, _, investigate = _render(AnswerIntent.INVESTIGATE)

    technical = next(
        block
        for block in explain.blocks
        if block.section_type is AnswerSectionType.TECHNICAL_CONTEXT
    )
    next_steps = next(
        block
        for block in investigate.blocks
        if block.section_type is AnswerSectionType.NEXT_STEPS
    )
    assert technical.text == "T1112 = Modify Registry."
    assert technical.source_refs == ("reference:mitre:T1112",)
    assert next_steps.text.startswith("As investigative guidance, ")
    assert next_steps.source_refs == ("advisory:registry-review",)


def test_duplicate_limitation_text_is_suppressed_across_sections() -> None:
    package = analytical_package(AnswerIntent.FACT_LOOKUP)
    plan = GroundedAnswerPlanV3(
        answer_intent=AnswerIntent.FACT_LOOKUP,
        detail_level=AnswerDetailLevel.CONCISE,
        audience=AnswerAudience.SOC_ANALYST,
        ordering=DiscourseOrdering.CONCLUSION_FIRST,
        sections=[
            AnswerSection(
                section_type=AnswerSectionType.DIRECT_ANSWER,
                units=[
                    AnalyticalUnit(
                        unit_type=AnalyticalUnitType.ABSENCE,
                        absence_field="severity",
                    )
                ],
            ),
            AnswerSection(
                section_type=AnswerSectionType.LIMITATIONS,
                units=[
                    AnalyticalUnit(
                        unit_type=AnalyticalUnitType.LIMITATION,
                        limitation=(
                            PlanLimitationCode.CANONICAL_SEVERITY_NOT_RECORDED
                        ),
                    )
                ],
            ),
        ],
    )

    rendered = RichGroundedDiscourseRenderer().render(plan, package=package)

    assert len(rendered.blocks) == 1
    assert rendered.blocks[0].section_type is AnswerSectionType.DIRECT_ANSWER


def test_intent_controls_response_length_and_block_order() -> None:
    _, fact_plan, fact = _render(AnswerIntent.FACT_LOOKUP)
    _, executive_plan, executive = _render(AnswerIntent.EXECUTIVE_SUMMARY)
    _, investigation_plan, investigation = _render(AnswerIntent.INVESTIGATE)

    assert fact_plan.detail_level is AnswerDetailLevel.CONCISE
    assert len(fact.blocks) == 1
    assert executive_plan.audience is AnswerAudience.EXECUTIVE
    assert len(executive.blocks) == 1
    assert investigation_plan.detail_level is AnswerDetailLevel.STANDARD
    assert [block.section_type for block in investigation.blocks] == [
        AnswerSectionType.DIRECT_ANSWER,
        AnswerSectionType.TECHNICAL_CONTEXT,
        AnswerSectionType.NEXT_STEPS,
    ]


def test_attribution_is_derived_from_plan_refs_without_text_matching() -> None:
    package, _, rendered = _render(AnswerIntent.CROSS_INCIDENT_ANALYSIS)

    attribution = build_v3_attribution(
        package=package,
        rendered=rendered,
        existing_sources=[],
        max_sources=8,
    )

    assert {source.record_id for source in attribution.sources} >= {"1", "2"}
    assert attribution.source_ids_by_ref["relationship:shared-host"]
    assert attribution.source_ids_by_ref["relationship:semantic"]
    known_ids = {source.source_id for source in attribution.sources}
    assert all(
        set(source_ids).issubset(known_ids)
        for source_ids in attribution.source_ids_by_ref.values()
    )


def test_attribution_fails_closed_when_source_budget_is_too_small() -> None:
    package, _, rendered = _render(AnswerIntent.CROSS_INCIDENT_ANALYSIS)

    try:
        build_v3_attribution(
            package=package,
            rendered=rendered,
            existing_sources=[],
            max_sources=1,
        )
    except ValueError as exc:
        assert "source attribution budget" in str(exc)
    else:
        raise AssertionError("expected the source budget to fail closed")
