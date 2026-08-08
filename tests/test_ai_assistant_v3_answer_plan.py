from __future__ import annotations

import pytest
from pydantic import ValidationError

from services.assistant.v3.contracts import AnswerIntent, FactField
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
)
from services.assistant.v3.plan_fallback import deterministic_answer_plan_v3
from services.assistant.v3.plan_prompting import build_v3_plan_messages
from services.assistant.v3.plan_schema import grounded_answer_plan_v3_schema
from services.assistant.v3.plan_validation import (
    GroundedAnswerPlanV3Validator,
    parse_grounded_answer_plan_v3,
)
from tests.assistant_v3_test_support import analytical_package


def _plan(*sections: AnswerSection) -> GroundedAnswerPlanV3:
    return GroundedAnswerPlanV3(
        answer_intent=AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        detail_level=AnswerDetailLevel.STANDARD,
        audience=AnswerAudience.SOC_ANALYST,
        ordering=DiscourseOrdering.COMPARISON_FIRST,
        sections=list(sections),
    )


def _non_implication() -> AnswerSection:
    return AnswerSection(
        section_type=AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
        units=[
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.NON_IMPLICATION,
                relationship_refs=["relationship:shared-host"],
                non_implication=(
                    NonImplicationCode.SHARED_HOST_NOT_COMMON_ROOT_CAUSE
                ),
            ),
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.NON_IMPLICATION,
                relationship_refs=["relationship:semantic"],
                non_implication=(
                    NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
                ),
            ),
        ],
    )


def test_dynamic_schema_restricts_all_refs_to_current_package() -> None:
    package = analytical_package()
    schema = grounded_answer_plan_v3_schema(package)
    unit = schema["properties"]["sections"]["items"]["properties"]["units"][
        "items"
    ]

    assert schema["additionalProperties"] is False
    assert schema["properties"]["answer_intent"]["const"] == (
        "CROSS_INCIDENT_ANALYSIS"
    )
    assert set(unit["properties"]["fact_refs"]["items"]["enum"]) == {
        atom.atom_id for atom in package.operational_atoms
    }
    assert set(unit["properties"]["relationship_refs"]["items"]["enum"]) == {
        item.relationship_id for item in package.cross_incident_graph.relationships
    }
    assert unit["properties"]["candidate_refs"]["items"]["enum"] == [
        "candidate:incident:2"
    ]
    assert "relationship:missing" not in str(schema)


def test_validator_accepts_grounded_cross_incident_plan() -> None:
    package = analytical_package()
    plan = _plan(
        AnswerSection(
            section_type=AnswerSectionType.DIRECT_ANSWER,
            units=[
                AnalyticalUnit(
                    unit_type=AnalyticalUnitType.RECORDED_FACT,
                    fact_refs=["incident:1:status", "incident:1:host"],
                )
            ],
        ),
        AnswerSection(
            section_type=AnswerSectionType.RELATED_INCIDENTS,
            units=[
                AnalyticalUnit(
                    unit_type=AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                    relationship_refs=["relationship:shared-host"],
                ),
                AnalyticalUnit(
                    unit_type=AnalyticalUnitType.SEMANTIC_SIMILARITY,
                    relationship_refs=["relationship:semantic"],
                ),
            ],
        ),
        _non_implication(),
    )

    assert GroundedAnswerPlanV3Validator().validate(plan, package=package).accepted


@pytest.mark.parametrize(
    ("unit", "reason"),
    [
        (
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.RECORDED_FACT,
                fact_refs=["incident:missing:status"],
            ),
            "unknown_fact_ref",
        ),
        (
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.RECORDED_CORRELATION,
                relationship_refs=["relationship:shared-host"],
            ),
            "recorded_correlation_authority_mismatch",
        ),
        (
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                relationship_refs=["relationship:semantic"],
            ),
            "analytical_relationship_authority_mismatch",
        ),
        (
            AnalyticalUnit(
                unit_type=AnalyticalUnitType.ABSENCE,
                absence_field=FactField.ESCALATED,
            ),
            "unsupported_absence",
        ),
    ],
)
def test_validator_rejects_invalid_refs_authority_and_absence(
    unit: AnalyticalUnit,
    reason: str,
) -> None:
    package = analytical_package()
    plan = _plan(
        AnswerSection(
            section_type=AnswerSectionType.DIRECT_ANSWER,
            units=[unit],
        )
    )

    result = GroundedAnswerPlanV3Validator().validate(plan, package=package)
    assert result.accepted is False
    assert result.reason == reason


def test_relationship_plan_requires_explicit_non_implication() -> None:
    package = analytical_package()
    plan = _plan(
        AnswerSection(
            section_type=AnswerSectionType.RELATED_INCIDENTS,
            units=[
                AnalyticalUnit(
                    unit_type=AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                    relationship_refs=["relationship:shared-host"],
                )
            ],
        )
    )

    result = GroundedAnswerPlanV3Validator().validate(plan, package=package)
    assert result.reason == "required_non_implication_missing"


def test_duplicate_units_and_excessive_plan_fail_closed() -> None:
    unit = AnalyticalUnit(
        unit_type=AnalyticalUnitType.RECORDED_FACT,
        fact_refs=["incident:1:status"],
    )
    with pytest.raises(ValidationError):
        _plan(
            AnswerSection(
                section_type=AnswerSectionType.DIRECT_ANSWER,
                units=[unit, unit],
            )
        )

    sections = [
        AnswerSection(
            section_type=section_type,
            units=[
                AnalyticalUnit(
                    unit_type=AnalyticalUnitType.RECORDED_FACT,
                    fact_refs=[f"incident:{index}:status"],
                )
                for index in range(4)
            ],
        )
        for section_type in list(AnswerSectionType)[:9]
    ]
    with pytest.raises(ValidationError):
        _plan(*sections)


def test_invalid_section_unit_pairing_is_rejected() -> None:
    package = analytical_package()
    plan = _plan(
        AnswerSection(
            section_type=AnswerSectionType.EVIDENCE,
            units=[
                AnalyticalUnit(
                    unit_type=AnalyticalUnitType.CANDIDATE_RELEVANCE,
                    candidate_refs=["candidate:incident:2"],
                )
            ],
        )
    )

    result = GroundedAnswerPlanV3Validator().validate(plan, package=package)
    assert result.reason == "section_unit_mismatch"


def test_deterministic_fallback_is_rich_valid_and_intent_aware() -> None:
    package = analytical_package()
    fallback = deterministic_answer_plan_v3(package)
    result = GroundedAnswerPlanV3Validator().validate(fallback, package=package)

    assert result.accepted is True
    assert len(fallback.sections) >= 3
    assert fallback.used_relationship_refs
    assert fallback.used_advisory_refs
    assert fallback.next_checks


@pytest.mark.parametrize("intent", list(AnswerIntent))
def test_deterministic_fallback_validates_for_every_intent(
    intent: AnswerIntent,
) -> None:
    package = analytical_package(intent)
    fallback = deterministic_answer_plan_v3(package)

    result = GroundedAnswerPlanV3Validator().validate(fallback, package=package)

    assert result.accepted is True, (intent, result.reason)


def test_reference_and_advisory_units_are_typed_and_valid() -> None:
    explain_package = analytical_package(AnswerIntent.EXPLAIN)
    explain = deterministic_answer_plan_v3(explain_package)
    next_action_package = analytical_package(AnswerIntent.NEXT_ACTION)
    next_action = deterministic_answer_plan_v3(next_action_package)

    assert GroundedAnswerPlanV3Validator().validate(
        explain,
        package=explain_package,
    ).accepted
    assert explain.used_reference_refs == ["reference:mitre:T1112"]
    assert GroundedAnswerPlanV3Validator().validate(
        next_action,
        package=next_action_package,
    ).accepted
    assert next_action.used_advisory_refs == ["advisory:registry-review"]


def test_relationship_cannot_be_smuggled_into_recorded_fact() -> None:
    with pytest.raises(ValidationError):
        AnalyticalUnit(
            unit_type=AnalyticalUnitType.RECORDED_FACT,
            fact_refs=["incident:1:status"],
            relationship_refs=["relationship:shared-host"],
        )


def test_parser_rejects_wrapped_or_repaired_json() -> None:
    assert parse_grounded_answer_plan_v3('{"answer_intent":') is None
    assert parse_grounded_answer_plan_v3('```json\n{}\n```') is None
    assert parse_grounded_answer_plan_v3('prefix {"answer_intent": "EXPLAIN"}') is None


def test_prompt_contains_typed_context_only_and_enforces_budget() -> None:
    package = analytical_package()
    result = build_v3_plan_messages(package, max_context_chars=24_000)

    assert len(result.messages) == 2
    assert "relationship:shared-host" in result.messages[1]["content"]
    assert "deterministic_derivation" not in result.messages[1]["content"]
    assert "Do not write answer prose" in result.messages[0]["content"]

    oversized = package.model_copy(update={"question": "x" * 4_000})
    with pytest.raises(ValueError, match="prompt budget"):
        build_v3_plan_messages(oversized, max_context_chars=4_000)
