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
    PlanLimitationCode,
    SECTION_UNIT_TYPES,
)
from services.assistant.v3.plan_fallback import deterministic_answer_plan_v3
from services.assistant.v3.plan_prompting import build_v3_plan_messages
from services.assistant.v3.plan_schema import (
    SECTION_WIRE_CODES,
    UNIT_WIRE_CODES,
    grounded_answer_plan_v3_schema,
)
from services.assistant.v3.quality_policy import enrich_unit
from services.assistant.v3.plan_validation import (
    GroundedAnswerPlanV3Validator,
    parse_grounded_answer_plan_v3,
)
from tests.assistant_v3_test_support import analytical_package


def _schema_units(section: dict) -> list[dict]:
    return section.get("prefixItems") or section["items"]["oneOf"]


def _plan(
    *sections: AnswerSection,
    package=None,
) -> GroundedAnswerPlanV3:
    if package is not None:
        sections = tuple(
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
        )
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
    section_properties = {
        name: schema["$defs"][value["$ref"].rsplit("/", 1)[-1]]
        for name, value in schema["properties"]["sections"]["properties"].items()
    }
    unit_variants = [
        unit
        for section in section_properties.values()
        for unit in _schema_units(section)
    ]

    def variants(unit_type: AnalyticalUnitType):
        return [
            unit
            for unit in unit_variants
            if unit["properties"]["kind"]["const"] == UNIT_WIRE_CODES[unit_type]
        ]

    assert schema["additionalProperties"] is False
    assert schema["required"] == ["order", "sections"]
    assert {
        ref for option in schema["$defs"]["fact_refs"]["enum"] for ref in option
    } == {
        atom.atom_id for atom in package.operational_atoms
    }
    assert {
        ref
        for option in schema["$defs"]["relationship_refs"]["enum"]
        for ref in option
    } == {
        item.relationship_id for item in package.cross_incident_graph.relationships
    }
    assert schema["$defs"]["candidate_refs"]["enum"] == [
        ["candidate:incident:2"]
    ]
    assert set(
        variants(AnalyticalUnitType.ANALYTICAL_RELATIONSHIP)[0]["properties"]
    ) == {
        "kind",
        "mode",
        "importance",
        "refs",
    }
    assert "relationship:missing" not in str(schema)


def test_dynamic_schema_is_intent_restricted_and_bounded() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    schema = grounded_answer_plan_v3_schema(package)
    sections = schema["properties"]["sections"]

    assert sections["minProperties"] == 2
    assert sections["maxProperties"] == 4
    assert set(sections["required"]) == {"answer", "technical"}
    assert set(sections["properties"]) == {
        "answer",
        "findings",
        "technical",
        "evidence",
    }
    section_types_by_wire = {
        value: key for key, value in SECTION_WIRE_CODES.items()
    }
    unit_types_by_wire = {value: key for key, value in UNIT_WIRE_CODES.items()}
    section_properties = {
        name: schema["$defs"][value["$ref"].rsplit("/", 1)[-1]]
        for name, value in sections["properties"].items()
    }
    for section_name, section in section_properties.items():
        section_type = section_types_by_wire[section_name]
        assert all(
            unit_types_by_wire[unit["properties"]["kind"]["const"]]
            in SECTION_UNIT_TYPES[section_type]
            for unit in _schema_units(section)
        )


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
        package=package,
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
        ),
        package=package,
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
        ),
        package=package,
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
    assert fallback.used_advisory_refs == []
    assert fallback.next_checks == []


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


def test_parser_normalizes_closed_section_map_without_repair() -> None:
    plan = deterministic_answer_plan_v3(analytical_package())
    payload = plan.model_dump(mode="json")
    payload["sections"] = {
        section["section_type"]: section["units"]
        for section in payload["sections"]
    }

    assert parse_grounded_answer_plan_v3(payload) == plan


def test_parser_canonicalizes_compact_wire_plan_from_current_package() -> None:
    package = analytical_package()
    payload = {
        "order": "comparison",
        "sections": {
            "answer": [{
                "kind": "fact",
                "mode": "primary:lead",
                "importance": "primary",
                "refs": ["incident:1:status"],
            }],
            "related": [{
                "kind": "relationship",
                "mode": "relationship:compare",
                "importance": "primary",
                "refs": ["relationship:shared-host"],
            }],
            "caveats": [{
                "kind": "non_implication",
                "mode": "caveat:caveat",
                "importance": "secondary",
                "code": "SHARED_HOST_NOT_COMMON_ROOT_CAUSE",
            }],
        }
    }

    plan = parse_grounded_answer_plan_v3(payload, package=package)

    assert plan is not None
    assert plan.answer_intent is AnswerIntent.CROSS_INCIDENT_ANALYSIS
    assert plan.detail_level is AnswerDetailLevel.STANDARD
    assert plan.audience is AnswerAudience.SOC_ANALYST
    assert plan.ordering is DiscourseOrdering.COMPARISON_FIRST
    assert GroundedAnswerPlanV3Validator().validate(plan, package=package).accepted


def test_parser_rejects_compact_wire_without_package_or_with_ambiguous_refs() -> None:
    package = analytical_package()
    payload = {
        "order": "comparison",
        "sections": {
            "answer": [{
                "kind": "recorded",
                "mode": "primary:lead",
                "importance": "primary",
                "refs": ["incident:1:status", "relationship:shared-host"],
            }]
        }
    }

    assert parse_grounded_answer_plan_v3(payload) is None
    assert parse_grounded_answer_plan_v3(payload, package=package) is None


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


def test_semantic_index_degradation_is_visible_but_not_authoritative() -> None:
    package = analytical_package().model_copy(
        update={"semantic_index_status": "degraded"}
    )
    fallback = deterministic_answer_plan_v3(package)

    result = GroundedAnswerPlanV3Validator().validate(fallback, package=package)

    assert result.accepted is True
    assert PlanLimitationCode.SEMANTIC_INDEX_DEGRADED in fallback.limitations
