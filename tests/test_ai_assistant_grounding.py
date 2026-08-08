from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from services.assistant.claims import (
    FACT_FIELD_REGISTRY,
    AdvisoryGuidanceCode,
    ClaimType,
    FactField,
    FactProvenance,
    GroundedClaim,
    GroundedClaimOutput,
    LimitationCode,
    NextCheckType,
    RelationNode,
    StructuredNextCheck,
    grounded_claim_output_schema,
)
from services.assistant.focus import FocusDimension, FocusSelection
from services.assistant.grounding import (
    deterministic_claim_output,
    parse_grounded_output,
    validate_focus,
    validate_grounded_output,
)
from services.assistant.rendering import render_claim_output, response_blocks
from services.assistant.sources import SourceRecord, assign_source_ids


FACTS = {
    "source_type": "incident",
    "incident_id": 5299,
    "status": "NEW",
    "status_description": "Recorded operational status",
    "severity": "LOW",
    "risk_normalization_severity": "MEDIUM",
    "recommended_priority": "HIGH",
    "risk_score": 35,
    "risk_band": "RECORDED_MEDIUM",
    "risk_method": "platform-v2",
    "risk_derived_from": ["correlation_score"],
    "correlated": True,
    "correlation_type": "SINGLE_HOST_PATTERN_CORRELATION",
    "correlation_score": 35,
    "agent": "darkstar-windows",
    "wazuh_level": 5,
    "evidence": [{"event_type": "ALERT_CREATED"}],
    "latest_timeline_event": {"event_type": "ALERT_CREATED"},
    "mitre": [{"id": "T1112", "name": "Modify Registry"}],
    "compromise_confirmed": False,
    "threat_assessment": "NOT_RECORDED_AS_IMMEDIATE",
    "urgency": "ROUTINE_REVIEW",
    "impact": "RECORDED_LIMITED",
    "escalated": False,
    "escalation_reason": None,
}


SOURCES = assign_source_ids(
    [
        SourceRecord(
            source_type="incident",
            authority="authoritative",
            record_id="5299",
            label="Incident 5299",
            url="/incidents/5299",
            excerpt="Authoritative incident record.",
        ),
        SourceRecord(
            source_type="detection_control",
            authority="advisory",
            record_id="registry-control",
            label="Registry control",
            url="/settings/detection-control",
            excerpt="Review related registry telemetry.",
        ),
    ],
    max_sources=8,
)


def _focus(*dimensions: FocusDimension) -> FocusSelection:
    selected = dimensions or (FocusDimension.GENERAL,)
    return FocusSelection(
        dimensions=selected,
        scores={dimension: 1.0 for dimension in selected},
        confidence=1.0,
    )


def _claim(
    field: FactField,
    value=None,
    *,
    claim_type: ClaimType | None = None,
    provenance: FactProvenance | None = None,
    source_ids: list[str] | None = None,
) -> GroundedClaim:
    policy = FACT_FIELD_REGISTRY[field]
    selected_type = claim_type
    if selected_type is None:
        if value is None:
            selected_type = ClaimType.ABSENCE
        elif policy.semantic_role.value == "distinct_value":
            selected_type = ClaimType.DISTINCT_VALUE
        else:
            selected_type = ClaimType.RECORDED_FACT
    return GroundedClaim(
        claim_type=selected_type,
        field=field,
        value=value,
        provenance=provenance or policy.provenance,
        source_ids=source_ids or ["S1"],
    )


def _output(*claims: GroundedClaim, **overrides) -> GroundedClaimOutput:
    values = {
        "claims": list(claims),
        "next_check": None,
        "limitations": [],
        "used_advisory_context": False,
    }
    values.update(overrides)
    return GroundedClaimOutput(**values)


def _structured_reference(
    field: FactField,
    *,
    source_ids: list[str] | None = None,
) -> GroundedClaim:
    return GroundedClaim(
        claim_type=ClaimType.STRUCTURED_REFERENCE,
        field=field,
        provenance=FACT_FIELD_REGISTRY[field].provenance,
        source_ids=source_ids or ["S1"],
    )


def _validate(
    output: GroundedClaimOutput,
    *,
    facts: dict | None = None,
    sources: list[SourceRecord] | None = None,
):
    return validate_grounded_output(
        output,
        fact_inventory=FACTS if facts is None else facts,
        sources=SOURCES if sources is None else sources,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (FactField.STATUS, "NEW"),
        (FactField.STATUS_DESCRIPTION, "Recorded operational status"),
        (FactField.SEVERITY, "LOW"),
        (FactField.RISK_NORMALIZATION_SEVERITY, "MEDIUM"),
        (FactField.RECOMMENDED_PRIORITY, "HIGH"),
        (FactField.RISK_SCORE, 35),
        (FactField.RISK_BAND, "RECORDED_MEDIUM"),
        (FactField.CORRELATED, True),
        (FactField.CORRELATION_TYPE, "SINGLE_HOST_PATTERN_CORRELATION"),
        (FactField.CORRELATION_SCORE, 35),
        (FactField.AGENT, "darkstar-windows"),
        (FactField.WAZUH_LEVEL, 5),
        (FactField.COMPROMISE_CONFIRMED, False),
        (FactField.ESCALATED, False),
    ],
)
def test_exact_recorded_facts_are_accepted(field, value) -> None:
    assert _validate(_output(_claim(field, value))).accepted is True


@pytest.mark.parametrize(
    ("field", "value", "facts"),
    [
        (FactField.CORRELATED, True, FACTS),
        (FactField.RISK_SCORE, 35, FACTS),
        (FactField.RISK_SCORE, 35.5, FACTS | {"risk_score": 35.5}),
        (FactField.STATUS, "NEW", FACTS),
    ],
)
def test_claim_value_accepts_only_policy_compatible_scalars(
    field,
    value,
    facts,
) -> None:
    assert _validate(_output(_claim(field, value)), facts=facts).accepted is True


@pytest.mark.parametrize(
    "value",
    [
        {"event_type": "ALERT_CREATED"},
        [{"event_type": "ALERT_CREATED"}],
    ],
)
def test_recorded_fact_rejects_arbitrary_structured_value(value) -> None:
    with pytest.raises(ValidationError):
        GroundedClaim(
            claim_type=ClaimType.RECORDED_FACT,
            field=FactField.EVIDENCE,
            value=value,
            provenance=FactProvenance.RECORDED_EVIDENCE,
            source_ids=["S1"],
        )


@pytest.mark.parametrize(
    "field",
    [FactField.EVIDENCE, FactField.MITRE, FactField.LATEST_TIMELINE_EVENT],
)
def test_structured_reference_accepts_recorded_structured_field(field) -> None:
    output = _output(_structured_reference(field))
    assert _validate(output).accepted is True


def test_structured_reference_rejects_scalar_field() -> None:
    result = _validate(
        _output(_structured_reference(FactField.RISK_SCORE))
    )
    assert result.accepted is False
    assert result.reason == "invalid_structured_reference"


def test_structured_reference_rejects_missing_field() -> None:
    facts = dict(FACTS)
    facts.pop("evidence")
    result = _validate(
        _output(_structured_reference(FactField.EVIDENCE)),
        facts=facts,
    )
    assert result.accepted is False
    assert result.reason == "invalid_structured_reference"


def test_structured_reference_rejects_non_structured_canonical_value() -> None:
    result = _validate(
        _output(_structured_reference(FactField.EVIDENCE)),
        facts=FACTS | {"evidence": "ALERT_CREATED"},
    )
    assert result.accepted is False
    assert result.reason == "invalid_structured_reference"


def test_structured_reference_outside_focus_is_rejected() -> None:
    output = _output(_structured_reference(FactField.EVIDENCE))
    assert _validate(output).accepted is True
    focus = validate_focus(
        output,
        focus=_focus(FocusDimension.STATUS),
        fact_inventory=FACTS,
    )
    assert focus.accepted is False
    assert focus.reason == "claim_outside_focus"


def test_structured_reference_requires_authoritative_source() -> None:
    result = _validate(
        _output(
            _structured_reference(FactField.MITRE, source_ids=["S2"])
        )
    )
    assert result.accepted is False
    assert result.reason == "unsupported_authoritative_source"


@pytest.mark.parametrize(
    "incompatible",
    [
        {"value": "free text"},
        {"subject": "correlation"},
        {"derived_from": ["risk_score"]},
        {"guidance_code": "review_related_telemetry"},
        {"path": "/0/event_type"},
        {"provenance": "invented_provenance"},
    ],
)
def test_structured_reference_shape_rejects_incompatible_properties(
    incompatible,
) -> None:
    payload = {
        "claim_type": "STRUCTURED_REFERENCE",
        "field": "evidence",
        "provenance": "recorded_evidence",
        "source_ids": ["S1"],
    }
    with pytest.raises(ValidationError):
        GroundedClaim.model_validate(payload | incompatible)


@pytest.mark.parametrize(
    ("field", "language", "expected"),
    [
        (
            FactField.MITRE,
            "en",
            "Recorded MITRE information is available.",
        ),
        (
            FactField.EVIDENCE,
            "it",
            "Sono disponibili evidenze registrate.",
        ),
    ],
)
def test_structured_reference_renders_neutral_localized_text(
    field,
    language,
    expected,
) -> None:
    rendered = render_claim_output(
        _output(_structured_reference(field)),
        fact_inventory=FACTS,
        response_language=language,
    )
    assert rendered.direct_answer == expected
    assert rendered.direct_source_ids == ["S1"]


def test_model_facing_schema_contains_no_arbitrary_json_values() -> None:
    schema = GroundedClaimOutput.model_json_schema()
    variants = schema["$defs"]["GroundedClaim"]["oneOf"]
    assert variants
    for variant in variants:
        assert variant["additionalProperties"] is False
        value_schema = variant["properties"].get("value")
        if value_schema is not None:
            assert value_schema != {}
            assert value_schema.get("type") != "null"
            assert all(
                branch.get("type") != "null"
                for branch in value_schema.get("anyOf", [])
            )

    def assert_closed(node) -> None:
        if isinstance(node, dict):
            assert node.get("items") != {}
            assert node.get("additionalProperties") is not True
            for value in node.values():
                assert_closed(value)
        elif isinstance(node, list):
            for value in node:
                assert_closed(value)

    assert_closed(schema)


def test_focused_schema_constrains_fields_roles_and_claim_budget() -> None:
    schema = grounded_claim_output_schema(
        fact_inventory={
            "source_type": "incident",
            "incident_id": 5299,
            "risk_score": 35,
            "severity": None,
            "risk_normalization_severity": "LOW",
        },
        allow_advisory=False,
    )
    variants = schema["$defs"]["GroundedClaim"]["oneOf"]
    field_claim_types = {
        (
            variant["properties"].get("field", {}).get("const"),
            variant["properties"]["claim_type"]["const"],
        )
        for variant in variants
        if "field" in variant["properties"]
    }

    assert {field for field, _ in field_claim_types} == {
        "source_type",
        "incident_id",
        "risk_score",
        "severity",
        "risk_normalization_severity",
    }
    assert (
        "risk_normalization_severity",
        "DISTINCT_VALUE",
    ) in field_claim_types
    assert (
        "risk_normalization_severity",
        "RECORDED_FACT",
    ) not in field_claim_types
    required_claims = schema["properties"]["claims"]["prefixItems"]
    assert [
        claim["properties"]["claim_type"]["const"]
        for claim in required_claims
    ] == ["RECORDED_FACT", "ABSENCE", "DISTINCT_VALUE"]
    assert [
        claim["properties"]["field"]["const"]
        for claim in required_claims
    ] == ["risk_score", "severity", "risk_normalization_severity"]
    assert schema["properties"]["claims"]["minItems"] == 3
    assert schema["properties"]["claims"]["maxItems"] == 3
    assert schema["properties"]["used_advisory_context"]["const"] is False
    assert schema["properties"]["limitations"] == {
        "type": "array",
        "items": {
            "type": "string",
            "enum": ["canonical_severity_missing"],
        },
        "maxItems": 1,
    }


def test_advisory_schema_keeps_claims_authoritative_and_fixed() -> None:
    schema = grounded_claim_output_schema(
        fact_inventory={
            "source_type": "incident",
            "incident_id": 5337,
            "latest_timeline_event": {"event_type": "ALERT_CREATED"},
            "mitre": [{"id": "T1110.001"}],
            "compromise_confirmed": None,
        },
        allow_advisory=True,
    )
    claims_schema = schema["properties"]["claims"]

    assert [
        (
            claim["properties"]["claim_type"]["const"],
            claim["properties"]["field"]["const"],
        )
        for claim in claims_schema["prefixItems"]
    ] == [
        ("STRUCTURED_REFERENCE", "latest_timeline_event"),
        ("STRUCTURED_REFERENCE", "mitre"),
        ("ABSENCE", "compromise_confirmed"),
    ]
    assert claims_schema["minItems"] == 3
    assert claims_schema["maxItems"] == 3
    assert "items" not in claims_schema
    assert schema["properties"]["next_check"] != {"type": "null"}
    assert "const" not in schema["properties"]["used_advisory_context"]
    assert schema["properties"]["limitations"]["maxItems"] == 0


def test_duplicate_claims_are_rejected_structurally() -> None:
    claim = _claim(FactField.RISK_SCORE, 35)
    result = _validate(_output(claim, claim))

    assert result.accepted is False
    assert result.reason == "duplicate_claim"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        (FactField.STATUS, "OPEN", "fact_contradiction"),
        (FactField.SEVERITY, "HIGH", "severity_contradiction"),
        (FactField.RISK_NORMALIZATION_SEVERITY, "LOW", "severity_contradiction"),
        (FactField.RECOMMENDED_PRIORITY, "LOW", "fact_contradiction"),
        (FactField.RISK_SCORE, 36, "risk_contradiction"),
        (FactField.RISK_SCORE, "35", "risk_contradiction"),
        (FactField.RISK_BAND, "MODERATE", "fact_contradiction"),
        (FactField.CORRELATED, False, "correlation_contradiction"),
        (FactField.CORRELATION_TYPE, "OTHER", "fact_contradiction"),
        (FactField.CORRELATION_SCORE, 34, "fact_contradiction"),
        (FactField.AGENT, "unknown-host", "fact_contradiction"),
        (FactField.ESCALATED, True, "unsupported_escalation_state"),
    ],
)
def test_wrong_fact_values_are_rejected(field, value, reason) -> None:
    result = _validate(_output(_claim(field, value)))
    assert result.accepted is False
    assert result.reason == reason


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        (FactField.SEVERITY, "LOW", "unsupported_severity_provenance"),
        (FactField.RISK_BAND, "MODERATE", "unsupported_risk_interpretation"),
        (FactField.STATUS_DESCRIPTION, "recent", "unsupported_status_interpretation"),
        (FactField.THREAT_ASSESSMENT, "immediate", "unsupported_threat_assessment"),
        (FactField.URGENCY, "urgent", "unsupported_threat_assessment"),
        (FactField.IMPACT, "limited", "unsupported_threat_assessment"),
        (FactField.ESCALATED, False, "unsupported_escalation_state"),
        (FactField.COMPROMISE_CONFIRMED, True, "unsupported_compromise_claim"),
        (FactField.AGENT, "host-a", "unsupported_recorded_fact"),
    ],
)
def test_missing_fields_are_rejected_structurally(field, value, reason) -> None:
    facts = dict(FACTS)
    facts.pop(field.value)
    result = _validate(_output(_claim(field, value)), facts=facts)
    assert result.accepted is False
    assert result.reason == reason


@pytest.mark.parametrize(
    ("field", "claim_type", "provenance", "reason"),
    [
        (
            FactField.SEVERITY,
            ClaimType.RECORDED_FACT,
            FactProvenance.RISK_NORMALIZATION,
            "unsupported_severity_provenance",
        ),
        (
            FactField.RISK_NORMALIZATION_SEVERITY,
            ClaimType.RECORDED_FACT,
            FactProvenance.RISK_NORMALIZATION,
            "unsupported_severity_provenance",
        ),
        (
            FactField.RISK_NORMALIZATION_SEVERITY,
            ClaimType.DISTINCT_VALUE,
            FactProvenance.CANONICAL_INCIDENT,
            "unsupported_severity_provenance",
        ),
        (
            FactField.RECOMMENDED_PRIORITY,
            ClaimType.RECORDED_FACT,
            FactProvenance.RECOMMENDATION,
            "unsupported_priority_provenance",
        ),
        (
            FactField.RECOMMENDED_PRIORITY,
            ClaimType.DISTINCT_VALUE,
            FactProvenance.CANONICAL_INCIDENT,
            "unsupported_priority_provenance",
        ),
        (
            FactField.STATUS,
            ClaimType.DISTINCT_VALUE,
            FactProvenance.RECORDED_OPERATIONAL,
            "unsupported_fact_provenance",
        ),
    ],
)
def test_provenance_and_semantic_roles_cannot_be_substituted(
    field,
    claim_type,
    provenance,
    reason,
) -> None:
    value = FACTS[field.value]
    result = _validate(
        _output(
            _claim(
                field,
                value,
                claim_type=claim_type,
                provenance=provenance,
            )
        )
    )
    assert result.accepted is False
    assert result.reason == reason


def test_canonical_severity_absence_and_normalized_value_are_distinct() -> None:
    facts = dict(FACTS, severity=None, risk_normalization_severity="LOW")
    output = _output(
        _claim(FactField.SEVERITY, None),
        _claim(FactField.RISK_NORMALIZATION_SEVERITY, "LOW"),
    )
    assert _validate(output, facts=facts).accepted is True


def test_absence_is_rejected_when_the_fact_has_a_value() -> None:
    result = _validate(_output(_claim(FactField.SEVERITY, None)))
    assert result.accepted is False
    assert result.reason == "severity_contradiction"


def test_absence_outside_focused_view_is_rejected() -> None:
    facts = {"source_type": "incident", "incident_id": 5299}
    result = _validate(_output(_claim(FactField.SEVERITY, None)), facts=facts)
    assert result.accepted is False
    assert result.reason == "absence_outside_focused_view"


@pytest.mark.parametrize(
    "target",
    [RelationNode.COMPROMISE, RelationNode.CAUSALITY],
)
def test_allowed_correlation_non_implications_are_accepted(target) -> None:
    claim = GroundedClaim(
        claim_type=ClaimType.NON_IMPLICATION,
        subject=RelationNode.CORRELATION,
        object=target,
    )
    assert _validate(_output(claim)).accepted is True


@pytest.mark.parametrize(
    ("subject", "target"),
    [
        (RelationNode.CORRELATION, RelationNode.THREAT),
        (RelationNode.CORRELATION, RelationNode.SEVERITY),
        (RelationNode.RISK_SCORE, RelationNode.RISK_BAND),
        (RelationNode.SEVERITY, RelationNode.URGENCY),
    ],
)
def test_unregistered_non_implications_are_rejected(subject, target) -> None:
    claim = GroundedClaim(
        claim_type=ClaimType.NON_IMPLICATION,
        subject=subject,
        object=target,
    )
    result = _validate(_output(claim))
    assert result.accepted is False
    assert result.reason == "unsupported_non_implication"


def test_unsupported_risk_derivation_is_rejected_without_provenance_fact() -> None:
    facts = dict(FACTS)
    facts.pop("risk_derived_from")
    claim = GroundedClaim(
        claim_type=ClaimType.DERIVATION,
        field=FactField.RISK_SCORE,
        provenance=FactProvenance.RECORDED_OPERATIONAL,
        source_ids=["S1"],
        derived_from=[FactField.CORRELATION_SCORE],
    )
    result = _validate(_output(claim), facts=facts)
    assert result.accepted is False
    assert result.reason == "unsupported_value_derivation"


def test_explicit_risk_derivation_provenance_is_accepted() -> None:
    claim = GroundedClaim(
        claim_type=ClaimType.DERIVATION,
        field=FactField.RISK_SCORE,
        provenance=FactProvenance.RECORDED_OPERATIONAL,
        source_ids=["S1"],
        derived_from=[FactField.CORRELATION_SCORE],
    )
    assert _validate(_output(claim)).accepted is True


def test_different_derivation_input_is_rejected_exactly() -> None:
    claim = GroundedClaim(
        claim_type=ClaimType.DERIVATION,
        field=FactField.RISK_SCORE,
        provenance=FactProvenance.RECORDED_OPERATIONAL,
        source_ids=["S1"],
        derived_from=[FactField.SEVERITY],
    )
    result = _validate(_output(claim))
    assert result.reason == "unsupported_value_derivation"


def test_bad_live_semantic_equivalents_are_rejected_structurally() -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 5299,
        "risk_score": 35,
        "correlation_score": 35,
        "escalation_reason": None,
    }
    bad_claims = (
        _claim(FactField.RISK_BAND, "MODERATE"),
        GroundedClaim(
            claim_type=ClaimType.DERIVATION,
            field=FactField.RISK_SCORE,
            provenance=FactProvenance.RECORDED_OPERATIONAL,
            source_ids=["S1"],
            derived_from=[FactField.CORRELATION_SCORE],
        ),
        _claim(FactField.ESCALATED, False),
    )
    expected = (
        "unsupported_risk_interpretation",
        "unsupported_value_derivation",
        "unsupported_escalation_state",
    )
    for claim, reason in zip(bad_claims, expected, strict=True):
        result = _validate(_output(claim), facts=facts)
        assert result.reason == reason


def test_escalation_false_requires_an_explicit_boolean() -> None:
    without_boolean = dict(FACTS)
    without_boolean.pop("escalated")
    result = _validate(
        _output(_claim(FactField.ESCALATED, False)),
        facts=without_boolean,
    )
    assert result.reason == "unsupported_escalation_state"
    assert _validate(_output(_claim(FactField.ESCALATED, False))).accepted is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (FactField.STATUS, "NEW"),
        (FactField.THREAT_ASSESSMENT, "NOT_RECORDED_AS_IMMEDIATE"),
        (FactField.URGENCY, "ROUTINE_REVIEW"),
        (FactField.IMPACT, "RECORDED_LIMITED"),
    ],
)
def test_opaque_and_assessment_values_require_exact_authoritative_facts(
    field,
    value,
) -> None:
    assert _validate(_output(_claim(field, value))).accepted is True


@pytest.mark.parametrize(
    ("focus", "field", "accepted"),
    [
        ((FocusDimension.RISK,), FactField.RISK_SCORE, True),
        ((FocusDimension.RISK,), FactField.STATUS, False),
        ((FocusDimension.CORRELATION,), FactField.CORRELATION_TYPE, True),
        ((FocusDimension.CORRELATION,), FactField.SEVERITY, False),
        ((FocusDimension.SEVERITY,), FactField.RISK_NORMALIZATION_SEVERITY, True),
        ((FocusDimension.PRIORITY,), FactField.RECOMMENDED_PRIORITY, True),
        ((FocusDimension.STATUS,), FactField.AGENT, False),
        ((FocusDimension.GENERAL,), FactField.STATUS, True),
    ],
)
def test_focus_validation_uses_claim_families_only(focus, field, accepted) -> None:
    output = _output(_claim(field, FACTS[field.value]))
    result = validate_focus(
        output,
        focus=_focus(*focus),
        fact_inventory=FACTS,
    )
    assert result.accepted is accepted
    assert result.reason == (None if accepted else "claim_outside_focus")


def test_correlation_non_implication_requires_correlation_focus() -> None:
    output = _output(
        GroundedClaim(
            claim_type=ClaimType.NON_IMPLICATION,
            subject=RelationNode.CORRELATION,
            object=RelationNode.COMPROMISE,
        )
    )
    result = validate_focus(
        output,
        focus=_focus(FocusDimension.STATUS),
        fact_inventory=FACTS,
    )
    assert result.reason == "claim_outside_focus"


def test_focus_validation_rejects_limitations_outside_the_fact_view() -> None:
    output = _output(
        _structured_reference(FactField.MITRE),
        limitations=[LimitationCode.CANONICAL_SEVERITY_MISSING],
    )

    result = validate_focus(
        output,
        focus=_focus(FocusDimension.EVIDENCE),
        fact_inventory={"mitre": FACTS["mitre"]},
    )

    assert result.accepted is False
    assert result.reason == "limitation_outside_focus"


def test_advisory_guidance_requires_advisory_source_and_declaration() -> None:
    claim = GroundedClaim(
        claim_type=ClaimType.ADVISORY_GUIDANCE,
        guidance_code=AdvisoryGuidanceCode.REVIEW_RELATED_TELEMETRY,
        source_ids=["S2"],
    )
    assert _validate(
        _output(claim, used_advisory_context=True)
    ).accepted is True
    assert _validate(_output(claim)).reason == "undeclared_advisory_use"


def test_advisory_guidance_cannot_use_authoritative_source() -> None:
    claim = GroundedClaim(
        claim_type=ClaimType.ADVISORY_GUIDANCE,
        guidance_code=AdvisoryGuidanceCode.REVIEW_RELATED_TELEMETRY,
        source_ids=["S1"],
    )
    result = _validate(_output(claim, used_advisory_context=True))
    assert result.reason == "unsupported_advisory_authority"


def test_advisory_claim_cannot_override_canonical_fact_by_schema() -> None:
    payload = {
        "claims": [
            {
                "claim_type": "ADVISORY_GUIDANCE",
                "field": "severity",
                "value": "CRITICAL",
                "guidance_code": "review_related_telemetry",
                "source_ids": ["S2"],
            }
        ],
        "next_check": None,
        "limitations": [],
        "used_advisory_context": True,
    }
    assert parse_grounded_output(payload) is None


def test_declared_advisory_use_requires_an_advisory_claim_or_next_check() -> None:
    result = _validate(
        _output(
            _claim(FactField.STATUS, "NEW"),
            used_advisory_context=True,
        )
    )
    assert result.reason == "missing_advisory_source"


def test_structured_next_check_accepts_only_advisory_sources() -> None:
    advisory_claim = GroundedClaim(
        claim_type=ClaimType.ADVISORY_GUIDANCE,
        guidance_code=AdvisoryGuidanceCode.FOLLOW_RECORDED_PLAYBOOK,
        source_ids=["S2"],
    )
    next_check = StructuredNextCheck(
        check_type=NextCheckType.REVIEW_ADVISORY_SOURCE,
        guidance_code=AdvisoryGuidanceCode.FOLLOW_RECORDED_PLAYBOOK,
        source_ids=["S2"],
    )
    output = _output(
        advisory_claim,
        next_check=next_check,
        used_advisory_context=True,
    )
    assert _validate(output).accepted is True


def test_unknown_source_id_is_rejected() -> None:
    result = _validate(
        _output(_claim(FactField.STATUS, "NEW", source_ids=["S99"]))
    )
    assert result.reason == "unknown_source_id"


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "not-json",
        {},
        {"claims": []},
        {"claims": [{"claim_type": "UNKNOWN"}]},
        {"claims": [{"claim_type": "RECORDED_FACT"}]},
        {
            "claims": [
                {
                    "claim_type": "RECORDED_FACT",
                    "field": "risk_score",
                    "value": 35,
                    "source_ids": ["S1"],
                }
            ]
        },
        {
            "claims": [
                {
                    "claim_type": "RECORDED_FACT",
                    "field": "unknown_field",
                    "value": 35,
                    "provenance": "recorded_operational",
                    "source_ids": ["S1"],
                }
            ]
        },
        {
            "claims": [
                {
                    "claim_type": "RECORDED_FACT",
                    "field": "risk_score",
                    "value": 35,
                    "provenance": "recorded_operational",
                    "source_ids": ["bad"],
                }
            ]
        },
        {
            "claims": [
                {
                    "claim_type": "RECORDED_FACT",
                    "field": "risk_score",
                    "value": 35,
                    "provenance": "recorded_operational",
                    "source_ids": ["S1"],
                    "claim_text": "moderate risk",
                }
            ]
        },
        {
            "claims": [
                {
                    "claim_type": "NON_IMPLICATION",
                    "subject": "correlation",
                    "object": "compromise",
                    "value": "free text",
                }
            ]
        },
        {
            "claims": [
                {
                    "claim_type": "ADVISORY_GUIDANCE",
                    "guidance_code": "invented_action",
                    "source_ids": ["S2"],
                }
            ]
        },
    ],
)
def test_parser_v2_rejects_invalid_or_open_ended_schema(payload) -> None:
    assert parse_grounded_output(payload) is None


def test_parser_v2_accepts_json_and_forbids_additional_properties() -> None:
    output = _output(_claim(FactField.RISK_SCORE, 35))
    encoded = output.model_dump_json()
    assert parse_grounded_output(encoded) == output
    with pytest.raises(ValidationError):
        GroundedClaimOutput.model_validate(
            output.model_dump() | {"arbitrary_text": "not allowed"}
        )


def test_deterministic_fallback_uses_focused_facts_and_structured_limitations() -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 5299,
        "risk_score": 35,
        "severity": None,
        "risk_normalization_severity": "LOW",
    }
    output = deterministic_claim_output(
        fact_inventory=facts,
        authoritative_source_ids=["S1"],
    )
    fields = {claim.field for claim in output.claims}
    assert fields == {
        FactField.RISK_SCORE,
        FactField.SEVERITY,
        FactField.RISK_NORMALIZATION_SEVERITY,
    }
    assert output.limitations == [LimitationCode.CANONICAL_SEVERITY_MISSING]


@pytest.mark.parametrize("language", ["en", "it"])
def test_renderer_localizes_validated_claims_without_parsing_text(language) -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 5299,
        "risk_score": 35,
        "severity": None,
        "risk_normalization_severity": "LOW",
        "correlated": True,
    }
    output = _output(
        _claim(FactField.RISK_SCORE, 35),
        _claim(FactField.CORRELATED, True),
        _claim(FactField.SEVERITY, None),
        _claim(FactField.RISK_NORMALIZATION_SEVERITY, "LOW"),
        GroundedClaim(
            claim_type=ClaimType.NON_IMPLICATION,
            subject=RelationNode.CORRELATION,
            object=RelationNode.COMPROMISE,
        ),
        limitations=[LimitationCode.CANONICAL_SEVERITY_MISSING],
    )
    rendered = render_claim_output(
        output,
        fact_inventory=facts,
        response_language=language,
    )
    combined = " ".join(
        value
        for value in (
            rendered.direct_answer,
            rendered.analysis,
            rendered.limitations,
        )
        if value
    )
    assert "35" in combined
    assert "LOW" in combined
    if language == "it":
        assert "severità canonica" in combined
        assert "compromissione" in combined
    else:
        assert "canonical incident severity" in combined
        assert "compromise" in combined


def test_response_blocks_preserve_claim_source_ids() -> None:
    output = _output(
        _claim(FactField.RISK_SCORE, 35),
        GroundedClaim(
            claim_type=ClaimType.ADVISORY_GUIDANCE,
            guidance_code=AdvisoryGuidanceCode.REVIEW_RELATED_TELEMETRY,
            source_ids=["S2"],
        ),
        used_advisory_context=True,
    )
    rendered = render_claim_output(
        output,
        fact_inventory=FACTS,
        response_language="en",
    )
    blocks = response_blocks(rendered, sources=SOURCES)
    assert blocks[0].source_ids == ["S1"]
    assert blocks[1].source_ids == ["S2"]


def test_test_c_compliant_ir_passes_grounding_and_focus() -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 5299,
        "risk_score": 35,
        "correlated": True,
        "correlation_type": "SINGLE_HOST_PATTERN_CORRELATION",
        "correlation_score": 35,
        "severity": None,
        "risk_normalization_severity": "LOW",
    }
    output = _output(
        _claim(FactField.RISK_SCORE, 35),
        _claim(FactField.CORRELATED, True),
        _claim(
            FactField.CORRELATION_TYPE,
            "SINGLE_HOST_PATTERN_CORRELATION",
        ),
        _claim(FactField.CORRELATION_SCORE, 35),
        _claim(FactField.SEVERITY, None),
        _claim(FactField.RISK_NORMALIZATION_SEVERITY, "LOW"),
        GroundedClaim(
            claim_type=ClaimType.NON_IMPLICATION,
            subject=RelationNode.CORRELATION,
            object=RelationNode.COMPROMISE,
        ),
        GroundedClaim(
            claim_type=ClaimType.NON_IMPLICATION,
            subject=RelationNode.CORRELATION,
            object=RelationNode.CAUSALITY,
        ),
    )
    assert all(
        claim.claim_type is not ClaimType.STRUCTURED_REFERENCE
        for claim in output.claims
    )
    assert _validate(output, facts=facts).accepted is True
    assert validate_focus(
        output,
        focus=_focus(
            FocusDimension.RISK,
            FocusDimension.CORRELATION,
            FocusDimension.SEVERITY,
        ),
        fact_inventory=facts,
    ).accepted is True


def test_grounding_and_claims_contain_no_regex_or_lexical_semantic_parser() -> None:
    service_dir = Path(__file__).parents[1] / "services" / "assistant"
    source = "\n".join(
        (service_dir / name).read_text(encoding="utf-8")
        for name in ("grounding.py", "claims.py")
    )
    forbidden = (
        "import re",
        "re.compile",
        "re.search",
        "re.match",
        "re.find",
        "text.lower()",
        '"moderate" in text',
        '"severity" in text',
    )
    assert all(token not in source for token in forbidden)
