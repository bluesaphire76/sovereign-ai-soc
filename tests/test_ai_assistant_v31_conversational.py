from __future__ import annotations

import json
import time
from dataclasses import replace

import pytest

from schemas.assistant import AssistantQueryRequest
from services.assistant.orchestrator import AssistantSettings, _run_v31_response
from services.assistant.retrieval import RetrievalResult
from services.assistant.sources import SourceRecord
from services.assistant.v3.conversational_contracts import (
    MAX_CONVERSATIONAL_CLAIMS,
    MAX_CONVERSATIONAL_SEGMENT_CHARS,
    MAX_CONVERSATIONAL_SEGMENTS,
    GroundedConversationalAnswerV31,
)
from services.assistant.v3.conversational_prompting import (
    build_v31_conversational_messages,
)
from services.assistant.v3.conversational_schema import (
    conversational_model_facing_evidence,
    grounded_conversational_answer_v31_schema,
)
from services.assistant.v3.conversational_validation import (
    GroundedConversationalAnswerV31Validator,
    conversational_parse_diagnostic,
    parse_grounded_conversational_answer_v31,
)
from services.assistant.v3.contracts import AnswerIntent
from tests.assistant_v3_test_support import analytical_package


def _answer() -> dict:
    return {
        "response_language": "en",
        "answer": {
            "segments": [
                {
                    "segment_id": "seg-1",
                    "kind": "direct_answer",
                    "text": (
                        "The incident is open and was raised by a registry-change "
                        "detection on endpoint-a."
                    ),
                    "claim_refs": ["claim-1"],
                },
                {
                    "segment_id": "seg-2",
                    "kind": "uncertainty",
                    "text": (
                        "A second incident shares the endpoint, making it useful "
                        "for a focused evidence comparison. This analytical "
                        "relationship does not establish causality."
                    ),
                    "claim_refs": ["claim-2", "claim-3"],
                },
            ]
        },
        "claims": [
            {
                "claim_id": "claim-1",
                "claim_type": "operational_fact",
                "source_refs": [
                    "incident:1:status",
                    "incident:1:detection",
                    "incident:1:host",
                ],
                "qualifier_code": "NONE",
            },
            {
                "claim_id": "claim-2",
                "claim_type": "analytical_relationship",
                "source_refs": ["relationship:shared-host"],
                "qualifier_code": "NONE",
            },
            {
                "claim_id": "claim-3",
                "claim_type": "non_implication",
                "source_refs": [],
                "qualifier_code": "ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY",
            },
        ],
    }


def _parsed(payload: dict | None = None) -> GroundedConversationalAnswerV31:
    return GroundedConversationalAnswerV31.model_validate(payload or _answer())


def test_conversational_schema_is_closed_and_prompt_requests_final_prose() -> None:
    package = analytical_package()
    schema = grounded_conversational_answer_v31_schema(package)
    prompt = build_v31_conversational_messages(package, max_context_chars=24_000)

    assert schema["additionalProperties"] is False
    assert schema["properties"]["answer"]["additionalProperties"] is False
    claim_schemas = schema["properties"]["claims"]["prefixItems"]
    assert claim_schemas[0]["additionalProperties"] is False
    assert all(item["additionalProperties"] is False for item in claim_schemas[1:])
    assert "Write the final user-facing SOC analyst answer" in prompt.messages[0][
        "content"
    ]
    assert "Do not write answer prose" not in prompt.messages[0]["content"]
    assert "Registry changed" in prompt.messages[1]["content"]
    assert "first segment MUST use kind direct_answer" in prompt.messages[0][
        "content"
    ]
    assert "MUST use kind uncertainty" in prompt.messages[0]["content"]
    assert "A numeric risk score is only the recorded number" in prompt.messages[0][
        "content"
    ]
    assert "analyst_utility code" in prompt.messages[0]["content"]
    assert '"analyst_utility":"identify_triggering_detection_rule"' in prompt.messages[
        1
    ]["content"]
    assert (
        '"unrecorded_security_conclusions":'
        '"EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS"'
    ) in (
        prompt.messages[1]["content"]
    )
    assert '"causality":"EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY"' in (
        prompt.messages[1]["content"]
    )
    assert '"anchor_incident_ids":[1]' in prompt.messages[1]["content"]
    assert '"eligible_comparison_target_ids":[2]' in prompt.messages[1][
        "content"
    ]
    assert "never present an anchor_incident_id" in prompt.messages[0]["content"]


def test_conversational_schema_uses_llama_cpp_compatible_string_bounds() -> None:
    schema = grounded_conversational_answer_v31_schema(analytical_package())
    segments_schema = schema["properties"]["answer"]["properties"]["segments"]
    text_schema = segments_schema["prefixItems"][0]["properties"]["text"]

    assert text_schema["maxLength"] == MAX_CONVERSATIONAL_SEGMENT_CHARS
    assert text_schema["maxLength"] <= 1_000
    assert (
        schema["properties"]["answer"]["properties"]["segments"]["maxItems"]
        == MAX_CONVERSATIONAL_SEGMENTS
    )
    assert schema["properties"]["claims"]["maxItems"] == MAX_CONVERSATIONAL_CLAIMS
    claims_schema = schema["properties"]["claims"]
    safety_claim = claims_schema["prefixItems"][0]
    claim_ids = [safety_claim["properties"]["claim_id"]["const"]] + [
        item["properties"]["claim_id"]["const"]
        for item in claims_schema["prefixItems"][1:]
    ]
    claim_refs = segments_schema["prefixItems"][0]["properties"]["claim_refs"]
    assert safety_claim["properties"]["claim_id"]["const"] == "c1"
    assert safety_claim["properties"]["claim_type"]["const"] == "non_implication"
    assert claim_ids == ["c1", "c2", "c3", "c4"]
    assert [item["const"] for item in claim_refs["prefixItems"]] == claim_ids
    assert segments_schema["minItems"] == MAX_CONVERSATIONAL_SEGMENTS
    assert segments_schema["prefixItems"][0]["properties"]["kind"]["const"] == (
        "direct_answer"
    )
    uncertainty = segments_schema["prefixItems"][1]
    assert uncertainty["properties"]["kind"]["const"] == "uncertainty"
    assert [
        item["const"]
        for item in uncertainty["properties"]["claim_refs"]["prefixItems"]
    ] == claim_ids


def test_schema_binds_each_evidence_claim_type_to_matching_typed_refs() -> None:
    schema = grounded_conversational_answer_v31_schema(
        analytical_package(AnswerIntent.EXPLAIN)
    )
    claim_schemas = schema["properties"]["claims"]["prefixItems"]
    assert claim_schemas[1]["properties"]["claim_type"]["const"] == (
        "operational_fact"
    )
    assert "incident:1:status" in claim_schemas[1]["properties"]["source_refs"][
        "items"
    ]["enum"]
    assert claim_schemas[3]["properties"]["claim_type"]["const"] == (
        "reference_explanation"
    )
    assert "reference:mitre:T1112" in claim_schemas[3]["properties"][
        "source_refs"
    ]["items"]["enum"]

    cross_claims = grounded_conversational_answer_v31_schema(
        analytical_package(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    )["properties"]["claims"]["prefixItems"]
    assert cross_claims[2]["properties"]["claim_type"]["const"] == (
        "analytical_relationship"
    )
    assert cross_claims[3]["properties"]["claim_type"]["const"] == (
        "semantic_candidate"
    )


def test_unrecorded_security_conclusions_share_an_explicit_safe_qualifier() -> None:
    payload = _answer()
    payload["claims"][1].update(
        {
            "claim_type": "operational_fact",
            "source_refs": ["incident:1:status"],
        }
    )
    payload["claims"][2]["qualifier_code"] = (
        "EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS"
    )
    payload["answer"]["segments"][1]["text"] = (
        "The relationship does not establish compromise or malicious activity."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is True


def test_positive_assertion_in_uncertainty_segment_is_still_rejected() -> None:
    payload = _answer()
    payload["claims"][1].update(
        {
            "claim_type": "operational_fact",
            "source_refs": ["incident:1:status"],
        }
    )
    payload["claims"][2]["qualifier_code"] = (
        "EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS"
    )
    payload["answer"]["segments"][1]["text"] = (
        "The incident confirms compromise and malicious activity."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is False
    assert result.reason == "unsupported_compromise_assertion"


def test_missing_escalation_state_can_only_be_described_as_uncertain() -> None:
    payload = _answer()
    payload["claims"][1].update(
        {
            "claim_type": "operational_fact",
            "source_refs": ["incident:1:status"],
        }
    )
    payload["claims"][2]["qualifier_code"] = (
        "EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS"
    )
    payload["answer"]["segments"][1]["text"] = (
        "The available evidence does not establish an escalation state."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is True


def test_schema_reserves_second_segment_for_grounded_uncertainty() -> None:
    package = analytical_package().model_copy(update={"advisory_atoms": []})
    schema = grounded_conversational_answer_v31_schema(package)
    segment_schemas = schema["properties"]["answer"]["properties"]["segments"][
        "prefixItems"
    ]
    assert [item["properties"]["kind"]["const"] for item in segment_schemas] == [
        "direct_answer",
        "uncertainty",
    ]


def test_conversational_view_is_bounded_and_keeps_relationship_evidence() -> None:
    package = analytical_package()
    view = conversational_model_facing_evidence(package)
    evidence_refs = {item.atom_id for item in view.operational_atoms} | {
        item.candidate_id for item in view.candidates
    }

    assert len(view.operational_atoms) <= 12
    assert len(view.relationships) <= 3
    assert len(view.candidates) <= 2
    assert all(
        set(item.evidence_atom_refs).issubset(evidence_refs)
        for item in view.relationships
    )

def test_valid_conversational_prose_and_typed_refs_are_accepted() -> None:
    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(),
        package=analytical_package(),
    )

    assert result.accepted is True


def test_code_only_claim_rejects_evidence_refs() -> None:
    payload = _answer()
    payload["claims"][2]["source_refs"] = ["relationship:shared-host"]

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is False
    assert result.reason == "code_qualifier_source_mismatch"


def test_valid_unreferenced_claim_does_not_affect_visible_answer() -> None:
    payload = _answer()
    payload["answer"]["segments"][1]["claim_refs"] = ["claim-2"]
    payload["answer"]["segments"][1][
        "text"
    ] = "A second incident shares the endpoint and is useful for comparison."

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is True


def test_dangling_ref_is_rejected_without_json_repair() -> None:
    payload = _answer()
    payload["claims"][0]["source_refs"] = ["atom:invented"]
    parsed = _parsed(payload)

    result = GroundedConversationalAnswerV31Validator().validate(
        parsed,
        package=analytical_package(),
    )

    assert result == replace(result, accepted=False, reason="unknown_source_ref")
    assert parse_grounded_conversational_answer_v31("```json\n{}\n```") is None
    assert parse_grounded_conversational_answer_v31('{"response_language":"en",}') is None
    assert conversational_parse_diagnostic({"unexpected": True}).startswith(
        "response_language:"
    )


def test_authorized_atom_omitted_from_model_view_is_rejected() -> None:
    package = analytical_package()
    extra_atoms = [
        package.operational_atoms[-1].model_copy(
            update={"atom_id": f"incident:2:status:extra-{index}"}
        )
        for index in range(16)
    ]
    package = package.model_copy(
        update={"operational_atoms": [*package.operational_atoms, *extra_atoms]}
    )
    visible_refs = {
        item.atom_id for item in conversational_model_facing_evidence(package).operational_atoms
    }
    omitted_ref = next(item.atom_id for item in extra_atoms if item.atom_id not in visible_refs)

    payload = _answer()
    payload["claims"][0]["source_refs"] = [omitted_ref]
    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=package,
    )

    assert result.accepted is False
    assert result.reason == "unknown_source_ref"


@pytest.mark.parametrize(
    ("claim_type", "source_ref", "expected_reason"),
    [
        (
            "operational_fact",
            "relationship:semantic",
            "operational_authority_mismatch",
        ),
        (
            "recorded_correlation",
            "relationship:shared-host",
            "recorded_correlation_authority_mismatch",
        ),
        (
            "operational_fact",
            "reference:mitre:T1112",
            "operational_authority_mismatch",
        ),
        (
            "operational_fact",
            "advisory:registry-review",
            "operational_authority_mismatch",
        ),
    ],
)
def test_authority_promotions_are_rejected(
    claim_type: str,
    source_ref: str,
    expected_reason: str,
) -> None:
    payload = _answer()
    payload["claims"][0].update(
        {"claim_type": claim_type, "source_refs": [source_ref]}
    )

    package = analytical_package(
        AnswerIntent.EXPLAIN
        if source_ref == "reference:mitre:T1112"
        else AnswerIntent.CROSS_INCIDENT_ANALYSIS
    )
    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=package,
    )

    assert result.accepted is False
    assert result.reason == expected_reason


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("The incident confirms compromise.", "unsupported_compromise_assertion"),
        ("Both records belong to the same attacker.", "unsupported_actor_campaign_assertion"),
        ("This is malicious activity.", "unsupported_maliciousness_assertion"),
        (
            "Questa è un'attività malintenzionata.",
            "unsupported_maliciousness_assertion",
        ),
        ("Lateral movement occurred.", "unsupported_lateral_movement_assertion"),
        ("Persistence is established.", "unsupported_persistence_assertion"),
        ("The incident was escalated.", "unsupported_escalation_assertion"),
        ("The severity is high.", "unsupported_severity_assertion"),
        ("This is high risk.", "unsupported_risk_band_assertion"),
        ("The incident has urgent business impact.", "unsupported_business_impact_assertion"),
    ],
)
def test_unsupported_high_risk_assertions_are_rejected(
    text: str,
    reason: str,
) -> None:
    payload = _answer()
    payload["answer"]["segments"][0]["text"] = text

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is False
    assert result.reason == reason


def test_recorded_severity_cannot_support_a_different_band() -> None:
    package = analytical_package()
    status = next(
        item for item in package.operational_atoms if item.atom_id == "incident:1:status"
    ).model_copy(update={"canonical_severity": "LOW"})
    package = package.model_copy(
        update={
            "operational_atoms": [
                status if item.atom_id == status.atom_id else item
                for item in package.operational_atoms
            ]
        }
    )
    payload = _answer()
    payload["claims"][0]["source_refs"] = [status.atom_id]
    payload["answer"]["segments"][0]["text"] = "The recorded severity is high."

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=package,
    )

    assert result.accepted is False
    assert result.reason == "unsupported_severity_assertion"


def test_recorded_risk_band_cannot_support_a_different_band() -> None:
    package = analytical_package()
    risk = next(
        item for item in package.operational_atoms if item.atom_id == "incident:1:risk"
    ).model_copy(update={"risk_normalization_severity": "LOW"})
    package = package.model_copy(
        update={
            "operational_atoms": [
                risk if item.atom_id == risk.atom_id else item
                for item in package.operational_atoms
            ]
        }
    )
    payload = _answer()
    payload["claims"][0]["source_refs"] = [risk.atom_id]
    payload["answer"]["segments"][0]["text"] = "The recorded risk is high."

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=package,
    )

    assert result.accepted is False
    assert result.reason == "unsupported_risk_band_assertion"


def test_next_step_requires_typed_advisory_guidance() -> None:
    payload = _answer()
    payload["answer"]["segments"][1].update(
        {
            "kind": "next_step",
            "text": "Inspect the endpoint next.",
        }
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is False
    assert result.reason == "next_step_without_advisory"


def test_advisory_language_requires_typed_advisory_guidance() -> None:
    payload = _answer()
    payload["answer"]["segments"][1][
        "text"
    ] = "The analyst should inspect the endpoint next."

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is False
    assert result.reason == "unsupported_advisory_guidance"


def test_unsupported_hypothetical_explanation_is_rejected() -> None:
    payload = _answer()
    payload["answer"]["segments"][0]["text"] = (
        "The registry change could be a routine configuration action."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is False
    assert result.reason == "unsupported_speculation"


def test_v31_normal_path_returns_model_authored_prose_with_one_generation() -> None:
    calls: list[dict] = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {
            "structured_output": _answer(),
            "generation_ms": 250,
            "finish_reason": "stop",
        }

    package = analytical_package()
    response = _run_v31_response(
        payload=AssistantQueryRequest(
            message=package.question,
            scope="incident",
            incident_id=1,
            include_semantic_memory=False,
        ),
        package=package,
        focused_fact_inventory={"incident_id": 1, "status": "OPEN"},
        source_records=[
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id="1",
                label="Incident 1",
                excerpt="Authoritative incident 1.",
                url="/incidents/1",
            )
        ],
        retrieval=RetrievalResult(scope="incident", incident_id=1),
        response_language="en",
        request_id="request-test",
        request_started=time.monotonic(),
        settings=AssistantSettings(
            enabled=True,
            response_architecture="v3_1",
            max_context_chars=24_000,
            v31_max_output_tokens=540,
        ),
        generator=generator,
        clock=time.monotonic,
    )

    assert len(calls) == 1
    assert calls[0]["output_schema"] == "assistant_grounded_v31"
    assert calls[0]["context"]["response_architecture"] == "v3_1"
    assert calls[0]["max_visible_tokens"] == 540
    assert 0 < calls[0]["timeout_seconds"] <= 45
    assert response.answer.startswith("The incident is open")
    assert response.generation_kind == "model"
    assert response.metadata.response_architecture == "v3_1"
    assert response.metadata.provider_generation_count == 1
    assert response.metadata.automatic_retries == 0


def test_v31_renderer_hides_internal_claim_ids_from_visible_prose() -> None:
    payload = _answer()
    payload["answer"]["segments"][0]["text"] = (
        payload["answer"]["segments"][0]["text"].removesuffix(".")
        + " (claim-1). CLAIM-1: This remains model-authored prose."
    )
    calls = 0

    def generator(**_kwargs):
        nonlocal calls
        calls += 1
        return {"structured_output": payload, "finish_reason": "stop"}

    package = analytical_package()
    response = _run_v31_response(
        payload=AssistantQueryRequest(
            message=package.question,
            scope="incident",
            incident_id=1,
            include_semantic_memory=False,
        ),
        package=package,
        focused_fact_inventory={"incident_id": 1, "status": "OPEN"},
        source_records=[],
        retrieval=RetrievalResult(scope="incident", incident_id=1),
        response_language="en",
        request_id="request-test",
        request_started=time.monotonic(),
        settings=AssistantSettings(enabled=True, response_architecture="v3_1"),
        generator=generator,
        clock=time.monotonic,
    )

    assert calls == 1
    assert "(claim-1)" not in response.answer
    assert "CLAIM-1:" not in response.answer
    assert response.generation_kind == "model"


def test_malformed_v31_output_fails_closed_without_second_generation() -> None:
    calls = 0

    def generator(**_kwargs):
        nonlocal calls
        calls += 1
        return {"structured_output": json.dumps({"unexpected": True})}

    package = analytical_package()
    response = _run_v31_response(
        payload=AssistantQueryRequest(
            message=package.question,
            scope="incident",
            incident_id=1,
            include_semantic_memory=False,
        ),
        package=package,
        focused_fact_inventory={"incident_id": 1, "status": "OPEN"},
        source_records=[],
        retrieval=RetrievalResult(scope="incident", incident_id=1),
        response_language="en",
        request_id="request-test",
        request_started=time.monotonic(),
        settings=AssistantSettings(enabled=True, response_architecture="v3_1"),
        generator=generator,
        clock=time.monotonic,
    )

    assert calls == 1
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.fallback_reason == "v31_invalid_structured_output"
    assert response.metadata.provider_generation_count == 1
    assert response.metadata.automatic_retries == 0
