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
from services.assistant.v3.contracts import (
    AnalyticalFocus,
    AnswerIntent,
    AuthorityClass,
    CompromiseStateAtom,
    PriorityAtom,
)
from tests.assistant_v3_test_support import analytical_package, operational_provenance


def _answer() -> dict:
    return {
        "response_language": "en",
        "answer": {
            "segments": [
                {
                    "segment_id": "s1",
                    "kind": "direct_answer",
                    "text": (
                        "The incident is open and was raised by a registry-change "
                        "detection on endpoint-a."
                    ),
                    "claim_refs": ["c1"],
                },
                {
                    "segment_id": "s2",
                    "kind": "uncertainty",
                    "text": (
                        "A second incident shares the endpoint, making it useful "
                        "for a focused evidence comparison. This analytical "
                        "relationship does not establish causality."
                    ),
                    "claim_refs": ["c2", "c3"],
                },
            ]
        },
        "claims": [
            {
                "claim_id": "c1",
                "claim_type": "operational_fact",
                "source_refs": [
                    "incident:1:status",
                    "incident:1:detection",
                    "incident:1:host",
                ],
                "qualifier_code": "NONE",
            },
            {
                "claim_id": "c2",
                "claim_type": "analytical_relationship",
                "source_refs": ["relationship:shared-host"],
                "qualifier_code": "NONE",
            },
            {
                "claim_id": "c3",
                "claim_type": "non_implication",
                "source_refs": [],
                "qualifier_code": "ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY",
            },
        ],
    }


def _parsed(payload: dict | None = None) -> GroundedConversationalAnswerV31:
    return GroundedConversationalAnswerV31.model_validate(payload or _answer())


def _operational_answer() -> dict:
    return {
        "response_language": "en",
        "answer": {
            "segments": [
                {
                    "segment_id": "s1",
                    "kind": "direct_answer",
                    "text": (
                        "The record shows an open incident raised by the Registry "
                        "changed rule on endpoint-a."
                    ),
                    "claim_refs": ["c1"],
                }
            ]
        },
        "claims": [
            {
                "claim_id": "c1",
                "claim_type": "operational_fact",
                "source_refs": [
                    "incident:1:status",
                    "incident:1:detection",
                    "incident:1:host",
                ],
                "qualifier_code": "NONE",
            }
        ],
    }


def _grounded_synthesis_answer() -> dict:
    return {
        "response_language": "en",
        "answer": {
            "segments": [
                {
                    "segment_id": "s1",
                    "kind": "direct_answer",
                    "text": (
                        "The Registry changed detection records a Registry modification "
                        "on endpoint-a."
                    ),
                    "claim_refs": ["c1"],
                },
                {
                    "segment_id": "s2",
                    "kind": "evidence_explanation",
                    "text": (
                        "MITRE T1112 technically classifies that observed Registry "
                        "activity as Modify Registry."
                    ),
                    "claim_refs": ["c2", "c3"],
                },
            ]
        },
        "claims": [
            {
                "claim_id": "c1",
                "claim_type": "operational_fact",
                "source_refs": ["incident:1:detection", "incident:1:host"],
                "qualifier_code": "NONE",
            },
            {
                "claim_id": "c2",
                "claim_type": "operational_fact",
                "source_refs": ["incident:1:mitre:T1112"],
                "qualifier_code": "NONE",
            },
            {
                "claim_id": "c3",
                "claim_type": "reference_explanation",
                "source_refs": ["reference:mitre:T1112"],
                "qualifier_code": "NONE",
            },
        ],
    }


def test_conversational_schema_is_closed_and_prompt_requests_final_prose() -> None:
    package = analytical_package()
    schema = grounded_conversational_answer_v31_schema(package)
    prompt = build_v31_conversational_messages(package, max_context_chars=24_000)
    explain_prompt = build_v31_conversational_messages(
        analytical_package(intent=AnswerIntent.EXPLAIN),
        max_context_chars=24_000,
    )

    assert schema["additionalProperties"] is False
    assert schema["properties"]["answer"]["additionalProperties"] is False
    claim_schema = schema["properties"]["claims"]["items"]
    assert claim_schema["additionalProperties"] is False
    assert "oneOf" not in claim_schema
    assert "Answer the user's actual question as a professional SOC analyst" in (
        prompt.messages[0]["content"]
    )
    assert "return the final user-facing answer as strict JSON" in prompt.messages[0][
        "content"
    ]
    assert "Do not write answer prose" not in prompt.messages[0]["content"]
    assert "Registry changed" in prompt.messages[1]["content"]
    assert "first segment MUST use kind direct_answer" in prompt.messages[0][
        "content"
    ]
    assert "Uncertainty is optional" in prompt.messages[0]["content"]
    assert "direct_answer, then comparison or pattern" in prompt.messages[0]["content"]
    assert "connect the strongest supplied facts" in explain_prompt.messages[0][
        "content"
    ]
    assert "create a matching reference_explanation claim" in (
        explain_prompt.messages[0]["content"]
    )
    assert "without imposing a layout" in explain_prompt.messages[0]["content"]
    assert "matching a selected MITRE technique is material" in (
        explain_prompt.messages[0]["content"]
    )
    assert "Code claim options are validation tools, not topics" in (
        explain_prompt.messages[0]["content"]
    )
    assert "never write or negate a protected concept" in explain_prompt.messages[0][
        "content"
    ]
    assert "do not turn available fields into an inventory" in explain_prompt.messages[
        0
    ]["content"]
    assert "never use could, might, possibly, potrebbe" in explain_prompt.messages[0][
        "content"
    ]
    assert "omit every protected concept entirely" in explain_prompt.messages[0][
        "content"
    ]
    assert explain_prompt.messages[0]["content"].casefold().count("compromise") == 1
    assert "do not suggest actions or use phrases such as should" in (
        explain_prompt.messages[0]["content"]
    )
    assert "never say that the level indicates suspicious" in explain_prompt.messages[0][
        "content"
    ]
    assert "if no matching claim is present" in prompt.messages[0]["content"]
    assert "Mention each protected concept in at most one segment" in (
        prompt.messages[0]["content"]
    )
    assert "exactly 2" not in prompt.messages[0]["content"]
    assert "exactly 4" not in prompt.messages[0]["content"]
    assert "75 and 105" not in prompt.messages[0]["content"]
    assert "c1 MUST" not in prompt.messages[0]["content"]
    assert "A numeric risk score is only the recorded number" in prompt.messages[0][
        "content"
    ]
    assert "never rename it incident_severity" in prompt.messages[1]["content"]
    assert "maximum defensible analytical meaning" in prompt.messages[0]["content"]
    assert "not wording to copy or a prose recipe" in prompt.messages[0]["content"]
    assert "Grounded synthesis is allowed" in explain_prompt.messages[0]["content"]
    assert "Grounded synthesis must not infer cause" in explain_prompt.messages[0][
        "content"
    ]
    assert "use declarative recorded statements only" not in explain_prompt.messages[0][
        "content"
    ]
    assert '"analyst_utility":"identify_triggering_detection_rule"' in prompt.messages[
        1
    ]["content"]
    model_payload = json.loads(explain_prompt.messages[1]["content"])
    assert all(
        item["claim_type"] == "non_implication"
        for item in model_payload["code_claim_options"]
    )
    atom_claim_types = {
        item["ref"]: item["allowed_claim_type"]
        for item in model_payload["operational_atoms"]
    }
    assert atom_claim_types["incident:1:detection"] == "operational_fact"
    detection_projection = next(
        item
        for item in model_payload["operational_atoms"]
        if item["ref"] == "incident:1:detection"
    )
    assert "level" not in detection_projection
    assert "evidence_priority" not in detection_projection
    assert all(
        value is not None
        for item in model_payload["operational_atoms"]
        for value in item.values()
    )
    assert all(
        item["ref"] not in {"incident:1:risk", "incident:1:priority"}
        for item in model_payload["operational_atoms"]
    )
    mitre_projection = next(
        item
        for item in model_payload["operational_atoms"]
        if item["ref"] == "incident:1:mitre:T1112"
    )
    assert mitre_projection["matching_reference_ref"] == "reference:mitre:T1112"
    assert "technique_name" not in mitre_projection
    assert model_payload["reference_knowledge"][0]["allowed_claim_type"] == (
        "reference_explanation"
    )
    assert model_payload["writing_contract"]["grounded_synthesis"]["allowed"] == [
        "connect_supplied_operational_facts",
        "explain_what_and_where_was_observed",
        "explain_exact_recorded_relationship_meaning",
        "use_reference_knowledge_for_technical_classification",
        "summarize_combined_supported_meaning",
    ]
    assert model_payload["writing_contract"]["explain_evidence_priority"].startswith(
        "observed_event_then_location"
    )
    assert "infer_compromise_persistence_or_lateral_movement" not in (
        model_payload["writing_contract"]["grounded_synthesis"]["forbidden"]
    )
    assert "enumerate_every_available_field" not in model_payload["writing_contract"]
    assert "active_case_ids" not in model_payload["scope"]
    cross_payload = json.loads(prompt.messages[1]["content"])
    cross_code_options = {
        item["qualifier_code"]: item for item in cross_payload["code_claim_options"]
    }
    assert cross_code_options["CORRELATION_NOT_COMPROMISE"]["claim_type"] == (
        "non_implication"
    )
    assert cross_code_options["ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY"][
        "source_refs"
    ] == []
    assert '"anchor_incident_ids":[1]' in prompt.messages[1]["content"]
    assert '"eligible_comparison_target_ids":[2]' in prompt.messages[1][
        "content"
    ]
    assert "never present an anchor_incident_id" in prompt.messages[0]["content"]


def test_conversational_schema_uses_llama_cpp_compatible_string_bounds() -> None:
    schema = grounded_conversational_answer_v31_schema(analytical_package())
    segments_schema = schema["properties"]["answer"]["properties"]["segments"]
    text_schema = segments_schema["items"]["properties"]["text"]

    assert text_schema["maxLength"] == MAX_CONVERSATIONAL_SEGMENT_CHARS
    assert text_schema["maxLength"] <= 1_000
    assert segments_schema["minItems"] == 1
    assert segments_schema["maxItems"] == MAX_CONVERSATIONAL_SEGMENTS
    assert schema["properties"]["claims"]["maxItems"] == MAX_CONVERSATIONAL_CLAIMS
    assert schema["properties"]["claims"]["minItems"] == 1
    later_kinds = segments_schema["items"]["properties"]["kind"]["enum"]
    assert "direct_answer" in later_kinds
    assert "analysis" in later_kinds
    assert "uncertainty" in later_kinds
    claim_refs = segments_schema["items"]["properties"]["claim_refs"]
    assert claim_refs["minItems"] == 1
    assert claim_refs["maxItems"] == 4
    assert claim_refs["items"]["enum"] == [f"c{index}" for index in range(1, 9)]


def test_schema_exposes_closed_claim_types_and_model_visible_refs() -> None:
    schema = grounded_conversational_answer_v31_schema(
        analytical_package(AnswerIntent.EXPLAIN)
    )
    claim_schema = schema["properties"]["claims"]["items"]
    properties = claim_schema["properties"]
    assert "operational_fact" in properties["claim_type"]["enum"]
    assert "reference_explanation" in properties["claim_type"]["enum"]
    assert "incident:1:status" in properties["source_refs"]["items"]["enum"]
    assert "reference:mitre:T1112" in properties["source_refs"]["items"]["enum"]
    assert properties["source_refs"]["minItems"] == 0
    assert properties["source_refs"]["maxItems"] == 4
    assert "NONE" in properties["qualifier_code"]["enum"]

    cross_claim_schema = grounded_conversational_answer_v31_schema(
        analytical_package(AnswerIntent.CROSS_INCIDENT_ANALYSIS)
    )["properties"]["claims"]["items"]["properties"]
    assert "analytical_relationship" in cross_claim_schema["claim_type"]["enum"]
    assert "semantic_candidate" in cross_claim_schema["claim_type"]["enum"]
    assert "relationship:shared-host" in cross_claim_schema["source_refs"]["items"][
        "enum"
    ]
    assert "relationship:semantic" in cross_claim_schema["source_refs"]["items"][
        "enum"
    ]


@pytest.mark.parametrize("segment_count", [1, 2, 3, 4])
def test_flexible_segment_counts_are_accepted(segment_count: int) -> None:
    payload = _operational_answer()
    for index in range(2, segment_count + 1):
        payload["answer"]["segments"].append(
            {
                "segment_id": f"s{index}",
                "kind": "evidence_explanation" if index == 2 else "analysis",
                "text": "This evidence locates the recorded activity for review.",
                "claim_refs": ["c1"],
            }
        )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.accepted is True


def test_more_than_maximum_segments_is_rejected_by_contract() -> None:
    payload = _operational_answer()
    payload["answer"]["segments"].extend(
        {
            "segment_id": f"s{min(index, 4)}",
            "kind": "analysis",
            "text": "The supplied evidence remains available for analysis.",
            "claim_refs": ["c1"],
        }
        for index in range(2, MAX_CONVERSATIONAL_SEGMENTS + 2)
    )

    assert parse_grounded_conversational_answer_v31(payload) is None


@pytest.mark.parametrize("claim_count", [1, 2, 5, 8])
def test_variable_claim_counts_are_accepted(claim_count: int) -> None:
    payload = _operational_answer()
    payload["claims"].extend(
        {
            "claim_id": f"c{index}",
            "claim_type": "operational_fact",
            "source_refs": ["incident:1:status"],
            "qualifier_code": "NONE",
        }
        for index in range(2, claim_count + 1)
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.accepted is True


def test_more_than_maximum_claims_is_rejected_by_contract() -> None:
    payload = _operational_answer()
    payload["claims"].extend(
        {
            "claim_id": f"c{min(index, 8)}",
            "claim_type": "operational_fact",
            "source_refs": ["incident:1:status"],
            "qualifier_code": "NONE",
        }
        for index in range(2, MAX_CONVERSATIONAL_CLAIMS + 2)
    )

    assert parse_grounded_conversational_answer_v31(payload) is None


def test_segment_claim_refs_are_granular_and_unknown_refs_fail() -> None:
    payload = _operational_answer()
    package = analytical_package(AnswerIntent.EXPLAIN)
    package = package.model_copy(
        update={
            "focus_selection": [*package.focus_selection, AnalyticalFocus.RISK]
        }
    )
    payload["claims"].append(
        {
            "claim_id": "c2",
            "claim_type": "operational_fact",
            "source_refs": ["incident:1:risk"],
            "qualifier_code": "NONE",
        }
    )

    accepted = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=package,
    )
    payload["answer"]["segments"][0]["claim_refs"] = ["c8"]
    rejected = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=package,
    )

    assert accepted.accepted is True
    assert rejected.reason == "unknown_claim_ref"


def test_explain_answer_does_not_require_uncertainty() -> None:
    payload = _operational_answer()
    payload["answer"]["segments"].append(
        {
            "segment_id": "s2",
            "kind": "analysis",
            "text": (
                "The triggering rule and endpoint identify where the analyst can "
                "focus the recorded evidence review."
            ),
            "claim_refs": ["c1"],
        }
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.accepted is True
    assert all(
        segment["kind"] != "uncertainty"
        for segment in payload["answer"]["segments"]
    )


def test_executive_summary_is_first_only_for_executive_intent() -> None:
    payload = _operational_answer()
    payload["answer"]["segments"][0]["kind"] = "executive_summary"

    rejected = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )
    accepted = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXECUTIVE_SUMMARY),
    )

    assert rejected.reason == "direct_answer_not_first"
    assert accepted.accepted is True


def test_direct_answer_cannot_be_repeated_after_first_segment() -> None:
    payload = _operational_answer()
    payload["answer"]["segments"].append(
        {
            "segment_id": "s2",
            "kind": "direct_answer",
            "text": "The same operational evidence remains recorded.",
            "claim_refs": ["c1"],
        }
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.reason == "direct_answer_repeated"


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


def test_explain_view_keeps_only_focused_secondary_metadata() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    view = conversational_model_facing_evidence(package)
    atom_types = {item.atom_type for item in view.operational_atoms}

    assert {"detection", "host", "mitre_technique"}.issubset(atom_types)
    assert "recorded_correlation" in atom_types
    assert "risk" not in atom_types
    assert "priority" not in atom_types
    assert "timeline_event" not in atom_types
    assert "incident_identity" not in atom_types

    risk_view = conversational_model_facing_evidence(
        package.model_copy(
            update={
                "focus_selection": [
                    *package.focus_selection,
                    AnalyticalFocus.RISK,
                    AnalyticalFocus.PRIORITY,
                ]
            }
        )
    )
    risk_types = {item.atom_type for item in risk_view.operational_atoms}

    assert "risk" in risk_types


@pytest.mark.parametrize("recorded_state", [False, True])
def test_only_explicit_compromise_state_is_model_visible(
    recorded_state: bool,
) -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    explicit_atom = CompromiseStateAtom(
        atom_id="incident:1:compromise-state",
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        provenance=operational_provenance(1),
        incident_id=1,
        compromise_confirmed=recorded_state,
    )
    unknown_atom = explicit_atom.model_copy(
        update={
            "atom_id": "incident:1:compromise-state-unknown",
            "compromise_confirmed": None,
        }
    )
    package = package.model_copy(
        update={
            "operational_atoms": [
                *package.operational_atoms,
                unknown_atom,
                explicit_atom,
            ]
        }
    )

    view = conversational_model_facing_evidence(package)
    visible_refs = {item.atom_id for item in view.operational_atoms}

    assert explicit_atom.atom_id in visible_refs
    assert unknown_atom.atom_id not in visible_refs


def test_valid_conversational_prose_and_typed_refs_are_accepted() -> None:
    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(),
        package=analytical_package(),
    )

    assert result.accepted is True


def test_direct_operational_explanation_needs_no_non_implication_claim() -> None:
    payload = _operational_answer()

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.accepted is True
    assert {claim["claim_type"] for claim in payload["claims"]} == {
        "operational_fact"
    }


def test_grounded_operational_and_reference_synthesis_is_accepted() -> None:
    payload = _grounded_synthesis_answer()

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.accepted is True
    assert all(
        claim["claim_type"] != "non_implication" for claim in payload["claims"]
    )


def test_t1112_does_not_support_persistence_inference() -> None:
    payload = _grounded_synthesis_answer()
    payload["answer"]["segments"][1]["text"] = (
        "MITRE T1112 shows persistence on endpoint-a."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.reason == "unsupported_persistence_assertion"


def test_negative_compromise_statement_requires_matching_segment_claim() -> None:
    payload = _operational_answer()
    payload["answer"]["segments"][0]["text"] = (
        "The recorded detection does not establish compromise."
    )
    missing = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )
    payload["claims"].append(
        {
            "claim_id": "c2",
            "claim_type": "non_implication",
            "source_refs": [],
            "qualifier_code": (
                "EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS"
            ),
        }
    )
    payload["answer"]["segments"][0]["claim_refs"].append("c2")
    accepted = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert missing.reason == "unsupported_compromise_assertion"
    assert accepted.accepted is True


def test_positive_compromise_inference_remains_rejected() -> None:
    payload = _operational_answer()
    payload["answer"]["segments"][0]["text"] = "This proves compromise."

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.reason == "unsupported_compromise_assertion"


def test_recorded_correlation_requires_exact_platform_meaning() -> None:
    payload = _operational_answer()
    payload["claims"][0].update(
        {
            "claim_type": "recorded_correlation",
            "source_refs": ["incident:1:recorded-correlation"],
        }
    )
    payload["answer"]["segments"][0]["text"] = (
        "The platform recorded a same-host correlation."
    )
    accepted = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )
    payload["answer"]["segments"][0]["text"] = (
        "The correlated incidents have the same cause."
    )
    rejected = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert accepted.accepted is True
    assert rejected.reason == "unsupported_causality_assertion"


def test_recorded_correlation_compromise_caveat_requires_matching_claim() -> None:
    payload = _operational_answer()
    payload["claims"][0].update(
        {
            "claim_type": "recorded_correlation",
            "source_refs": ["incident:1:recorded-correlation"],
        }
    )
    payload["answer"]["segments"][0]["text"] = (
        "The recorded correlation does not establish compromise."
    )
    missing = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )
    payload["claims"].append(
        {
            "claim_id": "c2",
            "claim_type": "non_implication",
            "source_refs": [],
            "qualifier_code": "CORRELATION_NOT_COMPROMISE",
        }
    )
    payload["answer"]["segments"][0]["claim_refs"].append("c2")
    accepted = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert missing.reason == "unsupported_compromise_assertion"
    assert accepted.accepted is True


def test_only_relevant_segment_references_non_implication_claim() -> None:
    payload = _operational_answer()
    payload["claims"].append(
        {
            "claim_id": "c2",
            "claim_type": "non_implication",
            "source_refs": [],
            "qualifier_code": "EVIDENCE_NOT_MALICIOUSNESS",
        }
    )
    payload["answer"]["segments"].extend(
        [
            {
                "segment_id": "s2",
                "kind": "analysis",
                "text": "The endpoint and rule focus the recorded evidence review.",
                "claim_refs": ["c1"],
            },
            {
                "segment_id": "s3",
                "kind": "uncertainty",
                "text": "The recorded evidence does not establish malicious activity.",
                "claim_refs": ["c2"],
            },
        ]
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.accepted is True
    assert payload["answer"]["segments"][0]["claim_refs"] == ["c1"]
    assert payload["answer"]["segments"][1]["claim_refs"] == ["c1"]
    assert payload["answer"]["segments"][2]["claim_refs"] == ["c2"]


def test_analytical_relationship_cannot_assert_causality() -> None:
    payload = _answer()
    payload["answer"]["segments"][1]["text"] = (
        "The shared endpoint establishes causality between the incidents."
    )
    payload["answer"]["segments"][1]["claim_refs"] = ["c2"]

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.reason == "unsupported_causality_assertion"


def test_semantic_similarity_cannot_be_presented_as_recorded_correlation() -> None:
    payload = _operational_answer()
    payload["claims"][0].update(
        {
            "claim_type": "semantic_candidate",
            "source_refs": ["relationship:semantic"],
        }
    )
    payload["answer"]["segments"][0]["text"] = (
        "The semantic similarity is a recorded correlation."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.reason == "semantic_candidate_as_recorded_correlation"


def test_semantic_correlation_boundary_requires_matching_non_implication() -> None:
    payload = _operational_answer()
    payload["claims"][0].update(
        {
            "claim_type": "semantic_candidate",
            "source_refs": ["relationship:semantic"],
        }
    )
    payload["claims"].append(
        {
            "claim_id": "c2",
            "claim_type": "non_implication",
            "source_refs": [],
            "qualifier_code": "SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION",
        }
    )
    payload["answer"]["segments"][0].update(
        {
            "text": "The semantic similarity is not a recorded correlation.",
            "claim_refs": ["c1", "c2"],
        }
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(),
    )

    assert result.accepted is True


def test_reference_knowledge_cannot_be_presented_as_current_state() -> None:
    payload = _operational_answer()
    payload["claims"][0].update(
        {
            "claim_type": "reference_explanation",
            "source_refs": ["reference:mitre:T1112"],
        }
    )
    payload["answer"]["segments"][0]["text"] = (
        "The incident is a Modify Registry event under MITRE T1112."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=analytical_package(AnswerIntent.EXPLAIN),
    )

    assert result.reason == "reference_current_state_promotion"


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
    payload["answer"]["segments"][1]["claim_refs"] = ["c2"]
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
            "This is potentially harmful activity.",
            "unsupported_maliciousness_assertion",
        ),
        (
            "Questa è un'attività malintenzionata.",
            "unsupported_maliciousness_assertion",
        ),
        (
            "Questa è un'attività potenzialmente dannosa.",
            "unsupported_maliciousness_assertion",
        ),
        (
            "Detection level 5 indicates suspicious activity.",
            "unsupported_maliciousness_assertion",
        ),
        (
            "Il livello 5 indica un'attività sospetta.",
            "unsupported_maliciousness_assertion",
        ),
        (
            "The detection proves anomalous activity.",
            "unsupported_maliciousness_assertion",
        ),
        (
            "La regola ha rilevato un'attività anomala.",
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


def test_recorded_low_risk_normalization_may_be_reported_exactly() -> None:
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
    payload = _operational_answer()
    payload["claims"][0]["source_refs"] = [risk.atom_id]
    payload["answer"]["segments"][0]["text"] = (
        "The recorded risk normalization is LOW."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=package,
    )

    assert result.accepted is True


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


def test_recorded_recommended_priority_is_not_advisory_guidance() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    provenance = package.operational_atoms[0].provenance
    priority = PriorityAtom(
        atom_id="incident:1:priority",
        authority_class=package.operational_atoms[0].authority_class,
        provenance=provenance,
        incident_id=1,
        recommended_priority="LOW",
    )
    package = package.model_copy(update={"operational_atoms": [priority]})
    payload = _operational_answer()
    payload["claims"][0]["source_refs"] = [priority.atom_id]
    payload["answer"]["segments"][0]["text"] = (
        "La priorità consigliata registrata è LOW."
    )

    result = GroundedConversationalAnswerV31Validator().validate(
        _parsed(payload),
        package=package,
    )

    assert result.accepted is True


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


def test_unsupported_italian_hypothetical_explanation_is_rejected() -> None:
    payload = _answer()
    payload["answer"]["segments"][0]["text"] = (
        "La modifica può indicare una normale attività di configurazione."
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


def test_v31_default_output_budget_covers_bounded_conversational_json() -> None:
    assert AssistantSettings().v31_max_output_tokens == 1024


def test_v31_renderer_hides_internal_claim_ids_from_visible_prose() -> None:
    payload = _answer()
    payload["answer"]["segments"][0]["text"] = (
        payload["answer"]["segments"][0]["text"].removesuffix(".")
        + " (c1). C1: This remains model-authored prose."
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
    assert "(c1)" not in response.answer
    assert "C1:" not in response.answer
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
