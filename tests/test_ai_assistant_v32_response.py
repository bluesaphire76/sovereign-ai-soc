from __future__ import annotations

import json
import time
from collections.abc import Sequence

from pydantic import ValidationError
import pytest

from services.assistant.v3.contracts import AnswerIntent
from schemas.assistant import AssistantQueryRequest
from services.assistant.orchestrator import AssistantSettings, _run_v32_response
from services.assistant.retrieval import RetrievalResult
from services.assistant.v3.response_v32 import (
    GroundedResponseV32Validator,
    build_v32_messages,
    compile_v32_proof_units,
    grounded_response_v32_schema,
    parse_grounded_response_v32,
    render_grounded_response_v32,
)
from services.assistant.v3.semantic_proof.contracts import (
    EntailmentDecision,
    EntailmentDecisionReason,
    EntailmentLabel,
    EntailmentPair,
    EntailmentProviderInfo,
    EvidenceKind,
    ProofPredicate,
)
from services.assistant.v3.semantic_proof.hybrid import HybridProofReason
from services.assistant.v3.semantic_proof.guards import (
    SemanticConcept,
    TypedSemanticGuard,
    detect_semantic_concepts,
    eligible_for_deterministic_proof,
)
from services.assistant.v3.semantic_proof.response_contracts import (
    GroundedResponseDraftV32,
    V32Proposition,
    V32SectionKind,
)
from tests.assistant_v3_test_support import analytical_package


class _EntailingProvider:
    def __init__(self, *, fail: bool = False) -> None:
        self._fail = fail

    @property
    def info(self) -> EntailmentProviderInfo:
        return EntailmentProviderInfo(
            backend="test",
            model="test",
            precision="none",
            quantization="none",
            device="none",
        )

    def evaluate(
        self,
        pairs: Sequence[EntailmentPair],
        *,
        batch_size: int,
    ) -> Sequence[EntailmentDecision]:
        del batch_size
        if self._fail:
            raise RuntimeError("provider unavailable")
        return [
            EntailmentDecision(
                pair_id=item.pair_id,
                proof_unit_id=item.proof_unit_id,
                hypothesis_id=item.hypothesis_id,
                label=EntailmentLabel.ENTAILMENT,
                entailment_score=1.0,
                accepted=True,
                reason=EntailmentDecisionReason.ENTAILED,
            )
            for item in pairs
        ]


class _SleepingProvider(_EntailingProvider):
    def evaluate(self, pairs, *, batch_size):
        time.sleep(0.1)
        return super().evaluate(pairs, batch_size=batch_size)


def _draft(proof_unit_id: str | list[str], text: str, *, language: str = "en"):
    proof_unit_refs = (
        [proof_unit_id] if isinstance(proof_unit_id, str) else proof_unit_id
    )
    return GroundedResponseDraftV32(
        response_language=language,
        propositions=[
            V32Proposition(
                proposition_id="p1",
                text=text,
                proof_unit_refs=proof_unit_refs,
                section_kind=V32SectionKind.DIRECT_ANSWER,
            )
        ],
    )


def test_v32_prompt_and_schema_expose_typed_proof_units_by_authority() -> None:
    package = analytical_package()
    proof_units = compile_v32_proof_units(package)

    schema = grounded_response_v32_schema(proof_units)
    prompt = build_v32_messages(package, proof_units, max_context_chars=24000)
    context = json.loads(prompt.messages[1]["content"])

    assert proof_units
    assert set(
        schema["properties"]["propositions"]["items"]["properties"][
            "proof_unit_refs"
        ]["items"]["enum"]
    ) == {item.proof_unit_id for item in proof_units}
    assert "OPERATIONAL_AUTHORITATIVE" in context["evidence_by_authority"]
    assert "ANALYTICAL_DERIVATION" in context["evidence_by_authority"]
    assert context["writing_contract"]["one_atomic_factual_proposition_per_sentence"]


def test_v32_compare_surface_contains_only_relationship_participating_facts() -> None:
    package = analytical_package(
        AnswerIntent.COMPARE,
        include_semantic=False,
    )
    proof_units = compile_v32_proof_units(package)

    assert any(
        item.predicate is ProofPredicate.ANALYTICAL_RELATIONSHIP
        for item in proof_units
    )
    assert any(item.predicate is ProofPredicate.AGENT for item in proof_units)
    assert not any(item.predicate is ProofPredicate.STATUS for item in proof_units)
    assert not any(
        item.predicate is ProofPredicate.RECORDED_CORRELATION_STATE
        for item in proof_units
    )


def test_v32_mitre_synthesis_preserves_both_authorities_and_blocks_promotion() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    proof_units = compile_v32_proof_units(package)
    synthesis = next(
        item for item in proof_units if item.predicate.value == "MITRE_CONTEXT"
    )
    proposition = (
        "La tecnica MITRE registrata per l'incidente è T1112, "
        "che corrisponde a Modify Registry."
    )

    assert synthesis.authority_class.value == "ANALYTICAL_DERIVATION"
    assert len(synthesis.source_refs) == 2
    registry = {item.source_ref: item for item in package.source_registry}
    assert {
        registry[source_ref].authority_class.value
        for source_ref in synthesis.source_refs
    } == {"OPERATIONAL_AUTHORITATIVE", "REFERENCE_KNOWLEDGE"}
    assert not any(
        item.predicate.value in {"MITRE_TECHNIQUE", "REFERENCE_EXPLANATION"}
        and item.source_refs[0] in synthesis.source_refs
        for item in proof_units
    )

    accepted = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(synthesis.proof_unit_id, proposition),
        package=package,
        proof_units=proof_units,
    )
    rejected = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(
            synthesis.proof_unit_id,
            "La tecnica MITRE T1112 conferma la compromissione dell'incidente.",
        ),
        package=package,
        proof_units=proof_units,
    )

    assert accepted.accepted
    assert accepted.proof_result is not None
    assert accepted.proof_result.provider_pair_count == 0
    assert not rejected.accepted
    assert rejected.proof_result is not None
    assert rejected.proof_result.decisions[0].reason is (
        HybridProofReason.TYPED_GUARD_REJECTED
    )


def test_v32_relationship_proof_carries_authoritative_value_and_typed_boundary() -> None:
    package = analytical_package(include_semantic=False)
    proof_units = compile_v32_proof_units(package)
    relationship = next(
        item
        for item in proof_units
        if item.predicate is ProofPredicate.ANALYTICAL_RELATIONSHIP
    )
    boundary = next(
        item
        for item in proof_units
        if item.predicate is ProofPredicate.NON_IMPLICATION
        and "relationship:shared-host" in item.source_refs
    )

    assert relationship.value.canonical_values == ["SHARED_AGENT", "endpoint-a"]
    assert relationship.value.required_anchors == ["1", "2"]
    assert "endpoint-a" in relationship.canonical_premise
    assert boundary.evidence_kind is EvidenceKind.ANALYTICAL_BOUNDARY
    assert boundary.authority_class.value == "ANALYTICAL_DERIVATION"
    assert set(boundary.source_refs) >= {
        "relationship:shared-host",
        "incident:1:host",
        "incident:2:host",
    }

    accepted = TypedSemanticGuard().evaluate(
        boundary,
        boundary.canonical_premise,
    )
    translated_relationship = TypedSemanticGuard().evaluate(
        relationship,
        "Incidents 1 and 2 use the same agent endpoint-a.",
    )
    rejected = TypedSemanticGuard().evaluate(
        boundary,
        "Analytical relationship SHARED_AGENT between Incidents 1 and 2 establishes compromise.",
    )

    assert accepted.accepted
    assert translated_relationship.accepted
    assert not rejected.accepted
    assert rejected.reason.value == "POLARITY_MISMATCH"


def test_v32_next_action_requires_advisory_or_typed_context_limitation() -> None:
    package = analytical_package(
        AnswerIntent.NEXT_ACTION,
        include_advisory=False,
    )
    package = package.model_copy(
        update={
            "context_plan": package.context_plan.model_copy(
                update={"include_advisory": True}
            )
        }
    )
    proof_units = compile_v32_proof_units(package)
    status = next(item for item in proof_units if item.predicate is ProofPredicate.STATUS)
    limitation = next(
        item
        for item in proof_units
        if item.predicate is ProofPredicate.CONTEXT_LIMITATION
    )

    unsupported = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(status.proof_unit_id, status.canonical_premise),
        package=package,
        proof_units=proof_units,
    )
    supported_draft = GroundedResponseDraftV32(
        response_language="en",
        propositions=[
            V32Proposition(
                proposition_id="p1",
                text=limitation.canonical_premise,
                proof_unit_refs=[limitation.proof_unit_id],
                section_kind=V32SectionKind.UNCERTAINTY,
            )
        ],
    )
    supported = GroundedResponseV32Validator(_EntailingProvider()).validate(
        supported_draft,
        package=package,
        proof_units=proof_units,
    )

    assert limitation.source_refs == []
    assert unsupported.reason == "next_action_contract_mismatch"
    assert supported.accepted


def test_v32_cross_incident_contract_requires_non_implication_boundary() -> None:
    package = analytical_package(include_semantic=False)
    proof_units = compile_v32_proof_units(package)
    relationship = next(
        item
        for item in proof_units
        if item.predicate is ProofPredicate.ANALYTICAL_RELATIONSHIP
    )
    boundary = next(
        item
        for item in proof_units
        if item.predicate is ProofPredicate.NON_IMPLICATION
        and "relationship:shared-host" in item.source_refs
    )
    relationship_only = _draft(
        relationship.proof_unit_id,
        relationship.canonical_premise,
    )
    complete = GroundedResponseDraftV32(
        response_language="en",
        propositions=[
            V32Proposition(
                proposition_id="p1",
                text=relationship.canonical_premise,
                proof_unit_refs=[relationship.proof_unit_id],
                section_kind=V32SectionKind.COMPARISON,
            ),
            V32Proposition(
                proposition_id="p2",
                text=boundary.canonical_premise,
                proof_unit_refs=[boundary.proof_unit_id],
                section_kind=V32SectionKind.UNCERTAINTY,
            ),
        ],
    )

    rejected = GroundedResponseV32Validator(_EntailingProvider()).validate(
        relationship_only,
        package=package,
        proof_units=proof_units,
    )
    accepted = GroundedResponseV32Validator(_EntailingProvider()).validate(
        complete,
        package=package,
        proof_units=proof_units,
    )

    assert rejected.reason == "cross_incident_boundary_missing"
    assert accepted.accepted


def test_v32_validator_accepts_only_whole_atomic_proof_and_derives_sources() -> None:
    package = analytical_package(AnswerIntent.INVESTIGATE)
    proof_units = compile_v32_proof_units(package)
    status = next(item for item in proof_units if item.predicate.value == "STATUS")
    draft = _draft(status.proof_unit_id, status.canonical_premise)

    validation = GroundedResponseV32Validator(_EntailingProvider()).validate(
        draft,
        package=package,
        proof_units=proof_units,
    )
    rendered = render_grounded_response_v32(draft, proof_units=proof_units)

    assert validation.accepted
    assert validation.proof_result is not None
    assert validation.proof_result.provider_pair_count == 0
    assert rendered.blocks[0].text == status.canonical_premise
    assert rendered.blocks[0].source_refs == tuple(status.source_refs)


def test_v32_combined_proof_accepts_supported_operational_conjunction_only() -> None:
    package = analytical_package()
    proof_units = compile_v32_proof_units(package)
    detection = next(
        item for item in proof_units if item.predicate.value == "DETECTION_LEVEL"
    )
    correlation = next(
        item
        for item in proof_units
        if item.predicate.value == "RECORDED_CORRELATION_STATE"
    )
    refs = [detection.proof_unit_id, correlation.proof_unit_id]

    accepted = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(
            refs,
            "Incident 1 has detection level 10 and recorded correlation score 75.",
        ),
        package=package,
        proof_units=proof_units,
    )
    rejected = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(
            refs,
            "Incident 1 has detection level 10 and recorded correlation score 99.",
        ),
        package=package,
        proof_units=proof_units,
    )

    assert accepted.accepted
    assert accepted.proof_result is not None
    assert accepted.proof_result.provider_pair_count == 1
    assert not rejected.accepted
    assert rejected.proof_result is not None
    assert rejected.proof_result.provider_pair_count == 0
    assert rejected.proof_result.decisions[0].reason is (
        HybridProofReason.TYPED_GUARD_REJECTED
    )

    single_host = correlation.model_copy(
        update={
            "canonical_premise": (
                "Incident 1 recorded correlation type "
                "SINGLE_HOST_PATTERN_CORRELATION with score 75."
            ),
            "value": correlation.value.model_copy(
                update={
                    "canonical_values": [
                        "SINGLE_HOST_PATTERN_CORRELATION",
                        "75",
                    ]
                }
            ),
        }
    )
    translated_type = TypedSemanticGuard().evaluate(
        single_host,
        "Incident 1 is correlated to a single host with score 75.",
    )
    assert translated_type.accepted
    assert eligible_for_deterministic_proof(
        single_host,
        "Incident 1 is correlated to a single host with score 75.",
    )


def test_v32_combined_proof_accepts_only_matching_operational_boundary_bundle() -> None:
    package = analytical_package(AnswerIntent.INVESTIGATE)
    proof_units = compile_v32_proof_units(package)
    risk = next(
        item for item in proof_units if item.predicate is ProofPredicate.RISK_SCORE
    )
    risk_boundary = next(
        item
        for item in proof_units
        if item.predicate is ProofPredicate.NON_IMPLICATION
        and "incident:1:risk" in item.source_refs
    )
    relationship = next(
        item
        for item in proof_units
        if item.predicate is ProofPredicate.ANALYTICAL_RELATIONSHIP
    )

    accepted = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(
            [risk.proof_unit_id, risk_boundary.proof_unit_id],
            "Incident 1 has risk score 72, but it does not establish compromise.",
        ),
        package=package,
        proof_units=proof_units,
    )
    rejected = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(
            [risk.proof_unit_id, relationship.proof_unit_id],
            "Incident 1 has risk score 72 and an analytical relationship.",
        ),
        package=package,
        proof_units=proof_units,
    )
    promotion = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(
            [risk.proof_unit_id, risk_boundary.proof_unit_id],
            "Incident 1 has risk score 72 and this establishes compromise.",
        ),
        package=package,
        proof_units=proof_units,
    )

    assert accepted.accepted
    assert not rejected.accepted
    assert not promotion.accepted
    assert rejected.proof_result is not None
    assert rejected.proof_result.decisions[0].reason is (
        HybridProofReason.TYPED_GUARD_REJECTED
    )
    assert promotion.proof_result is not None
    assert promotion.proof_result.decisions[0].reason is (
        HybridProofReason.TYPED_GUARD_REJECTED
    )


def test_v32_combined_proof_rejects_semantic_candidate_authority_mix() -> None:
    package = analytical_package(AnswerIntent.INVESTIGATE)
    proof_units = compile_v32_proof_units(package)
    status = next(item for item in proof_units if item.predicate.value == "STATUS")
    candidate = next(
        item
        for item in proof_units
        if item.predicate.value == "CANDIDATE_DISCOVERY"
    )

    validation = GroundedResponseV32Validator(_EntailingProvider()).validate(
        _draft(
            [status.proof_unit_id, candidate.proof_unit_id],
            "Incident 1 is OPEN and Incident 2 is a semantic candidate.",
        ),
        package=package,
        proof_units=proof_units,
    )

    assert not validation.accepted
    assert validation.proof_result is not None
    assert validation.proof_result.decisions[0].reason is (
        HybridProofReason.TYPED_GUARD_REJECTED
    )


def test_v32_validator_rejects_compound_overreach_before_nli_acceptance() -> None:
    package = analytical_package(AnswerIntent.INVESTIGATE)
    proof_units = compile_v32_proof_units(package)
    status = next(item for item in proof_units if item.predicate.value == "STATUS")
    text = f"{status.canonical_premise[:-1]} and the incident is malicious."
    draft = _draft(status.proof_unit_id, text)

    validation = GroundedResponseV32Validator(_EntailingProvider()).validate(
        draft,
        package=package,
        proof_units=proof_units,
    )

    assert not validation.accepted
    assert validation.proof_result is not None
    assert validation.proof_result.provider_pair_count == 0
    assert validation.proof_result.decisions[0].reason is (
        HybridProofReason.TYPED_GUARD_REJECTED
    )


def test_italian_timestamp_participle_is_not_operational_status() -> None:
    package = analytical_package()
    unit = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "INCIDENT_TIMESTAMP"
    )

    decision = TypedSemanticGuard().evaluate(
        unit,
        f"L'incidente 1 è stato registrato il {unit.value.canonical_values[0]}.",
    )

    assert decision.accepted


def test_correlation_state_phrase_is_not_incident_status() -> None:
    concepts = detect_semantic_concepts(
        "Lo stato di correlazione non stabilisce causalità."
    )

    assert SemanticConcept.RECORDED_CORRELATION in concepts
    assert SemanticConcept.STATUS not in concepts


def test_mitre_guard_requires_id_but_allows_nli_to_prove_translated_name() -> None:
    package = analytical_package()
    unit = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "MITRE_TECHNIQUE"
    )

    assert unit.value.required_anchors == ["T1112"]
    proposition = (
        "La tecnica MITRE registrata per l'incidente 1 è T1112, "
        "che corrisponde a Modify Registry."
    )
    decision = TypedSemanticGuard().evaluate(
        unit,
        proposition,
    )

    assert decision.accepted
    assert eligible_for_deterministic_proof(unit, proposition)


def test_dated_timeline_event_uses_exact_timestamp_as_translation_anchor() -> None:
    package = analytical_package()
    unit = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "TIMELINE_EVENT"
        and len(item.value.canonical_values) == 2
    )
    timestamp = unit.value.canonical_values[1]

    assert unit.value.required_anchors == [timestamp]
    decision = TypedSemanticGuard().evaluate(
        unit,
        f"Per l'incidente 1 è registrato un evento tradotto alle {timestamp}.",
    )

    assert decision.accepted


def test_v32_validator_fails_closed_when_nli_is_unavailable() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    proof_units = compile_v32_proof_units(package)
    advisory = next(
        item for item in proof_units if item.predicate.value == "ADVISORY_GUIDANCE"
    )
    draft = _draft(
        advisory.proof_unit_id,
        "Registry investigation playbook recommends reviewing registry telemetry.",
    )

    validation = GroundedResponseV32Validator(
        _EntailingProvider(fail=True)
    ).validate(
        draft,
        package=package,
        proof_units=proof_units,
    )

    assert not validation.accepted
    assert validation.proof_result is not None
    assert validation.proof_result.decisions[0].reason is (
        HybridProofReason.PROVIDER_UNAVAILABLE
    )


def test_v32_contract_covers_all_visible_text_and_rejects_model_provenance() -> None:
    package = analytical_package()
    proof_units = compile_v32_proof_units(package)
    status = next(item for item in proof_units if item.predicate.value == "STATUS")
    payload = _draft(status.proof_unit_id, status.canonical_premise).model_dump(
        mode="json"
    )
    payload["propositions"][0]["source_refs"] = ["model:invented"]

    assert parse_grounded_response_v32(payload) is None
    with pytest.raises(ValidationError):
        GroundedResponseDraftV32(
            response_language="en",
            propositions=[
                V32Proposition(
                    proposition_id="p1",
                    text=status.canonical_premise,
                    proof_unit_refs=[status.proof_unit_id],
                    section_kind=V32SectionKind.DIRECT_ANSWER,
                ),
                V32Proposition(
                    proposition_id="p1",
                    text=status.canonical_premise,
                    proof_unit_refs=[status.proof_unit_id],
                    section_kind=V32SectionKind.EVIDENCE,
                ),
            ],
        )


def _run_v32(monkeypatch, package, payload, *, provider=None):
    calls = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {
            "structured_output": payload,
            "generation_ms": 41,
            "finish_reason": "stop",
        }

    monkeypatch.setattr(
        "services.assistant.orchestrator.get_semantic_proof_provider",
        lambda: provider or _EntailingProvider(),
    )
    response = _run_v32_response(
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
        response_language=package.response_language,
        request_id="request-v32-test",
        request_started=time.monotonic(),
        settings=AssistantSettings(
            enabled=True,
            response_architecture="v3_2",
            max_context_chars=24_000,
            v32_max_output_tokens=700,
        ),
        generator=generator,
        clock=time.monotonic,
    )
    return response, calls


def test_v32_runner_publishes_whole_proven_response_with_one_generation(
    monkeypatch,
) -> None:
    package = analytical_package(AnswerIntent.INVESTIGATE)
    status = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "STATUS"
    )
    payload = _draft(status.proof_unit_id, status.canonical_premise).model_dump(
        mode="json"
    )

    response, calls = _run_v32(monkeypatch, package, payload)

    assert len(calls) == 1
    assert calls[0]["output_schema"] == "assistant_grounded_v32"
    assert calls[0]["context"]["response_architecture"] == "v3_2"
    assert calls[0]["max_visible_tokens"] == 700
    assert response.generation_kind == "model"
    assert response.answer == status.canonical_premise
    assert response.metadata.response_architecture == "v3_2"
    assert response.metadata.semantic_proof_status == "passed"
    assert response.metadata.semantic_proof_pairs == 1
    assert response.metadata.deterministic_proofs == 1
    assert response.metadata.nli_proofs == 0
    assert response.metadata.provider_generation_count == 1
    assert response.metadata.automatic_retries == 0


def test_v32_runner_rejects_overreach_without_repair_generation(monkeypatch) -> None:
    package = analytical_package(AnswerIntent.INVESTIGATE)
    status = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "STATUS"
    )
    payload = _draft(
        status.proof_unit_id,
        f"{status.canonical_premise[:-1]} and the incident is malicious.",
    ).model_dump(mode="json")

    response, calls = _run_v32(monkeypatch, package, payload)

    assert len(calls) == 1
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.fallback_reason == "v32_semantic_proof_failed"
    assert response.metadata.semantic_proof_status == "failed"
    assert response.metadata.typed_guard_rejects == 1
    assert response.metadata.provider_generation_count == 1
    assert response.metadata.automatic_retries == 0


def test_v32_runner_fails_closed_when_required_nli_is_unavailable(
    monkeypatch,
) -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    advisory = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "ADVISORY_GUIDANCE"
    )
    payload = _draft(
        advisory.proof_unit_id,
        "Registry investigation playbook recommends reviewing registry telemetry.",
    ).model_dump(mode="json")

    response, calls = _run_v32(
        monkeypatch,
        package,
        payload,
        provider=_EntailingProvider(fail=True),
    )

    assert len(calls) == 1
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.fallback_reason == "v32_semantic_proof_unavailable"
    assert response.metadata.semantic_proof_status == "unavailable"
    assert response.metadata.nli_proofs == 1
    assert response.metadata.provider_generation_count == 1


def test_v32_runner_fails_closed_when_semantic_proof_times_out(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AI_SOC_ASSISTANT_V32_PROOF_TIMEOUT_SECONDS", "0.05")
    package = analytical_package(AnswerIntent.EXPLAIN)
    advisory = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "ADVISORY_GUIDANCE"
    )
    payload = _draft(
        advisory.proof_unit_id,
        "Registry investigation playbook recommends reviewing registry telemetry.",
    ).model_dump(mode="json")

    response, calls = _run_v32(
        monkeypatch,
        package,
        payload,
        provider=_SleepingProvider(),
    )

    assert len(calls) == 1
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.fallback_reason == "v32_semantic_proof_unavailable"
    assert response.metadata.semantic_proof_status == "unavailable"
    assert response.metadata.provider_generation_count == 1


def test_v32_runner_rejects_malformed_output_without_second_generation(
    monkeypatch,
) -> None:
    response, calls = _run_v32(
        monkeypatch,
        analytical_package(),
        {"unexpected": True},
    )

    assert len(calls) == 1
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.fallback_reason == "v32_invalid_structured_output"
    assert response.metadata.semantic_proof_status == "not_run"
    assert response.metadata.provider_generation_count == 1
    assert response.metadata.automatic_retries == 0
