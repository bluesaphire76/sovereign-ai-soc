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
)
from services.assistant.v3.semantic_proof.hybrid import HybridProofReason
from services.assistant.v3.semantic_proof.response_contracts import (
    GroundedResponseDraftV32,
    V32Proposition,
    V32Section,
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


def _draft(proof_unit_id: str, text: str, *, language: str = "en"):
    return GroundedResponseDraftV32(
        response_language=language,
        propositions=[
            V32Proposition(
                proposition_id="p1",
                text=text,
                proof_unit_ref=proof_unit_id,
            )
        ],
        sections=[
            V32Section(
                section_id="s1",
                kind=V32SectionKind.DIRECT_ANSWER,
                proposition_refs=["p1"],
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
            "proof_unit_ref"
        ]["enum"]
    ) == {item.proof_unit_id for item in proof_units}
    assert "OPERATIONAL_AUTHORITATIVE" in context["evidence_by_authority"]
    assert "ANALYTICAL_DERIVATION" in context["evidence_by_authority"]
    assert context["writing_contract"]["one_atomic_factual_proposition_per_sentence"]


def test_v32_validator_accepts_only_whole_atomic_proof_and_derives_sources() -> None:
    package = analytical_package()
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


def test_v32_validator_rejects_compound_overreach_before_nli_acceptance() -> None:
    package = analytical_package()
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


def test_v32_validator_fails_closed_when_nli_is_unavailable() -> None:
    package = analytical_package(AnswerIntent.EXPLAIN)
    proof_units = compile_v32_proof_units(package)
    reference = next(
        item for item in proof_units if item.predicate.value == "REFERENCE_EXPLANATION"
    )
    draft = _draft(
        reference.proof_unit_id,
        "MITRE defines T1112 as Modify Registry.",
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
                    proof_unit_ref=status.proof_unit_id,
                ),
                V32Proposition(
                    proposition_id="p2",
                    text=status.canonical_premise,
                    proof_unit_ref=status.proof_unit_id,
                ),
            ],
            sections=[
                V32Section(
                    section_id="s1",
                    kind=V32SectionKind.DIRECT_ANSWER,
                    proposition_refs=["p1"],
                )
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
    package = analytical_package()
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
    package = analytical_package()
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
    reference = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "REFERENCE_EXPLANATION"
    )
    payload = _draft(
        reference.proof_unit_id,
        "MITRE defines T1112 as Modify Registry.",
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
    reference = next(
        item
        for item in compile_v32_proof_units(package)
        if item.predicate.value == "REFERENCE_EXPLANATION"
    )
    payload = _draft(
        reference.proof_unit_id,
        "MITRE defines T1112 as Modify Registry.",
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
