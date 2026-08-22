from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from services.assistant.v3.conversational_schema import (
    conversational_model_facing_evidence,
)
from services.assistant.v3.contracts import V3AnalyticalContextPackage
from services.assistant.v3.discourse import (
    RenderedV3Answer,
    RenderedV3Block,
)
from services.assistant.v3.plan_contracts import AnswerSectionType
from services.assistant.v3.semantic_proof.compiler import EvidenceProofUnitCompiler
from services.assistant.v3.semantic_proof.contracts import (
    EntailmentPair,
    EntailmentProvider,
    EvidenceProofUnit,
)
from services.assistant.v3.semantic_proof.hybrid import (
    HybridProofBatchResult,
    HybridSemanticProofEvaluator,
)
from services.assistant.v3.semantic_proof.response_contracts import (
    MAX_V32_PROPOSITIONS,
    MAX_V32_PROPOSITIONS_PER_SECTION,
    MAX_V32_SECTIONS,
    GroundedResponseDraftV32,
    V32SectionKind,
)


@dataclass(frozen=True)
class V32PromptBuildResult:
    messages: list[dict[str, str]]
    context_chars: int


@dataclass(frozen=True)
class V32ValidationResult:
    accepted: bool
    reason: str | None
    proof_result: HybridProofBatchResult | None
    proof_ms: int


_SECTION_TYPES = {
    V32SectionKind.DIRECT_ANSWER: AnswerSectionType.DIRECT_ANSWER,
    V32SectionKind.ANALYSIS: AnswerSectionType.TIMELINE,
    V32SectionKind.EVIDENCE: AnswerSectionType.EVIDENCE,
    V32SectionKind.COMPARISON: AnswerSectionType.COMPARISON,
    V32SectionKind.CONCLUSION: AnswerSectionType.WHAT_WE_CAN_CONCLUDE,
    V32SectionKind.UNCERTAINTY: AnswerSectionType.WHAT_WE_CANNOT_CONCLUDE,
    V32SectionKind.NEXT_STEP: AnswerSectionType.NEXT_STEPS,
    V32SectionKind.EXECUTIVE_SUMMARY: AnswerSectionType.KEY_FINDINGS,
}


def compile_v32_proof_units(
    package: V3AnalyticalContextPackage,
) -> tuple[EvidenceProofUnit, ...]:
    view = conversational_model_facing_evidence(package)
    visible_refs = {
        *[item.atom_id for item in view.operational_atoms],
        *[item.relationship_id for item in view.relationships],
        *[item.candidate_id for item in view.candidates],
        *[item.knowledge_id for item in view.reference_atoms],
        *[item.knowledge_id for item in view.advisory_atoms],
    }
    compiled = EvidenceProofUnitCompiler().compile(
        package,
        premise_languages=(package.response_language,),
    )
    return tuple(
        item
        for item in compiled
        if item.source_refs and item.source_refs[0] in visible_refs
    )


def grounded_response_v32_schema(
    proof_units: tuple[EvidenceProofUnit, ...],
) -> dict[str, Any]:
    proof_unit_ids = [item.proof_unit_id for item in proof_units]
    if not proof_unit_ids:
        raise ValueError("V3.2 response schema requires proof units")
    proposition_ids = [f"p{index}" for index in range(1, MAX_V32_PROPOSITIONS + 1)]
    section_ids = [f"s{index}" for index in range(1, MAX_V32_SECTIONS + 1)]
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["response_language", "propositions", "sections"],
        "properties": {
            "response_language": {"type": "string", "enum": ["it", "en"]},
            "propositions": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_V32_PROPOSITIONS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["proposition_id", "text", "proof_unit_ref"],
                    "properties": {
                        "proposition_id": {
                            "type": "string",
                            "enum": proposition_ids,
                        },
                        "text": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 600,
                        },
                        "proof_unit_ref": {
                            "type": "string",
                            "enum": proof_unit_ids,
                        },
                    },
                },
            },
            "sections": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_V32_SECTIONS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["section_id", "kind", "proposition_refs"],
                    "properties": {
                        "section_id": {"type": "string", "enum": section_ids},
                        "kind": {
                            "type": "string",
                            "enum": [item.value for item in V32SectionKind],
                        },
                        "proposition_refs": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": MAX_V32_PROPOSITIONS_PER_SECTION,
                            "uniqueItems": True,
                            "items": {"type": "string", "enum": proposition_ids},
                        },
                    },
                },
            },
        },
    }


def build_v32_messages(
    package: V3AnalyticalContextPackage,
    proof_units: tuple[EvidenceProofUnit, ...],
    *,
    max_context_chars: int,
) -> V32PromptBuildResult:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in proof_units:
        grouped.setdefault(item.authority_class.value, []).append(
            {
                "proof_unit_id": item.proof_unit_id,
                "evidence_kind": item.evidence_kind.value,
                "predicate": item.predicate.value,
                "scope": item.scope.model_dump(mode="json"),
                "premise": item.canonical_premise,
                "allowed_semantic_role": item.allowed_semantic_role.value,
            }
        )
    context = {
        "question": package.question,
        "response_language": package.response_language,
        "answer_intent": package.intent_selection.primary_intent.value,
        "evidence_by_authority": grouped,
        "writing_contract": {
            "answer_directly": True,
            "natural_analyst_prose": True,
            "one_atomic_factual_proposition_per_sentence": True,
            "one_proof_unit_ref_per_proposition": True,
            "no_visible_text_outside_propositions": True,
            "preserve_exact_entity_numeric_boolean_and_relationship_values": True,
            "do_not_add_cause_intent_maliciousness_compromise_impact_or_urgency": True,
            "do_not_promote_authority": True,
            "do_not_write_citations_or_provenance": True,
            "use_only_the_semantic_meaning_of_the_selected_proof_unit": True,
        },
    }
    serialized = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
    if len(serialized) > max_context_chars:
        raise ValueError("V3.2 proof context exceeds the configured context budget")
    system = (
        "You are the writing component of a grounded SOC assistant. Write a useful, "
        "natural answer, but express every material factual statement as one atomic "
        "proposition backed by exactly one supplied proof unit. Preserve its exact "
        "scope, value, authority and semantic role. Never add an interpretation, "
        "causal link, security conclusion, recommendation or relationship not stated "
        "by that proof unit. The proof system, not you, decides publication and "
        "attribution. Return only the required structured object."
    )
    return V32PromptBuildResult(
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": serialized},
        ],
        context_chars=len(serialized),
    )


def parse_grounded_response_v32(value: Any) -> GroundedResponseDraftV32 | None:
    payload = value
    if isinstance(value, GroundedResponseDraftV32):
        return value
    if isinstance(value, str):
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(payload, dict):
        return None
    try:
        return GroundedResponseDraftV32.model_validate(payload)
    except ValidationError:
        return None


def _contains_multiple_sentences(value: str) -> bool:
    stripped = value.strip()
    for index, character in enumerate(stripped[:-1]):
        if character not in {".", "!", "?", ";", "\n"}:
            continue
        if character == "." and index > 0 and stripped[index - 1].isalnum():
            next_character = stripped[index + 1]
            if next_character.isalnum():
                continue
        if character in {";", "\n"} or stripped[index + 1].isspace():
            return True
    return False


class GroundedResponseV32Validator:
    def __init__(self, provider: EntailmentProvider) -> None:
        self._provider = provider

    def validate(
        self,
        draft: GroundedResponseDraftV32,
        *,
        package: V3AnalyticalContextPackage,
        proof_units: tuple[EvidenceProofUnit, ...],
        batch_size: int = 8,
    ) -> V32ValidationResult:
        started = time.perf_counter()
        if draft.response_language != package.response_language:
            return self._rejected("response_language_mismatch", started)
        if any(_contains_multiple_sentences(item.text) for item in draft.propositions):
            return self._rejected("compound_or_multiple_proposition", started)
        proof_refs = [item.proof_unit_ref for item in draft.propositions]
        if len(proof_refs) != len(set(proof_refs)):
            return self._rejected("duplicate_proof_unit_ref", started)

        units_by_id = {item.proof_unit_id: item for item in proof_units}
        if not set(proof_refs).issubset(units_by_id):
            return self._rejected("unknown_proof_unit_ref", started)
        pairs = [
            EntailmentPair(
                pair_id=f"v32:{item.proposition_id}",
                proof_unit_id=item.proof_unit_ref,
                premise=units_by_id[item.proof_unit_ref].canonical_premise,
                premise_language=units_by_id[item.proof_unit_ref].premise_language,
                hypothesis_id=item.proposition_id,
                hypothesis=item.text,
                hypothesis_language=draft.response_language,
            )
            for item in draft.propositions
        ]
        result = HybridSemanticProofEvaluator(self._provider).evaluate(
            proof_units=proof_units,
            pairs=pairs,
            batch_size=batch_size,
        )
        return V32ValidationResult(
            accepted=result.accepted,
            reason=None if result.accepted else "semantic_proof_failed",
            proof_result=result,
            proof_ms=max(0, int((time.perf_counter() - started) * 1000)),
        )

    @staticmethod
    def _rejected(reason: str, started: float) -> V32ValidationResult:
        return V32ValidationResult(
            accepted=False,
            reason=reason,
            proof_result=None,
            proof_ms=max(0, int((time.perf_counter() - started) * 1000)),
        )


def render_grounded_response_v32(
    draft: GroundedResponseDraftV32,
    *,
    proof_units: tuple[EvidenceProofUnit, ...],
) -> RenderedV3Answer:
    propositions = {item.proposition_id: item for item in draft.propositions}
    units_by_id = {item.proof_unit_id: item for item in proof_units}
    blocks: list[RenderedV3Block] = []
    for section in draft.sections:
        selected = [propositions[item] for item in section.proposition_refs]
        blocks.append(
            RenderedV3Block(
                section_type=_SECTION_TYPES[section.kind],
                text=" ".join(item.text for item in selected),
                source_refs=tuple(
                    dict.fromkeys(
                        source_ref
                        for proposition in selected
                        for source_ref in units_by_id[
                            proposition.proof_unit_ref
                        ].source_refs
                    )
                ),
            )
        )
    return RenderedV3Answer(blocks=tuple(blocks), render_ms=0.0)
