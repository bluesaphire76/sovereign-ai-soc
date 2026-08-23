from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from services.assistant.v3.conversational_schema import (
    conversational_model_facing_evidence,
)
from services.assistant.v3.contracts import (
    AnalysisScope,
    AnswerIntent,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.discourse import (
    RenderedV3Answer,
    RenderedV3Block,
)
from services.assistant.v3.plan_contracts import AnswerSectionType
from services.assistant.v3.semantic_proof.compiler import EvidenceProofUnitCompiler
from services.assistant.v3.semantic_proof.contracts import (
    EntailmentDecision,
    EntailmentLabel,
    EntailmentPair,
    EntailmentProvider,
    EvidenceKind,
    EvidenceProofUnit,
    ProofPredicate,
)
from services.assistant.v3.semantic_proof.evaluation import SemanticProofEvaluator
from services.assistant.v3.semantic_proof.guards import TypedSemanticGuard
from services.assistant.v3.semantic_proof.hybrid import (
    HybridProofBatchResult,
    HybridProofDecision,
    HybridProofReason,
    HybridSemanticProofEvaluator,
)
from services.assistant.v3.semantic_proof.provider import fail_closed_decision
from services.assistant.v3.semantic_proof.response_contracts import (
    MAX_V32_PROPOSITIONS,
    MAX_V32_PROPOSITION_CHARS,
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
    visible_operational_refs = {item.atom_id for item in view.operational_atoms}
    if (
        package.intent_selection.primary_intent is AnswerIntent.COMPARE
        and view.relationships
    ):
        visible_operational_refs &= {
            ref
            for relationship in view.relationships
            for ref in relationship.evidence_atom_refs
        }
    visible_refs = {
        *visible_operational_refs,
        *[item.relationship_id for item in view.relationships],
        *[item.candidate_id for item in view.candidates],
        *[item.knowledge_id for item in view.reference_atoms],
        *[item.knowledge_id for item in view.advisory_atoms],
    }
    compiled = EvidenceProofUnitCompiler().compile(
        package,
        premise_languages=(package.response_language,),
    )
    visible = tuple(
        item
        for item in compiled
        if (
            not item.source_refs
            and item.predicate is ProofPredicate.CONTEXT_LIMITATION
        )
        or (item.source_refs and set(item.source_refs).issubset(visible_refs))
    )
    synthesis_refs = {
        source_ref
        for item in visible
        if item.evidence_kind is EvidenceKind.TYPED_SYNTHESIS
        for source_ref in item.source_refs
    }
    selected = tuple(
        item
        for item in visible
        if item.evidence_kind is EvidenceKind.TYPED_SYNTHESIS
        or item.predicate
        not in {ProofPredicate.MITRE_TECHNIQUE, ProofPredicate.REFERENCE_EXPLANATION}
        or item.source_refs[0] not in synthesis_refs
    )
    intent = package.intent_selection.primary_intent
    analytical_kinds = {
        EvidenceKind.ANALYTICAL_COUNT,
        EvidenceKind.ANALYTICAL_DISTRIBUTION,
        EvidenceKind.ANALYTICAL_TREND,
        EvidenceKind.ANALYTICAL_COMPARISON,
        EvidenceKind.ANALYTICAL_TOP_K,
        EvidenceKind.ANALYTICAL_RESULT_SET,
    }

    def priority(item: EvidenceProofUnit) -> int:
        if (
            package.resolved_scope.analysis_scope is AnalysisScope.GLOBAL
            and item.evidence_kind in analytical_kinds
        ):
            return 0
        if intent is AnswerIntent.NEXT_ACTION:
            if item.evidence_kind is EvidenceKind.ADVISORY_KNOWLEDGE:
                return 0
            if item.predicate is ProofPredicate.CONTEXT_LIMITATION:
                return 0
            if item.evidence_kind is EvidenceKind.ANALYTICAL_BOUNDARY:
                return 1
        if intent in {
            AnswerIntent.COMPARE,
            AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        }:
            if item.evidence_kind in {
                EvidenceKind.RECORDED_CORRELATION,
                EvidenceKind.ANALYTICAL_RELATIONSHIP,
                EvidenceKind.SEMANTIC_CANDIDATE,
            }:
                return 0
            if item.evidence_kind is EvidenceKind.ANALYTICAL_BOUNDARY:
                return 1
        return 2

    return tuple(sorted(selected, key=priority))


def grounded_response_v32_schema(
    proof_units: tuple[EvidenceProofUnit, ...],
) -> dict[str, Any]:
    proof_unit_ids = [item.proof_unit_id for item in proof_units]
    if not proof_unit_ids:
        raise ValueError("V3.2 response schema requires proof units")
    proposition_ids = [f"p{index}" for index in range(1, MAX_V32_PROPOSITIONS + 1)]
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["response_language", "propositions"],
        "properties": {
            "response_language": {"type": "string", "enum": ["it", "en"]},
            "propositions": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_V32_PROPOSITIONS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "proposition_id",
                        "text",
                        "proof_unit_refs",
                        "section_kind",
                    ],
                    "properties": {
                        "proposition_id": {
                            "type": "string",
                            "enum": proposition_ids,
                        },
                        "text": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_V32_PROPOSITION_CHARS,
                        },
                        "proof_unit_refs": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 4,
                            "uniqueItems": True,
                            "items": {
                                "type": "string",
                                "enum": proof_unit_ids,
                            },
                        },
                        "section_kind": {
                            "type": "string",
                            "enum": [item.value for item in V32SectionKind],
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
    intent_contract: dict[str, Any] = {
        "use_section_kind_for_each_proposition_rhetorical_purpose": True,
    }
    intent = package.intent_selection.primary_intent
    analytical_kinds = {
        EvidenceKind.ANALYTICAL_COUNT,
        EvidenceKind.ANALYTICAL_DISTRIBUTION,
        EvidenceKind.ANALYTICAL_TREND,
        EvidenceKind.ANALYTICAL_COMPARISON,
        EvidenceKind.ANALYTICAL_TOP_K,
        EvidenceKind.ANALYTICAL_RESULT_SET,
    }
    if package.resolved_scope.analysis_scope is AnalysisScope.GLOBAL:
        intent_contract.update(
            {
                "must_answer_from_a_typed_analytical_result": True,
                "required_analytical_proof_unit_ids": [
                    item.proof_unit_id
                    for item in proof_units
                    if item.evidence_kind in analytical_kinds
                ],
                "must_state_the_resolved_absolute_window_when_relevant": True,
                "must_not_describe_analytical_derivations_as_raw_recorded_facts": True,
            }
        )
    if intent is AnswerIntent.NEXT_ACTION:
        next_action_refs = [
            item.proof_unit_id
            for item in proof_units
            if item.evidence_kind is EvidenceKind.ADVISORY_KNOWLEDGE
            or item.predicate is ProofPredicate.CONTEXT_LIMITATION
        ]
        intent_contract.update(
            {
                "must_address_next_checks": True,
                "when_advisory_exists_use_advisory_guidance_in_next_step": True,
                "when_advisory_is_unavailable_use_context_limitation_and_do_not_invent_checks": True,
                "required_next_action_proof_unit_ids": next_action_refs,
                "required_section_kinds": [
                    V32SectionKind.NEXT_STEP.value,
                    V32SectionKind.UNCERTAINTY.value,
                ],
            }
        )
    elif intent is AnswerIntent.CROSS_INCIDENT_ANALYSIS:
        relationship_refs = [
            item.proof_unit_id
            for item in proof_units
            if item.evidence_kind
            in {
                EvidenceKind.RECORDED_CORRELATION,
                EvidenceKind.ANALYTICAL_RELATIONSHIP,
                EvidenceKind.SEMANTIC_CANDIDATE,
            }
        ]
        boundary_refs = [
            item.proof_unit_id
            for item in proof_units
            if item.predicate is ProofPredicate.NON_IMPLICATION
        ]
        intent_contract.update(
            {
                "must_identify_a_supported_relationship_or_candidate": True,
                "must_include_an_uncertainty_boundary_for_analytical_or_semantic_relationships": True,
                "required_relationship_proof_unit_ids": relationship_refs,
                "required_boundary_proof_unit_ids": boundary_refs,
            }
        )
    elif intent is AnswerIntent.COMPARE:
        comparison_refs = [
            item.proof_unit_id
            for item in proof_units
            if item.evidence_kind
            in {
                EvidenceKind.RECORDED_CORRELATION,
                EvidenceKind.ANALYTICAL_RELATIONSHIP,
                EvidenceKind.ANALYTICAL_COMPARISON,
            }
        ]
        intent_contract.update(
            {
                "must_compare_a_non_anchor_incident_using_relationship_evidence": True,
                "do_not_rank_the_anchor_incident_as_its_own_comparison_target": True,
                "required_comparison_proof_unit_ids": comparison_refs,
                "required_section_kinds": [V32SectionKind.COMPARISON.value],
            }
        )
    elif intent is AnswerIntent.EXECUTIVE_SUMMARY:
        intent_contract["use_executive_summary_section"] = True

    context = {
        "question": package.question,
        "response_language": package.response_language,
        "answer_intent": package.intent_selection.primary_intent.value,
        "evidence_by_authority": grouped,
        "intent_contract": intent_contract,
        "writing_contract": {
            "answer_directly": True,
            "natural_analyst_prose": True,
            "select_only_the_strongest_question_relevant_evidence": True,
            "target_two_to_six_short_propositions_when_evidence_allows": True,
            "maximum_words_per_proposition": 30,
            "one_atomic_factual_proposition_per_sentence": True,
            "one_to_four_proof_unit_refs_per_proposition": True,
            "every_fact_and_value_must_be_covered_by_the_selected_proof_units": True,
            "use_an_aggregate_proof_unit_for_multiple_values_from_one_typed_record": True,
            "never_infer_missing_or_absent_information_from_the_evidence_list": True,
            "no_visible_text_outside_propositions": True,
            "preserve_exact_entity_numeric_boolean_and_relationship_values": True,
            "do_not_add_cause_intent_maliciousness_compromise_impact_or_urgency": True,
            "do_not_promote_authority": True,
            "do_not_write_citations_or_provenance": True,
            "use_only_the_semantic_meaning_of_the_selected_proof_unit": True,
            "use_uncertainty_boundaries_when_the_question_asks_what_is_not_proven": True,
            "describe_sql_aggregates_as_analytical_results_not_raw_recorded_facts": True,
        },
    }
    serialized = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
    if len(serialized) > max_context_chars:
        raise ValueError("V3.2 proof context exceeds the configured context budget")
    system = (
        "You are the writing component of a grounded SOC assistant. Write a useful, "
        "natural and concise answer. Select only the strongest evidence relevant to "
        "the question; do not enumerate every available proof unit. Prefer two to "
        "six short propositions and keep each under 30 words. Express every material "
        "factual statement as one proposition backed by one to four supplied proof "
        "units. Select every proof unit whose fact or value appears in the sentence. "
        "Multiple values may share one sentence only when the selected proof units "
        "jointly contain all of them. Keep unrelated facts in separate propositions. "
        "The answer is invalid unless the intent_contract is satisfied before any "
        "optional supporting evidence is added. Use one of its required proof-unit "
        "IDs and required section kinds exactly as directed. "
        "Never "
        "infer that information is absent "
        "or unavailable merely because it is not listed. Preserve each unit's exact "
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
        units_by_id = {item.proof_unit_id: item for item in proof_units}
        proof_refs = {
            proof_ref
            for item in draft.propositions
            for proof_ref in item.proof_unit_refs
        }
        if not proof_refs.issubset(units_by_id):
            return self._rejected("unknown_proof_unit_ref", started)
        intent_reason = self._intent_contract_reason(
            draft,
            package=package,
            units_by_id=units_by_id,
        )
        if intent_reason is not None:
            return self._rejected(intent_reason, started)

        single_pairs: list[EntailmentPair] = []
        combined: list[
            tuple[Any, EntailmentPair, Any]
        ] = []
        combined_guard = TypedSemanticGuard()
        for item in draft.propositions:
            selected = [units_by_id[proof_ref] for proof_ref in item.proof_unit_refs]
            if len(selected) == 1:
                unit = selected[0]
                single_pairs.append(
                    EntailmentPair(
                        pair_id=f"v32:{item.proposition_id}",
                        proof_unit_id=unit.proof_unit_id,
                        premise=unit.canonical_premise,
                        premise_language=unit.premise_language,
                        hypothesis_id=item.proposition_id,
                        hypothesis=item.text,
                        hypothesis_language=draft.response_language,
                    )
                )
                continue
            guard = combined_guard.evaluate_combined(selected, item.text)
            premise_language = (
                draft.response_language
                if all(
                    unit.premise_language == draft.response_language
                    for unit in selected
                )
                else "und"
            )
            combined.append(
                (
                    item,
                    EntailmentPair(
                        pair_id=f"v32:{item.proposition_id}",
                        proof_unit_id=guard.proof_unit_id,
                        premise=" ".join(unit.canonical_premise for unit in selected),
                        premise_language=premise_language,
                        hypothesis_id=item.proposition_id,
                        hypothesis=item.text,
                        hypothesis_language=draft.response_language,
                    ),
                    guard,
                )
            )

        decisions_by_hypothesis: dict[str, HybridProofDecision] = {}
        provider_pair_count = 0
        if single_pairs:
            single_result = HybridSemanticProofEvaluator(self._provider).evaluate(
                proof_units=proof_units,
                pairs=single_pairs,
                batch_size=batch_size,
            )
            provider_pair_count += single_result.provider_pair_count
            decisions_by_hypothesis.update(
                (decision.hypothesis_id, decision)
                for decision in single_result.decisions
            )

        composite_provider_pairs = [
            pair for _item, pair, guard in combined if guard.accepted
        ]
        provider_pair_count += len(composite_provider_pairs)
        provider_decisions = self._provider_decisions(
            composite_provider_pairs,
            batch_size=batch_size,
        )
        provider_by_pair = {item.pair_id: item for item in provider_decisions}
        for item, pair, guard in combined:
            if not guard.accepted:
                decision = HybridProofDecision(
                    pair_id=pair.pair_id,
                    proof_unit_id=pair.proof_unit_id,
                    hypothesis_id=item.proposition_id,
                    accepted=False,
                    reason=HybridProofReason.TYPED_GUARD_REJECTED,
                    guard_decision=guard,
                )
            else:
                entailment = provider_by_pair.get(pair.pair_id)
                if entailment is None:
                    reason = HybridProofReason.INVALID_PROVIDER_OUTPUT
                elif entailment.accepted:
                    reason = HybridProofReason.ENTAILED
                elif entailment.label is EntailmentLabel.UNAVAILABLE:
                    reason = HybridProofReason.PROVIDER_UNAVAILABLE
                else:
                    reason = HybridProofReason.NOT_ENTAILED
                decision = HybridProofDecision(
                    pair_id=pair.pair_id,
                    proof_unit_id=pair.proof_unit_id,
                    hypothesis_id=item.proposition_id,
                    accepted=bool(entailment and entailment.accepted),
                    reason=reason,
                    guard_decision=guard,
                    entailment_decision=entailment,
                )
            decisions_by_hypothesis[item.proposition_id] = decision

        ordered_decisions = [
            decisions_by_hypothesis[item.proposition_id]
            for item in draft.propositions
        ]
        result = HybridProofBatchResult(
            accepted=all(item.accepted for item in ordered_decisions),
            pair_count=len(ordered_decisions),
            typed_guard_reject_count=sum(
                item.reason is HybridProofReason.TYPED_GUARD_REJECTED
                for item in ordered_decisions
            ),
            provider_pair_count=provider_pair_count,
            decisions=ordered_decisions,
        )
        return V32ValidationResult(
            accepted=result.accepted,
            reason=None if result.accepted else "semantic_proof_failed",
            proof_result=result,
            proof_ms=max(0, int((time.perf_counter() - started) * 1000)),
        )

    @staticmethod
    def _intent_contract_reason(
        draft: GroundedResponseDraftV32,
        *,
        package: V3AnalyticalContextPackage,
        units_by_id: dict[str, EvidenceProofUnit],
    ) -> str | None:
        selected = [
            units_by_id[proof_ref]
            for proposition in draft.propositions
            for proof_ref in proposition.proof_unit_refs
        ]
        sections = {item.section_kind for item in draft.propositions}
        intent = package.intent_selection.primary_intent
        analytical_kinds = {
            EvidenceKind.ANALYTICAL_COUNT,
            EvidenceKind.ANALYTICAL_DISTRIBUTION,
            EvidenceKind.ANALYTICAL_TREND,
            EvidenceKind.ANALYTICAL_COMPARISON,
            EvidenceKind.ANALYTICAL_TOP_K,
            EvidenceKind.ANALYTICAL_RESULT_SET,
        }
        if (
            package.resolved_scope.analysis_scope is AnalysisScope.GLOBAL
            and not any(item.evidence_kind in analytical_kinds for item in selected)
        ):
            return "global_analytics_contract_mismatch"
        if intent is AnswerIntent.NEXT_ACTION:
            if package.advisory_atoms:
                valid_evidence = any(
                    item.evidence_kind is EvidenceKind.ADVISORY_KNOWLEDGE
                    for item in selected
                )
            else:
                valid_evidence = any(
                    item.predicate is ProofPredicate.CONTEXT_LIMITATION
                    for item in selected
                )
            if not valid_evidence or not sections.intersection(
                {V32SectionKind.NEXT_STEP, V32SectionKind.UNCERTAINTY}
            ):
                return "next_action_contract_mismatch"
        elif intent is AnswerIntent.CROSS_INCIDENT_ANALYSIS:
            relationship_kinds = {
                EvidenceKind.RECORDED_CORRELATION,
                EvidenceKind.ANALYTICAL_RELATIONSHIP,
                EvidenceKind.SEMANTIC_CANDIDATE,
            }
            if not any(item.evidence_kind in relationship_kinds for item in selected):
                return "cross_incident_contract_mismatch"
            if any(
                item.evidence_kind
                in {
                    EvidenceKind.ANALYTICAL_RELATIONSHIP,
                    EvidenceKind.SEMANTIC_CANDIDATE,
                }
                for item in selected
            ) and not any(
                item.predicate is ProofPredicate.NON_IMPLICATION
                for item in selected
            ):
                return "cross_incident_boundary_missing"
        elif intent is AnswerIntent.COMPARE:
            if not any(
                item.evidence_kind
                in {
                    EvidenceKind.RECORDED_CORRELATION,
                    EvidenceKind.ANALYTICAL_RELATIONSHIP,
                    EvidenceKind.ANALYTICAL_COMPARISON,
                }
                for item in selected
            ):
                return "comparison_contract_mismatch"
        elif (
            intent is AnswerIntent.EXECUTIVE_SUMMARY
            and V32SectionKind.EXECUTIVE_SUMMARY not in sections
        ):
            return "executive_summary_contract_mismatch"
        return None

    def _provider_decisions(
        self,
        pairs: list[EntailmentPair],
        *,
        batch_size: int,
    ) -> tuple[EntailmentDecision, ...]:
        if not pairs:
            return ()
        try:
            decisions = tuple(self._provider.evaluate(pairs, batch_size=batch_size))
        except Exception:
            return tuple(fail_closed_decision(pair) for pair in pairs)
        validated = SemanticProofEvaluator._validated_decisions(pairs, decisions)
        return () if validated is None else validated

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
    units_by_id = {item.proof_unit_id: item for item in proof_units}
    grouped: dict[V32SectionKind, list[Any]] = {}
    for proposition in draft.propositions:
        grouped.setdefault(proposition.section_kind, []).append(proposition)
    blocks: list[RenderedV3Block] = []
    for section_kind, selected in grouped.items():
        blocks.append(
            RenderedV3Block(
                section_type=_SECTION_TYPES[section_kind],
                text=" ".join(item.text for item in selected),
                source_refs=tuple(
                    dict.fromkeys(
                        source_ref
                        for proposition in selected
                        for proof_ref in proposition.proof_unit_refs
                        for source_ref in units_by_id[proof_ref].source_refs
                    )
                ),
            )
        )
    return RenderedV3Answer(blocks=tuple(blocks), render_ms=0.0)
