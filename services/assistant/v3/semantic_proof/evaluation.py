from __future__ import annotations

import hashlib
from collections.abc import Sequence

from services.assistant.v3.semantic_proof.contracts import (
    EntailmentDecision,
    EntailmentDecisionReason,
    EntailmentLabel,
    EntailmentPair,
    EntailmentProvider,
    EvidenceProofUnit,
    HypothesisFragment,
    SemanticProofResult,
)
from services.assistant.v3.semantic_proof.provider import fail_closed_decision


def _pair_id(proof_unit_id: str, fragment_id: str) -> str:
    material = f"{proof_unit_id}\x1f{fragment_id}"
    return f"pair:{hashlib.sha256(material.encode('utf-8')).hexdigest()[:32]}"


def build_entailment_pairs(
    proof_units: Sequence[EvidenceProofUnit],
    fragments: Sequence[HypothesisFragment],
) -> tuple[EntailmentPair, ...]:
    return tuple(
        EntailmentPair(
            pair_id=_pair_id(proof_unit.proof_unit_id, fragment.fragment_id),
            proof_unit_id=proof_unit.proof_unit_id,
            premise=proof_unit.canonical_premise,
            premise_language=proof_unit.premise_language,
            hypothesis_id=fragment.fragment_id,
            hypothesis=fragment.text,
            hypothesis_language=fragment.language,
        )
        for fragment in fragments
        for proof_unit in proof_units
    )


class SemanticProofEvaluator:
    def __init__(self, provider: EntailmentProvider) -> None:
        self._provider = provider

    def evaluate(
        self,
        *,
        proof_units: Sequence[EvidenceProofUnit],
        fragments: Sequence[HypothesisFragment],
        batch_size: int = 8,
    ) -> SemanticProofResult:
        if not fragments:
            raise ValueError("semantic proof requires at least one hypothesis fragment")
        if not proof_units:
            return SemanticProofResult(
                accepted=False,
                fragment_count=len(fragments),
                reason="no_candidate_evidence",
            )
        pairs = build_entailment_pairs(proof_units, fragments)
        try:
            decisions = tuple(self._provider.evaluate(pairs, batch_size=batch_size))
        except Exception:
            decisions = tuple(fail_closed_decision(pair) for pair in pairs)

        validated = self._validated_decisions(pairs, decisions)
        if validated is None:
            invalid = tuple(
                fail_closed_decision(
                    pair,
                    reason=EntailmentDecisionReason.INVALID_PROVIDER_OUTPUT,
                )
                for pair in pairs
            )
            return SemanticProofResult(
                accepted=False,
                fragment_count=len(fragments),
                decisions=list(invalid),
                reason="invalid_provider_output",
            )
        if any(item.label is EntailmentLabel.UNAVAILABLE for item in validated):
            return SemanticProofResult(
                accepted=False,
                fragment_count=len(fragments),
                decisions=list(validated),
                reason="provider_unavailable",
            )

        supported: list[str] = []
        matched: list[str] = []
        for fragment in fragments:
            accepted = [
                item
                for item in validated
                if item.hypothesis_id == fragment.fragment_id and item.accepted
            ]
            if not accepted:
                continue
            supported.append(fragment.fragment_id)
            matched.extend(item.proof_unit_id for item in accepted)
        all_supported = len(supported) == len(fragments)
        return SemanticProofResult(
            accepted=all_supported,
            fragment_count=len(fragments),
            supported_fragment_ids=supported,
            matched_proof_unit_ids=list(dict.fromkeys(matched)),
            decisions=list(validated),
            reason=(
                "all_fragments_entailed" if all_supported else "fragment_not_entailed"
            ),
        )

    @staticmethod
    def _validated_decisions(
        pairs: Sequence[EntailmentPair],
        decisions: Sequence[EntailmentDecision],
    ) -> tuple[EntailmentDecision, ...] | None:
        expected = {item.pair_id: item for item in pairs}
        if len(decisions) != len(expected):
            return None
        by_id = {item.pair_id: item for item in decisions}
        if len(by_id) != len(decisions) or set(by_id) != set(expected):
            return None
        for pair_id, decision in by_id.items():
            pair = expected[pair_id]
            if (
                decision.proof_unit_id != pair.proof_unit_id
                or decision.hypothesis_id != pair.hypothesis_id
            ):
                return None
        return tuple(by_id[pair.pair_id] for pair in pairs)
