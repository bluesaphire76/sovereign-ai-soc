from __future__ import annotations

from collections.abc import Sequence
from enum import Enum

from pydantic import Field, model_validator

from services.assistant.v3.contracts import ClosedModel
from services.assistant.v3.semantic_proof.contracts import (
    EntailmentDecision,
    EntailmentLabel,
    EntailmentPair,
    EntailmentProvider,
    EvidenceProofUnit,
)
from services.assistant.v3.semantic_proof.evaluation import SemanticProofEvaluator
from services.assistant.v3.semantic_proof.guards import (
    TypedGuardDecision,
    TypedSemanticGuard,
    eligible_for_deterministic_proof,
)
from services.assistant.v3.semantic_proof.provider import fail_closed_decision


class HybridProofReason(str, Enum):
    ENTAILED = "ENTAILED"
    TYPED_DETERMINISTIC_PROOF = "TYPED_DETERMINISTIC_PROOF"
    TYPED_GUARD_REJECTED = "TYPED_GUARD_REJECTED"
    NOT_ENTAILED = "NOT_ENTAILED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    INVALID_PROVIDER_OUTPUT = "INVALID_PROVIDER_OUTPUT"
    INVALID_PROOF_REFERENCE = "INVALID_PROOF_REFERENCE"


class HybridProofDecision(ClosedModel):
    pair_id: str = Field(min_length=1, max_length=240)
    proof_unit_id: str = Field(min_length=1, max_length=220)
    hypothesis_id: str = Field(min_length=1, max_length=160)
    accepted: bool
    reason: HybridProofReason
    guard_decision: TypedGuardDecision | None = None
    entailment_decision: EntailmentDecision | None = None

    @model_validator(mode="after")
    def validate_decision(self):
        if self.accepted:
            nli_proof = (
                self.reason is HybridProofReason.ENTAILED
                and self.entailment_decision is not None
                and self.entailment_decision.accepted
            )
            deterministic_proof = (
                self.reason is HybridProofReason.TYPED_DETERMINISTIC_PROOF
                and self.entailment_decision is None
            )
            if (
                self.guard_decision is None
                or not self.guard_decision.accepted
                or not (nli_proof or deterministic_proof)
            ):
                raise ValueError(
                    "accepted hybrid proof requires deterministic or NLI proof"
                )
        if self.reason is HybridProofReason.TYPED_GUARD_REJECTED and (
            self.guard_decision is None or self.guard_decision.accepted
        ):
            raise ValueError("typed guard rejection requires a rejected guard decision")
        return self


class HybridProofBatchResult(ClosedModel):
    accepted: bool
    pair_count: int = Field(ge=1)
    typed_guard_reject_count: int = Field(ge=0)
    provider_pair_count: int = Field(ge=0)
    decisions: list[HybridProofDecision] = Field(min_length=1, max_length=512)

    @model_validator(mode="after")
    def validate_batch(self):
        if self.pair_count != len(self.decisions):
            raise ValueError("hybrid proof pair count does not match decisions")
        if self.accepted != all(item.accepted for item in self.decisions):
            raise ValueError("hybrid batch acceptance must cover every pair")
        return self


class HybridSemanticProofEvaluator:
    def __init__(
        self,
        provider: EntailmentProvider,
        *,
        guard: TypedSemanticGuard | None = None,
    ) -> None:
        self._provider = provider
        self._guard = guard or TypedSemanticGuard()

    def evaluate(
        self,
        *,
        proof_units: Sequence[EvidenceProofUnit],
        pairs: Sequence[EntailmentPair],
        batch_size: int = 8,
        evaluate_guard_rejects_for_diagnostics: bool = False,
    ) -> HybridProofBatchResult:
        if not pairs:
            raise ValueError("hybrid semantic proof requires at least one pair")
        units_by_id = {item.proof_unit_id: item for item in proof_units}
        if len(units_by_id) != len(proof_units):
            raise ValueError("hybrid semantic proof requires unique proof unit IDs")

        guards: dict[str, TypedGuardDecision] = {}
        deterministic_pair_ids: set[str] = set()
        invalid_pair_ids: set[str] = set()
        provider_pairs: list[EntailmentPair] = []
        for pair in pairs:
            unit = units_by_id.get(pair.proof_unit_id)
            if unit is None or (
                pair.premise != unit.canonical_premise
                or pair.premise_language != unit.premise_language
            ):
                invalid_pair_ids.add(pair.pair_id)
                continue
            guard = self._guard.evaluate(unit, pair.hypothesis)
            guards[pair.pair_id] = guard
            if guard.accepted and eligible_for_deterministic_proof(
                unit,
                pair.hypothesis,
            ):
                deterministic_pair_ids.add(pair.pair_id)
            elif guard.accepted or evaluate_guard_rejects_for_diagnostics:
                provider_pairs.append(pair)

        provider_decisions = self._provider_decisions(
            provider_pairs,
            batch_size=batch_size,
        )
        by_pair_id = {item.pair_id: item for item in provider_decisions}
        decisions: list[HybridProofDecision] = []
        for pair in pairs:
            if pair.pair_id in invalid_pair_ids:
                decisions.append(
                    HybridProofDecision(
                        pair_id=pair.pair_id,
                        proof_unit_id=pair.proof_unit_id,
                        hypothesis_id=pair.hypothesis_id,
                        accepted=False,
                        reason=HybridProofReason.INVALID_PROOF_REFERENCE,
                    )
                )
                continue
            guard = guards[pair.pair_id]
            nli = by_pair_id.get(pair.pair_id)
            if not guard.accepted:
                decisions.append(
                    HybridProofDecision(
                        pair_id=pair.pair_id,
                        proof_unit_id=pair.proof_unit_id,
                        hypothesis_id=pair.hypothesis_id,
                        accepted=False,
                        reason=HybridProofReason.TYPED_GUARD_REJECTED,
                        guard_decision=guard,
                        entailment_decision=nli,
                    )
                )
                continue
            if pair.pair_id in deterministic_pair_ids:
                decisions.append(
                    HybridProofDecision(
                        pair_id=pair.pair_id,
                        proof_unit_id=pair.proof_unit_id,
                        hypothesis_id=pair.hypothesis_id,
                        accepted=True,
                        reason=HybridProofReason.TYPED_DETERMINISTIC_PROOF,
                        guard_decision=guard,
                    )
                )
                continue
            if nli is None:
                decisions.append(
                    HybridProofDecision(
                        pair_id=pair.pair_id,
                        proof_unit_id=pair.proof_unit_id,
                        hypothesis_id=pair.hypothesis_id,
                        accepted=False,
                        reason=HybridProofReason.INVALID_PROVIDER_OUTPUT,
                        guard_decision=guard,
                    )
                )
                continue
            if nli.accepted:
                reason = HybridProofReason.ENTAILED
            elif nli.label is EntailmentLabel.UNAVAILABLE:
                reason = HybridProofReason.PROVIDER_UNAVAILABLE
            else:
                reason = HybridProofReason.NOT_ENTAILED
            decisions.append(
                HybridProofDecision(
                    pair_id=pair.pair_id,
                    proof_unit_id=pair.proof_unit_id,
                    hypothesis_id=pair.hypothesis_id,
                    accepted=nli.accepted,
                    reason=reason,
                    guard_decision=guard,
                    entailment_decision=nli,
                )
            )

        typed_guard_reject_count = sum(
            item.reason is HybridProofReason.TYPED_GUARD_REJECTED
            for item in decisions
        )
        return HybridProofBatchResult(
            accepted=all(item.accepted for item in decisions),
            pair_count=len(pairs),
            typed_guard_reject_count=typed_guard_reject_count,
            provider_pair_count=len(provider_pairs),
            decisions=decisions,
        )

    def _provider_decisions(
        self,
        pairs: Sequence[EntailmentPair],
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
        if validated is None:
            return ()
        return validated
