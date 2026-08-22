from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from services.assistant.v3.semantic_proof.contracts import (
    EntailmentDecision,
    EntailmentDecisionReason,
    EntailmentLabel,
    EntailmentPair,
    EntailmentProviderInfo,
)


_NORMALIZED_LABELS = {
    "ENTAIL": EntailmentLabel.ENTAILMENT,
    "ENTAILED": EntailmentLabel.ENTAILMENT,
    "ENTAILMENT": EntailmentLabel.ENTAILMENT,
    "NEUTRAL": EntailmentLabel.NEUTRAL,
    "CONTRADICT": EntailmentLabel.CONTRADICTION,
    "CONTRADICTS": EntailmentLabel.CONTRADICTION,
    "CONTRADICTION": EntailmentLabel.CONTRADICTION,
}


def normalize_entailment_label(value: Any) -> EntailmentLabel | None:
    normalized = "_".join(str(value or "").strip().upper().replace("-", " ").split())
    return _NORMALIZED_LABELS.get(normalized)


def fail_closed_decision(
    pair: EntailmentPair,
    *,
    reason: EntailmentDecisionReason = EntailmentDecisionReason.PROVIDER_UNAVAILABLE,
) -> EntailmentDecision:
    return EntailmentDecision(
        pair_id=pair.pair_id,
        proof_unit_id=pair.proof_unit_id,
        hypothesis_id=pair.hypothesis_id,
        label=EntailmentLabel.UNAVAILABLE,
        accepted=False,
        reason=reason,
    )


class TransformersNliProvider:
    """Replaceable GPU-only NLI provider used only by the offline proof lab."""

    def __init__(
        self,
        *,
        model: str,
        device: str = "cuda:0",
        precision: str = "float32",
        quantization: str = "none",
        entailment_threshold: float,
        local_files_only: bool = True,
        max_length: int = 512,
    ) -> None:
        if not 0.0 < entailment_threshold <= 1.0:
            raise ValueError("entailment threshold must be in (0, 1]")
        if not device.startswith("cuda"):
            raise ValueError("semantic proof benchmark provider is GPU-only")
        if precision not in {"float32", "float16", "bfloat16"}:
            raise ValueError("unsupported benchmark precision")
        if quantization != "none":
            raise ValueError("quantized NLI loading is not implemented in Phase 0")

        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("transformers NLI dependencies are unavailable") from exc
        if not torch.cuda.is_available():
            raise RuntimeError("CUDA is unavailable for the GPU-only NLI provider")

        dtype = {
            "float32": torch.float32,
            "float16": torch.float16,
            "bfloat16": torch.bfloat16,
        }[precision]
        self._torch = torch
        self._device = device
        self._threshold = entailment_threshold
        self._max_length = max(32, min(int(max_length), 2048))
        self._tokenizer = AutoTokenizer.from_pretrained(
            model,
            local_files_only=local_files_only,
        )
        self._model = AutoModelForSequenceClassification.from_pretrained(
            model,
            local_files_only=local_files_only,
            torch_dtype=dtype,
        )
        self._label_by_index = self._validated_label_map(self._model.config.id2label)
        self._model.to(device)
        self._model.eval()
        torch.cuda.synchronize(device)
        self._info = EntailmentProviderInfo(
            backend="transformers_sequence_classification",
            model=model,
            precision=precision,
            quantization=quantization,
            device=device,
        )

    @staticmethod
    def _validated_label_map(id2label: Mapping[Any, Any]) -> dict[int, EntailmentLabel]:
        result: dict[int, EntailmentLabel] = {}
        for raw_index, raw_label in id2label.items():
            try:
                index = int(raw_index)
            except (TypeError, ValueError) as exc:
                raise ValueError("NLI provider exposes an invalid label index") from exc
            label = normalize_entailment_label(raw_label)
            if label is None:
                raise ValueError(f"NLI provider exposes unknown label {raw_label!r}")
            result[index] = label
        if set(result.values()) != {
            EntailmentLabel.ENTAILMENT,
            EntailmentLabel.NEUTRAL,
            EntailmentLabel.CONTRADICTION,
        }:
            raise ValueError("NLI provider must expose entailment, neutral and contradiction")
        if len(result) != 3:
            raise ValueError("NLI provider must expose exactly three unique labels")
        return result

    @property
    def info(self) -> EntailmentProviderInfo:
        return self._info

    def evaluate(
        self,
        pairs: Sequence[EntailmentPair],
        *,
        batch_size: int,
    ) -> Sequence[EntailmentDecision]:
        if batch_size <= 0:
            raise ValueError("batch size must be positive")
        if not pairs:
            return ()
        decisions: list[EntailmentDecision] = []
        try:
            for offset in range(0, len(pairs), batch_size):
                batch = pairs[offset : offset + batch_size]
                encoded = self._tokenizer(
                    [item.premise for item in batch],
                    [item.hypothesis for item in batch],
                    padding=True,
                    truncation=True,
                    max_length=self._max_length,
                    return_tensors="pt",
                )
                encoded = {
                    key: value.to(self._device) for key, value in encoded.items()
                }
                with self._torch.inference_mode():
                    logits = self._model(**encoded).logits
                    probabilities = self._torch.softmax(logits.float(), dim=-1)
                for pair, row in zip(batch, probabilities.detach().cpu().tolist()):
                    scores = {
                        self._label_by_index[index]: float(score)
                        for index, score in enumerate(row)
                    }
                    selected = max(scores, key=scores.get)
                    accepted = (
                        selected is EntailmentLabel.ENTAILMENT
                        and scores[EntailmentLabel.ENTAILMENT] >= self._threshold
                    )
                    reason = (
                        EntailmentDecisionReason.ENTAILED
                        if accepted
                        else EntailmentDecisionReason.LOW_CONFIDENCE
                        if selected is EntailmentLabel.ENTAILMENT
                        else EntailmentDecisionReason.NOT_ENTAILED
                    )
                    decisions.append(
                        EntailmentDecision(
                            pair_id=pair.pair_id,
                            proof_unit_id=pair.proof_unit_id,
                            hypothesis_id=pair.hypothesis_id,
                            label=selected,
                            entailment_score=scores[EntailmentLabel.ENTAILMENT],
                            neutral_score=scores[EntailmentLabel.NEUTRAL],
                            contradiction_score=scores[EntailmentLabel.CONTRADICTION],
                            accepted=accepted,
                            reason=reason,
                        )
                    )
        except Exception:
            return tuple(fail_closed_decision(pair) for pair in pairs)
        return tuple(decisions)
