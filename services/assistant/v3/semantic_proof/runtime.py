from __future__ import annotations

import hashlib
import logging
import os
import threading
import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal, TypeVar

from services.assistant.v3.semantic_proof.contracts import (
    EntailmentDecision,
    EntailmentPair,
    EntailmentProvider,
    EntailmentProviderInfo,
)
from services.assistant.v3.semantic_proof.models import MULTILINGUAL_MINILMV2_L6
from services.assistant.v3.semantic_proof.provider import (
    TransformersNliProvider,
    fail_closed_decision,
)


logger = logging.getLogger(__name__)
_T = TypeVar("_T")


@dataclass(frozen=True)
class SemanticProofRuntimeSettings:
    model_path: str = MULTILINGUAL_MINILMV2_L6.local_path
    device: str = "cuda:0"
    precision: Literal["float16", "float32", "bfloat16"] = "float16"
    entailment_threshold: float = 0.80
    batch_size: int = 8
    timeout_seconds: float = 3.0


class SemanticProofTimeout(RuntimeError):
    pass


class UnavailableEntailmentProvider:
    def __init__(self, reason: str) -> None:
        self.reason = reason

    @property
    def info(self) -> EntailmentProviderInfo:
        return EntailmentProviderInfo(
            backend="unavailable_fail_closed",
            model=MULTILINGUAL_MINILMV2_L6.model_id,
            precision="none",
            quantization="none",
            device="cuda_unavailable",
        )

    def evaluate(
        self,
        pairs: Sequence[EntailmentPair],
        *,
        batch_size: int,
    ) -> Sequence[EntailmentDecision]:
        del batch_size
        return tuple(fail_closed_decision(item) for item in pairs)


_LOCK = threading.Lock()
_PROVIDER: EntailmentProvider | None = None
_STATE = "cold"
_SAFE_ERROR: str | None = None
_LOAD_MS = 0
_PREWARM_MS = 0
_PROOF_EXECUTOR = ThreadPoolExecutor(
    max_workers=1,
    thread_name_prefix="assistant-v32-proof",
)


def run_semantic_proof_with_timeout(
    operation: Callable[[], _T],
    *,
    timeout_seconds: float,
) -> _T:
    future = _PROOF_EXECUTOR.submit(operation)
    try:
        return future.result(timeout=timeout_seconds)
    except FutureTimeoutError as exc:
        future.cancel()
        raise SemanticProofTimeout("semantic proof exceeded its phase budget") from exc


def get_semantic_proof_runtime_settings() -> SemanticProofRuntimeSettings:
    device = os.getenv("AI_SOC_ASSISTANT_V32_NLI_DEVICE", "cuda:0").strip()
    if not device.startswith("cuda"):
        raise ValueError("V3.2 semantic proof runtime is GPU-only")
    precision = os.getenv(
        "AI_SOC_ASSISTANT_V32_NLI_PRECISION",
        "float16",
    ).strip()
    if precision not in {"float16", "float32", "bfloat16"}:
        raise ValueError("invalid V3.2 semantic proof precision")
    try:
        threshold = float(
            os.getenv("AI_SOC_ASSISTANT_V32_NLI_ENTAILMENT_THRESHOLD", "0.80")
        )
    except ValueError as exc:
        raise ValueError("invalid V3.2 entailment threshold") from exc
    if not 0.0 < threshold <= 1.0:
        raise ValueError("V3.2 entailment threshold must be in (0, 1]")
    try:
        batch_size = int(os.getenv("AI_SOC_ASSISTANT_V32_NLI_BATCH_SIZE", "8"))
    except ValueError as exc:
        raise ValueError("invalid V3.2 NLI batch size") from exc
    if not 1 <= batch_size <= 32:
        raise ValueError("V3.2 NLI batch size must be between 1 and 32")
    try:
        timeout_seconds = float(
            os.getenv("AI_SOC_ASSISTANT_V32_PROOF_TIMEOUT_SECONDS", "3.0")
        )
    except ValueError as exc:
        raise ValueError("invalid V3.2 semantic proof timeout") from exc
    if not 0.05 <= timeout_seconds <= 10.0:
        raise ValueError("V3.2 semantic proof timeout must be between 0.05 and 10")
    return SemanticProofRuntimeSettings(
        model_path=os.getenv(
            "AI_SOC_ASSISTANT_V32_NLI_MODEL_PATH",
            MULTILINGUAL_MINILMV2_L6.local_path,
        ).strip(),
        device=device,
        precision=precision,
        entailment_threshold=threshold,
        batch_size=batch_size,
        timeout_seconds=timeout_seconds,
    )


def _verify_pinned_model(model_path: str) -> None:
    expected_path = Path(MULTILINGUAL_MINILMV2_L6.local_path).resolve()
    selected_path = Path(model_path).resolve()
    if selected_path != expected_path:
        raise RuntimeError("semantic proof model path is not the pinned candidate")
    weight_path = selected_path / MULTILINGUAL_MINILMV2_L6.weight_file
    if not weight_path.is_file():
        raise RuntimeError("semantic proof model weights are missing")
    if weight_path.stat().st_size != MULTILINGUAL_MINILMV2_L6.weight_size_bytes:
        raise RuntimeError("semantic proof model weight size mismatch")
    digest = hashlib.sha256()
    with weight_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != MULTILINGUAL_MINILMV2_L6.weight_sha256:
        raise RuntimeError("semantic proof model weight checksum mismatch")


def get_semantic_proof_provider() -> EntailmentProvider:
    global _LOAD_MS, _PROVIDER, _SAFE_ERROR, _STATE
    if _PROVIDER is not None:
        return _PROVIDER
    with _LOCK:
        if _PROVIDER is not None:
            return _PROVIDER
        started = time.perf_counter()
        _STATE = "loading"
        try:
            settings = get_semantic_proof_runtime_settings()
            _verify_pinned_model(settings.model_path)
            _PROVIDER = TransformersNliProvider(
                model=settings.model_path,
                device=settings.device,
                precision=settings.precision,
                quantization="none",
                entailment_threshold=settings.entailment_threshold,
                local_files_only=True,
            )
        except Exception as exc:
            _SAFE_ERROR = exc.__class__.__name__
            _STATE = "unavailable"
            _PROVIDER = UnavailableEntailmentProvider(_SAFE_ERROR)
            logger.error(
                "assistant_v32_semantic_proof_unavailable reason=%s",
                _SAFE_ERROR,
            )
        else:
            _SAFE_ERROR = None
            _STATE = "ready"
        _LOAD_MS = max(0, int((time.perf_counter() - started) * 1000))
        return _PROVIDER


def prewarm_semantic_proof_runtime() -> dict[str, object]:
    global _PREWARM_MS, _PROVIDER, _SAFE_ERROR, _STATE
    provider = get_semantic_proof_provider()
    if _STATE != "ready":
        return semantic_proof_runtime_snapshot()
    settings = get_semantic_proof_runtime_settings()
    pair = EntailmentPair(
        pair_id="semantic-proof-prewarm",
        proof_unit_id="semantic-proof-prewarm",
        premise="The incident status is OPEN.",
        premise_language="en",
        hypothesis_id="semantic-proof-prewarm",
        hypothesis="The incident status is OPEN.",
        hypothesis_language="en",
    )
    started = time.perf_counter()
    try:
        decisions = tuple(provider.evaluate((pair,), batch_size=settings.batch_size))
        if len(decisions) != 1 or not decisions[0].accepted:
            raise RuntimeError("semantic proof prewarm decision was not entailed")
    except Exception as exc:
        with _LOCK:
            _SAFE_ERROR = exc.__class__.__name__
            _STATE = "unavailable"
            _PROVIDER = UnavailableEntailmentProvider(_SAFE_ERROR)
    _PREWARM_MS = max(0, int((time.perf_counter() - started) * 1000))
    return semantic_proof_runtime_snapshot()


def semantic_proof_runtime_snapshot() -> dict[str, object]:
    provider_info = _PROVIDER.info.model_dump(mode="json") if _PROVIDER else None
    return {
        "state": _STATE,
        "safe_error": _SAFE_ERROR,
        "load_ms": _LOAD_MS,
        "prewarm_ms": _PREWARM_MS,
        "provider": provider_info,
        "model_id": MULTILINGUAL_MINILMV2_L6.model_id,
        "model_revision": MULTILINGUAL_MINILMV2_L6.revision,
    }


def reset_semantic_proof_runtime_for_tests() -> None:
    global _LOAD_MS, _PREWARM_MS, _PROVIDER, _SAFE_ERROR, _STATE
    with _LOCK:
        _PROVIDER = None
        _STATE = "cold"
        _SAFE_ERROR = None
        _LOAD_MS = 0
        _PREWARM_MS = 0
