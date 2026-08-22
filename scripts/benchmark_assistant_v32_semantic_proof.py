#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Sequence
from uuid import uuid4

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from services.assistant.v3.semantic_proof.contracts import (
    EntailmentDecision,
    EntailmentLabel,
    EntailmentPair,
)
from services.assistant.v3.semantic_proof.corpus import (
    GoldenProofCase,
    build_golden_proof_corpus,
)
from services.assistant.v3.semantic_proof.provider import TransformersNliProvider
from services.ai_execution.client import AiExecutionClient
from services.ai_execution.contracts import AiExecutionRequest
from services.ai_execution.priorities import AiExecutionPriority


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the explicit GPU-only Assistant V3.2 semantic proof benchmark. "
            "The command never manages production services or models."
        )
    )
    parser.add_argument("--model", required=True, help="Local NLI model path or cached ID.")
    parser.add_argument("--device", default="cuda:0")
    parser.add_argument(
        "--precision",
        choices=("float32", "float16", "bfloat16"),
        default="float32",
    )
    parser.add_argument("--quantization", choices=("none",), default="none")
    parser.add_argument("--entailment-threshold", required=True, type=float)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--warmup-batches", type=int, default=2)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--min-free-gpu-mib", type=int, default=1536)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument(
        "--allow-model-download",
        action="store_true",
        help="Allow the explicitly selected NLI model loader to use the network.",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--qwen-models-url",
        default="http://127.0.0.1:8081/models",
    )
    parser.add_argument("--qwen-model", default="ai-soc-standard")
    parser.add_argument("--qwen-api-key-env", default="LLAMA_CPP_API_KEY")
    parser.add_argument("--gateway-socket-path")
    parser.add_argument("--http-timeout-seconds", type=float, default=45.0)
    parser.add_argument(
        "--measure-qwen-latency",
        action="store_true",
        help="Opt in to controlled Qwen probes before and while NLI is resident.",
    )
    parser.add_argument(
        "--allow-generative-probe",
        action="store_true",
        help="Second explicit acknowledgement required for Qwen generation probes.",
    )
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    if not args.device.startswith("cuda"):
        raise SystemExit("semantic proof benchmark is GPU-only; --device must be CUDA")
    if args.batch_size <= 0 or args.runs <= 0 or args.warmup_batches < 0:
        raise SystemExit("batch size and runs must be positive; warmups cannot be negative")
    if args.min_free_gpu_mib <= 0:
        raise SystemExit("--min-free-gpu-mib must be positive")
    if args.measure_qwen_latency != args.allow_generative_probe:
        raise SystemExit(
            "Qwen latency probes require both --measure-qwen-latency and "
            "--allow-generative-probe"
        )
    return args


def _emit(report: dict[str, Any], output: Path | None) -> None:
    rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    print(rendered)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(f"{rendered}\n", encoding="utf-8")


def _gpu_snapshot(device: str) -> dict[str, float]:
    try:
        import torch
    except ImportError as exc:
        raise RuntimeError("PyTorch is unavailable") from exc
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is unavailable")
    torch.cuda.set_device(device)
    torch.cuda.synchronize(device)
    free_bytes, total_bytes = torch.cuda.mem_get_info(device)
    return {
        "free_mib": free_bytes / (1024 * 1024),
        "total_mib": total_bytes / (1024 * 1024),
        "process_allocated_mib": torch.cuda.memory_allocated(device) / (1024 * 1024),
        "process_reserved_mib": torch.cuda.memory_reserved(device) / (1024 * 1024),
    }


def _request_json(
    url: str,
    *,
    api_key: str,
    timeout_seconds: float,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            decoded = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _qwen_residency(
    *,
    url: str,
    model: str,
    api_key: str,
    timeout_seconds: float,
) -> str:
    payload = _request_json(
        url,
        api_key=api_key,
        timeout_seconds=timeout_seconds,
    )
    if payload is None:
        return "not_verifiable"
    models = payload.get("data")
    if not isinstance(models, list):
        return "not_verifiable"
    selected = next(
        (
            item
            for item in models
            if isinstance(item, dict) and str(item.get("id") or "") == model
        ),
        None,
    )
    if selected is None:
        return "not_resident"
    raw_status = selected.get("status")
    status = (
        str(raw_status.get("value") or "")
        if isinstance(raw_status, dict)
        else str(raw_status or "")
    ).strip().lower()
    if status in {"loaded", "running"}:
        return "resident"
    if status in {"loading", "initializing", "starting", "warming"}:
        return "warming"
    if status in {"unloaded", "stopped"}:
        return "not_resident"
    return "listed_status_unknown"


def _qwen_latency_probe(
    *,
    socket_path: str | None,
    timeout_seconds: float,
) -> float | None:
    deadline_ms = max(100, min(int(timeout_seconds * 1000), 300_000))
    request = AiExecutionRequest(
        task="soc_assistant",
        priority=AiExecutionPriority.INTERACTIVE,
        request_id=f"semantic-proof-benchmark-{uuid4().hex[:16]}",
        deadline_ms=deadline_ms,
        system_instructions=(
            "Return only the requested visible text. Do not expose hidden reasoning."
        ),
        input="Return exactly the single token OK.",
        output_schema="text_v1",
        max_output_tokens=16,
        temperature=0,
    )
    try:
        response = AiExecutionClient(socket_path=socket_path).generate(request)
    except Exception:
        return None
    if response.status != "success" or not isinstance(response.output, str):
        return None
    return float(response.generation_ms)


def _pairs(cases: Sequence[GoldenProofCase]) -> tuple[EntailmentPair, ...]:
    return tuple(
        EntailmentPair(
            pair_id=item.case_id,
            proof_unit_id=item.proof_unit.proof_unit_id,
            premise=item.proof_unit.canonical_premise,
            premise_language=item.proof_unit.premise_language,
            hypothesis_id=item.case_id,
            hypothesis=item.hypothesis,
            hypothesis_language=item.hypothesis_language,
        )
        for item in cases
    )


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _accuracy_by_language(
    cases: Sequence[GoldenProofCase],
    decisions: Sequence[EntailmentDecision],
) -> dict[str, float]:
    by_id = {item.pair_id: item for item in decisions}
    result: dict[str, float] = {}
    for language_pair in ("IT_IT", "EN_IT", "EN_EN"):
        selected = [item for item in cases if item.language_pair == language_pair]
        correct = sum(
            by_id.get(item.case_id) is not None
            and by_id[item.case_id].label is item.expected_label
            for item in selected
        )
        result[language_pair] = round(correct / len(selected), 6) if selected else 0.0
    return result


def _quality_metrics(
    cases: Sequence[GoldenProofCase],
    decisions: Sequence[EntailmentDecision],
) -> dict[str, Any]:
    by_id = {item.pair_id: item for item in decisions}
    false_accept_ids = [
        item.case_id
        for item in cases
        if not item.expected_accept
        and by_id.get(item.case_id) is not None
        and by_id[item.case_id].accepted
    ]
    false_reject_ids = [
        item.case_id
        for item in cases
        if item.expected_accept
        and (
            by_id.get(item.case_id) is None or not by_id[item.case_id].accepted
        )
    ]
    critical = {
        item.case_id for item in cases if item.security_critical and not item.expected_accept
    }
    labels = Counter(item.label.value for item in decisions)
    return {
        "accuracy": _accuracy_by_language(cases, decisions),
        "false_accept_count": len(false_accept_ids),
        "false_reject_count": len(false_reject_ids),
        "security_critical_false_accept_count": len(critical.intersection(false_accept_ids)),
        "false_accept_case_ids": false_accept_ids,
        "false_reject_case_ids": false_reject_ids,
        "decision_labels": dict(sorted(labels.items())),
    }


def _benchmark_outcome(
    *,
    unavailable_count: int,
    coexistence_verified: bool,
    security_critical_false_accept_count: int,
) -> tuple[str, int]:
    if unavailable_count:
        return "provider_failed_closed", 2
    if not coexistence_verified:
        return "completed_coexistence_not_verified", 2
    if security_critical_false_accept_count:
        return "completed", 1
    return "completed", 0


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report: dict[str, Any] = {
        "status": "preflight",
        "backend": "transformers_sequence_classification",
        "model": args.model,
        "precision": args.precision,
        "quantization": args.quantization,
        "device": args.device,
        "batch_size": args.batch_size,
        "qwen_generation_latency_before_nli_ms": None,
        "qwen_generation_latency_while_nli_resident_ms": None,
        "qwen_coexistence_status": "not_verified",
    }
    api_key = os.getenv(args.qwen_api_key_env, "")
    qwen_before = _qwen_residency(
        url=args.qwen_models_url,
        model=args.qwen_model,
        api_key=api_key,
        timeout_seconds=min(args.http_timeout_seconds, 5.0),
    )
    report["qwen_residency_before_nli"] = qwen_before
    if args.measure_qwen_latency:
        report["qwen_generation_latency_before_nli_ms"] = _qwen_latency_probe(
            socket_path=args.gateway_socket_path,
            timeout_seconds=args.http_timeout_seconds,
        )

    try:
        before = _gpu_snapshot(args.device)
    except RuntimeError as exc:
        report.update(status="gpu_unavailable", safe_error=str(exc))
        _emit(report, args.output)
        return 2
    report["gpu_before"] = before
    if before["free_mib"] < args.min_free_gpu_mib:
        report.update(
            status="insufficient_gpu_memory",
            required_free_gpu_mib=args.min_free_gpu_mib,
            qwen_coexistence_status="insufficient_gpu_memory",
        )
        _emit(report, args.output)
        return 2

    try:
        cold_started = time.perf_counter()
        provider = TransformersNliProvider(
            model=args.model,
            device=args.device,
            precision=args.precision,
            quantization=args.quantization,
            entailment_threshold=args.entailment_threshold,
            local_files_only=not args.allow_model_download,
            max_length=args.max_length,
        )
        cold_startup_ms = (time.perf_counter() - cold_started) * 1000
        after = _gpu_snapshot(args.device)
    except Exception as exc:
        report.update(
            status="nli_model_load_failed",
            safe_error=exc.__class__.__name__,
            qwen_coexistence_status="nli_load_failed",
        )
        _emit(report, args.output)
        return 2

    resident_delta = max(0.0, before["free_mib"] - after["free_mib"])
    report.update(
        provider=provider.info.model_dump(mode="json"),
        cold_startup_ms=round(cold_startup_ms, 3),
        gpu_after=after,
        resident_gpu_memory_delta_mib=round(resident_delta, 3),
    )
    qwen_after = _qwen_residency(
        url=args.qwen_models_url,
        model=args.qwen_model,
        api_key=api_key,
        timeout_seconds=min(args.http_timeout_seconds, 5.0),
    )
    report["qwen_residency_while_nli_resident"] = qwen_after
    coexistence_verified = qwen_before == "resident" and qwen_after == "resident"
    report["qwen_coexistence_status"] = (
        "qwen_resident_nli_loaded" if coexistence_verified else "qwen_not_verified"
    )
    if args.measure_qwen_latency:
        report["qwen_generation_latency_while_nli_resident_ms"] = _qwen_latency_probe(
            socket_path=args.gateway_socket_path,
            timeout_seconds=args.http_timeout_seconds,
        )
        if (
            coexistence_verified
            and report["qwen_generation_latency_before_nli_ms"] is not None
            and report["qwen_generation_latency_while_nli_resident_ms"] is not None
        ):
            report["qwen_coexistence_status"] = "qwen_resident_latency_probed"

    cases = build_golden_proof_corpus()
    pairs = _pairs(cases)
    warmup = pairs[: args.batch_size]
    for _ in range(args.warmup_batches):
        provider.evaluate(warmup, batch_size=args.batch_size)

    batch_latencies: list[float] = []
    latest_decisions: list[EntailmentDecision] = []
    measured_pairs = 0
    measured_started = time.perf_counter()
    for _ in range(args.runs):
        run_decisions: list[EntailmentDecision] = []
        for offset in range(0, len(pairs), args.batch_size):
            batch = pairs[offset : offset + args.batch_size]
            started = time.perf_counter()
            run_decisions.extend(provider.evaluate(batch, batch_size=args.batch_size))
            batch_latencies.append((time.perf_counter() - started) * 1000)
            measured_pairs += len(batch)
        latest_decisions = run_decisions
    measured_seconds = max(time.perf_counter() - measured_started, 0.000001)
    unavailable = sum(
        item.label is EntailmentLabel.UNAVAILABLE for item in latest_decisions
    )
    quality = _quality_metrics(cases, latest_decisions)
    benchmark_status, exit_code = _benchmark_outcome(
        unavailable_count=unavailable,
        coexistence_verified=coexistence_verified,
        security_critical_false_accept_count=quality[
            "security_critical_false_accept_count"
        ],
    )
    report.update(
        status=benchmark_status,
        corpus_case_count=len(cases),
        warm_latency_ms=round(statistics.mean(batch_latencies), 3),
        latency_p50_ms=round(_percentile(batch_latencies, 0.50), 3),
        latency_p95_ms=round(_percentile(batch_latencies, 0.95), 3),
        pairs_per_second=round(measured_pairs / measured_seconds, 3),
        unavailable_decision_count=unavailable,
        **quality,
    )
    _emit(report, args.output)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
