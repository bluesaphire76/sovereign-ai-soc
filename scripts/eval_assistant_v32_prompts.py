#!/usr/bin/env python3
"""Run the read-only V3.2 Prompt 1-8 product proof on existing SOC records."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from sentence_transformers import SentenceTransformer

from database import SessionLocal
from models import Incident
from qdrant_knowledge import (
    embedding_runtime_snapshot,
    start_embedding_prewarm,
)
from schemas.assistant import AssistantQueryRequest
from services.ai_execution.client import AiExecutionClient
from services.ai_execution.client import generate_ai_response
from services.assistant.focus import FocusDimension, FocusSelection
from services.assistant.orchestrator import AssistantSettings, run_assistant_query
from services.assistant.v3.builder import V3AnalyticalContextBuilder
from services.assistant.v3.contracts import (
    AnswerIntent,
    IntentSelection,
)
from services.assistant.v3.semantic_index import IncidentSemanticQueryResult
from services.assistant.v3.semantic_proof.runtime import (
    prewarm_semantic_proof_runtime,
)


PROMPTS = (
    (
        AnswerIntent.INVESTIGATE,
        "Analizza questo incidente: spiegami cosa è successo, quali sono le "
        "evidenze più importanti, cosa possiamo concludere dai dati disponibili "
        "e cosa invece non possiamo concludere.",
    ),
    (
        AnswerIntent.INVESTIGATE,
        "Quali sono le evidenze più importanti di questo incidente e perché "
        "contano dal punto di vista dell'analista SOC?",
    ),
    (
        AnswerIntent.NEXT_ACTION,
        "Analizza questo incidente come farebbe un analista SOC e indicami cosa "
        "controlleresti subito dopo.",
    ),
    (
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        "Ci sono altri incidenti realmente rilevanti rispetto a questo? Spiegami "
        "quali e perché, senza assumere che appartengano allo stesso attacco.",
    ),
    (
        AnswerIntent.COMPARE,
        "Tra quelli che hai citato, quale merita di essere confrontato per primo "
        "e perché?",
    ),
    (
        AnswerIntent.INVESTIGATE,
        "Cosa possiamo affermare con sicurezza e cosa non è ancora dimostrato?",
    ),
    (
        AnswerIntent.EXECUTIVE_SUMMARY,
        "Spiegami il significato operativo di questo incidente in modo "
        "comprensibile a un responsabile non tecnico.",
    ),
    (
        AnswerIntent.NEXT_ACTION,
        "In base alle evidenze e ai playbook disponibili, quali verifiche sono "
        "più pertinenti e perché?",
    ),
)


@dataclass(frozen=True)
class _FixedRouter:
    value: Any

    def route(self, _message: str) -> Any:
        return self.value


class _UnavailableIncidentSemanticIndex:
    def query(self, *_args, **_kwargs) -> IncidentSemanticQueryResult:
        return IncidentSemanticQueryResult(
            status="unavailable",
            error_category="CONTROLLED_PRODUCT_EVAL_NO_DUPLICATE_GPU_ENCODER",
        )


def _intent_selection(intent: AnswerIntent) -> IntentSelection:
    return IntentSelection(
        primary_intent=intent,
        confidence=1.0,
        routing_status="ok",
        routing_ms=0.0,
    )


def _focus_selection(intent: AnswerIntent) -> FocusSelection:
    if intent in {
        AnswerIntent.COMPARE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
    }:
        dimensions = (FocusDimension.CORRELATION, FocusDimension.EVIDENCE)
    elif intent is AnswerIntent.EXECUTIVE_SUMMARY:
        dimensions = (FocusDimension.GENERAL,)
    else:
        dimensions = (FocusDimension.EVIDENCE, FocusDimension.GENERAL)
    return FocusSelection(dimensions=dimensions, confidence=1.0)


def _wait_for_cpu_embedding(timeout_seconds: float = 60.0) -> dict[str, Any]:
    start_embedding_prewarm(
        loader=lambda model: SentenceTransformer(
            model,
            local_files_only=True,
            device="cpu",
        )
    )
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        snapshot = embedding_runtime_snapshot()
        if snapshot.get("embedding_ready"):
            return snapshot
        if snapshot.get("embedding_cache_state") == "unavailable":
            raise RuntimeError("controlled CPU semantic embedding prewarm failed")
        time.sleep(0.1)
    raise TimeoutError("controlled CPU semantic embedding prewarm timed out")


def _verify_records(incident_ids: tuple[int, ...]) -> None:
    db = SessionLocal()
    try:
        found = {
            int(item[0])
            for item in db.query(Incident.id)
            .filter(Incident.id.in_(incident_ids))
            .all()
        }
    finally:
        db.close()
    missing = set(incident_ids) - found
    if missing:
        raise RuntimeError(f"required read-only incidents are missing: {sorted(missing)}")


def _gpu_temperature() -> float:
    completed = subprocess.run(
        [
            "nvidia-smi",
            "--query-gpu=temperature.gpu",
            "--format=csv,noheader,nounits",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=3,
    )
    return max(float(item.strip()) for item in completed.stdout.splitlines())


def _wait_for_thermal_gate(maximum_celsius: float) -> float:
    deadline = time.monotonic() + 600
    while True:
        temperature = _gpu_temperature()
        if temperature <= maximum_celsius:
            return temperature
        if time.monotonic() >= deadline:
            raise TimeoutError("GPU did not cool below the product proof threshold")
        time.sleep(5)


def _run(args: argparse.Namespace) -> dict[str, Any]:
    _verify_records((args.incident_id, args.compare_incident_id))
    gateway_before = AiExecutionClient().status().model_dump(mode="json")
    if gateway_before.get("state") != "ready":
        raise RuntimeError("AI Execution Gateway is not ready")

    embedding = _wait_for_cpu_embedding()
    proof_runtime = prewarm_semantic_proof_runtime()
    if proof_runtime.get("state") != "ready":
        raise RuntimeError("V3.2 semantic proof runtime did not prewarm")

    settings = AssistantSettings(
        enabled=True,
        response_architecture="v3_2",
        max_context_chars=16_000,
        max_sources=8,
        semantic_limit=4,
        semantic_timeout_seconds=2.0,
        request_timeout_seconds=120.0,
        v32_max_output_tokens=1024,
    )
    builder = V3AnalyticalContextBuilder(
        incident_semantic_index=_UnavailableIncidentSemanticIndex()
    )
    conversation_id = f"v32-product-proof-{os.getpid()}-{int(time.time())}"
    results: list[dict[str, Any]] = []
    selected_prompt_ids = (
        args.prompts
        if args.prompts is not None
        else ([args.prompt] if args.prompt is not None else list(range(1, 9)))
    )
    selected_prompts = [
        (prompt_id, PROMPTS[prompt_id - 1])
        for prompt_id in selected_prompt_ids
    ]
    for result_offset, (index, (intent, question)) in enumerate(selected_prompts):
        if result_offset:
            time.sleep(args.inter_query_delay_seconds)
        starting_temperature = _wait_for_thermal_gate(
            args.max_gpu_temperature_celsius
        )
        compare_ids = [args.compare_incident_id] if index == 4 else []
        include_semantic = index in {3, 8}
        started = time.monotonic()
        model_draft: Any = None

        def recording_generator(**kwargs):
            nonlocal model_draft
            generated = generate_ai_response(**kwargs)
            model_draft = generated.get("structured_output")
            if model_draft is None:
                model_draft = generated.get("text")
            return generated

        response = run_assistant_query(
            AssistantQueryRequest(
                message=question,
                scope="incident",
                incident_id=args.incident_id,
                compare_incident_ids=compare_ids,
                conversation_id=conversation_id if index in {4, 5} else None,
                include_semantic_memory=include_semantic,
            ),
            current_user={"username": "v32-product-validator", "role": "ANALYST"},
            settings=settings,
            intent_router=_FixedRouter(_intent_selection(intent)),
            focus_router=_FixedRouter(_focus_selection(intent)),
            v3_context_builder=builder,
            generator=recording_generator,
        )
        results.append(
            {
                "prompt": index,
                "question": question,
                "expected_intent": intent.value,
                "model_draft": model_draft,
                "answer": response.answer,
                "blocks": [item.model_dump(mode="json") for item in response.blocks],
                "sources": [item.model_dump(mode="json") for item in response.sources],
                "limitations": response.limitations,
                "metadata": response.metadata.model_dump(mode="json"),
                "wall_ms": round((time.monotonic() - started) * 1000, 3),
                "starting_gpu_temperature_celsius": starting_temperature,
            }
        )

    gateway_after = AiExecutionClient().status().model_dump(mode="json")
    metadata = [item["metadata"] for item in results]
    return {
        "status": "completed",
        "architecture": "v3_2",
        "incident_id": args.incident_id,
        "compare_incident_id": args.compare_incident_id,
        "read_only": True,
        "embedding_runtime": {
            **embedding,
            "controlled_eval_device": "cpu",
        },
        "proof_runtime": proof_runtime,
        "gateway_before": gateway_before,
        "gateway_after": gateway_after,
        "summary": {
            "query_count": len(results),
            "model_responses": sum(
                item["generation_kind"] == "model" for item in metadata
            ),
            "deterministic_fallbacks": sum(
                item["generation_kind"] == "deterministic_fallback"
                for item in metadata
            ),
            "provider_generation_count": sum(
                item["provider_generation_count"] for item in metadata
            ),
            "automatic_retries": sum(item["automatic_retries"] for item in metadata),
            "model_switches": sum(item["model_switches"] for item in metadata),
            "semantic_proof_passes": sum(
                item["semantic_proof_status"] == "passed" for item in metadata
            ),
            "semantic_proof_failures": sum(
                item["semantic_proof_status"] in {"failed", "unavailable"}
                for item in metadata
            ),
        },
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident-id", type=int, default=5333)
    parser.add_argument("--compare-incident-id", type=int, default=5318)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--prompt", type=int, choices=range(1, 9))
    selection.add_argument(
        "--prompts",
        type=int,
        choices=range(1, 9),
        nargs="+",
        help="Run an ordered prompt subset in one process and conversation.",
    )
    parser.add_argument("--inter-query-delay-seconds", type=float, default=15.0)
    parser.add_argument("--max-gpu-temperature-celsius", type=float, default=75.0)
    parser.add_argument(
        "--output",
        default="/tmp/ai-soc-v32-prompt-1-8.json",
    )
    args = parser.parse_args()
    report = _run(args)
    output = Path(args.output)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({"output": str(output), **report["summary"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
