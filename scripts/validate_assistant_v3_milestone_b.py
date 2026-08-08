#!/usr/bin/env python3
"""Run the Milestone B read-only real-data Assistant V3 quality matrix."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

import httpx
from prometheus_client.parser import text_string_to_metric_families
from sqlalchemy import func

from database import SessionLocal
from models import CaseIncident, Incident
from qdrant_knowledge import get_knowledge_base
from schemas.assistant import AssistantQueryRequest
from services.assistant.focus import get_semantic_focus_router
from services.assistant.orchestrator import AssistantSettings, run_assistant_query
from services.assistant.v3.contracts import AnswerIntent
from services.assistant.v3.discourse import closed_safety_sentences
from services.assistant.v3.intent import get_semantic_intent_router


OPEN_INTENTS = {
    AnswerIntent.EXPLAIN,
    AnswerIntent.INVESTIGATE,
    AnswerIntent.COMPARE,
    AnswerIntent.CROSS_INCIDENT_ANALYSIS,
    AnswerIntent.PATTERN_ANALYSIS,
    AnswerIntent.NEXT_ACTION,
    AnswerIntent.HANDOVER,
    AnswerIntent.SUMMARY,
    AnswerIntent.EXECUTIVE_SUMMARY,
}
CROSS_INTENTS = {
    AnswerIntent.COMPARE,
    AnswerIntent.CROSS_INCIDENT_ANALYSIS,
    AnswerIntent.PATTERN_ANALYSIS,
}
QUESTION_BY_INTENT = {
    AnswerIntent.EXPLAIN: (
        "Explain the meaning and significance of this security record using "
        "supporting facts."
    ),
    AnswerIntent.INVESTIGATE: "What happened and what evidence supports it?",
    AnswerIntent.COMPARE: "Compare these two incidents.",
    AnswerIntent.CROSS_INCIDENT_ANALYSIS: "Could this connect to other incidents?",
    AnswerIntent.PATTERN_ANALYSIS: "Find recurring patterns across alerts.",
    AnswerIntent.NEXT_ACTION: "What should the analyst verify next?",
    AnswerIntent.HANDOVER: "Prepare this for shift handover.",
    AnswerIntent.SUMMARY: "Summarize this record.",
    AnswerIntent.EXECUTIVE_SUMMARY: "Give leadership an executive summary.",
    AnswerIntent.FACT_LOOKUP: "What status is recorded?",
}


@dataclass(frozen=True)
class QuerySpec:
    sequence: int
    expected_intent: AnswerIntent
    question: str
    scope: str
    incident_id: int | None = None
    case_id: int | None = None
    compare_incident_ids: tuple[int, ...] = ()
    conversation_id: str | None = None
    expected_followup: bool = False


class _FixedRouter:
    def __init__(self, value: Any) -> None:
        self._value = value

    def route(self, _question: str) -> Any:
        return self._value


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {key: 0.0 for key in ("min", "p50", "p90", "p95", "max", "mean")}
    return {
        "min": round(min(values), 3),
        "p50": round(_percentile(values, 0.50), 3),
        "p90": round(_percentile(values, 0.90), 3),
        "p95": round(_percentile(values, 0.95), 3),
        "max": round(max(values), 3),
        "mean": round(statistics.fmean(values), 3),
    }


def _compact_stats(values: list[float]) -> dict[str, float]:
    full = _stats(values)
    return {key: full[key] for key in ("min", "p50", "p95", "max")}


def _normalized(text: str) -> str:
    return " ".join(str(text or "").lower().split())


def _ngrams(text: str, size: int = 3) -> set[tuple[str, ...]]:
    words = _normalized(text).split()
    return {tuple(words[index : index + size]) for index in range(len(words) - size + 1)}


def _jaccard(left: set[Any], right: set[Any]) -> float:
    if not left and not right:
        return 1.0
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _gateway_counters(socket_path: str) -> dict[str, float]:
    transport = httpx.HTTPTransport(uds=socket_path)
    with httpx.Client(transport=transport, base_url="http://gateway") as client:
        response = client.get("/metrics", timeout=10)
        response.raise_for_status()
    counters: dict[str, float] = {}
    for family in text_string_to_metric_families(response.text):
        if family.name != "ai_execution_requests":
            continue
        for sample in family.samples:
            if sample.labels.get("task") != "soc_assistant":
                continue
            status = sample.labels.get("status", "unknown")
            counters[status] = counters.get(status, 0.0) + float(sample.value)
    return counters


def _runtime_records() -> tuple[list[int], list[int]]:
    db = SessionLocal()
    try:
        incident_ids = [
            int(row[0])
            for row in db.query(Incident.id).order_by(Incident.id).limit(100).all()
        ]
        case_ids = [
            int(row[0])
            for row in (
                db.query(CaseIncident.case_id)
                .group_by(CaseIncident.case_id)
                .having(func.count(CaseIncident.incident_id) >= 2)
                .order_by(CaseIncident.case_id)
                .limit(4)
                .all()
            )
        ]
    finally:
        db.close()
    if len(incident_ids) < 60:
        raise RuntimeError("Milestone B validation requires at least 60 incidents")
    if len(case_ids) < 4:
        raise RuntimeError("Milestone B validation requires four multi-incident cases")
    return incident_ids, case_ids


def _intent_sequence() -> list[AnswerIntent]:
    counts = (
        [(AnswerIntent.EXPLAIN, 10), (AnswerIntent.INVESTIGATE, 10)]
        + [(AnswerIntent.CROSS_INCIDENT_ANALYSIS, 10), (AnswerIntent.COMPARE, 10)]
        + [(AnswerIntent.PATTERN_ANALYSIS, 10)]
        + [(AnswerIntent.NEXT_ACTION, 5), (AnswerIntent.HANDOVER, 5)]
        + [(AnswerIntent.SUMMARY, 5), (AnswerIntent.EXECUTIVE_SUMMARY, 5)]
        + [(AnswerIntent.FACT_LOOKUP, 10)]
    )
    buckets = [[intent] * count for intent, count in counts]
    result: list[AnswerIntent] = []
    while any(buckets):
        for bucket in buckets:
            if bucket:
                result.append(bucket.pop())
    return result


def _query_specs(incident_ids: list[int], case_ids: list[int]) -> tuple[list[QuerySpec], list[QuerySpec], list[QuerySpec]]:
    intents = _intent_sequence()
    initial: list[QuerySpec] = []
    for index, incident_id in enumerate(incident_ids[:60]):
        intent = intents[index]
        comparison = (
            (incident_ids[(index + 1) % 60],)
            if intent is AnswerIntent.COMPARE
            else ()
        )
        initial.append(
            QuerySpec(
                sequence=index,
                expected_intent=intent,
                question=QUESTION_BY_INTENT[intent],
                scope="incident",
                incident_id=incident_id,
                compare_incident_ids=comparison,
                conversation_id=(f"milestone-b-flow-{index:02d}" if index < 10 else None),
            )
        )
    followups: list[QuerySpec] = []
    for offset in range(20):
        sequence = 60 + offset
        intent = intents[sequence]
        flow_offset = offset % 10
        incident_id = incident_ids[flow_offset]
        comparison = (
            (incident_ids[(offset + 20) % 60],)
            if intent is AnswerIntent.COMPARE
            else ()
        )
        followups.append(
            QuerySpec(
                sequence=sequence,
                expected_intent=intent,
                question=QUESTION_BY_INTENT[intent],
                scope="incident",
                incident_id=incident_id,
                compare_incident_ids=comparison,
                conversation_id=f"milestone-b-flow-{flow_offset:02d}",
                expected_followup=True,
            )
        )
    cases = [
        QuerySpec(
            sequence=80 + index,
            expected_intent=AnswerIntent.PATTERN_ANALYSIS,
            question=QUESTION_BY_INTENT[AnswerIntent.PATTERN_ANALYSIS],
            scope="case",
            case_id=case_id,
            conversation_id=f"milestone-b-case-{index:02d}",
        )
        for index, case_id in enumerate(case_ids)
    ]
    return initial, followups, cases


def _run_spec(
    spec: QuerySpec,
    *,
    settings: AssistantSettings,
    intent_selections: dict[str, Any],
    focus_selections: dict[str, Any],
) -> dict[str, Any]:
    started = time.monotonic()
    try:
        response = run_assistant_query(
            AssistantQueryRequest(
                message=spec.question,
                scope=spec.scope,
                incident_id=spec.incident_id,
                case_id=spec.case_id,
                compare_incident_ids=list(spec.compare_incident_ids),
                conversation_id=spec.conversation_id,
                include_semantic_memory=spec.expected_intent
                in {AnswerIntent.NEXT_ACTION, AnswerIntent.HANDOVER},
            ),
            current_user={
                "username": "milestone-b-validator",
                "role": "ANALYST",
            },
            settings=settings,
            intent_router=_FixedRouter(intent_selections[spec.question]),
            focus_router=_FixedRouter(focus_selections[spec.question]),
        )
    except Exception as exc:
        return {
            "sequence": spec.sequence,
            "scope": spec.scope,
            "incident_id": spec.incident_id,
            "case_id": spec.case_id,
            "question": spec.question,
            "expected_intent": spec.expected_intent.value,
            "expected_followup": spec.expected_followup,
            "exception": exc.__class__.__name__,
            "wall_ms": round((time.monotonic() - started) * 1000, 3),
        }
    source_ids = {source.source_id for source in response.sources}
    dangling = sorted(
        {
            source_id
            for block in response.blocks
            for source_id in block.source_ids
            if source_id not in source_ids
        }
    )
    return {
        "sequence": spec.sequence,
        "scope": spec.scope,
        "incident_id": spec.incident_id,
        "case_id": spec.case_id,
        "question": spec.question,
        "expected_intent": spec.expected_intent.value,
        "expected_followup": spec.expected_followup,
        "status": response.status,
        "generation_kind": response.generation_kind,
        "answer": response.answer,
        "blocks": [block.model_dump(mode="json") for block in response.blocks],
        "sources": [source.model_dump(mode="json") for source in response.sources],
        "dangling_source_ids": dangling,
        "metadata": response.metadata.model_dump(mode="json"),
        "wall_ms": round((time.monotonic() - started) * 1000, 3),
    }


def _run_phase(
    specs: list[QuerySpec],
    *,
    concurrency: int,
    settings: AssistantSettings,
    intent_selections: dict[str, Any],
    focus_selections: dict[str, Any],
) -> list[dict[str, Any]]:
    if concurrency != 1:
        raise ValueError("the inference gateway coordinator requires serial validation")
    return [
        _run_spec(
            spec,
            settings=settings,
            intent_selections=intent_selections,
            focus_selections=focus_selections,
        )
        for spec in specs
    ]


def _quality_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    successful = [item for item in results if "metadata" in item]
    open_results = [
        item
        for item in successful
        if AnswerIntent(item["metadata"]["assistant_intent"]) in OPEN_INTENTS
    ]

    def record_key(item: dict[str, Any]) -> tuple[object, ...]:
        source_records = tuple(
            sorted(
                (
                    str(source.get("source_type") or ""),
                    str(source.get("record_id") or ""),
                )
                for source in item.get("sources", [])
                if source.get("record_id") is not None
            )
        )
        if source_records:
            return ("sources", *source_records)
        return (
            str(item["scope"]),
            item["case_id"] if item["scope"] == "case" else item["incident_id"],
        )

    normalized = [_normalized(item["answer"]) for item in open_results]
    exact_records: dict[str, set[tuple[object, ...]]] = {}
    for item, answer in zip(open_results, normalized):
        exact_records.setdefault(answer, set()).add(record_key(item))
    identical = sum(
        sum(answer == candidate for candidate in normalized)
        for answer, records in exact_records.items()
        if len(records) > 1
    )
    ngrams = [_ngrams(item["answer"]) for item in open_results]
    near_indexes: set[int] = set()
    for left in range(len(open_results)):
        for right in range(left + 1, len(open_results)):
            if record_key(open_results[left]) == record_key(open_results[right]):
                continue
            if _jaccard(ngrams[left], ngrams[right]) >= 0.90:
                near_indexes.update({left, right})
    safety_sentences = {_normalized(item) for item in closed_safety_sentences()}
    sentence_records: dict[str, set[tuple[object, ...]]] = {}
    sentences: list[str] = []
    for item in open_results:
        for block in item["blocks"]:
            if block["kind"] == "limitations":
                continue
            selected = [
                _normalized(sentence)
                for sentence in re.split(
                    r"(?<=[.!?])\s+(?=[A-ZÀ-Ý])",
                    block["text"],
                )
                if _normalized(sentence)
                and _normalized(sentence) not in safety_sentences
            ]
            sentences.extend(selected)
            for sentence in selected:
                sentence_records.setdefault(sentence, set()).add(record_key(item))
    sentence_counts = Counter(sentences)
    repeated = sum(
        count
        for sentence, count in sentence_counts.items()
        if len(sentence_records[sentence]) > 1
    )
    cross_results = [
        item
        for item in successful
        if AnswerIntent(item["metadata"]["assistant_intent"]) in CROSS_INTENTS
    ]
    return {
        "identical_open_responses": identical,
        "near_identical_open_responses": len(near_indexes),
        "near_identical_rate": round(
            len(near_indexes) / len(open_results) if open_results else 0.0,
            4,
        ),
        "repeated_boilerplate_sentence_rate": round(
            repeated / len(sentences) if sentences else 0.0,
            4,
        ),
        "open_grounded_section_coverage": round(
            sum(len(item["blocks"]) >= 2 for item in open_results)
            / len(open_results)
            if open_results
            else 0.0,
            4,
        ),
        "open_three_unit_coverage": round(
            sum(item["metadata"]["plan_units"] >= 3 for item in open_results)
            / len(open_results)
            if open_results
            else 0.0,
            4,
        ),
        "cross_relationship_explanation_coverage": round(
            sum(
                any(
                    block["kind"] in {"related_incidents", "analysis"}
                    for block in item["blocks"]
                )
                for item in cross_results
            )
            / len(cross_results)
            if cross_results
            else 0.0,
            4,
        ),
    }


def _structure_by_intent(results: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in results:
        if "metadata" not in item:
            continue
        grouped.setdefault(item["metadata"]["assistant_intent"], []).append(item)
    return {
        intent: {
            "count": len(items),
            "word_count": _compact_stats(
                [float(len(item["answer"].split())) for item in items]
            ),
            "section_count": _compact_stats(
                [float(len(item["blocks"])) for item in items]
            ),
            "plan_units": _compact_stats(
                [float(item["metadata"]["plan_units"]) for item in items]
            ),
            "sources_per_answer": _compact_stats(
                [float(len(item["sources"])) for item in items]
            ),
        }
        for intent, items in sorted(grouped.items())
    }


def _representative_samples(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    desired = [
        AnswerIntent.EXPLAIN,
        AnswerIntent.INVESTIGATE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.COMPARE,
        AnswerIntent.PATTERN_ANALYSIS,
        AnswerIntent.NEXT_ACTION,
        AnswerIntent.HANDOVER,
        AnswerIntent.EXECUTIVE_SUMMARY,
        AnswerIntent.SUMMARY,
        AnswerIntent.FACT_LOOKUP,
    ]
    samples: list[dict[str, Any]] = []
    for intent in desired:
        matches = [
            item
            for item in results
            if item.get("metadata", {}).get("assistant_intent") == intent.value
        ]
        if not matches:
            continue
        selected = matches[0]
        samples.append(
            {
                "intent": intent.value,
                "scope": selected["scope"],
                "incident_id": selected["incident_id"],
                "case_id": selected["case_id"],
                "question": selected["question"],
                "answer": selected["answer"],
                "followup": selected["metadata"]["conversation_followup"],
            }
        )
    followup = next(
        (
            item
            for item in results
            if item.get("metadata", {}).get("conversation_followup")
        ),
        None,
    )
    case_sample = next((item for item in results if item.get("case_id")), None)
    for label, selected in (("FOLLOW_UP", followup), ("CASE_PATTERN", case_sample)):
        if selected is not None:
            samples.append(
                {
                    "intent": label,
                    "scope": selected["scope"],
                    "incident_id": selected["incident_id"],
                    "case_id": selected["case_id"],
                    "question": selected["question"],
                    "answer": selected["answer"],
                    "followup": selected["metadata"]["conversation_followup"],
                }
            )
    return samples[:12]


def _build_report(
    *,
    incident_ids: list[int],
    case_ids: list[int],
    results: list[dict[str, Any]],
    counters_before: dict[str, float],
    counters_after: dict[str, float],
    started: float,
) -> dict[str, Any]:
    successful = [item for item in results if "metadata" in item]
    metadata = [item["metadata"] for item in successful]
    generation = [float(item["generation_ms"]) for item in metadata]
    total = [float(item["total_latency_ms"]) for item in metadata]
    gateway_delta = {
        status: counters_after.get(status, 0.0) - counters_before.get(status, 0.0)
        for status in sorted(set(counters_before) | set(counters_after))
    }
    intent_counts = Counter(item["assistant_intent"] for item in metadata)
    runtime_failures = [
        item
        for item in results
        if item.get("generation_kind") != "model"
        or item.get("metadata", {}).get("plan_validation_status") != "passed"
        or item.get("metadata", {}).get("fallback_reason") is not None
    ]
    dangling = sum(len(item.get("dangling_source_ids", [])) for item in results)
    phases = {
        name: _stats([float(item[name]) for item in metadata])
        for name in (
            "intent_routing_ms",
            "focus_routing_ms",
            "context_build_ms",
            "semantic_candidate_ms",
            "semantic_index_query_ms",
            "authoritative_rehydration_ms",
            "graph_ms",
            "schema_build_ms",
            "generation_ms",
            "plan_validation_ms",
            "rendering_ms",
            "total_latency_ms",
            "prompt_tokens",
            "structured_output_tokens",
        )
    }
    return {
        "generated_at_epoch": time.time(),
        "duration_ms": round((time.monotonic() - started) * 1000, 3),
        "dataset": {
            "unique_anchor_incidents": len(set(incident_ids[:60])),
            "incident_ids": incident_ids[:60],
            "unique_cases": len(set(case_ids)),
            "case_ids": case_ids,
            "runtime_queries": len(results),
            "cross_incident_queries": sum(
                intent_counts.get(intent.value, 0) for intent in CROSS_INTENTS
            ),
            "followup_messages": sum(
                bool(item.get("conversation_followup")) for item in metadata
            ),
            "conversation_flows": 10,
            "intent_counts": dict(sorted(intent_counts.items())),
        },
        "runtime_gates": {
            "normal_model_successes": len(results) - len(runtime_failures),
            "failures": runtime_failures,
            "dangling_visible_source_refs": dangling,
            "provider_generation_count": sum(
                int(item["provider_generation_count"]) for item in metadata
            ),
            "automatic_retries": sum(int(item["automatic_retries"]) for item in metadata),
            "model_switches": sum(int(item["model_switches"]) for item in metadata),
            "structured_output_truncations": sum(
                str(item.get("finish_reason") or "").lower()
                in {"length", "max_length", "max_tokens", "token_limit"}
                for item in metadata
            ),
        },
        "gateway_counters": {
            "before": counters_before,
            "after": counters_after,
            "delta": gateway_delta,
            "aggregate_delta": round(sum(gateway_delta.values()), 3),
        },
        "quality": _quality_summary(results),
        "structure_by_intent": _structure_by_intent(results),
        "performance": {
            "generation_ms": _stats(generation),
            "total_latency_ms": _stats(total),
            "latency_thresholds": {
                f"gt_{seconds}s": sum(value > seconds * 1000 for value in total)
                for seconds in (15, 20, 25, 35, 45)
            },
            "phases": phases,
        },
        "representative_samples": _representative_samples(results),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="/tmp/ai_assistant_v3_milestone_b_runtime.json",
    )
    parser.add_argument("--concurrency", type=int, choices=(1,), default=1)
    args = parser.parse_args()
    concurrency = args.concurrency
    socket_path = os.getenv(
        "AI_INFERENCE_GATEWAY_SOCKET",
        "/run/ai-soc/inference-gateway.sock",
    )
    started = time.monotonic()
    incident_ids, case_ids = _runtime_records()
    initial, followups, cases = _query_specs(incident_ids, case_ids)

    get_knowledge_base().embed("prewarm Assistant V3 Milestone B validation")
    intent_router = get_semantic_intent_router()
    focus_router = get_semantic_focus_router()
    questions = sorted({item.question for item in [*initial, *followups, *cases]})
    intent_selections = {question: intent_router.route(question) for question in questions}
    focus_selections = {question: focus_router.route(question) for question in questions}
    expected = {item.question: item.expected_intent for item in [*initial, *followups, *cases]}
    mismatches = {
        question: {
            "expected": expected[question].value,
            "actual": intent_selections[question].primary_intent.value,
        }
        for question in questions
        if intent_selections[question].primary_intent is not expected[question]
    }
    if mismatches:
        raise RuntimeError(f"semantic intent calibration failed: {mismatches}")

    settings = AssistantSettings(
        enabled=True,
        response_architecture="v3",
        max_context_chars=16_000,
        max_sources=8,
        semantic_limit=4,
        semantic_timeout_seconds=2.0,
        request_timeout_seconds=120.0,
        v3_max_output_tokens=384,
    )
    counters_before = _gateway_counters(socket_path)
    results = _run_phase(
        initial,
        concurrency=concurrency,
        settings=settings,
        intent_selections=intent_selections,
        focus_selections=focus_selections,
    )
    results.extend(
        _run_phase(
            followups,
            concurrency=concurrency,
            settings=settings,
            intent_selections=intent_selections,
            focus_selections=focus_selections,
        )
    )
    results.extend(
        _run_phase(
            cases,
            concurrency=concurrency,
            settings=settings,
            intent_selections=intent_selections,
            focus_selections=focus_selections,
        )
    )
    results.sort(key=lambda item: item["sequence"])
    counters_after = _gateway_counters(socket_path)
    report = _build_report(
        incident_ids=incident_ids,
        case_ids=case_ids,
        results=results,
        counters_before=counters_before,
        counters_after=counters_after,
        started=started,
    )
    output = Path(args.output)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    summary = {
        "output": str(output),
        "dataset": report["dataset"],
        "runtime_gates": {
            key: value
            for key, value in report["runtime_gates"].items()
            if key != "failures"
        },
        "failure_count": len(report["runtime_gates"]["failures"]),
        "quality": report["quality"],
        "performance": report["performance"],
        "gateway_delta": report["gateway_counters"]["delta"],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if not report["runtime_gates"]["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
