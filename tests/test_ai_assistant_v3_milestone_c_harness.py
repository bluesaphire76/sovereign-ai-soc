from __future__ import annotations

from scripts.eval_assistant_v3 import (
    NvidiaThermalGate,
    RuntimeDataset,
    _acceptance_summary,
    _acceptance_phase,
    _adversarial_phase,
    _phase_gate_failures,
    _performance,
    _quality_phase,
)
from services.assistant.v3.contracts import AnswerIntent


def _dataset() -> RuntimeDataset:
    return RuntimeDataset(
        incident_ids=tuple(range(1, 181)),
        case_ids=(1, 2, 3, 4, 5, 6, 7, 8),
        case_incident_ids={value: (value, value + 20) for value in range(1, 9)},
        diversity={},
    )


def test_thermal_gate_waits_between_requests_until_gpu_is_below_threshold() -> None:
    temperatures = iter((82.0, 78.0, 74.0))
    elapsed = 0.0

    def clock() -> float:
        return elapsed

    def sleep(seconds: float) -> None:
        nonlocal elapsed
        elapsed += seconds

    gate = NvidiaThermalGate(
        maximum_celsius=75.0,
        poll_seconds=2.0,
        temperature_reader=lambda: next(temperatures),
        sleeper=sleep,
        clock=clock,
    )

    gate.wait()

    assert gate.report() == {
        "enabled": True,
        "maximum_celsius": 75.0,
        "maximum_observed_celsius": 82.0,
        "wait_count": 1,
        "total_wait_seconds": 4.0,
    }


def test_thermal_gate_fails_closed_when_temperature_is_unavailable() -> None:
    gate = NvidiaThermalGate(
        maximum_celsius=75.0,
        temperature_reader=lambda: None,
    )

    try:
        gate.wait()
    except RuntimeError as exc:
        assert "temperature is unavailable" in str(exc)
    else:
        raise AssertionError("thermal gate must fail closed")


def test_quality_phase_uses_real_record_slots_and_seeded_followups() -> None:
    phase = _quality_phase(_dataset())

    assert len(phase.specs) == 155
    assert len({spec.incident_id for spec in phase.specs if spec.incident_id}) >= 100
    assert len({spec.case_id for spec in phase.specs if spec.case_id}) >= 5
    assert sum(spec.expected_followup for spec in phase.specs) == 25
    assert sum(bool(spec.compare_incident_ids) for spec in phase.specs) == 20
    seeded = {
        spec.conversation_id
        for spec in phase.specs
        if not spec.expected_followup and spec.conversation_id
    }
    assert all(
        spec.conversation_id in seeded
        for spec in phase.specs
        if spec.expected_followup
    )


def test_adversarial_phase_covers_records_and_conversation_poisoning_pairs() -> None:
    phase = _adversarial_phase(_dataset())

    assert len(phase.specs) >= 80
    assert len({spec.incident_id for spec in phase.specs}) >= 40
    assert any(spec.expected_followup for spec in phase.specs)
    seeded = {
        spec.conversation_id
        for spec in phase.specs
        if not spec.expected_followup and spec.conversation_id
    }
    assert all(
        spec.conversation_id in seeded
        for spec in phase.specs
        if spec.expected_followup
    )


def test_acceptance_phase_meets_scale_and_intent_distribution() -> None:
    phase = _acceptance_phase(_dataset())
    intent_counts = {
        intent: sum(spec.expected_intent is intent for spec in phase.specs)
        for intent in AnswerIntent
    }

    assert len(phase.specs) == 250
    assert all(count >= 10 for count in intent_counts.values())
    assert sum(spec.expected_intent in {
        AnswerIntent.COMPARE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.PATTERN_ANALYSIS,
    } for spec in phase.specs) == 80
    assert sum(spec.expected_followup for spec in phase.specs) == 50
    assert sum(bool(spec.compare_incident_ids) for spec in phase.specs) == 30
    assert len({spec.case_id for spec in phase.specs if spec.case_id}) >= 5
    assert len({spec.incident_id for spec in phase.specs if spec.incident_id}) >= 150
    positions = {
        spec.conversation_id: index
        for index, spec in enumerate(phase.specs)
        if spec.conversation_id and not spec.expected_followup
    }
    assert all(
        index == positions[spec.conversation_id] + 1
        for index, spec in enumerate(phase.specs)
        if spec.expected_followup
    )


def test_performance_report_contains_required_phase_and_cohort_timings() -> None:
    metadata = {
        "assistant_intent": "FACT_LOOKUP",
        "conversation_followup": False,
        "generation_ms": 10,
        "total_latency_ms": 20,
        "prompt_tokens": 100,
        "schema_chars": 200,
        "structured_output_tokens": 30,
        "finish_reason": "stop",
    }
    result = _performance([{"metadata": metadata}])

    assert result["requests"] == 1
    assert result["cohorts"]["fact_lookup"]["count"] == 1
    assert result["generation_ms"]["p99"] == 10
    for phase in (
        "intent_routing_ms",
        "scope_resolution_ms",
        "operational_retrieval_ms",
        "semantic_index_query_ms",
        "authoritative_rehydration_ms",
        "generation_ms",
        "plan_validation_ms",
        "rendering_ms",
        "total_latency_ms",
    ):
        assert phase in result["phases"]


def test_acceptance_summary_separates_matrix_targets_from_effective_routing() -> None:
    phase = _acceptance_phase(_dataset())
    results = [
        {
            "scope": spec.scope,
            "incident_id": spec.incident_id,
            "case_id": spec.case_id,
            "compare_incident_ids": list(spec.compare_incident_ids),
            "metadata": {
                "assistant_intent": "SUMMARY",
                "conversation_followup": spec.expected_followup,
                "plan_units": 3,
                "response_language": "it" if spec.sequence % 2 else "en",
            },
            "sources": [],
            "blocks": [],
            "answer": "Grounded summary.",
            "dangling_source_ids": [],
        }
        for spec in phase.specs
    ]

    summary = _acceptance_summary(phase.specs, results)

    assert summary["cross_incident"] == 80
    assert summary["unique_incidents"] >= 150
    assert summary["unique_visible_incidents"] == 0
    assert summary["intent_counts"] == {"SUMMARY": 250}
    assert all(
        count >= 10 for count in summary["expected_intent_counts"].values()
    )


def test_acceptance_gate_rejects_grounding_and_quality_placeholders() -> None:
    acceptance = {
        "runtime_queries": 250,
        "unique_incidents": 150,
        "unique_cases": 5,
        "cross_incident": 80,
        "followups": 50,
        "explicit_comparisons": 30,
        "advisory_next_action": 30,
        "executive_handover": 25,
        "italian": 125,
        "english": 125,
        "intent_counts": {intent.value: 25 for intent in AnswerIntent},
        "grounding": {
            "unsupported_claims": 1,
            "authority_violations": 0,
            "dangling_refs": 0,
            "qdrant_only_operational_claims": 0,
            "semantic_to_correlation": 0,
            "relationship_to_causality": 0,
            "advisory_to_fact": 0,
            "reference_to_state": 0,
            "invented_severity": 0,
            "invented_risk_band": 0,
            "invented_escalation": 0,
            "invented_compromise": 0,
            "invented_actor_campaign": 0,
        },
        "quality": {
            "compare_scope_drift_count": 0,
            "raw_advisory_payload_count": 0,
            "field_list_like_rate": 0.0,
            "limitation_first_rate": 0.0,
            "single_sentence_open_answer_rate": 0.0,
            "near_identical_rate": 0.0,
        },
    }

    failures = _phase_gate_failures(
        {"acceptance": {"acceptance": acceptance}}
    )

    assert {"acceptance": "grounding gate failure"} in failures
