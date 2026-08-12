from __future__ import annotations

import pytest

from scripts.validate_assistant_v3_milestone_b import (
    QuerySpec,
    _quality_summary,
    _query_specs,
    _run_phase,
)
from services.assistant.v3.contracts import AnswerIntent


def test_runtime_matrix_rejects_concurrency_against_serial_gateway() -> None:
    with pytest.raises(ValueError, match="serial validation"):
        _run_phase(
            [],
            concurrency=2,
            settings=None,
            intent_selections={},
            focus_selections={},
        )


def test_runtime_matrix_cools_only_between_measured_queries(monkeypatch) -> None:
    specs = [
        QuerySpec(
            sequence=index,
            expected_intent=AnswerIntent.EXPLAIN,
            question=f"question-{index}",
            scope="incident",
            incident_id=index + 1,
        )
        for index in range(2)
    ]
    sleeps: list[float] = []
    monkeypatch.setattr(
        "scripts.validate_assistant_v3_milestone_b._run_spec",
        lambda spec, **_kwargs: {"sequence": spec.sequence},
    )
    monkeypatch.setattr(
        "scripts.validate_assistant_v3_milestone_b.time.sleep",
        sleeps.append,
    )

    results = _run_phase(
        specs,
        concurrency=1,
        settings=None,
        intent_selections={},
        focus_selections={},
        inter_query_delay_seconds=1.25,
    )

    assert results == [{"sequence": 0}, {"sequence": 1}]
    assert sleeps == [1.25]


def test_runtime_matrix_uses_twenty_followups_within_store_owner_bound() -> None:
    initial, followups, cases = _query_specs(list(range(1, 101)), [1, 2, 3, 4])

    initial_conversations = {
        item.conversation_id for item in initial if item.conversation_id
    }
    followup_conversations = [item.conversation_id for item in followups]

    assert len(initial) == 60
    assert len(followups) == 20
    assert len(cases) == 20
    assert len({item.case_id for item in cases}) == 4
    assert len([*initial, *followups, *cases]) == 100
    assert sum(bool(item.compare_incident_ids) for item in [*initial, *followups]) == 10
    assert len(initial_conversations) == 10
    assert set(followup_conversations) == initial_conversations
    assert all(followup_conversations.count(item) == 2 for item in initial_conversations)
    assert all(item.expected_followup for item in followups)


def _quality_item(
    *,
    incident_id: int,
    answer: str,
    text: str,
    sources: list[dict] | None = None,
) -> dict:
    return {
        "scope": "incident",
        "incident_id": incident_id,
        "case_id": None,
        "answer": answer,
        "blocks": [{"kind": "analysis", "text": text}],
        "sources": sources or [],
        "metadata": {
            "assistant_intent": "EXPLAIN",
            "plan_units": 3,
        },
    }


def test_quality_metrics_compare_distinct_records_and_exclude_closed_safety() -> None:
    safety = "Correlation does not by itself establish compromise."
    results = [
        _quality_item(
            incident_id=1,
            answer="same",
            text=f"Shared prose. Unique one. {safety}",
        ),
        _quality_item(
            incident_id=1,
            answer="same",
            text=f"Shared prose. Unique one. {safety}",
        ),
        _quality_item(
            incident_id=2,
            answer="different",
            text=f"Shared prose. Unique two. {safety}",
        ),
    ]

    quality = _quality_summary(results)

    assert quality["identical_open_responses"] == 0
    assert quality["repeated_boilerplate_sentence_rate"] == pytest.approx(0.5)


def test_quality_metrics_treat_same_evidence_set_as_same_record_context() -> None:
    source = [{"source_type": "incident", "record_id": "7"}]
    incident = _quality_item(
        incident_id=7,
        answer="same grounded answer",
        text="Same grounded answer.",
        sources=source,
    )
    case = {
        **_quality_item(
            incident_id=0,
            answer="same grounded answer",
            text="Same grounded answer.",
            sources=source,
        ),
        "scope": "case",
        "incident_id": None,
        "case_id": 3,
    }

    quality = _quality_summary([incident, case])

    assert quality["identical_open_responses"] == 0
    assert quality["repeated_boilerplate_sentence_rate"] == 0


def test_quality_metrics_detect_raw_payload_and_explicit_compare_drift() -> None:
    result = _quality_item(
        incident_id=1,
        answer="Evidence follows. {'raw_payload': 1}. Final point.",
        text="Evidence follows. {'raw_payload': 1}. Final point.",
        sources=[
            {"source_type": "incident", "record_id": "1"},
            {"source_type": "incident", "record_id": "3"},
        ],
    )
    result["compare_incident_ids"] = [2]

    quality = _quality_summary([result])

    assert quality["raw_advisory_payload_count"] == 1
    assert quality["compare_scope_drift_count"] == 1


def test_quality_metrics_support_explicit_case_comparison_without_anchor() -> None:
    result = _quality_item(
        incident_id=0,
        answer="Case comparison uses the selected records. Evidence differs.",
        text="Case comparison uses the selected records. Evidence differs.",
        sources=[
            {"source_type": "incident", "record_id": "1"},
            {"source_type": "incident", "record_id": "2"},
        ],
    )
    result.update(
        {
            "scope": "case",
            "incident_id": None,
            "case_id": 7,
            "compare_incident_ids": [1, 2],
        }
    )

    quality = _quality_summary([result])

    assert quality["compare_scope_drift_count"] == 0


def test_cross_relationship_coverage_includes_v3_comparison_and_pattern_blocks() -> None:
    comparison = _quality_item(
        incident_id=1,
        answer="The selected records differ in their recorded status.",
        text="The selected records differ in their recorded status.",
        sources=[
            {"source_type": "incident", "record_id": "1"},
            {"source_type": "incident", "record_id": "2"},
        ],
    )
    comparison["metadata"]["assistant_intent"] = "COMPARE"
    comparison["blocks"][0]["kind"] = "comparison"
    comparison["compare_incident_ids"] = [2]

    pattern = _quality_item(
        incident_id=3,
        answer="A shared rule is recorded across the related incidents.",
        text="A shared rule is recorded across the related incidents.",
        sources=[
            {"source_type": "incident", "record_id": "3"},
            {"source_type": "incident", "record_id": "4"},
        ],
    )
    pattern["metadata"]["assistant_intent"] = "PATTERN_ANALYSIS"
    pattern["blocks"][0]["kind"] = "pattern"

    quality = _quality_summary([comparison, pattern])

    assert quality["cross_relationship_explanation_coverage"] == 1.0
