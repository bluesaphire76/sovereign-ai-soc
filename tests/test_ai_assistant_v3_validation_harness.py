from __future__ import annotations

import pytest

from scripts.validate_assistant_v3_milestone_b import (
    _quality_summary,
    _query_specs,
    _run_phase,
)


def test_runtime_matrix_rejects_concurrency_against_serial_gateway() -> None:
    with pytest.raises(ValueError, match="serial validation"):
        _run_phase(
            [],
            concurrency=2,
            settings=None,
            intent_selections={},
            focus_selections={},
        )


def test_runtime_matrix_uses_twenty_followups_within_store_owner_bound() -> None:
    initial, followups, cases = _query_specs(list(range(1, 101)), [1, 2, 3, 4])

    initial_conversations = {
        item.conversation_id for item in initial if item.conversation_id
    }
    followup_conversations = [item.conversation_id for item in followups]

    assert len(initial) == 60
    assert len(followups) == 20
    assert len(cases) == 4
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
