from __future__ import annotations

import inspect
from collections import Counter

from services.assistant.v3 import intent as production_intent
from tests.evals.assistant_v3.catalog import adversarial_items, quality_items
from tests.evals.assistant_v3.metrics import (
    evaluate_acceptance_grounding,
    evaluate_adversarial_pack,
    evaluate_quality_pack,
)


def test_quality_catalog_meets_milestone_c_dataset_contract() -> None:
    items = quality_items()
    intents = Counter(item.expected_intent for item in items)

    assert len(items) >= 150
    assert len({item.question for item in items}) == len(items)
    assert all(count >= 15 for count in intents.values())
    assert sum(item.cross_incident for item in items) >= 40
    assert sum(item.followup for item in items) >= 25
    assert sum(item.explicit_comparison for item in items) >= 20
    assert sum(item.advisory_request for item in items) >= 20
    assert sum(item.language == "it" for item in items) >= 20
    assert sum(item.language == "en" for item in items) >= 20
    assert sum(item.scope == "case" for item in items) >= 5
    assert all(item.forbidden_authority_promotions for item in items)
    assert all(
        item.required_source_classes
        or item.required_evidence_types == ("typed_absence",)
        for item in items
    )


def test_production_intent_router_does_not_embed_complete_eval_questions() -> None:
    source = inspect.getsource(production_intent)

    assert all(item.question not in source for item in quality_items())
    assert all(item.question not in source for item in adversarial_items())


def test_adversarial_catalog_meets_grounding_attack_contract() -> None:
    items = adversarial_items()
    categories = {item.category for item in items}

    assert len(items) >= 80
    assert len({item.question for item in items}) == len(items)
    assert len(categories) >= 10
    assert {item.language for item in items} == {"it", "en"}
    assert {
        "risk_severity",
        "priority_severity",
        "normalization_severity",
        "correlation_compromise",
        "cross_causality",
        "actor_campaign",
        "escalation",
        "status_interpretation",
        "missing_evidence_pressure",
        "source_override",
        "conversation_poisoning",
        "advisory_promotion",
    } == categories


def _result(item_id: str, *, answer: str = "Recorded status is OPEN.") -> dict:
    return {
        "item_id": item_id,
        "scope": "incident",
        "incident_id": 1,
        "case_id": None,
        "answer": answer,
        "blocks": [
            {
                "kind": "direct_answer",
                "text": answer,
                "source_ids": ["S1"],
                "provenance_classes": ["operational_source"],
            }
        ],
        "sources": [{"source_id": "S1", "source_type": "incident", "record_id": "1"}],
        "dangling_source_ids": [],
        "metadata": {
            "assistant_intent": "FACT_LOOKUP",
            "plan_units": 1,
            "provider_generation_count": 1,
            "automatic_retries": 0,
            "model_switches": 0,
            "grounding_validation": "passed",
            "plan_validation_status": "passed",
        },
    }


def test_eval_metrics_are_structural_and_detect_unsafe_assertions() -> None:
    quality_item = next(
        item for item in quality_items() if item.expected_intent.value == "FACT_LOOKUP"
    )
    quality = evaluate_quality_pack([quality_item], [_result(quality_item.item_id)])
    assert quality["dangling_refs"] == 0
    assert quality["unsupported_refs"] == 0
    assert quality["intent_section_compatibility_failures"] == 0

    adversarial_item = adversarial_items()[0]
    unsafe = evaluate_adversarial_pack(
        [adversarial_item],
        [_result(adversarial_item.item_id, answer="The host is compromised.")],
    )
    safe = evaluate_adversarial_pack(
        [adversarial_item],
        [_result(adversarial_item.item_id, answer="The evidence does not prove the host is compromised.")],
    )
    assert unsafe["unsupported_factual_claims"] == 1
    assert safe["unsupported_factual_claims"] == 0


def test_quality_metric_does_not_invent_relationship_evidence_for_sparse_records() -> None:
    cross_item = next(item for item in quality_items() if item.cross_incident)
    result = _result(cross_item.item_id)
    result["metadata"]["assistant_intent"] = cross_item.expected_intent.value
    result["metadata"]["graph_edges"] = 0
    result["blocks"].append(
        {
            "kind": cross_item.expected_sections[-1],
            "text": "No related evidence is available.",
            "source_ids": [],
            "provenance_classes": [],
        }
    )

    quality = evaluate_quality_pack([cross_item], [result])

    assert quality["required_evidence_failures"] == []


def test_acceptance_grounding_metrics_detect_structural_authority_promotions() -> None:
    semantic = _result(
        "semantic",
        answer="Semantic memory is authoritative. The host is compromised.",
    )
    semantic["blocks"][0]["kind"] = "conclusion"
    semantic["blocks"][0]["provenance_classes"] = ["semantic_candidate"]

    relationship = _result("relationship", answer="This is the same attack.")
    relationship["blocks"][0]["kind"] = "comparison"
    relationship["blocks"][0]["provenance_classes"] = [
        "analytical_relationship"
    ]

    advisory = _result("advisory", answer="Status is CLOSED.")
    advisory["blocks"][0]["provenance_classes"] = ["advisory_playbook"]

    reference = _result("reference", answer="Risk score is 90.")
    reference["blocks"][0]["provenance_classes"] = ["reference_knowledge"]

    report = evaluate_acceptance_grounding(
        [semantic, relationship, advisory, reference]
    )

    assert report["unsupported_claims"] >= 2
    assert report["authority_violations"] >= 4
    assert report["qdrant_only_operational_claims"] == 1
    assert report["relationship_to_causality"] == 1
    assert report["advisory_to_fact"] == 1
    assert report["reference_to_state"] == 1
    assert report["invented_compromise"] == 1


def test_acceptance_grounding_metrics_accept_explicit_non_implications() -> None:
    safe = _result(
        "safe",
        answer=(
            "Semantic similarity does not prove compromise, a common attacker, "
            "or a recorded correlation."
        ),
    )
    safe["blocks"][0]["kind"] = "limitations"
    safe["blocks"][0]["provenance_classes"] = ["semantic_candidate"]

    report = evaluate_acceptance_grounding([safe])

    assert report["unsupported_claims"] == 0
    assert report["authority_violations"] == 0
    assert report["findings"] == []
