from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

import pytest

from schemas.assistant import AssistantQueryRequest
from services.assistant.orchestrator import (
    AssistantError,
    AssistantSettings,
    get_assistant_settings,
    run_assistant_query,
)
from services.assistant.focus import FocusDimension, FocusSelection
from services.assistant.prompting import (
    ASSISTANT_SYSTEM_PROMPT,
    build_response_contract,
)
from services.assistant.retrieval import (
    IncidentNotFound,
    RetrievalResult,
)
from services.assistant.sources import SourceRecord


FACTS = {
    "source_type": "incident",
    "incident_id": 245,
    "case_id": None,
    "status": "NEW",
    "severity": "LOW",
    "wazuh_level": 5,
    "risk_score": 35,
    "correlated": True,
    "correlation_type": "PATTERN",
    "agent": "darkstar-windows",
    "mitre": [{"id": "T1112", "name": "Modify Registry"}],
    "latest_timeline_event": "ALERT_CREATED",
    "compromise_confirmed": False,
}


class _Db:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _StaticFocusRouter:
    def __init__(self, selection: FocusSelection) -> None:
        self.selection = selection
        self.calls: list[str] = []

    def route(self, analyst_question: str) -> FocusSelection:
        self.calls.append(analyst_question)
        return self.selection


def _focus(*dimensions: FocusDimension) -> FocusSelection:
    selected = dimensions or (FocusDimension.GENERAL,)
    return FocusSelection(
        dimensions=selected,
        scores={dimension: 1.0 for dimension in selected},
        confidence=1.0,
    )


def _settings(**overrides: Any) -> AssistantSettings:
    values = {
        "enabled": True,
        "max_message_chars": 2000,
        "max_context_chars": 16000,
        "max_sources": 8,
        "semantic_limit": 4,
        "semantic_timeout_seconds": 2,
        "request_timeout_seconds": 30,
        "max_output_tokens": 384,
    }
    values.update(overrides)
    return AssistantSettings(**values)


def test_settings_use_dedicated_assistant_request_timeout(monkeypatch) -> None:
    monkeypatch.setenv("AI_INFERENCE_REQUEST_TIMEOUT_SECONDS", "35")
    monkeypatch.delenv(
        "AI_SOC_ASSISTANT_REQUEST_TIMEOUT_SECONDS",
        raising=False,
    )

    assert get_assistant_settings().request_timeout_seconds == 45

    monkeypatch.setenv("AI_SOC_ASSISTANT_REQUEST_TIMEOUT_SECONDS", "52")
    assert get_assistant_settings().request_timeout_seconds == 52


def _retrieval(*, advisory: bool = False) -> RetrievalResult:
    sources = [
        SourceRecord(
            source_type="incident",
            authority="authoritative",
            record_id="245",
            label="Incident 245",
            url="/incidents/245",
            excerpt="Incident 245 status NEW severity LOW risk score 35.",
        )
    ]
    if advisory:
        sources.append(
            SourceRecord(
                source_type="detection_control",
                authority="advisory",
                record_id="registry-control",
                label="Registry control",
                url="/settings/detection-control",
                excerpt="Registry telemetry should be reviewed for persistence.",
            )
        )
    return RetrievalResult(
        scope="incident",
        incident_id=245,
        fact_inventory=dict(FACTS),
        sources=sources,
        semantic_memory_requested=advisory,
        semantic_memory_attempted=advisory,
        semantic_memory_available=advisory,
        semantic_status="ok" if advisory else "not_requested",
    )


def _english_output(*, advisory: bool = False) -> dict[str, Any]:
    claims = [
        {
            "claim_type": "RECORDED_FACT",
            "field": "status",
            "value": "NEW",
            "provenance": "recorded_operational",
            "source_ids": ["S1"],
        },
        {
            "claim_type": "RECORDED_FACT",
            "field": "severity",
            "value": "LOW",
            "provenance": "canonical_incident",
            "source_ids": ["S1"],
        },
        {
            "claim_type": "RECORDED_FACT",
            "field": "risk_score",
            "value": 35,
            "provenance": "recorded_operational",
            "source_ids": ["S1"],
        },
        {
            "claim_type": "RECORDED_FACT",
            "field": "correlated",
            "value": True,
            "provenance": "recorded_operational",
            "source_ids": ["S1"],
        },
        {
            "claim_type": "NON_IMPLICATION",
            "subject": "correlation",
            "object": "compromise",
            "source_ids": [],
        },
    ]
    if advisory:
        claims.append(
            {
                "claim_type": "ADVISORY_GUIDANCE",
                "guidance_code": "review_related_telemetry",
                "source_ids": ["S2"],
            }
        )
    return {
        "claims": claims,
        "next_check": None,
        "limitations": [],
        "used_advisory_context": advisory,
    }


def _italian_output() -> dict[str, Any]:
    return _english_output()


def _run(
    monkeypatch,
    generator,
    *,
    message: str = "Explain the risk and correlation.",
    retrieval: RetrievalResult | None = None,
    focus: FocusSelection | None = None,
):
    selected = retrieval or _retrieval()
    monkeypatch.setattr(
        "services.assistant.orchestrator.retrieve_assistant_context",
        lambda *args, **kwargs: selected,
    )
    db = _Db()
    response = run_assistant_query(
        AssistantQueryRequest(
            message=message,
            scope="incident",
            incident_id=selected.incident_id or 245,
            include_semantic_memory=selected.semantic_memory_requested,
        ),
        settings=_settings(),
        db_factory=lambda: db,
        knowledge_base_factory=lambda: None,
        generator=generator,
        focus_router=_StaticFocusRouter(focus or _focus()),
    )
    assert db.closed is True
    return response


def test_system_prompt_requires_typed_claims_and_severity_provenance() -> None:
    assert "read-only claim extraction component" in ASSISTANT_SYSTEM_PROMPT
    assert "Do not write prose" in ASSISTANT_SYSTEM_PROMPT
    assert "RECORDED_FACT" in ASSISTANT_SYSTEM_PROMPT
    assert "DISTINCT_VALUE" in ASSISTANT_SYSTEM_PROMPT
    assert "risk-normalization severity" in ASSISTANT_SYSTEM_PROMPT
    assert "canonical severity" in ASSISTANT_SYSTEM_PROMPT


def test_response_contract_for_live_c_is_fact_bound_and_focused() -> None:
    contract = build_response_contract(
        focus=_focus(
            FocusDimension.RISK,
            FocusDimension.CORRELATION,
            FocusDimension.SEVERITY,
        ),
        fact_inventory={
            "source_type": "incident",
            "incident_id": 5299,
            "severity": None,
            "risk_score": 35,
            "risk_normalization_severity": "LOW",
            "correlated": True,
            "correlation_score": 35,
            "correlation_type": "SINGLE_HOST_PATTERN_CORRELATION",
        },
        response_language="en",
    )
    assert "Selected focus dimensions: risk, correlation, severity" in contract
    assert "risk_score" in contract
    assert "correlation_type" in contract
    assert "severity" in contract
    assert "canonical_incident" in contract
    assert "risk_normalization" in contract
    assert "correlation->compromise" in contract


def test_response_contract_uses_dynamic_values_and_omits_unrelated_facts() -> None:
    contract = build_response_contract(
        focus=_focus(
            FocusDimension.RISK,
            FocusDimension.CORRELATION,
            FocusDimension.SEVERITY,
        ),
        fact_inventory={
            "incident_id": 7002,
            "risk_score": 72,
            "severity": "HIGH",
            "risk_normalization_severity": "MEDIUM",
            "correlated": True,
            "correlation_type": "MULTI_SIGNAL",
            "rule": "UNRELATED_RULE_VALUE",
            "agent": "unrelated-host-value",
            "status": "UNRELATED_STATUS_VALUE",
            "recommended_priority": "UNRELATED_PRIORITY_VALUE",
            "latest_timeline_event": "UNRELATED_TIMELINE_VALUE",
        },
        response_language="en",
    )
    lowered = contract.lower()

    assert "risk_score" in lowered
    assert "severity" in lowered
    assert "risk_normalization_severity" in lowered
    assert "correlation_type" in lowered
    assert "risk_score 35" not in lowered
    assert "single_host_pattern_correlation" not in lowered
    for unrelated in (
        "unrelated_rule_value",
        "unrelated-host-value",
        "unrelated_status_value",
        "unrelated_priority_value",
        "unrelated_timeline_value",
    ):
        assert unrelated not in lowered


def test_grounded_model_response_uses_one_fixed_gateway_generation(
    monkeypatch,
) -> None:
    calls = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {
            "structured_output": _english_output(),
            "finish_reason": "stop",
            "queue_wait_ms": 12,
            "generation_ms": 450,
        }

    response = _run(monkeypatch, generator)

    assert len(calls) == 1
    assert calls[0]["requested_mode"] == "standard"
    assert calls[0]["output_schema"] == "assistant_grounded_v2"
    structured_schema = calls[0]["structured_output_schema"]
    claim_variants = structured_schema["$defs"]["GroundedClaim"]["oneOf"]
    schema_fields = {
        variant["properties"].get("field", {}).get("const")
        for variant in claim_variants
    } - {None}
    assert schema_fields <= set(FACTS)
    assert all(
        variant["properties"]["claim_type"]["const"]
        != "ADVISORY_GUIDANCE"
        for variant in claim_variants
    )
    required_claims = structured_schema["properties"]["claims"]["prefixItems"]
    required_fields = {
        item["properties"]["field"]["const"] for item in required_claims
    }
    assert required_fields <= set(FACTS)
    assert "source_type" not in required_fields
    assert "incident_id" not in required_fields
    assert calls[0]["user_triggered"] is True
    assert "[s#" not in str(calls[0]).lower()
    assert "allowed_citations" not in str(calls[0]).lower()
    assert "Do not write prose" in calls[0]["messages"][0]["content"]
    assert "DERIVATION" in calls[0]["messages"][0]["content"]
    assert response.status == "ok"
    assert response.generation_kind == "model"
    assert response.metadata.grounding_validation == "passed"
    assert response.metadata.focus_validation == "passed"
    assert response.metadata.queue_wait_ms == 12
    assert response.metadata.generation_ms == 450
    assert [block.kind for block in response.blocks] == [
        "direct_answer",
        "analysis",
    ]
    assert response.sources[0].source_id == "S1"
    assert all(block.source_ids == ["S1"] for block in response.blocks)


def test_advisory_generation_uses_fixed_facts_and_typed_next_check(
    monkeypatch,
) -> None:
    calls = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {
            "structured_output": {
                "claims": [
                    {
                        "claim_type": "STRUCTURED_REFERENCE",
                        "field": "latest_timeline_event",
                        "provenance": "recorded_evidence",
                        "source_ids": ["S1"],
                    },
                    {
                        "claim_type": "STRUCTURED_REFERENCE",
                        "field": "mitre",
                        "provenance": "recorded_evidence",
                        "source_ids": ["S1"],
                    },
                    {
                        "claim_type": "RECORDED_FACT",
                        "field": "compromise_confirmed",
                        "value": False,
                        "provenance": "explicit_assessment",
                        "source_ids": ["S1"],
                    },
                ],
                "next_check": {
                    "check_type": "review_advisory_source",
                    "guidance_code": "follow_recorded_playbook",
                    "source_ids": ["S2"],
                },
                "limitations": [],
                "used_advisory_context": True,
            },
            "finish_reason": "stop",
        }

    response = _run(
        monkeypatch,
        generator,
        retrieval=replace(
            _retrieval(advisory=True),
            fact_inventory={
                **FACTS,
                "latest_timeline_event": {"event_type": "ALERT_CREATED"},
            },
        ),
        focus=_focus(FocusDimension.EVIDENCE),
    )

    claims_schema = calls[0]["structured_output_schema"]["properties"]["claims"]
    assert [
        claim["properties"]["field"]["const"]
        for claim in claims_schema["prefixItems"]
    ] == ["latest_timeline_event", "mitre", "compromise_confirmed"]
    assert claims_schema["minItems"] == claims_schema["maxItems"] == 3
    assert "items" not in claims_schema
    assert response.status == "ok"
    assert response.metadata.grounding_validation == "passed"
    assert response.metadata.focus_validation == "passed"
    assert [source.authority for source in response.sources] == [
        "authoritative",
        "advisory",
    ]
    assert response.blocks[-1].kind == "next_check"
    assert response.blocks[-1].source_ids == ["S2"]


@pytest.mark.parametrize(
    ("structured_output", "finish_reason", "reason"),
    [
        (
            {"unexpected": "shape"},
            "stop",
            "invalid_structured_claim_schema",
        ),
        (
            {
                "claims": [
                    {
                        "claim_type": "RECORDED_FACT",
                        "field": "risk_band",
                        "value": "MODERATE",
                        "provenance": "recorded_operational",
                        "source_ids": ["S1"],
                    }
                ],
                "next_check": None,
                "limitations": [],
                "used_advisory_context": False,
            },
            "stop",
            "grounding_validation_failed",
        ),
        (_english_output(), "length", "invalid_structured_output"),
    ],
)
def test_invalid_or_truncated_output_uses_one_deterministic_fallback(
    monkeypatch,
    structured_output,
    finish_reason,
    reason,
) -> None:
    calls = 0

    def generator(**kwargs):
        nonlocal calls
        calls += 1
        return {
            "structured_output": structured_output,
            "finish_reason": finish_reason,
        }

    response = _run(monkeypatch, generator)

    assert calls == 1
    assert response.status == "fallback"
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.fallback_reason == reason
    assert len(response.blocks) >= 1
    assert response.sources[0].source_id == "S1"
    assert all("[S" not in block.text for block in response.blocks)


def test_gateway_failure_is_safe_and_does_not_claim_model_attribution(
    monkeypatch,
) -> None:
    response = _run(
        monkeypatch,
        lambda **kwargs: {
            "text": "",
            "safe_error": "gateway_unavailable",
            "error_type": "gateway_unavailable",
        },
    )

    assert response.status == "fallback"
    assert response.metadata.fallback_reason == "gateway_unavailable"
    assert response.metadata.effective_profile == "standard"
    assert response.metadata.effective_model == "ai-soc-standard"
    assert response.generation_kind == "deterministic_fallback"


@pytest.mark.parametrize(
    ("safe_error", "expected_reason"),
    [
        ("queue_deadline_exceeded", "queue_deadline_exceeded"),
        ("generation_timeout", "generation_timeout"),
        ("invalid_visible_output", "invalid_visible_output"),
        ("invalid_json", "invalid_json"),
        ("invalid_json_type", "invalid_json_type"),
    ],
)
def test_gateway_failure_reasons_remain_distinct(
    monkeypatch,
    safe_error,
    expected_reason,
) -> None:
    response = _run(
        monkeypatch,
        lambda **kwargs: {
            "text": "",
            "safe_error": safe_error,
            "error_type": safe_error,
        },
    )

    assert response.status == "fallback"
    assert response.metadata.fallback_reason == expected_reason


def test_context_budget_failure_skips_generation_and_falls_back(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "services.assistant.orchestrator.build_assistant_context",
        lambda **kwargs: (_ for _ in ()).throw(
            ValueError("oversized authoritative context")
        ),
    )
    calls = 0

    def generator(**kwargs):
        nonlocal calls
        calls += 1
        return {"structured_output": _english_output()}

    response = _run(monkeypatch, generator)

    assert calls == 0
    assert response.status == "fallback"
    assert response.metadata.fallback_reason == "invalid_structured_output"
    assert "oversized authoritative context" not in str(response.model_dump())
    assert any(
        "model context budget" in limitation.lower()
        for limitation in response.limitations
    )


def test_advisory_source_is_attached_only_when_declared_and_used(
    monkeypatch,
) -> None:
    retrieval = _retrieval(advisory=True)
    response = _run(
        monkeypatch,
        lambda **kwargs: {
            "structured_output": _english_output(advisory=True),
            "finish_reason": "stop",
        },
        retrieval=retrieval,
    )

    assert response.status == "ok"
    assert [source.source_id for source in response.sources] == ["S1", "S2"]
    direct = next(
        block for block in response.blocks if block.kind == "direct_answer"
    )
    analysis = next(
        block for block in response.blocks if block.kind == "analysis"
    )
    assert direct.source_ids == ["S1"]
    assert analysis.source_ids == ["S1", "S2"]


def test_not_requested_semantic_memory_has_no_response_limitation(
    monkeypatch,
) -> None:
    retrieval = _retrieval()
    retrieval.limitations.append(
        "Semantic memory was not requested for this assistant query."
    )

    response = _run(
        monkeypatch,
        lambda **kwargs: {
            "structured_output": _english_output(),
            "finish_reason": "stop",
        },
        retrieval=retrieval,
    )

    assert response.metadata.semantic_status == "not_requested"
    assert response.metadata.semantic_degraded is False
    assert response.limitations == []


@pytest.mark.parametrize(
    (
        "semantic_status",
        "semantic_degraded",
        "raw_limitation",
        "expected_limitation",
    ),
    [
        (
            "timed_out",
            True,
            (
                "Semantic memory was unavailable within its time budget; the "
                "answer uses authoritative platform data."
            ),
            (
                "La memoria semantica non era disponibile entro il tempo "
                "previsto; la risposta usa i dati autorevoli della piattaforma."
            ),
        ),
        (
            "disabled",
            False,
            "Semantic memory is disabled; continuing without advisory context.",
            (
                "La memoria semantica è disabilitata; la risposta usa i dati "
                "autorevoli della piattaforma."
            ),
        ),
        (
            "failed",
            True,
            (
                "Semantic memory retrieval failed safely; exact operational "
                "facts remain usable."
            ),
            (
                "Il recupero dalla memoria semantica non è riuscito; i fatti "
                "operativi autorevoli restano disponibili."
            ),
        ),
    ],
)
def test_semantic_limitations_match_the_actual_state_in_italian(
    monkeypatch,
    semantic_status,
    semantic_degraded,
    raw_limitation,
    expected_limitation,
) -> None:
    retrieval = replace(
        _retrieval(),
        semantic_memory_requested=True,
        semantic_memory_attempted=semantic_status != "disabled",
        semantic_status=semantic_status,
        semantic_degraded=semantic_degraded,
        limitations=[raw_limitation],
    )

    response = _run(
        monkeypatch,
        lambda **kwargs: {
            "structured_output": _italian_output(),
            "finish_reason": "stop",
        },
        message="Spiega il rischio e la correlazione dell'incidente.",
        retrieval=retrieval,
    )

    assert response.metadata.semantic_status == semantic_status
    assert response.metadata.semantic_degraded is semantic_degraded
    assert response.limitations == [expected_limitation]
    if semantic_status in {"disabled", "failed"}:
        assert "tempo previsto" not in response.limitations[0]


def test_live_b1_response_uses_one_grounding_fallback_without_inferences(
    monkeypatch,
) -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 9001,
        "status": "NEW",
        "severity": "LOW",
        "risk_score": 35,
        "agent": "darkstar-windows",
        "compromise_confirmed": False,
    }
    retrieval = RetrievalResult(
        scope="incident",
        incident_id=9001,
        fact_inventory=facts,
        sources=[
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id="9001",
                label="Incident 9001",
                url="/incidents/9001",
                excerpt="Incident 9001 status NEW severity LOW risk score 35.",
            )
        ],
    )
    live_output = {
        "claims": [
            {
                "claim_type": "RECORDED_FACT",
                "field": "risk_band",
                "value": "MODERATE",
                "provenance": "recorded_operational",
                "source_ids": ["S1"],
            }
        ],
        "next_check": None,
        "limitations": [],
        "used_advisory_context": False,
    }
    calls = 0

    def generator(**kwargs):
        nonlocal calls
        calls += 1
        return {"structured_output": live_output, "finish_reason": "stop"}

    response = _run(
        monkeypatch,
        generator,
        message="Summarize the current incident status and risk.",
        retrieval=retrieval,
    )

    assert calls == 1
    assert response.status == "fallback"
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.grounding_validation == "failed"
    assert response.metadata.fallback_reason == "grounding_validation_failed"
    answer = " ".join(block.text for block in response.blocks).lower()
    assert "9001" in answer
    assert "new" in answer
    assert "low" in answer
    assert "35" in answer
    assert "recently detected" not in answer
    assert "moderate risk" not in answer
    assert "immediate high threat" not in answer
    assert "correlation" not in answer
    assert "compromise" not in answer
    assert "agent" not in answer
    assert "timeline" not in answer
    assert all(block.kind != "next_check" for block in response.blocks)


def test_live_b2_derivation_uses_one_focused_grounding_fallback(
    monkeypatch,
) -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 5299,
        "status": "NEW",
        "severity": "LOW",
        "risk_score": 35,
    }
    retrieval = RetrievalResult(
        scope="incident",
        incident_id=5299,
        fact_inventory=facts,
        sources=[
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id="5299",
                label="Incident 5299",
                url="/incidents/5299",
                excerpt="Incident 5299 status NEW severity LOW risk score 35.",
            )
        ],
        limitations=[
            "Semantic memory was not requested for this assistant query."
        ],
        semantic_status="not_requested",
        semantic_degraded=False,
    )
    live_output = {
        "claims": [
            {
                "claim_type": "DERIVATION",
                "field": "risk_score",
                "provenance": "recorded_operational",
                "source_ids": ["S1"],
                "derived_from": ["correlation_score"],
            }
        ],
        "next_check": None,
        "limitations": [],
        "used_advisory_context": False,
    }
    calls = 0

    def generator(**kwargs):
        nonlocal calls
        calls += 1
        return {"structured_output": live_output, "finish_reason": "stop"}

    response = _run(
        monkeypatch,
        generator,
        message=(
            "Riepiloga esclusivamente lo stato, la severità e il punteggio di "
            "rischio registrati per questo incidente. Non aggiungere "
            "interpretazioni qualitative e non proporre controlli successivi."
        ),
        retrieval=retrieval,
        focus=_focus(
            FocusDimension.RISK,
            FocusDimension.SEVERITY,
            FocusDimension.STATUS,
        ),
    )

    assert calls == 1
    assert response.status == "fallback"
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.grounding_validation == "failed"
    assert response.metadata.fallback_reason == "grounding_validation_failed"
    assert response.metadata.semantic_status == "not_requested"
    assert response.metadata.semantic_degraded is False
    answer = " ".join(block.text for block in response.blocks).lower()
    assert "5299" in answer
    assert "new" in answer
    assert "low" in answer
    assert "35" in answer
    assert "normalizz" not in answer
    assert "metod" not in answer
    assert "derivat" not in answer
    assert all(block.kind != "next_check" for block in response.blocks)
    assert response.limitations == []


def test_live_b3_ambiguous_severity_uses_one_provenance_aware_fallback(
    monkeypatch,
) -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 5299,
        "status": "NEW",
        "severity": None,
        "risk_score": 35,
        "risk_normalization_severity": "LOW",
        "recommended_priority": "LOW",
        "ai_analysis": "Actual severity: High",
    }
    retrieval = RetrievalResult(
        scope="incident",
        incident_id=5299,
        fact_inventory=facts,
        sources=[
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id="5299",
                label="Incident 5299",
                url="/incidents/5299",
                excerpt="Incident 5299 status NEW risk score 35.",
            )
        ],
        semantic_status="not_requested",
        semantic_degraded=False,
    )
    ambiguous_output = {
        "claims": [
            {
                "claim_type": "RECORDED_FACT",
                "field": "severity",
                "value": "LOW",
                "provenance": "canonical_incident",
                "source_ids": ["S1"],
            }
        ],
        "next_check": None,
        "limitations": [],
        "used_advisory_context": False,
    }
    calls = 0

    def generator(**kwargs):
        nonlocal calls
        calls += 1
        return {
            "structured_output": ambiguous_output,
            "finish_reason": "stop",
        }

    response = _run(
        monkeypatch,
        generator,
        message=(
            "Riepiloga esclusivamente lo stato, la severità e il punteggio di "
            "rischio registrati per questo incidente."
        ),
        retrieval=retrieval,
        focus=_focus(
            FocusDimension.RISK,
            FocusDimension.SEVERITY,
            FocusDimension.STATUS,
        ),
    )

    assert calls == 1
    assert response.status == "fallback"
    assert response.generation_kind == "deterministic_fallback"
    assert response.metadata.grounding_validation == "failed"
    assert response.metadata.fallback_reason == "grounding_validation_failed"
    answer = " ".join(block.text for block in response.blocks).lower()
    assert "5299" in answer
    assert "new" in answer
    assert "35" in answer
    assert "severità canonica" in answer
    assert "normalizzazione del rischio registra severità low" in answer
    assert "priority" not in answer
    assert "priorità" not in answer
    assert "high" not in answer
    assert "correlazione" not in answer
    assert "comprom" not in answer
    assert "timeline" not in answer
    assert "agent" not in answer
    assert all(block.kind != "next_check" for block in response.blocks)


def test_live_c_compliant_severity_provenance_remains_model_direct(
    monkeypatch,
) -> None:
    facts = {
        "source_type": "incident",
        "incident_id": 5299,
        "status": "NEW",
        "severity": None,
        "risk_score": 35,
        "risk_normalization_severity": "LOW",
        "correlated": True,
        "correlation_score": 35,
        "correlation_type": "SINGLE_HOST_PATTERN_CORRELATION",
        "recommended_priority": "LOW",
        "rule": "Registry Key Integrity Checksum Changed",
        "agent": "darkstar-windows",
        "latest_timeline_event": "ALERT_CREATED",
        "escalation_reason": None,
    }
    retrieval = RetrievalResult(
        scope="incident",
        incident_id=5299,
        fact_inventory=facts,
        sources=[
            SourceRecord(
                source_type="incident",
                authority="authoritative",
                record_id="5299",
                label="Incident 5299",
                url="/incidents/5299",
                excerpt=(
                    "Incident 5299 status NEW risk score 35 correlation "
                    "SINGLE_HOST_PATTERN_CORRELATION."
                ),
            )
        ],
        semantic_status="not_requested",
        semantic_degraded=False,
    )
    compliant_output = {
        "claims": [
            {
                "claim_type": "RECORDED_FACT",
                "field": "risk_score",
                "value": 35,
                "provenance": "recorded_operational",
                "source_ids": ["S1"],
            },
            {
                "claim_type": "RECORDED_FACT",
                "field": "correlated",
                "value": True,
                "provenance": "recorded_operational",
                "source_ids": ["S1"],
            },
            {
                "claim_type": "RECORDED_FACT",
                "field": "correlation_type",
                "value": "SINGLE_HOST_PATTERN_CORRELATION",
                "provenance": "recorded_operational",
                "source_ids": ["S1"],
            },
            {
                "claim_type": "RECORDED_FACT",
                "field": "correlation_score",
                "value": 35,
                "provenance": "recorded_operational",
                "source_ids": ["S1"],
            },
            {
                "claim_type": "ABSENCE",
                "field": "severity",
                "provenance": "canonical_incident",
                "source_ids": ["S1"],
            },
            {
                "claim_type": "DISTINCT_VALUE",
                "field": "risk_normalization_severity",
                "value": "LOW",
                "provenance": "risk_normalization",
                "source_ids": ["S1"],
            },
            {
                "claim_type": "NON_IMPLICATION",
                "subject": "correlation",
                "object": "compromise",
            },
            {
                "claim_type": "NON_IMPLICATION",
                "subject": "correlation",
                "object": "causality",
            },
        ],
        "next_check": None,
        "limitations": [],
        "used_advisory_context": False,
    }
    calls = []

    def generator(**kwargs):
        calls.append(kwargs)
        return {
            "structured_output": compliant_output,
            "finish_reason": "stop",
        }

    response = _run(
        monkeypatch,
        generator,
        message=(
            "Explain the risk and correlation without changing the recorded "
            "severity."
        ),
        retrieval=retrieval,
        focus=_focus(
            FocusDimension.RISK,
            FocusDimension.CORRELATION,
            FocusDimension.SEVERITY,
        ),
    )

    assert len(calls) == 1
    response_contract = calls[0]["messages"][0]["content"]
    model_context = json.loads(calls[0]["messages"][1]["content"])
    assert "risk_score" in response_contract
    assert "correlation_type" in response_contract
    assert "provenance=canonical_incident" in response_contract
    assert model_context["authoritative_facts"] == {
        "correlated": True,
        "correlation_score": 35,
        "correlation_type": "SINGLE_HOST_PATTERN_CORRELATION",
        "incident_id": 5299,
        "risk_normalization_severity": "LOW",
        "risk_score": 35,
        "severity": None,
        "source_type": "incident",
    }
    assert model_context["allowed_sources"] == [
        {
            "authority": "authoritative",
            "label": "Incident 5299",
            "source_id": "S1",
            "source_type": "incident",
        }
    ]
    assert calls[0]["context"]["focus_dimensions"] == [
        "risk",
        "correlation",
        "severity",
    ]
    assert calls[0]["context"]["focus_degraded"] is False
    assert calls[0]["context"]["focus_routing_ms"] == 0.0
    assert response.status == "ok"
    assert response.generation_kind == "model"
    assert response.metadata.grounding_validation == "passed"
    assert response.metadata.focus_validation == "passed"
    assert response.metadata.fallback_reason is None


def test_italian_response_is_accepted_and_fallback_preserves_language(
    monkeypatch,
) -> None:
    italian_output = _italian_output()
    response = _run(
        monkeypatch,
        lambda **kwargs: {
            "structured_output": italian_output,
            "finish_reason": "stop",
        },
        message=(
            "Spiega il rischio e la correlazione senza modificare la severità "
            "registrata."
        ),
    )
    assert response.status == "ok"
    assert response.metadata.response_language == "it"

    fallback = _run(
        monkeypatch,
        lambda **kwargs: {
            "safe_error": "gateway_unavailable",
            "text": "",
        },
        message="Quale host è registrato per questo incidente?",
        focus=_focus(FocusDimension.HOST),
    )
    assert fallback.status == "fallback"
    assert fallback.metadata.response_language == "it"
    assert "agente registrato" in fallback.blocks[0].text.lower()
    assert "darkstar-windows" in fallback.blocks[0].text


def test_disabled_and_missing_scope_errors_remain_safe(monkeypatch) -> None:
    payload = AssistantQueryRequest(
        message="Explain",
        scope="incident",
        incident_id=245,
    )
    with pytest.raises(AssistantError) as disabled:
        run_assistant_query(
            payload,
            settings=_settings(enabled=False),
            db_factory=_Db,
        )
    assert disabled.value.status_code == 503

    monkeypatch.setattr(
        "services.assistant.orchestrator.retrieve_assistant_context",
        lambda *args, **kwargs: (_ for _ in ()).throw(IncidentNotFound()),
    )
    with pytest.raises(AssistantError) as missing:
        run_assistant_query(
            payload,
            settings=_settings(),
            db_factory=_Db,
        )
    assert missing.value.status_code == 404
