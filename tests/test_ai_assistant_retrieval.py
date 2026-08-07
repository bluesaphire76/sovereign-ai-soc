from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseAudit,
    CaseClosureChecklist,
    CaseIncident,
    Incident,
    IncidentAudit,
    IncidentCase,
)
from schemas.assistant import AssistantQueryRequest
from services.assistant.context_builder import build_assistant_context
from services.assistant.orchestrator import AssistantSettings
from services.assistant.retrieval import (
    CaseNotFound,
    IncidentNotFound,
    retrieve_assistant_context,
)
from services.assistant.sources import SourceRecord, assign_source_ids


class FakeQuery:
    def __init__(self, rows):
        self.rows = list(rows)
        self.limit_value = None

    def filter(self, *args, **kwargs):
        return self

    def join(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, value):
        self.limit_value = value
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        if self.limit_value is None:
            return list(self.rows)
        return list(self.rows[: self.limit_value])

    def count(self):
        return len(self.rows)


class FakeDb:
    def __init__(self, rows_by_model):
        self.rows_by_model = rows_by_model
        self.closed = False

    def query(self, model):
        return FakeQuery(self.rows_by_model.get(model, []))

    def close(self):
        self.closed = True


class FakeKb:
    def __init__(
        self,
        *,
        enabled=True,
        contexts=None,
        error: Exception | None = None,
        score_threshold: float | None = None,
    ):
        self.config = SimpleNamespace(
            enabled=enabled,
            score_threshold=score_threshold,
        )
        self.contexts = contexts or []
        self.error = error
        self.calls = []

    def retrieve_contexts(self, query, **kwargs):
        self.calls.append({"query": query, **kwargs})
        if self.error:
            raise self.error
        return self.contexts

    def upsert(self, *args, **kwargs):
        raise AssertionError("assistant retrieval must not write Qdrant data")

    def delete(self, *args, **kwargs):
        raise AssertionError("assistant retrieval must not delete Qdrant data")


def settings() -> AssistantSettings:
    return AssistantSettings(enabled=True, max_sources=8, semantic_limit=4)


def incident(**overrides) -> Incident:
    values = {
        "id": 245,
        "status": "NEW",
        "timestamp": "2026-07-29T10:00:00Z",
        "agent": "endpoint-1",
        "rule": "SSH brute force authentication failures",
        "level": 10,
        "mitre": "T1110",
        "risk_score": 72,
        "correlation_summary": '{"pattern": "auth burst"}',
        "correlation_score": 84,
        "attack_chain": "Initial Access",
        "correlation_type": "auth_burst",
        "escalation_reason": "Repeated failures",
        "recommended_priority": "HIGH",
        "ai_analysis": "Validate the authentication timeline.",
        "raw_alert": "full raw alert should not be included",
    }
    values.update(overrides)
    return Incident(**values)


def case(**overrides) -> IncidentCase:
    values = {
        "id": 12,
        "group_key": "case-12",
        "title": "Authentication case",
        "status": "OPEN",
        "severity": "HIGH",
        "owner": "analyst",
        "summary": "Case summary",
        "agent": "endpoint-1",
        "correlation_type": "auth_burst",
        "risk_score": 72,
    }
    values.update(overrides)
    return IncidentCase(**values)


def _retrieve_incident(**overrides):
    return retrieve_assistant_context(
        AssistantQueryRequest(
            message="Summarize the recorded severity.",
            scope="incident",
            incident_id=245,
            include_semantic_memory=False,
        ),
        db=FakeDb({Incident: [incident(**overrides)]}),
        settings=settings(),
        knowledge_base_factory=lambda: (_ for _ in ()).throw(
            AssertionError("knowledge base must not be created")
        ),
    )


def test_exact_incident_retrieval_is_bounded_and_omits_raw_alert() -> None:
    kb = FakeKb(enabled=False)
    payload = AssistantQueryRequest(message="Explain", scope="incident", incident_id=245)
    result = retrieve_assistant_context(
        payload,
        db=FakeDb(
            {
                Incident: [incident()],
                IncidentAudit: [IncidentAudit(event_type="STATUS_CHANGE", created_by="analyst")],
            }
        ),
        settings=settings(),
        knowledge_base_factory=lambda: kb,
    )

    assert result.sources[0].source_type == "incident"
    assert result.sources[0].authority == "authoritative"
    assert "Incident 245" in result.sources[0].excerpt
    assert "full raw alert should not be included" not in result.sources[0].excerpt
    assert "Raw alert omitted" in result.sources[0].excerpt
    assert "Current AI analysis" not in result.sources[0].excerpt
    assert len(result.sources[0].excerpt) < 800
    assert result.semantic_memory_attempted is False


@pytest.mark.parametrize(
    ("correlation_summary", "expected"),
    [
        ('{"risk_normalization": {"severity": "LOW"}}', "LOW"),
        ({"risk_normalization": {"severity": "MEDIUM"}}, "MEDIUM"),
        ('{"pattern": "auth burst"}', None),
        ("not-json", None),
        ('{"risk_normalization": {"severity": null}}', None),
        ('{"risk_normalization": {"severity": "  "}}', None),
        ('{"risk_normalization": {"severity": 7}}', None),
        (None, None),
    ],
)
def test_incident_risk_normalization_severity_is_extracted_safely(
    correlation_summary,
    expected,
) -> None:
    result = _retrieve_incident(correlation_summary=correlation_summary)

    assert result.fact_inventory["severity"] is None
    assert result.fact_inventory["risk_normalization_severity"] == expected


def test_incident_severity_provenance_reaches_context_without_ai_promotion() -> None:
    result = _retrieve_incident(
        correlation_summary={"risk_normalization": {"severity": "LOW"}},
        recommended_priority="LOW",
        ai_analysis="Actual severity: High",
    )
    facts = result.fact_inventory

    assert facts["severity"] is None
    assert facts["risk_normalization_severity"] == "LOW"
    assert facts["recommended_priority"] == "LOW"
    assert "ai_analysis" not in facts

    context = build_assistant_context(
        message="Summarize severity.",
        fact_inventory=facts,
        sources=result.sources,
        max_context_chars=16000,
    )
    authoritative_facts = json.loads(context.context)["authoritative_facts"]
    assert authoritative_facts["severity"] is None
    assert authoritative_facts["risk_normalization_severity"] == "LOW"
    assert authoritative_facts["recommended_priority"] == "LOW"
    assert "ai_analysis" not in authoritative_facts


def test_priority_and_persisted_ai_text_do_not_create_incident_severity() -> None:
    facts = _retrieve_incident(
        correlation_summary={"pattern": "auth burst"},
        recommended_priority="LOW",
        ai_analysis="Actual severity: High",
    ).fact_inventory

    assert facts["severity"] is None
    assert facts["risk_normalization_severity"] is None
    assert facts["recommended_priority"] == "LOW"
    assert "ai_analysis" not in facts


def test_semantic_memory_not_requested_has_no_user_limitation() -> None:
    factory_calls = 0

    def knowledge_base_factory():
        nonlocal factory_calls
        factory_calls += 1
        raise AssertionError("knowledge base must not be created")

    result = retrieve_assistant_context(
        AssistantQueryRequest(
            message="Explain the recorded status.",
            scope="incident",
            incident_id=245,
            include_semantic_memory=False,
        ),
        db=FakeDb({Incident: [incident()]}),
        settings=settings(),
        knowledge_base_factory=knowledge_base_factory,
    )

    assert result.semantic_status == "not_requested"
    assert result.semantic_degraded is False
    assert result.semantic_memory_attempted is False
    assert result.limitations == []
    assert factory_calls == 0


def test_incident_not_found_short_circuits_before_qdrant() -> None:
    kb = FakeKb()
    payload = AssistantQueryRequest(message="Explain", scope="incident", incident_id=999)

    with pytest.raises(IncidentNotFound):
        retrieve_assistant_context(
            payload,
            db=FakeDb({Incident: []}),
            settings=settings(),
            knowledge_base_factory=lambda: kb,
        )

    assert kb.calls == []


def test_case_retrieval_includes_bounded_linked_incident_summaries() -> None:
    linked = [incident(id=index) for index in range(1, 13)]
    payload = AssistantQueryRequest(message="Explain", scope="case", case_id=12, include_semantic_memory=False)
    result = retrieve_assistant_context(
        payload,
        db=FakeDb(
            {
                IncidentCase: [case()],
                CaseIncident: [CaseIncident(case_id=12, incident_id=1)],
                CaseAIAnalysis: [CaseAIAnalysis(model="m", analysis="Stored analysis")],
                CaseClosureChecklist: [CaseClosureChecklist(case_id=12, closure_decision="RESOLVED")],
                CaseAction: [CaseAction(case_id=12, title="Review auth")],
                CaseAudit: [CaseAudit(case_id=12, event_type="CASE_WORKFLOW_UPDATED")],
                Incident: linked,
            }
        ),
        settings=settings(),
    )

    linked_source = next(source for source in result.sources if source.source_type == "case_linked_incidents")
    assert "Linked incident count: 1" in result.sources[0].excerpt
    assert '"id": 10' in linked_source.excerpt
    assert '"id": 11' not in linked_source.excerpt


def test_case_not_found_short_circuits_before_qdrant() -> None:
    kb = FakeKb()
    payload = AssistantQueryRequest(message="Explain", scope="case", case_id=99)

    with pytest.raises(CaseNotFound):
        retrieve_assistant_context(
            payload,
            db=FakeDb({IncidentCase: []}),
            settings=settings(),
            knowledge_base_factory=lambda: kb,
        )

    assert kb.calls == []


def test_qdrant_advisory_sources_are_normalized() -> None:
    kb = FakeKb(
        contexts=[
            {
                "source_type": "historical_incident",
                "incident_id": 188,
                "source": "incident:188",
                "text": "Historical authentication burst.",
                "score": 0.87,
            },
            {
                "source_type": "unknown",
                "source": "ignored",
                "text": "Ignored unknown source type.",
            },
        ]
    )
    payload = AssistantQueryRequest(message="Explain", scope="incident", incident_id=245)
    result = retrieve_assistant_context(
        payload,
        db=FakeDb({Incident: [incident()]}),
        settings=settings(),
        knowledge_base_factory=lambda: kb,
    )

    advisory = [source for source in result.sources if source.authority == "advisory"]
    assert len(advisory) == 1
    assert advisory[0].source_type == "historical_incident"
    assert advisory[0].record_id == "188"
    assert advisory[0].url == "/incidents/188"
    assert advisory[0].score == 0.87
    assert result.semantic_memory_attempted is True
    assert result.semantic_memory_available is True


def test_semantic_gate_rejects_systemd_for_windows_registry_incident() -> None:
    kb = FakeKb(
        contexts=[
            {
                "source_type": "historical_incident",
                "incident_id": 300,
                "title": "systemd unit failure",
                "text": "Linux systemd service unit failed after systemctl restart.",
                "score": 0.96,
            },
            {
                "source_type": "historical_incident",
                "incident_id": 301,
                "title": "Windows Registry deletion",
                "text": "Modify Registry activity followed by File Deletion.",
                "mitre_techniques": ["T1112", "T1070.004"],
                "score": 0.84,
            },
        ]
    )
    registry_incident = incident(
        rule="Windows Registry deletion followed by File Deletion",
        mitre="T1112,T1070.004",
    )

    result = retrieve_assistant_context(
        AssistantQueryRequest(
            message="Explain the risk and correlation",
            scope="incident",
            incident_id=245,
        ),
        db=FakeDb({Incident: [registry_incident]}),
        settings=settings(),
        knowledge_base_factory=lambda: kb,
    )

    advisory = [source for source in result.sources if source.authority == "advisory"]
    assert [source.record_id for source in advisory] == ["301"]
    assert result.semantic_candidates == 2
    assert result.semantic_sources_accepted == 1
    assert result.semantic_sources_rejected == 1
    assert result.semantic_rejection_reason == "os_mismatch:1"


def test_semantic_gate_rejects_numeric_similarity_and_enforces_threshold() -> None:
    kb = FakeKb(
        score_threshold=0.8,
        contexts=[
            {
                "source_type": "historical_incident",
                "incident_id": 302,
                "text": "Risk score 72 and correlation score 84.",
                "score": 0.99,
            },
            {
                "source_type": "historical_incident",
                "incident_id": 303,
                "text": "Authentication brute force activity T1110.",
                "score": 0.4,
            },
        ],
    )

    result = retrieve_assistant_context(
        AssistantQueryRequest(
            message="Explain",
            scope="incident",
            incident_id=245,
        ),
        db=FakeDb({Incident: [incident()]}),
        settings=settings(),
        knowledge_base_factory=lambda: kb,
    )

    assert [source.authority for source in result.sources] == ["authoritative"]
    assert result.semantic_memory_attempted is True
    assert result.semantic_memory_available is False
    assert result.semantic_candidates == 2
    assert result.semantic_sources_accepted == 0
    assert result.semantic_sources_rejected == 2
    assert result.semantic_rejection_reason == (
        "below_score_threshold:1,insufficient_relevance:1"
    )


def test_zero_of_four_relevance_gate_never_invokes_generative_provider(
    monkeypatch,
) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("semantic relevance must remain LLM-free")

    monkeypatch.setattr(
        "ai_provider_abstraction.build_provider_client",
        forbidden,
    )
    monkeypatch.setattr("llm_client.generate_ai_response", forbidden)
    kb = FakeKb(
        contexts=[
            {
                "source_type": "historical_incident",
                "incident_id": 900 + index,
                "title": "systemd service failure",
                "text": "Linux systemd unit failed after systemctl restart.",
                "score": 0.99,
            }
            for index in range(4)
        ]
    )

    result = retrieve_assistant_context(
        AssistantQueryRequest(
            message="Explain the authentication risk",
            scope="incident",
            incident_id=245,
        ),
        db=FakeDb({Incident: [incident()]}),
        settings=settings(),
        knowledge_base_factory=lambda: kb,
        semantic_timeout_seconds=3,
    )

    assert result.semantic_candidates == 4
    assert result.semantic_sources_accepted == 0
    assert result.semantic_sources_rejected == 4


def test_qdrant_exception_degrades_without_losing_exact_context() -> None:
    kb = FakeKb(error=TimeoutError("qdrant timed out"))
    payload = AssistantQueryRequest(message="Explain", scope="incident", incident_id=245)
    result = retrieve_assistant_context(
        payload,
        db=FakeDb({Incident: [incident()]}),
        settings=settings(),
        knowledge_base_factory=lambda: kb,
    )

    assert [source.source_type for source in result.sources] == ["incident"]
    assert result.semantic_memory_attempted is True
    assert result.semantic_memory_available is False
    assert result.semantic_error_category == "TimeoutError"
    assert any("within its time budget" in item for item in result.limitations)
    assert result.semantic_status == "timed_out"
    assert result.semantic_degraded is True
    assert result.semantic_timeout_phase == "semantic_qdrant_timeout"


def test_source_ordering_and_context_limits_are_deterministic() -> None:
    advisory = SourceRecord("knowledge_base", "advisory", "KB", "advisory")
    authoritative = SourceRecord("incident", "authoritative", "Incident", "x" * 1400)
    sources = assign_source_ids([advisory, authoritative], max_sources=2)

    assert [source.source_id for source in sources] == ["S1", "S2"]
    assert [source.authority for source in sources] == ["authoritative", "advisory"]

    context = build_assistant_context(
        message="Explain",
        fact_inventory={
            "incident_id": 245,
            "status": "NEW",
            "summary": "x" * 1400,
        },
        sources=sources,
        max_context_chars=1000,
    )
    payload = json.loads(context.context)
    assert len(context.context) <= 1000
    assert context.limitations
    assert payload["authoritative_facts"]["incident_id"] == 245
    assert payload["authoritative_facts"]["status"] == "NEW"
    assert payload["analyst_question"] == "Explain"
    assert "[S1]" not in context.context


def test_model_context_has_stable_prefix_and_question_last() -> None:
    first_sources = assign_source_ids(
        [
            SourceRecord("knowledge_base", "advisory", "KB B", "advisory B"),
            SourceRecord("incident", "authoritative", "Incident B", "Status: NEW"),
        ],
        max_sources=2,
    )
    second_sources = assign_source_ids(
        [
            SourceRecord("incident", "authoritative", "Incident A", "Status: OPEN"),
            SourceRecord("knowledge_base", "advisory", "KB A", "advisory A"),
        ],
        max_sources=2,
    )

    first = build_assistant_context(
        message="First analyst question",
        fact_inventory={"incident_id": 245, "status": "NEW"},
        sources=first_sources,
        max_context_chars=4000,
    ).context
    second = build_assistant_context(
        message="Second analyst question",
        fact_inventory={"incident_id": 246, "status": "OPEN"},
        sources=second_sources,
        max_context_chars=4000,
    ).context

    first_payload = json.loads(first)
    second_payload = json.loads(second)
    assert list(first_payload) == [
        "advisory_context",
        "allowed_sources",
        "analyst_question",
        "authoritative_facts",
    ]
    assert first_payload["analyst_question"] == "First analyst question"
    assert second_payload["analyst_question"] == "Second analyst question"
    assert first_payload["advisory_context"][0]["label"] == "KB B"
    assert first_payload["advisory_context"][0]["source_id"] == "S2"
    assert [
        source["source_id"] for source in first_payload["allowed_sources"]
    ] == ["S1", "S2"]
    assert "allowed_citations" not in first
    assert "assistant_request_id" not in first


def test_advisory_context_is_abbreviated_before_authoritative_facts() -> None:
    authoritative = SourceRecord(
        "incident",
        "authoritative",
        "Incident 245",
        "Status: NEW\nRisk score: 72\n" + ("A" * 500),
        source_id="S1",
    )
    advisory = SourceRecord(
        "historical_incident",
        "advisory",
        "Historical incident",
        "B" * 1200,
        source_id="S2",
    )

    context = build_assistant_context(
        message="Explain",
        fact_inventory={
            "incident_id": 245,
            "status": "NEW",
            "risk_score": 72,
            "summary": "A" * 500,
        },
        sources=[authoritative, advisory],
        max_context_chars=1000,
    )

    payload = json.loads(context.context)
    assert payload["authoritative_facts"]["status"] == "NEW"
    assert payload["authoritative_facts"]["risk_score"] == 72
    assert [
        source["source_id"] for source in payload["allowed_sources"]
    ] == ["S1"]
    assert "B" * 100 not in context.context
    assert any("Advisory semantic context" in item for item in context.limitations)


def test_semantic_retrieval_receives_bounded_timeout() -> None:
    kb = FakeKb(contexts=[])
    payload = AssistantQueryRequest(
        message="Explain",
        scope="incident",
        incident_id=245,
    )

    retrieve_assistant_context(
        payload,
        db=FakeDb({Incident: [incident()]}),
        settings=settings(),
        knowledge_base_factory=lambda: kb,
        semantic_timeout_seconds=1.5,
    )

    assert kb.calls[0]["timeout_seconds"] == pytest.approx(1.5, abs=0.01)
