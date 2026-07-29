from __future__ import annotations

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
    def __init__(self, *, enabled=True, contexts=None, error: Exception | None = None):
        self.config = SimpleNamespace(enabled=enabled)
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
    assert result.semantic_memory_attempted is False


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
    assert any("failed safely" in item for item in result.limitations)


def test_source_ordering_and_context_limits_are_deterministic() -> None:
    advisory = SourceRecord("knowledge_base", "advisory", "KB", "advisory")
    authoritative = SourceRecord("incident", "authoritative", "Incident", "x" * 1400)
    sources = assign_source_ids([advisory, authoritative], max_sources=2)

    assert [source.source_id for source in sources] == ["S1", "S2"]
    assert [source.authority for source in sources] == ["authoritative", "advisory"]

    context = build_assistant_context(
        message="Explain",
        sources=sources,
        max_context_chars=500,
        max_excerpt_chars=200,
    )
    assert len(context.context) <= 500
    assert context.limitations
