import unittest
from types import SimpleNamespace

from models import Incident
from routers.similar_incidents import (
    SIMILAR_INCIDENTS_DECISION_BOUNDARY,
    SIMILAR_INCIDENTS_SOURCE_TYPE,
    build_similar_incidents_response,
    serialize_similar_incident_context,
)


class FakeQuery:
    def __init__(self, incident):
        self.incident = incident

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.incident


class FakeDb:
    def __init__(self, incident):
        self.incident = incident

    def query(self, model):
        return FakeQuery(self.incident)


class FakeKnowledgeBase:
    def __init__(self, contexts=None, *, enabled=True, error=None):
        self.config = SimpleNamespace(enabled=enabled)
        self.contexts = contexts or []
        self.error = error
        self.calls = []

    def retrieve_contexts(self, query, *, limit=None, source_type=None, payload_fields=None):
        self.calls.append(
            {
                "query": query,
                "limit": limit,
                "source_type": source_type,
                "payload_fields": payload_fields,
            }
        )
        if self.error:
            raise self.error
        return self.contexts


def current_incident():
    return Incident(
        id=5100,
        status="OPEN",
        agent="endpoint-51",
        rule="Multiple failed SSH logins",
        level=10,
        mitre="T1110",
        risk_score=75,
        ai_analysis="Brute force investigation context.",
        correlation_type="auth_burst",
        attack_chain="Initial Access",
        escalation_reason="Repeated authentication failures.",
        recommended_priority="HIGH",
    )


def historical_context(incident_id, *, score=0.78, status="FALSE_POSITIVE"):
    return {
        "id": f"point-{incident_id}",
        "source_type": SIMILAR_INCIDENTS_SOURCE_TYPE,
        "source": f"incident:{incident_id}",
        "incident_id": incident_id,
        "score": score,
        "status": status,
        "risk_score": 50,
        "level": 8,
        "recommended_priority": "MEDIUM",
        "rule": "Multiple failed SSH logins",
        "agent": "server-01",
        "mitre": "T1110",
        "correlation_type": "auth_burst",
        "text": "Historical Incident Memory. Analyst reviewed similar failed SSH activity.",
    }


class SimilarIncidentsApiTests(unittest.TestCase):
    def test_builds_response_from_historical_semantic_results(self):
        kb = FakeKnowledgeBase(
            contexts=[
                historical_context(4210, score=0.78),
                historical_context(4211, score=0.74, status="CLOSED"),
            ]
        )
        response = build_similar_incidents_response(
            FakeDb(current_incident()),
            5100,
            limit=2,
            knowledge_base_factory=lambda: kb,
        )

        self.assertTrue(response["enabled"])
        self.assertEqual(response["status"], "OK")
        self.assertEqual(response["result_count"], 2)
        self.assertEqual(response["results"][0]["incident_id"], 4210)
        self.assertEqual(response["results"][0]["score"], 0.78)
        self.assertEqual(response["results"][0]["source"], "incident:4210")
        self.assertIn("Historical Incident Memory", response["results"][0]["excerpt"])
        self.assertEqual(response["decision_boundary"], SIMILAR_INCIDENTS_DECISION_BOUNDARY)

    def test_requests_only_historical_incident_source_type(self):
        kb = FakeKnowledgeBase(contexts=[historical_context(4210)])

        build_similar_incidents_response(
            FakeDb(current_incident()),
            5100,
            limit=5,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(kb.calls[0]["source_type"], SIMILAR_INCIDENTS_SOURCE_TYPE)
        self.assertIn("incident_id", kb.calls[0]["payload_fields"])
        self.assertIn("risk_score", kb.calls[0]["payload_fields"])

    def test_excludes_current_incident_from_results(self):
        kb = FakeKnowledgeBase(
            contexts=[
                historical_context(5100, score=0.99),
                historical_context(4210, score=0.78),
            ]
        )
        response = build_similar_incidents_response(
            FakeDb(current_incident()),
            5100,
            limit=5,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(response["result_count"], 1)
        self.assertEqual(response["results"][0]["incident_id"], 4210)

    def test_decision_boundary_is_present_and_prevents_operational_use(self):
        item = serialize_similar_incident_context(
            historical_context(4210),
            current_incident_id=5100,
        )

        self.assertIsNotNone(item)
        self.assertIn("historical context only", SIMILAR_INCIDENTS_DECISION_BOUNDARY)
        self.assertIn("does not mean duplicate", SIMILAR_INCIDENTS_DECISION_BOUNDARY)
        self.assertIn("must not determine severity", SIMILAR_INCIDENTS_DECISION_BOUNDARY)
        self.assertIn("must not close or suppress", SIMILAR_INCIDENTS_DECISION_BOUNDARY)

    def test_qdrant_error_returns_safe_empty_response(self):
        kb = FakeKnowledgeBase(error=RuntimeError("qdrant down"))
        response = build_similar_incidents_response(
            FakeDb(current_incident()),
            5100,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(response["status"], "WARN")
        self.assertEqual(response["result_count"], 0)
        self.assertEqual(response["results"], [])
        self.assertEqual(response["error_type"], "RuntimeError")
        self.assertIn("no operational decision", response["message"])

    def test_does_not_mutate_incident_status_or_severity_fields(self):
        incident = current_incident()
        before = (
            incident.status,
            incident.risk_score,
            incident.recommended_priority,
            incident.correlation_type,
        )
        kb = FakeKnowledgeBase(contexts=[historical_context(4210)])

        build_similar_incidents_response(
            FakeDb(incident),
            5100,
            knowledge_base_factory=lambda: kb,
        )

        after = (
            incident.status,
            incident.risk_score,
            incident.recommended_priority,
            incident.correlation_type,
        )
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
