import unittest
from types import SimpleNamespace

from pydantic import ValidationError

from api import is_request_authorized
from routers.detection_quality import (
    DETECTION_QUALITY_SEMANTIC_DECISION_BOUNDARY,
    DetectionQualitySemanticContextRequest,
    build_detection_quality_semantic_context,
)


class FakeKnowledgeBase:
    def __init__(self, contexts=None, *, enabled=True, error=None):
        self.config = SimpleNamespace(enabled=enabled)
        self.contexts = contexts or []
        self.error = error
        self.calls = []
        self.mutation_calls = []

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

    def create_rule(self, *args, **kwargs):
        self.mutation_calls.append(("create_rule", args, kwargs))
        raise AssertionError("semantic context must not create rules")

    def apply_config(self, *args, **kwargs):
        self.mutation_calls.append(("apply_config", args, kwargs))
        raise AssertionError("semantic context must not apply config")


def payload():
    return DetectionQualitySemanticContextRequest(
        rule="Multiple failed SSH logins",
        recommended_action="Review brute force threshold and false positive handling",
        evidence="Several failed login events from same source",
        mitre="T1110",
        agent="demo-host",
        severity="MEDIUM",
    )


def knowledge_base_context():
    return {
        "source_type": "knowledge_base",
        "source": "knowledge_base/security_playbook.md",
        "score": 0.82,
        "text": "SSH brute force playbook: validate accepted logins after failures.",
        "chunk_index": 1,
    }


def historical_false_positive_context():
    return {
        "source_type": "historical_incident",
        "source": "incident:4210",
        "incident_id": 4210,
        "status": "FALSE_POSITIVE",
        "score": 0.77,
        "risk_score": 40,
        "rule": "Multiple failed SSH logins",
        "agent": "server-01",
        "mitre": "T1110",
        "text": "Historical Incident Memory: benign maintenance noise after SSH checks.",
    }


def historical_tuning_context():
    return {
        "source_type": "historical_incident",
        "source": "incident:4211",
        "incident_id": 4211,
        "status": "CLOSED",
        "score": 0.73,
        "risk_score": 65,
        "rule": "Multiple failed SSH logins",
        "agent": "server-02",
        "mitre": "T1110",
        "text": "Historical Incident Memory: threshold review required analyst validation.",
    }


class DetectionQualitySemanticContextTests(unittest.TestCase):
    def test_endpoint_context_separates_knowledge_base_and_historical_incidents(self):
        kb = FakeKnowledgeBase(
            contexts=[
                knowledge_base_context(),
                historical_false_positive_context(),
                historical_tuning_context(),
            ]
        )

        result = build_detection_quality_semantic_context(
            payload(),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["result_count"], 3)
        self.assertEqual(len(result["related_playbooks"]), 1)
        self.assertEqual(len(result["similar_false_positives"]), 1)
        self.assertEqual(len(result["similar_tuning_examples"]), 1)
        self.assertEqual(
            result["related_playbooks"][0]["source"],
            "knowledge_base/security_playbook.md",
        )
        self.assertEqual(result["similar_false_positives"][0]["incident_id"], 4210)
        self.assertEqual(result["similar_tuning_examples"][0]["incident_id"], 4211)

    def test_decision_boundary_is_advisory_and_forbids_tuning_mutation(self):
        kb = FakeKnowledgeBase(contexts=[knowledge_base_context()])
        result = build_detection_quality_semantic_context(
            payload(),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(
            result["decision_boundary"],
            DETECTION_QUALITY_SEMANTIC_DECISION_BOUNDARY,
        )
        self.assertIn("advisory only", result["decision_boundary"])
        self.assertIn("must not create, update, approve or apply", result["decision_boundary"])
        self.assertIn("Human validation", result["decision_boundary"])

    def test_context_request_does_not_call_mutation_functions(self):
        kb = FakeKnowledgeBase(contexts=[knowledge_base_context()])

        build_detection_quality_semantic_context(
            payload(),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(len(kb.calls), 1)
        self.assertEqual(kb.mutation_calls, [])
        self.assertEqual(kb.calls[0]["source_type"], None)
        self.assertIn("incident_id", kb.calls[0]["payload_fields"])

    def test_qdrant_unavailable_returns_safe_warning(self):
        kb = FakeKnowledgeBase(error=RuntimeError("qdrant unavailable"))
        result = build_detection_quality_semantic_context(
            payload(),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "WARN")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(result["related_playbooks"], [])
        self.assertEqual(result["similar_false_positives"], [])
        self.assertEqual(result["similar_tuning_examples"], [])
        self.assertEqual(result["error_type"], "RuntimeError")
        self.assertIn("no detection-control change", result["message"])

    def test_disabled_semantic_memory_returns_safe_disabled_response(self):
        kb = FakeKnowledgeBase(enabled=False)
        result = build_detection_quality_semantic_context(
            payload(),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "DISABLED")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(kb.calls, [])

    def test_payload_rejects_overly_large_input(self):
        with self.assertRaises(ValidationError):
            DetectionQualitySemanticContextRequest(
                rule="x" * 501,
                recommended_action="Review",
                evidence="Evidence",
            )

    def test_rbac_allows_operators_and_denies_viewers(self):
        self.assertTrue(
            is_request_authorized(
                "POST",
                "/detection-quality/semantic-context",
                {"role": "ANALYST"},
            )
        )
        self.assertFalse(
            is_request_authorized(
                "POST",
                "/detection-quality/semantic-context",
                {"role": "VIEWER"},
            )
        )


if __name__ == "__main__":
    unittest.main()
