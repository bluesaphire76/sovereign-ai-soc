import unittest
from types import SimpleNamespace

from api import is_request_authorized
from detection_control_semantic_context import (
    CASE_CLOSURE_SOURCE_TYPE,
    DETECTION_CONTROL_CONTEXT_DECISION_BOUNDARY,
    DETECTION_CONTROL_SOURCE_TYPE,
    HISTORICAL_INCIDENT_SOURCE_TYPE,
    KNOWLEDGE_BASE_SOURCE_TYPE,
    DetectionControlSemanticContextRequest,
    build_detection_control_semantic_context,
)


class FakeKnowledgeBase:
    def __init__(self, contexts_by_source=None, *, enabled=True, error=None):
        self.config = SimpleNamespace(enabled=enabled)
        self.contexts_by_source = contexts_by_source or {}
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
        return list(self.contexts_by_source.get(source_type, []))[: limit or 25]

    def create_detection_control_rule(self, *args, **kwargs):
        self.mutation_calls.append(("create_detection_control_rule", args, kwargs))
        raise AssertionError("semantic context must not create detection controls")

    def apply_detection_control(self, *args, **kwargs):
        self.mutation_calls.append(("apply_detection_control", args, kwargs))
        raise AssertionError("semantic context must not apply detection controls")


def payload(**overrides):
    base = {
        "current_rule_id": "dcr-current",
        "name": "Scanner noise suppression",
        "type": "NOISE_SUPPRESSION",
        "status": "ACTIVE",
        "scope": "global",
        "matcher_kind": "CONTAINS",
        "matcher_value": "scanner maintenance window",
        "reason": "Reviewed scanner noise during maintenance.",
        "owner": "soc-admin",
        "enabled": True,
        "description": "Suppress reviewed scanner authentication noise.",
        "metadata": {"inventory_category": "exceptions"},
    }
    base.update(overrides)
    return DetectionControlSemanticContextRequest(**base)


def detection_context(rule_id="dcr-other"):
    return {
        "source_type": DETECTION_CONTROL_SOURCE_TYPE,
        "source": f"detection_control:{rule_id}",
        "rule_id": rule_id,
        "rule_type": "NOISE_SUPPRESSION",
        "name": "Existing scanner suppression",
        "status": "ACTIVE",
        "enabled": True,
        "scope": "global",
        "matcher_kind": "CONTAINS",
        "score": 0.82,
        "text": "Detection Control Semantic Memory for scanner maintenance noise.",
    }


def closure_context(case_id=7):
    return {
        "source_type": CASE_CLOSURE_SOURCE_TYPE,
        "source": f"case_closure:{case_id}",
        "case_id": case_id,
        "case_title": "Scanner false positive",
        "case_status": "CLOSED",
        "closure_decision": "FALSE_POSITIVE",
        "final_severity": "HIGH",
        "closure_approved": True,
        "score": 0.78,
        "text": "Case closure marked false positive after scanner review.",
    }


def historical_context(incident_id=9001):
    return {
        "source_type": HISTORICAL_INCIDENT_SOURCE_TYPE,
        "source": f"incident:{incident_id}",
        "incident_id": incident_id,
        "risk_score": 82,
        "rule": "Multiple failed SSH logins",
        "recommended_priority": "HIGH",
        "score": 0.74,
        "text": "Historical incident with scanner-like authentication burst.",
    }


class DetectionControlSemanticContextTests(unittest.TestCase):
    def test_groups_semantic_context_without_mutating_detection_state(self):
        kb = FakeKnowledgeBase(
            contexts_by_source={
                DETECTION_CONTROL_SOURCE_TYPE: [
                    detection_context("dcr-current"),
                    detection_context("dcr-other"),
                ],
                CASE_CLOSURE_SOURCE_TYPE: [closure_context()],
                HISTORICAL_INCIDENT_SOURCE_TYPE: [historical_context()],
                KNOWLEDGE_BASE_SOURCE_TYPE: [
                    {
                        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
                        "source": "knowledge_base/detection_noise_tuning_guide.md",
                        "score": 0.69,
                        "text": "Noise tuning requires narrow scope and reviewed evidence.",
                    }
                ],
            }
        )

        result = build_detection_control_semantic_context(
            payload(),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["result_count"], 4)
        self.assertEqual(len(result["similar_detection_controls"]), 1)
        self.assertEqual(result["similar_detection_controls"][0]["rule_id"], "dcr-other")
        self.assertEqual(len(result["similar_case_closures"]), 1)
        self.assertEqual(len(result["similar_historical_incidents"]), 1)
        self.assertEqual(len(result["related_playbooks"]), 1)
        self.assertEqual(kb.mutation_calls, [])
        self.assertEqual(
            {call["source_type"] for call in kb.calls},
            {
                DETECTION_CONTROL_SOURCE_TYPE,
                CASE_CLOSURE_SOURCE_TYPE,
                HISTORICAL_INCIDENT_SOURCE_TYPE,
                KNOWLEDGE_BASE_SOURCE_TYPE,
            },
        )

    def test_decision_boundary_and_warnings_prevent_operational_use(self):
        kb = FakeKnowledgeBase(
            contexts_by_source={
                DETECTION_CONTROL_SOURCE_TYPE: [detection_context()],
                CASE_CLOSURE_SOURCE_TYPE: [closure_context()],
                HISTORICAL_INCIDENT_SOURCE_TYPE: [historical_context()],
            }
        )

        result = build_detection_control_semantic_context(
            payload(matcher_value=".*"),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["decision_boundary"], DETECTION_CONTROL_CONTEXT_DECISION_BOUNDARY)
        self.assertIn("must not create", result["decision_boundary"])
        self.assertTrue(any("overlapping scope" in warning for warning in result["warnings"]))
        self.assertTrue(any("Global scope" in warning for warning in result["warnings"]))
        self.assertTrue(any("broad" in warning for warning in result["warnings"]))
        self.assertTrue(any("HIGH/CRITICAL" in warning for warning in result["warnings"]))
        self.assertTrue(any("high-risk" in warning for warning in result["warnings"]))

    def test_disabled_semantic_memory_returns_safe_empty_response(self):
        kb = FakeKnowledgeBase(enabled=False)

        result = build_detection_control_semantic_context(
            payload(),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "DISABLED")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(kb.calls, [])

    def test_qdrant_error_returns_safe_warning(self):
        kb = FakeKnowledgeBase(error=RuntimeError("qdrant down"))

        result = build_detection_control_semantic_context(
            payload(),
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "WARN")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(result["error_type"], "RuntimeError")
        self.assertIn("no Detection Control", result["message"])

    def test_rbac_allows_operators_and_denies_viewers(self):
        self.assertTrue(
            is_request_authorized(
                "POST",
                "/detection-control/semantic-context",
                {"role": "ANALYST"},
            )
        )
        self.assertFalse(
            is_request_authorized(
                "POST",
                "/detection-control/semantic-context",
                {"role": "VIEWER"},
            )
        )


if __name__ == "__main__":
    unittest.main()
