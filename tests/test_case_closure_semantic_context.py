import unittest
from types import SimpleNamespace

from api import is_request_authorized
from models import CaseAIAnalysis, CaseAction, CaseClosureChecklist, Incident, IncidentCase
from routers.case_closure_semantic_context import (
    CASE_CLOSURE_CONTEXT_DECISION_BOUNDARY,
    CASE_CLOSURE_SOURCE_TYPE,
    DETECTION_CONTROL_SOURCE_TYPE,
    HISTORICAL_INCIDENT_SOURCE_TYPE,
    KNOWLEDGE_BASE_SOURCE_TYPE,
    build_case_closure_semantic_context,
)


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows if isinstance(rows, list) else [rows] if rows else []

    def filter(self, *args, **kwargs):
        return self

    def join(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def limit(self, *_args, **_kwargs):
        return self

    def first(self):
        return self.rows[0] if self.rows else None

    def all(self):
        return self.rows

    def count(self):
        return len(self.rows)


class FakeDb:
    def __init__(
        self,
        *,
        case,
        closure=None,
        incidents=None,
        actions=None,
        open_actions=None,
        latest_analysis=None,
    ):
        self.case = case
        self.closure = closure
        self.incidents = incidents or []
        self.actions = actions or []
        self.open_actions = open_actions if open_actions is not None else []
        self.latest_analysis = latest_analysis

    def query(self, model):
        if model is IncidentCase:
            return FakeQuery(self.case)
        if model is CaseClosureChecklist:
            return FakeQuery(self.closure)
        if model is Incident:
            return FakeQuery(self.incidents)
        if model is CaseAction:
            if self.open_actions:
                return FakeQuery(self.open_actions)
            return FakeQuery(self.actions)
        if model is CaseAIAnalysis:
            return FakeQuery(self.latest_analysis)
        return FakeQuery([])


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

    def close_case(self, *args, **kwargs):
        self.mutation_calls.append(("close_case", args, kwargs))
        raise AssertionError("semantic context must not close cases")

    def apply_detection_control(self, *args, **kwargs):
        self.mutation_calls.append(("apply_detection_control", args, kwargs))
        raise AssertionError("semantic context must not apply detection controls")


def case():
    return IncidentCase(
        id=42,
        group_key="case-42",
        title="SSH brute force closure review",
        status="INVESTIGATING",
        severity="LOW",
        severity_review="LOW",
        risk_score=30,
        summary="Multiple failed SSH logins reviewed as possible scanner noise.",
        correlation_type="auth_burst",
    )


def closure():
    return CaseClosureChecklist(
        case_id=42,
        root_cause="Expected scanner activity.",
        evidence_reviewed="Wazuh alerts and scanner schedule.",
        actions_summary="Reviewed authentication pattern.",
        closure_reason="Benign scanner activity.",
        closure_decision="RESOLVED",
        final_severity="LOW",
        residual_risk="Low residual risk accepted.",
        closure_approved=True,
    )


def incident():
    return Incident(
        id=9001,
        rule="Multiple failed SSH logins",
        agent="server-01",
        mitre="T1110",
        correlation_type="auth_burst",
        risk_score=35,
        recommended_priority="MEDIUM",
    )


def action(status="DONE"):
    return CaseAction(
        id=1,
        case_id=42,
        title="Review scanner activity",
        description="Validate scanner maintenance window.",
        category="INVESTIGATION",
        priority="MEDIUM",
        status=status,
    )


def analysis():
    return CaseAIAnalysis(
        case_id=42,
        analysis="AI analysis says this resembles scanner authentication noise.",
        recommended_status="TRIAGED",
        recommended_severity="LOW",
    )


def closure_context(case_id=7, *, decision="FALSE_POSITIVE", final_severity="HIGH"):
    return {
        "source_type": CASE_CLOSURE_SOURCE_TYPE,
        "source": f"case_closure:{case_id}",
        "case_id": case_id,
        "case_title": "Historical scanner false positive",
        "case_status": "CLOSED",
        "case_severity": "MEDIUM",
        "closure_decision": decision,
        "final_severity": final_severity,
        "closure_approved": True,
        "score": 0.81,
        "text": "Case Closure Semantic Memory with reviewed scanner closure.",
    }


class CaseClosureSemanticContextTests(unittest.TestCase):
    def test_groups_semantic_context_without_mutating_case_state(self):
        kb = FakeKnowledgeBase(
            contexts_by_source={
                CASE_CLOSURE_SOURCE_TYPE: [
                    closure_context(case_id=42, decision="RESOLVED", final_severity="LOW"),
                    closure_context(case_id=7),
                ],
                DETECTION_CONTROL_SOURCE_TYPE: [
                    {
                        "source_type": DETECTION_CONTROL_SOURCE_TYPE,
                        "source": "detection_control:dcr-test",
                        "rule_id": "dcr-test",
                        "rule_type": "NOISE_SUPPRESSION",
                        "name": "Scanner noise suppression",
                        "score": 0.73,
                        "text": "Detection Control Semantic Memory for scanner noise.",
                    }
                ],
                HISTORICAL_INCIDENT_SOURCE_TYPE: [
                    {
                        "source_type": HISTORICAL_INCIDENT_SOURCE_TYPE,
                        "source": "incident:9000",
                        "incident_id": 9000,
                        "status": "FALSE_POSITIVE",
                        "score": 0.7,
                        "text": "Historical Incident Memory for scanner activity.",
                    }
                ],
                KNOWLEDGE_BASE_SOURCE_TYPE: [
                    {
                        "source_type": KNOWLEDGE_BASE_SOURCE_TYPE,
                        "source": "knowledge_base/case_closure_policy.md",
                        "score": 0.66,
                        "text": "Case closure policy requires human approval.",
                    }
                ],
            }
        )

        result = build_case_closure_semantic_context(
            FakeDb(
                case=case(),
                closure=closure(),
                incidents=[incident()],
                actions=[action()],
                latest_analysis=analysis(),
            ),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "OK")
        self.assertEqual(result["result_count"], 4)
        self.assertEqual(len(result["similar_closures"]), 1)
        self.assertEqual(result["similar_closures"][0]["case_id"], 7)
        self.assertEqual(len(result["related_detection_controls"]), 1)
        self.assertEqual(len(result["similar_historical_incidents"]), 1)
        self.assertEqual(len(result["related_playbooks"]), 1)
        self.assertEqual(kb.mutation_calls, [])
        self.assertEqual(
            {call["source_type"] for call in kb.calls},
            {
                CASE_CLOSURE_SOURCE_TYPE,
                DETECTION_CONTROL_SOURCE_TYPE,
                HISTORICAL_INCIDENT_SOURCE_TYPE,
                KNOWLEDGE_BASE_SOURCE_TYPE,
            },
        )

    def test_decision_boundary_and_warnings_prevent_operational_use(self):
        kb = FakeKnowledgeBase(
            contexts_by_source={
                CASE_CLOSURE_SOURCE_TYPE: [closure_context()],
                DETECTION_CONTROL_SOURCE_TYPE: [
                    {
                        "source_type": DETECTION_CONTROL_SOURCE_TYPE,
                        "source": "detection_control:dcr-test",
                        "score": 0.72,
                        "text": "Related detection control.",
                    }
                ],
            }
        )

        result = build_case_closure_semantic_context(
            FakeDb(
                case=case(),
                closure=closure(),
                incidents=[incident()],
                actions=[action(status="OPEN")],
                open_actions=[action(status="OPEN")],
            ),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["decision_boundary"], CASE_CLOSURE_CONTEXT_DECISION_BOUNDARY)
        self.assertIn("must not close cases", result["decision_boundary"])
        self.assertFalse(result["ready_to_close"])
        self.assertTrue(any("blockers" in warning for warning in result["warnings"]))
        self.assertTrue(any("different closure decisions" in warning for warning in result["warnings"]))
        self.assertTrue(any("higher final severity" in warning for warning in result["warnings"]))
        self.assertTrue(any("detection controls" in warning for warning in result["warnings"]))

    def test_disabled_semantic_memory_returns_safe_empty_response(self):
        kb = FakeKnowledgeBase(enabled=False)

        result = build_case_closure_semantic_context(
            FakeDb(case=case(), closure=closure()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "DISABLED")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(kb.calls, [])

    def test_qdrant_error_returns_safe_warning(self):
        kb = FakeKnowledgeBase(error=RuntimeError("qdrant down"))

        result = build_case_closure_semantic_context(
            FakeDb(case=case(), closure=closure()),
            42,
            knowledge_base_factory=lambda: kb,
        )

        self.assertEqual(result["status"], "WARN")
        self.assertEqual(result["result_count"], 0)
        self.assertEqual(result["error_type"], "RuntimeError")
        self.assertIn("no case closure", result["message"])

    def test_rbac_allows_operators_and_denies_viewers(self):
        self.assertTrue(
            is_request_authorized(
                "GET",
                "/cases/42/closure/semantic-context",
                {"role": "ANALYST"},
            )
        )
        self.assertFalse(
            is_request_authorized(
                "GET",
                "/cases/42/closure/semantic-context",
                {"role": "VIEWER"},
            )
        )


if __name__ == "__main__":
    unittest.main()
