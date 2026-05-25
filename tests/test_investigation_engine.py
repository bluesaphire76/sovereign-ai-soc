import json
import unittest

from investigation_ai.adapters import context_from_command_room_payload
from investigation_ai.engine import generate_investigation_brief
from investigation_ai.models import (
    InvestigationClaimClassification,
    InvestigationConfidenceLevel,
    InvestigationSessionStatus,
    RecommendedActionApprovalRequirement,
)
from investigation_ai.validators import validate_investigation_brief


def sample_incident():
    return {
        "id": 321,
        "status": "TRIAGED",
        "timestamp": "2026-05-20T10:00:00+00:00",
        "agent": "endpoint-01",
        "rule": "Suspicious authentication pattern",
        "level": 10,
        "risk_score": 72,
        "mitre": "T1110",
        "correlation_score": 68,
        "correlation_type": "SINGLE_HOST_PATTERN_CORRELATION",
        "escalation_reason": "Multiple related signals were observed in the selected window.",
        "recommended_priority": "HIGH",
    }


class InvestigationEngineTests(unittest.TestCase):
    def test_deterministic_generation_returns_valid_brief(self):
        brief = generate_investigation_brief(
            incident=sample_incident(),
            raw_events=[
                {
                    "id": 1,
                    "source": "wazuh",
                    "event_timestamp": "2026-05-20T09:59:00+00:00",
                    "agent": "endpoint-01",
                    "rule_id": "5710",
                    "rule_description": "Suspicious authentication pattern",
                }
            ],
            security_alerts=[
                {
                    "id": 2,
                    "source": "wazuh",
                    "event_timestamp": "2026-05-20T10:00:00+00:00",
                    "agent": "endpoint-01",
                    "rule_id": "5710",
                    "rule_description": "Suspicious authentication pattern",
                }
            ],
            correlation_summary={"final_correlation_score": 68, "related_events": 3},
            timeline=[{"timestamp": "2026-05-20T10:00:00+00:00", "kind": "incident"}],
        )

        self.assertEqual(brief.incident_id, 321)
        self.assertEqual(brief.status, InvestigationSessionStatus.READY_FOR_ANALYST)
        self.assertGreaterEqual(len(brief.hypotheses), 1)
        self.assertGreaterEqual(len(brief.evidence_used), 3)
        self.assertEqual(validate_investigation_brief(brief), [])

    def test_llm_confidence_is_recalculated_deterministically(self):
        def llm_client(_messages):
            return json.dumps(
                {
                    "summary": "Structured investigation is ready for analyst review.",
                    "risk_assessment": "Risk is elevated and requires analyst validation.",
                    "hypotheses": [
                        {
                            "hypothesis_id": "hypothesis-llm",
                            "title": "Suspicious authentication behavior",
                            "statement": "The source alert may represent suspicious authentication behavior.",
                            "status": "ACTIVE",
                            "confidence": {"score": 150, "level": "UNKNOWN"},
                            "supporting_evidence": [],
                            "missing_evidence": ["full host timeline"],
                        }
                    ],
                    "findings": [],
                    "recommended_checks": [],
                    "recommended_actions": [],
                    "confidence": {"score": 150, "level": "UNKNOWN"},
                    "limitations": [],
                }
            )

        brief = generate_investigation_brief(
            incident=sample_incident(),
            llm_client=llm_client,
        )

        self.assertLess(brief.confidence.score, 100)
        self.assertNotEqual(brief.confidence.level, InvestigationConfidenceLevel.HIGH)
        self.assertTrue(brief.confidence.scoring_factors)
        self.assertEqual(validate_investigation_brief(brief), [])

    def test_malformed_llm_output_triggers_deterministic_fallback(self):
        def llm_client(_messages):
            return "not-json"

        brief = generate_investigation_brief(
            incident=sample_incident(),
            llm_client=llm_client,
        )

        self.assertEqual(brief.status, InvestigationSessionStatus.NEEDS_HUMAN_INPUT)
        self.assertTrue(any(item.limitation_id == "investigation-engine-fallback" for item in brief.limitations))
        self.assertEqual(validate_investigation_brief(brief), [])

    def test_llm_exception_triggers_deterministic_fallback(self):
        def llm_client(_messages):
            raise TimeoutError("timeout")

        brief = generate_investigation_brief(
            incident=sample_incident(),
            llm_client=llm_client,
        )

        self.assertEqual(brief.status, InvestigationSessionStatus.NEEDS_HUMAN_INPUT)
        self.assertGreaterEqual(len(brief.recommended_checks), 1)
        self.assertEqual(validate_investigation_brief(brief), [])

    def test_unsupported_claims_are_downgraded_and_flagged(self):
        def llm_client(_messages):
            return json.dumps(
                {
                    "summary": "Structured investigation is available.",
                    "findings": [
                        {
                            "finding_id": "finding-unsupported",
                            "finding_type": "BEHAVIOR",
                            "title": "Unsupported claim",
                            "description": "This definitely proves compromise.",
                            "claim_classification": "UNSUPPORTED",
                            "confidence": {"score": 80, "level": "HIGH"},
                            "evidence": [],
                        }
                    ],
                    "confidence": {"score": 80, "level": "HIGH"},
                }
            )

        brief = generate_investigation_brief(
            incident=sample_incident(),
            llm_client=llm_client,
        )

        self.assertEqual(
            brief.findings[0].claim_classification,
            InvestigationClaimClassification.SPECULATIVE,
        )
        self.assertIn("may support", brief.findings[0].description)
        self.assertTrue(any(item.limitation_id == "unsupported-claims-normalized" for item in brief.limitations))
        self.assertEqual(validate_investigation_brief(brief), [])

    def test_operational_actions_remain_non_executable_and_require_approval(self):
        def llm_client(_messages):
            return json.dumps(
                {
                    "summary": "Structured investigation is available.",
                    "recommended_actions": [
                        {
                            "action_id": "action-isolate",
                            "title": "Isolate affected host",
                            "description": "Isolate the endpoint from the network.",
                            "category": "CONTAINMENT",
                            "approval_requirement": "NONE",
                            "execution_supported": True,
                        }
                    ],
                    "confidence": {"score": 60, "level": "MEDIUM"},
                }
            )

        brief = generate_investigation_brief(
            incident=sample_incident(),
            llm_client=llm_client,
        )

        action = brief.recommended_actions[0]
        self.assertFalse(action.execution_supported)
        self.assertEqual(action.approval_requirement, RecommendedActionApprovalRequirement.ANALYST_APPROVAL)
        self.assertEqual(validate_investigation_brief(brief), [])

    def test_missing_evidence_is_handled_gracefully(self):
        brief = generate_investigation_brief(incident_id=999)

        self.assertEqual(brief.incident_id, 999)
        self.assertGreaterEqual(len(brief.limitations), 1)
        self.assertGreaterEqual(len(brief.hypotheses[0].missing_evidence), 1)
        self.assertEqual(validate_investigation_brief(brief), [])

    def test_partial_context_without_incident_is_supported(self):
        brief = generate_investigation_brief(
            raw_events=[{"id": 5, "source": "wazuh", "rule_description": "Sample raw event"}]
        )

        self.assertEqual(brief.incident_id, 0)
        self.assertGreaterEqual(len(brief.evidence_used), 1)
        self.assertEqual(validate_investigation_brief(brief), [])

    def test_existing_command_room_payload_can_be_adapted(self):
        context = context_from_command_room_payload(
            {
                "incident": sample_incident(),
                "command_brief": "Review source alert and correlation context.",
                "timeline": [{"timestamp": "2026-05-20T10:00:00+00:00"}],
            }
        )

        brief = generate_investigation_brief(context=context)

        self.assertEqual(context.existing_ai_analysis, "Review source alert and correlation context.")
        self.assertEqual(brief.incident_id, 321)
        self.assertEqual(validate_investigation_brief(brief), [])


if __name__ == "__main__":
    unittest.main()
