import unittest
from unittest.mock import patch

from remediation.models import RemediationActionType
from remediation.rollback_engine import (
    RollbackEngineOverallStatus,
    build_rollback_engine_response,
    generate_incident_remediation_rollback_readiness,
)
from remediation.simulation import build_remediation_plan_from_intelligence
from routers.remediation import get_incident_remediation_rollback_readiness
from security.rbac import is_request_authorized


def intelligence_payload(action_type: str = "COLLECT_FORENSIC_EVIDENCE", rollback_possible=True):
    return {
        "incident_id": 42,
        "generated_at": "2026-05-31T00:00:00+00:00",
        "source": "deterministic_fallback",
        "plan": {
            "executive_summary": "Rollback readiness test plan.",
            "remediation_objective": "Validate rollback readiness before remediation approval.",
            "recommended_actions": [
                {
                    "action_type": action_type,
                    "title": "Review rollback readiness",
                    "description": "Assess rollback readiness without execution.",
                    "approval_requirement": "ANALYST_APPROVAL",
                    "risk_level": "LOW",
                    "rollback_possible": rollback_possible,
                    "evidence_basis": ["Incident evidence supports readiness review."],
                }
            ],
            "rollback_considerations": ["Rollback requires human validation."],
            "limitations": ["Planning only."],
        },
    }


class RemediationRollbackEngineTests(unittest.TestCase):
    def test_rollback_engine_response_is_planning_only(self):
        plan = build_remediation_plan_from_intelligence(intelligence_payload())
        response = build_rollback_engine_response(plan, remediation_source="deterministic_fallback")

        self.assertFalse(response.execution_supported)
        self.assertFalse(response.rollback_execution_supported)
        self.assertTrue(response.human_approval_required)
        self.assertEqual(response.source, "rollback_engine")
        self.assertEqual(response.incident_id, 42)
        self.assertGreaterEqual(len(response.actions), 1)
        self.assertIn("No rollback execution is available.", response.notes)

    def test_unavailable_rollback_produces_not_ready_status(self):
        plan = build_remediation_plan_from_intelligence(
            intelligence_payload(
                RemediationActionType.ISOLATE_HOST.value,
                rollback_possible=False,
            )
        )
        response = build_rollback_engine_response(plan)

        self.assertEqual(response.overall_status, RollbackEngineOverallStatus.NOT_READY)
        self.assertTrue(response.blockers)
        self.assertEqual(response.actions[0].rollback_status, RollbackEngineOverallStatus.NOT_READY)

    def test_partial_rollback_produces_conditional_status(self):
        plan = build_remediation_plan_from_intelligence(
            intelligence_payload(RemediationActionType.COLLECT_FORENSIC_EVIDENCE.value)
        )
        response = build_rollback_engine_response(plan)

        self.assertEqual(response.overall_status, RollbackEngineOverallStatus.CONDITIONAL)
        self.assertTrue(response.warnings)

    def test_endpoint_returns_structured_response(self):
        with patch(
            "remediation.rollback_engine.generate_remediation_intelligence",
            return_value=intelligence_payload(),
        ):
            response = generate_incident_remediation_rollback_readiness(42)

        self.assertEqual(response.incident_id, 42)
        self.assertFalse(response.execution_supported)
        self.assertFalse(response.rollback_execution_supported)
        self.assertTrue(response.human_approval_required)

    def test_router_rejects_invalid_incident_id(self):
        with self.assertRaises(Exception) as context:
            get_incident_remediation_rollback_readiness(0)

        self.assertEqual(getattr(context.exception, "status_code", None), 404)

    def test_router_maps_unknown_incident_to_404(self):
        with patch(
            "routers.remediation.generate_incident_remediation_rollback_readiness",
            side_effect=ValueError("Incident not found"),
        ):
            with self.assertRaises(Exception) as context:
                get_incident_remediation_rollback_readiness(999)

        self.assertEqual(getattr(context.exception, "status_code", None), 404)

    def test_rbac_allows_read_only_rollback_readiness_endpoint(self):
        self.assertTrue(
            is_request_authorized(
                "GET",
                "/incidents/42/remediation-rollback-readiness",
                {"role": "VIEWER"},
            )
        )


if __name__ == "__main__":
    unittest.main()
