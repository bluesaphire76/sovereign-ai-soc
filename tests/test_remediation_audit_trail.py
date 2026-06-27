import unittest
from unittest.mock import patch

from remediation.audit_trail import (
    RemediationAuditTrailEventType,
    build_remediation_audit_trail,
    generate_incident_remediation_audit_trail,
)
from remediation.simulation import build_remediation_plan_from_intelligence
from routers.remediation import get_incident_remediation_audit_trail
from security.rbac import is_request_authorized


def intelligence_payload(source: str = "deterministic_fallback"):
    return {
        "incident_id": 42,
        "generated_at": "2026-06-01T00:00:00+00:00",
        "source": source,
        "plan": {
            "executive_summary": "Audit trail test plan.",
            "remediation_objective": "Validate audit trail before remediation approval.",
            "recommended_actions": [
                {
                    "action_type": "COLLECT_FORENSIC_EVIDENCE",
                    "title": "Collect supporting evidence",
                    "description": "Collect evidence before selecting an operational action.",
                    "approval_requirement": "ANALYST_APPROVAL",
                    "risk_level": "LOW",
                    "rollback_possible": True,
                    "evidence_basis": ["Incident evidence supports audit trail review."],
                }
            ],
            "rollback_considerations": ["Rollback requires human validation."],
            "limitations": ["Planning only."],
        },
    }


class RemediationAuditTrailTests(unittest.TestCase):
    def test_audit_trail_is_read_only_and_blocks_execution(self):
        plan = build_remediation_plan_from_intelligence(intelligence_payload())
        response = build_remediation_audit_trail(
            plan,
            remediation_source="deterministic_fallback",
        )

        self.assertFalse(response.execution_supported)
        self.assertFalse(response.summary.execution_attempted)
        self.assertTrue(response.summary.execution_blocked)
        self.assertTrue(response.summary.approval_required)
        self.assertIn("No remediation execution is supported.", response.notes)

    def test_audit_trail_contains_required_governance_events(self):
        plan = build_remediation_plan_from_intelligence(intelligence_payload("local_ai"))
        response = build_remediation_audit_trail(plan, remediation_source="local_ai")
        event_types = {record.event_type for record in response.records}

        self.assertIn(RemediationAuditTrailEventType.PLAN_GENERATED, event_types)
        self.assertIn(RemediationAuditTrailEventType.AI_REMEDIATION_INTELLIGENCE_USED, event_types)
        self.assertIn(RemediationAuditTrailEventType.APPROVAL_REQUIRED, event_types)
        self.assertIn(RemediationAuditTrailEventType.DRY_RUN_COMPLETED, event_types)
        self.assertIn(RemediationAuditTrailEventType.ROLLBACK_READINESS_CHECKED, event_types)
        self.assertIn(RemediationAuditTrailEventType.HUMAN_VALIDATION_REQUIRED, event_types)
        self.assertIn(RemediationAuditTrailEventType.EXECUTION_NOT_SUPPORTED, event_types)

    def test_deterministic_fallback_source_is_represented(self):
        plan = build_remediation_plan_from_intelligence(intelligence_payload())
        response = build_remediation_audit_trail(
            plan,
            remediation_source="deterministic_fallback",
        )
        event_types = {record.event_type for record in response.records}

        self.assertIn(RemediationAuditTrailEventType.DETERMINISTIC_FALLBACK_USED, event_types)

    def test_plan_builder_accepts_structured_rollback_considerations(self):
        payload = intelligence_payload("local_ai")
        payload["plan"]["rollback_considerations"] = [
            {
                "title": "Review control configuration",
                "description": "Confirm whether the control change is reversible.",
                "reason": "Generated remediation output used structured rollback text.",
            }
        ]
        payload["plan"]["limitations"] = [
            {
                "title": "Human validation required",
                "description": "The plan is advisory and does not execute changes.",
            }
        ]

        plan = build_remediation_plan_from_intelligence(payload)

        self.assertIn(
            "Review control configuration",
            plan.rollback_plan.limitations[0],
        )
        self.assertIn("Human validation required", plan.limitations[0])

    def test_endpoint_service_returns_structured_audit_trail(self):
        with patch(
            "remediation.audit_trail.generate_remediation_intelligence",
            return_value=intelligence_payload(),
        ):
            response = generate_incident_remediation_audit_trail(42)

        self.assertEqual(response.incident_id, 42)
        self.assertFalse(response.execution_supported)
        self.assertFalse(response.summary.execution_attempted)
        self.assertGreaterEqual(len(response.records), 1)

    def test_router_rejects_invalid_incident_id(self):
        with self.assertRaises(Exception) as context:
            get_incident_remediation_audit_trail(0)

        self.assertEqual(getattr(context.exception, "status_code", None), 404)

    def test_router_maps_unknown_incident_to_404(self):
        with patch(
            "routers.remediation.generate_incident_remediation_audit_trail",
            side_effect=ValueError("Incident not found"),
        ):
            with self.assertRaises(Exception) as context:
                get_incident_remediation_audit_trail(999)

        self.assertEqual(getattr(context.exception, "status_code", None), 404)

    def test_rbac_allows_read_only_audit_trail_endpoint(self):
        self.assertTrue(
            is_request_authorized(
                "GET",
                "/incidents/42/remediation-audit-trail",
                {"role": "VIEWER"},
            )
        )


if __name__ == "__main__":
    unittest.main()
