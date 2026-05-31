import unittest
from pathlib import Path
from unittest.mock import patch

from routers.remediation import get_incident_remediation_dry_run
from remediation.simulation import (
    RemediationDryRunSimulationResponse,
    RemediationRollbackReadinessPreview,
    generate_incident_remediation_dry_run,
)


def remediation_intelligence_payload(incident_id: int = 42):
    return {
        "incident_id": incident_id,
        "generated_at": "2026-05-31T00:00:00+00:00",
        "source": "deterministic_fallback",
        "plan": {
            "executive_summary": "Review remediation governance.",
            "remediation_objective": "Validate incident evidence before remediation.",
            "recommended_actions": [
                {
                    "action_type": "COLLECT_FORENSIC_EVIDENCE",
                    "title": "Collect supporting evidence",
                    "description": "Collect supporting host and network evidence before action.",
                    "approval_requirement": "ANALYST_APPROVAL",
                    "risk_level": "LOW",
                    "rollback_possible": True,
                    "evidence_basis": ["Incident alert and structured remediation context."],
                }
            ],
            "rollback_considerations": ["No operational change is performed by dry-run."],
            "limitations": ["Simulation only."],
        },
    }


class RemediationDryRunRouterTests(unittest.TestCase):
    def test_dry_run_service_is_read_only_and_requires_human_approval(self):
        with patch(
            "remediation.simulation.generate_remediation_intelligence",
            return_value=remediation_intelligence_payload(),
        ):
            response = generate_incident_remediation_dry_run(42)

        self.assertEqual(response.source, "dry_run_simulation")
        self.assertFalse(response.execution_supported)
        self.assertFalse(response.state_mutated)
        self.assertTrue(response.human_approval_required)
        self.assertGreaterEqual(len(response.findings), 1)
        self.assertEqual(response.rollback_readiness.status, "PARTIAL")

    def test_router_returns_structured_dry_run_response(self):
        payload = RemediationDryRunSimulationResponse(
            incident_id=42,
            summary="Dry-run test response.",
            status="MISSING_APPROVAL",
            rollback_readiness=RemediationRollbackReadinessPreview(
                status="PARTIAL",
                blockers=[],
                limitations=[],
            ),
        )

        with patch(
            "routers.remediation.generate_incident_remediation_dry_run",
            return_value=payload,
        ):
            response = get_incident_remediation_dry_run(42)

        self.assertEqual(response["incident_id"], 42)
        self.assertEqual(response["source"], "dry_run_simulation")
        self.assertFalse(response["execution_supported"])
        self.assertFalse(response["state_mutated"])
        self.assertTrue(response["human_approval_required"])

    def test_router_rejects_invalid_incident_id(self):
        with self.assertRaises(Exception) as context:
            get_incident_remediation_dry_run(0)

        self.assertEqual(getattr(context.exception, "status_code", None), 404)

    def test_router_maps_missing_incident_to_404(self):
        with patch(
            "routers.remediation.generate_incident_remediation_dry_run",
            side_effect=ValueError("Incident not found"),
        ):
            with self.assertRaises(Exception) as context:
                get_incident_remediation_dry_run(999)

        self.assertEqual(getattr(context.exception, "status_code", None), 404)

    def test_rbac_allows_read_only_dry_run_endpoint(self):
        api_source = Path("api.py").read_text(encoding="utf-8")

        self.assertIn(
            '("GET", r"^/incidents/\\d+/remediation-dry-run$", ALL_ROLES)',
            api_source,
        )


if __name__ == "__main__":
    unittest.main()
