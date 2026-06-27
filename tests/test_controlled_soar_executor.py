import unittest
from unittest.mock import patch

from models import CaseAction, Incident, IncidentAudit, IncidentCase, IncidentNote
from remediation.controlled_soar import (
    ControlledSoarActor,
    ControlledSoarExecutionStatus,
    controlled_soar_support_for_action_type,
    execute_approved_controlled_soar_action,
)
from remediation.models import RemediationActionType
from security.rbac import is_request_authorized


def remediation_intelligence_payload(action_type: str = "CREATE_TICKET"):
    return {
        "incident_id": 42,
        "generated_at": "2026-06-02T00:00:00+00:00",
        "source": "local_ai",
        "model_profile": "quality",
        "model": "llama3.1:8b-instruct-q4_K_M",
        "model_task": "remediation",
        "plan": {
            "executive_summary": "Controlled workflow action test.",
            "remediation_objective": "Create a governed internal workflow record only.",
            "recommended_actions": [
                {
                    "action_type": action_type,
                    "title": "Create controlled remediation record",
                    "description": "Record remediation review as product workflow metadata.",
                    "approval_requirement": "ANALYST_APPROVAL",
                    "risk_level": "LOW",
                    "rollback_possible": True,
                    "evidence_basis": ["Incident alert and remediation governance context."],
                }
            ],
            "rollback_considerations": ["Internal workflow records can be reviewed and closed."],
            "limitations": ["No target system action is performed."],
        },
        "governance": {
            "status": "PASSED",
            "policy_warnings": [],
            "limitations": [],
        },
    }


class FakeQuery:
    def __init__(self, db, model):
        self.db = db
        self.model = model

    def filter(self, *args, **kwargs):
        return self

    def join(self, *args, **kwargs):
        return self

    def order_by(self, *args, **kwargs):
        return self

    def first(self):
        if self.model is Incident:
            return self.db.incident
        if self.model is IncidentCase:
            return self.db.case
        return None


class FakeSession:
    def __init__(self, *, case_exists=True):
        self.incident = Incident(id=42, status="NEW", agent="demo-host", rule="Demo rule")
        self.case = (
            IncidentCase(id=7, group_key="case-demo", title="Demo case")
            if case_exists
            else None
        )
        self.added = []
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self._next_id = 100

    def query(self, model):
        return FakeQuery(self, model)

    def add(self, item):
        if getattr(item, "id", None) is None:
            item.id = self._next_id
            self._next_id += 1
        self.added.append(item)

    def flush(self):
        return None

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class ControlledSoarExecutorTests(unittest.TestCase):
    def test_allowlisted_action_creates_case_action_only_internal_records(self):
        db = FakeSession(case_exists=True)
        with patch("remediation.controlled_soar.SessionLocal", return_value=db), patch(
            "remediation.controlled_soar.generate_remediation_intelligence",
            return_value=remediation_intelligence_payload("CREATE_TICKET"),
        ):
            result = execute_approved_controlled_soar_action(
                incident_id=42,
                action_id="incident-42-dry-run-action-1",
                actor=ControlledSoarActor(username="analyst", role="ANALYST"),
                approval_confirmed=True,
            )

        self.assertEqual(result.status, ControlledSoarExecutionStatus.SUCCEEDED)
        self.assertTrue(result.execution_supported)
        self.assertTrue(result.product_workflow_mutated)
        self.assertFalse(result.target_system_mutated)
        self.assertFalse(result.external_system_mutated)
        self.assertTrue(any(isinstance(item, CaseAction) for item in db.added))
        self.assertTrue(any(isinstance(item, IncidentAudit) for item in db.added))
        self.assertFalse(any(isinstance(item, IncidentNote) for item in db.added))

    def test_allowlisted_action_without_case_creates_incident_note(self):
        db = FakeSession(case_exists=False)
        with patch("remediation.controlled_soar.SessionLocal", return_value=db), patch(
            "remediation.controlled_soar.generate_remediation_intelligence",
            return_value=remediation_intelligence_payload("NOTIFY_OWNER"),
        ):
            result = execute_approved_controlled_soar_action(
                incident_id=42,
                action_id="incident-42-dry-run-action-1",
                actor=ControlledSoarActor(username="analyst", role="ANALYST"),
                approval_confirmed=True,
            )

        self.assertEqual(result.status, ControlledSoarExecutionStatus.SUCCEEDED)
        self.assertTrue(any(isinstance(item, IncidentNote) for item in db.added))
        self.assertFalse(result.target_system_mutated)
        self.assertFalse(result.external_system_mutated)

    def test_unsupported_high_impact_action_returns_not_supported(self):
        db = FakeSession(case_exists=True)
        with patch("remediation.controlled_soar.SessionLocal", return_value=db), patch(
            "remediation.controlled_soar.generate_remediation_intelligence",
            return_value=remediation_intelligence_payload("BLOCK_IP"),
        ):
            result = execute_approved_controlled_soar_action(
                incident_id=42,
                action_id="incident-42-dry-run-action-1",
                actor=ControlledSoarActor(username="admin", role="ADMIN"),
                approval_confirmed=True,
            )

        self.assertEqual(result.status, ControlledSoarExecutionStatus.NOT_SUPPORTED)
        self.assertFalse(result.execution_supported)
        self.assertFalse(result.product_workflow_mutated)
        self.assertFalse(any(isinstance(item, CaseAction) for item in db.added))
        self.assertFalse(result.target_system_mutated)

    def test_missing_approval_blocks_supported_action(self):
        db = FakeSession(case_exists=True)
        with patch("remediation.controlled_soar.SessionLocal", return_value=db), patch(
            "remediation.controlled_soar.generate_remediation_intelligence",
            return_value=remediation_intelligence_payload("CREATE_TICKET"),
        ):
            result = execute_approved_controlled_soar_action(
                incident_id=42,
                action_id="incident-42-dry-run-action-1",
                actor=ControlledSoarActor(username="analyst", role="ANALYST"),
                approval_confirmed=False,
            )

        self.assertEqual(result.status, ControlledSoarExecutionStatus.BLOCKED)
        self.assertFalse(result.product_workflow_mutated)
        self.assertTrue(any(check.check == "HUMAN_APPROVAL_CONFIRMED" for check in result.policy_checks))

    def test_viewer_cannot_execute(self):
        db = FakeSession(case_exists=True)
        with patch("remediation.controlled_soar.SessionLocal", return_value=db):
            result = execute_approved_controlled_soar_action(
                incident_id=42,
                action_id="incident-42-dry-run-action-1",
                actor=ControlledSoarActor(username="viewer", role="VIEWER"),
                approval_confirmed=True,
            )

        self.assertEqual(result.status, ControlledSoarExecutionStatus.REJECTED)
        self.assertFalse(result.execution_supported)
        self.assertFalse(result.target_system_mutated)

    def test_support_mapping_is_strict(self):
        supported = controlled_soar_support_for_action_type(RemediationActionType.CREATE_TICKET)
        unsupported = controlled_soar_support_for_action_type(RemediationActionType.DISABLE_USER)

        self.assertTrue(supported.execution_supported)
        self.assertEqual(supported.controlled_action_type.value, "CREATE_REMEDIATION_TASK")
        self.assertFalse(unsupported.execution_supported)
        self.assertIn("not supported", unsupported.unsupported_reason.lower())

    def test_rbac_allows_execute_approved_only_for_operator_roles(self):
        self.assertTrue(
            is_request_authorized(
                "POST",
                "/incidents/42/remediation-actions/create-ticket/execute-approved",
                {"role": "ANALYST"},
            )
        )
        self.assertFalse(
            is_request_authorized(
                "POST",
                "/incidents/42/remediation-actions/create-ticket/execute-approved",
                {"role": "VIEWER"},
            )
        )


if __name__ == "__main__":
    unittest.main()
