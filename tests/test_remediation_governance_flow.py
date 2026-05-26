import unittest
from pathlib import Path

from executor.models import ExecutorMode
from remediation.audit import RemediationAuditEventType
from remediation.workflow import (
    RemediationWorkflowStep,
    RemediationWorkflowStatus,
    advance_to_mock_dispatch,
)
from tests.remediation_workflow_utils import (
    approval_record,
    remediation_action,
    remediation_plan,
)


class RemediationGovernanceFlowTests(unittest.TestCase):
    def test_governance_timeline_ordering_is_deterministic(self):
        action = remediation_action()
        plan = remediation_plan(action)
        approval = approval_record(action)

        first = advance_to_mock_dispatch(plan, action.action_id, approval_record=approval)
        second = advance_to_mock_dispatch(plan, action.action_id, approval_record=approval)

        self.assertEqual(
            [entry.step for entry in first.state.timeline],
            [
                RemediationWorkflowStep.PLAN,
                RemediationWorkflowStep.APPROVAL,
                RemediationWorkflowStep.DRY_RUN,
                RemediationWorkflowStep.ROLLBACK_READINESS,
                RemediationWorkflowStep.EXECUTION_READINESS,
                RemediationWorkflowStep.EXECUTOR_POLICY,
                RemediationWorkflowStep.MOCK_NOOP_DISPATCH,
                RemediationWorkflowStep.AUDIT,
            ],
        )
        self.assertEqual(
            [entry.entry_id for entry in first.state.timeline],
            [entry.entry_id for entry in second.state.timeline],
        )

    def test_audit_events_use_non_misleading_wording(self):
        action = remediation_action()
        plan = remediation_plan(action)
        approval = approval_record(action)
        result = advance_to_mock_dispatch(plan, action.action_id, approval_record=approval)

        remediation_event_values = [event.event_type.value for event in result.remediation_audit_events]
        executor_event_values = [event.event_type.value for event in result.executor_audit_events]

        self.assertIn(
            RemediationAuditEventType.REMEDIATION_MOCK_DISPATCH_COMPLETED.value,
            remediation_event_values,
        )
        for event_value in remediation_event_values + executor_event_values:
            self.assertNotEqual(event_value, "REMEDIATION_EXECUTED")
            self.assertNotEqual(event_value, "EXECUTOR_ACTION_EXECUTED")
        for event in result.remediation_audit_events:
            self.assertFalse(event.details.get("production_impact", False))
            self.assertFalse(event.details.get("execution_supported", False))

    def test_mock_dispatch_does_not_mutate_production_state(self):
        action = remediation_action()
        plan = remediation_plan(action)
        approval = approval_record(action)
        result = advance_to_mock_dispatch(
            plan,
            action.action_id,
            approval_record=approval,
            mode=ExecutorMode.MOCK,
        )

        self.assertEqual(result.state.status, RemediationWorkflowStatus.MOCK_DISPATCH_COMPLETED)
        self.assertIsNotNone(result.execution_audit_record)
        self.assertFalse(result.dispatch_result.state_mutated)
        self.assertFalse(result.dispatch_result.production_impact)
        self.assertFalse(result.execution_audit_record.execution_attempted)

    def test_no_dangerous_execute_endpoint_exists(self):
        checked_files = [Path("api.py"), *Path("routers").glob("*.py")]
        content = "\n".join(path.read_text(encoding="utf-8") for path in checked_files)

        self.assertNotIn("/remediation/actions/{action_id}/execute", content)
        self.assertNotIn("/remediation/plans/{plan_id}/execute", content)
        self.assertNotIn("remediation_executed", content.lower())

    def test_no_arbitrary_command_payload_is_accepted_by_workflow(self):
        action = remediation_action()
        plan = remediation_plan(action)
        approval = approval_record(action)
        result = advance_to_mock_dispatch(
            plan,
            action.action_id,
            approval_record=approval,
            parameters={"shell_command": "iptables -A INPUT; rm -rf /tmp/anything"},
        )

        self.assertEqual(result.state.status, RemediationWorkflowStatus.BLOCKED_BY_POLICY)
        self.assertIsNone(result.dispatch_result)
        self.assertIsNotNone(result.policy_decision)
        self.assertTrue(
            any("FORBIDDEN_PARAMETER" in blocker for blocker in result.policy_decision.blockers)
        )


if __name__ == "__main__":
    unittest.main()
