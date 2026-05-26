import unittest

from executor.models import ExecutorMode
from remediation.approvals import RemediationApprovalDecision
from remediation.models import RemediationActionType
from remediation.workflow import (
    RemediationWorkflowStatus,
    advance_to_mock_dispatch,
    advance_to_policy_check,
    advance_to_readiness_check,
    build_governance_summary,
    get_workflow_state,
)
from tests.remediation_workflow_utils import (
    approval_record,
    remediation_action,
    remediation_plan,
)


class RemediationWorkflowTests(unittest.TestCase):
    def test_workflow_blocks_without_plan(self):
        state = get_workflow_state(None, "missing-action")

        self.assertEqual(state.status, RemediationWorkflowStatus.FAILED_VALIDATION)
        self.assertEqual(state.blockers[0].blocker_id, "plan-missing")
        self.assertFalse(state.production_impact)
        self.assertTrue(state.execution_disabled)

    def test_workflow_blocks_without_required_approval(self):
        action = remediation_action()
        plan = remediation_plan(action)
        state = get_workflow_state(plan, action.action_id)

        self.assertEqual(state.status, RemediationWorkflowStatus.AWAITING_APPROVAL)
        self.assertTrue(any("approval" in blocker.blocker_id for blocker in state.blockers))
        self.assertFalse(state.production_impact)

    def test_workflow_blocks_rejected_action(self):
        action = remediation_action()
        plan = remediation_plan(action)
        approval = approval_record(action, decision=RemediationApprovalDecision.REJECT)
        state = get_workflow_state(plan, action.action_id, approval_record=approval)

        self.assertEqual(state.status, RemediationWorkflowStatus.REJECTED)
        self.assertEqual(state.approval_id, approval.approval_id)

    def test_workflow_blocks_forbidden_action(self):
        action = remediation_action(RemediationActionType.KILL_PROCESS)
        plan = remediation_plan(action)
        state = get_workflow_state(plan, action.action_id)

        self.assertEqual(state.status, RemediationWorkflowStatus.BLOCKED_BY_POLICY)
        self.assertTrue(any(blocker.severity == "CRITICAL" for blocker in state.blockers))

    def test_workflow_blocks_missing_rollback_readiness(self):
        action = remediation_action(include_rollback=False)
        plan = remediation_plan(action)
        approval = approval_record(action)
        result = advance_to_readiness_check(plan, action.action_id, approval_record=approval)

        self.assertEqual(result.state.status, RemediationWorkflowStatus.BLOCKED_BY_ROLLBACK)
        self.assertIsNotNone(result.rollback_readiness)
        self.assertFalse(result.state.production_impact)

    def test_workflow_blocks_failed_policy_check(self):
        action = remediation_action()
        plan = remediation_plan(action)
        approval = approval_record(action)
        result = advance_to_policy_check(
            plan,
            action.action_id,
            approval_record=approval,
            parameters={"command": "rm -rf /tmp/anything"},
        )

        self.assertEqual(result.state.status, RemediationWorkflowStatus.BLOCKED_BY_POLICY)
        self.assertIsNotNone(result.policy_decision)
        self.assertFalse(result.policy_decision.allowed)
        self.assertTrue(any("FORBIDDEN_PARAMETER" in blocker for blocker in result.policy_decision.blockers))

    def test_workflow_allows_mock_dispatch_after_gates_pass(self):
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
        self.assertIsNotNone(result.dispatch_result)
        self.assertFalse(result.dispatch_result.state_mutated)
        self.assertFalse(result.dispatch_result.production_impact)
        self.assertFalse(result.dispatch_result.execution_supported)

    def test_workflow_allows_noop_dispatch_after_gates_pass(self):
        action = remediation_action()
        plan = remediation_plan(action)
        approval = approval_record(action)
        result = advance_to_mock_dispatch(
            plan,
            action.action_id,
            approval_record=approval,
            mode=ExecutorMode.NOOP,
        )

        self.assertEqual(result.state.status, RemediationWorkflowStatus.NOOP_DISPATCH_COMPLETED)
        self.assertIsNotNone(result.dispatch_result)
        self.assertFalse(result.dispatch_result.state_mutated)

    def test_governance_summary_keeps_execution_disabled(self):
        action = remediation_action()
        plan = remediation_plan(action)
        approval = approval_record(action)
        result = advance_to_mock_dispatch(plan, action.action_id, approval_record=approval)
        summary = build_governance_summary(result)

        self.assertEqual(summary.status, RemediationWorkflowStatus.MOCK_DISPATCH_COMPLETED)
        self.assertFalse(summary.production_execution_enabled)
        self.assertIn("Production execution is disabled", summary.summary)


if __name__ == "__main__":
    unittest.main()
