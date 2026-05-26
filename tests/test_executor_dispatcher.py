import unittest

from executor.dispatcher import dispatch_executor_action
from executor.models import ExecutorDispatchStatus, ExecutorMode
from executor.policy import evaluate_executor_policy
from tests.test_executor_policy import executor_context, remediation_action


class ExecutorDispatcherTests(unittest.TestCase):
    def test_dispatcher_records_noop_without_state_mutation(self):
        executor_action, approval, dry_run, rollback, readiness = executor_context(
            remediation_action()
        )
        decision = evaluate_executor_policy(
            executor_action,
            approval_record=approval,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )

        result = dispatch_executor_action(executor_action, decision)

        self.assertEqual(result.status, ExecutorDispatchStatus.NOOP_RECORDED)
        self.assertFalse(result.state_mutated)
        self.assertFalse(result.production_impact)
        self.assertFalse(result.execution_supported)

    def test_dispatcher_records_mock_without_state_mutation(self):
        executor_action, approval, dry_run, rollback, readiness = executor_context(
            remediation_action(),
            mode=ExecutorMode.MOCK,
        )
        decision = evaluate_executor_policy(
            executor_action,
            approval_record=approval,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )

        result = dispatch_executor_action(executor_action, decision)

        self.assertEqual(result.status, ExecutorDispatchStatus.MOCK_RECORDED)
        self.assertFalse(result.state_mutated)
        self.assertFalse(result.production_impact)
        self.assertFalse(result.execution_supported)

    def test_dispatcher_blocks_when_policy_blocks(self):
        executor_action, _approval, dry_run, rollback, readiness = executor_context(
            remediation_action()
        )
        decision = evaluate_executor_policy(
            executor_action,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )

        result = dispatch_executor_action(executor_action, decision)

        self.assertEqual(result.status, ExecutorDispatchStatus.BLOCKED_BY_POLICY)
        self.assertFalse(result.state_mutated)


if __name__ == "__main__":
    unittest.main()
