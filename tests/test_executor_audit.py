import unittest

from executor.audit import (
    ExecutorAuditEventType,
    audit_event_from_dispatch_result,
    audit_event_from_policy_decision,
)
from executor.dispatcher import dispatch_executor_action
from executor.policy import evaluate_executor_policy
from tests.test_executor_policy import executor_context, remediation_action


class ExecutorAuditTests(unittest.TestCase):
    def test_policy_audit_event_is_sanitized(self):
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

        event = audit_event_from_policy_decision(decision)

        self.assertEqual(event.event_type, ExecutorAuditEventType.EXECUTOR_POLICY_EVALUATED)
        self.assertFalse(event.details["execution_supported"])
        self.assertFalse(event.details["production_impact_allowed"])
        self.assertNotIn("command_preview", event.details)

    def test_dispatch_audit_event_does_not_claim_real_execution(self):
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
        event = audit_event_from_dispatch_result(result)

        self.assertEqual(event.event_type, ExecutorAuditEventType.EXECUTOR_ACTION_DISPATCHED_NOOP)
        self.assertFalse(event.details["state_mutated"])
        self.assertFalse(event.details["production_impact"])
        self.assertFalse(event.details["execution_supported"])


if __name__ == "__main__":
    unittest.main()
