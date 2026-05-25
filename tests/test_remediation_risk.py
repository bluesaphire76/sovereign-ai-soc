import unittest

from remediation.models import (
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationTarget,
    RemediationTargetCriticality,
    RemediationTargetType,
    RollbackAvailability,
    RollbackPlan,
)
from remediation.risk import approval_for_action, assess_action_risk
from remediation.rollback import build_rollback_plan


class RemediationRiskTests(unittest.TestCase):
    def test_operational_actions_require_approval(self):
        approval = approval_for_action(RemediationActionType.BLOCK_IP)

        self.assertEqual(approval, RemediationApprovalRequirement.ADMIN_APPROVAL)

    def test_destructive_actions_are_forbidden_by_default(self):
        approval = approval_for_action(RemediationActionType.KILL_PROCESS)

        self.assertEqual(approval, RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT)

    def test_risk_increases_when_rollback_unavailable(self):
        target = RemediationTarget(
            target_type=RemediationTargetType.HOST,
            value="endpoint-01",
            criticality=RemediationTargetCriticality.HIGH,
        )
        full = build_rollback_plan(RemediationActionType.BLOCK_IP, action_id="block-ip")
        unavailable = RollbackPlan(
            rollback_id="rollback-unavailable",
            availability=RollbackAvailability.UNAVAILABLE,
            limitations=["No rollback path exists."],
        )

        lower = assess_action_risk(
            RemediationActionType.BLOCK_IP,
            target=target,
            rollback_plan=full,
            confidence_score=80,
            evidence_count=2,
        )
        higher = assess_action_risk(
            RemediationActionType.BLOCK_IP,
            target=target,
            rollback_plan=unavailable,
            confidence_score=80,
            evidence_count=2,
        )

        self.assertGreater(higher.score, lower.score)

    def test_rollback_plan_validation_for_unavailable_actions(self):
        rollback = build_rollback_plan(RemediationActionType.ISOLATE_HOST, action_id="isolate")

        self.assertEqual(rollback.availability, RollbackAvailability.UNAVAILABLE)
        self.assertTrue(rollback.limitations)


if __name__ == "__main__":
    unittest.main()
