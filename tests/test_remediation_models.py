import unittest

from investigation_ai.models import EvidenceReference, InvestigationEvidenceType
from remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationImpactAssessment,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationTarget,
    RemediationTargetType,
    RollbackAvailability,
    RollbackPlan,
)
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan


def evidence():
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Incident evidence supports remediation planning.",
    )


def action(action_type=RemediationActionType.BLOCK_IP):
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
    )
    rollback = build_rollback_plan(action_type, action_id="action-1")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=80,
        evidence_count=1,
    )
    return RemediationAction(
        action_id="action-1",
        action_type=action_type,
        title="Review proposed remediation",
        description="Review proposed remediation before approval.",
        target=target,
        reason="Evidence indicates review is warranted.",
        evidence=[evidence()],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(
            technical_impact="Planning-only action.",
        ),
        rollback_steps=rollback.steps,
        command_preview="PREVIEW ONLY: block network traffic for IP 10.0.0.5",
        command_preview_is_executable=True,
        execution_supported=True,
    )


class RemediationModelTests(unittest.TestCase):
    def test_remediation_action_defaults_to_non_executable(self):
        remediation_action = action()

        self.assertFalse(remediation_action.execution_supported)
        self.assertFalse(remediation_action.command_preview_is_executable)

    def test_remediation_plan_validation_model(self):
        remediation_action = action()
        rollback = RollbackPlan(
            rollback_id="plan-rollback",
            availability=RollbackAvailability.PARTIAL,
            steps=remediation_action.rollback_steps,
            limitations=["Plan-level rollback depends on future execution details."],
        )
        plan = RemediationPlan(
            plan_id="plan-1",
            incident_id=1,
            status=RemediationPlanStatus.PROPOSED,
            summary="Plan ready for review.",
            rationale="Planning-only remediation.",
            actions=[remediation_action],
            overall_risk=remediation_action.risk,
            rollback_plan=rollback,
            evidence_used=[evidence()],
            execution_supported=True,
        )

        self.assertFalse(plan.execution_supported)
        self.assertTrue(plan.approval_required)


if __name__ == "__main__":
    unittest.main()
