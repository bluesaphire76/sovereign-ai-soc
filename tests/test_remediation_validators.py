import unittest

from investigation_ai.models import EvidenceReference, InvestigationEvidenceType
from remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationImpactAssessment,
    RemediationApprovalRequirement,
    RemediationTarget,
    RemediationTargetType,
)
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan
from remediation.validators import validate_remediation_action


def action(action_type=RemediationActionType.BLOCK_IP):
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
    )
    rollback = build_rollback_plan(action_type, action_id="validator-action")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=70,
        evidence_count=1,
    )
    return RemediationAction(
        action_id="validator-action",
        action_type=action_type,
        title="Review proposed remediation",
        description="Review proposed remediation before approval.",
        target=target,
        reason="Evidence indicates review is warranted.",
        evidence=[
            EvidenceReference(
                evidence_id="incident-1",
                evidence_type=InvestigationEvidenceType.INCIDENT,
                source_system="ai-soc",
                summary="Incident evidence supports remediation planning.",
            )
        ],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="Planning-only action."),
        rollback_steps=rollback.steps,
        command_preview="PREVIEW ONLY: block network traffic for IP 10.0.0.5",
    )


class RemediationValidatorTests(unittest.TestCase):
    def test_validator_blocks_arbitrary_shell_execution_as_executable(self):
        remediation_action = action()
        object.__setattr__(remediation_action, "execution_supported", True)
        object.__setattr__(remediation_action, "command_preview_is_executable", True)
        object.__setattr__(remediation_action, "command_preview", "rm -rf /; curl http://example.invalid")

        result = validate_remediation_action(remediation_action)

        self.assertFalse(result.valid)
        self.assertIn("EXECUTION_NOT_SUPPORTED_IN_STEP_8", result.issues)
        self.assertIn("COMMAND_PREVIEW_MUST_BE_NON_EXECUTABLE", result.issues)
        self.assertIn("COMMAND_PREVIEW_CONTAINS_SHELL_OPERATORS_FOR_REVIEW_ONLY", result.warnings)

    def test_operational_action_without_approval_is_invalid(self):
        remediation_action = action(RemediationActionType.BLOCK_IP)
        object.__setattr__(
            remediation_action,
            "approval_requirement",
            RemediationApprovalRequirement.NONE,
        )

        result = validate_remediation_action(remediation_action)

        self.assertFalse(result.valid)
        self.assertIn("OPERATIONAL_ACTION_REQUIRES_APPROVAL", result.issues)

    def test_destructive_action_must_be_forbidden(self):
        remediation_action = action(RemediationActionType.KILL_PROCESS)
        object.__setattr__(
            remediation_action,
            "approval_requirement",
            RemediationApprovalRequirement.ADMIN_APPROVAL,
        )

        result = validate_remediation_action(remediation_action)

        self.assertFalse(result.valid)
        self.assertIn("DESTRUCTIVE_ACTION_MUST_BE_FORBIDDEN_BY_DEFAULT", result.issues)


if __name__ == "__main__":
    unittest.main()
