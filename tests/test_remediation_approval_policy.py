import unittest

from investigation_ai.models import EvidenceReference, InvestigationEvidenceType
from remediation.approvals import (
    RemediationApprovalActor,
    RemediationApprovalDecision,
    RemediationApprovalRequest,
    RemediationApprovalStatus,
    create_approval_record,
    evaluate_action_approval,
)
from remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationImpactAssessment,
    RemediationTarget,
    RemediationTargetCriticality,
    RemediationTargetType,
)
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan
from remediation.validators import validate_approval_record


def actor(role: str) -> RemediationApprovalActor:
    return RemediationApprovalActor(username=f"{role.lower()}-user", role=role)


def evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Structured incident evidence supports review.",
    )


def action(action_type: RemediationActionType) -> RemediationAction:
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
        criticality=RemediationTargetCriticality.LOW,
    )
    rollback = build_rollback_plan(action_type, action_id=f"action-{action_type.value.lower()}")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=90,
        evidence_count=1,
    )
    return RemediationAction(
        action_id=f"action-{action_type.value.lower()}",
        action_type=action_type,
        title="Review remediation action",
        description="Review remediation action before any future execution design.",
        target=target,
        reason="Evidence indicates a governed review is warranted.",
        evidence=[evidence()],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="Planning-only action."),
        rollback_steps=rollback.steps,
    )


class RemediationApprovalPolicyTests(unittest.TestCase):
    def test_viewer_cannot_approve(self):
        result = evaluate_action_approval(
            actor("VIEWER"),
            action(RemediationActionType.CREATE_TICKET),
            RemediationApprovalDecision.APPROVE,
            rationale="Reviewed for governance.",
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.status, RemediationApprovalStatus.FORBIDDEN)
        self.assertIn("VIEWER_CANNOT_APPROVE_REMEDIATION", result.issues)

    def test_analyst_can_approve_low_risk_action(self):
        result = evaluate_action_approval(
            actor("ANALYST"),
            action(RemediationActionType.CREATE_TICKET),
            RemediationApprovalDecision.APPROVE,
            rationale="Low-risk ticket creation approved for review tracking.",
        )

        self.assertTrue(result.allowed)
        self.assertEqual(result.status, RemediationApprovalStatus.APPROVED)

    def test_analyst_cannot_approve_admin_required_action(self):
        result = evaluate_action_approval(
            actor("ANALYST"),
            action(RemediationActionType.BLOCK_IP),
            RemediationApprovalDecision.APPROVE,
            rationale="Block request reviewed.",
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.status, RemediationApprovalStatus.REQUIRES_ADMIN)
        self.assertIn("ADMIN_APPROVAL_REQUIRED", result.issues)

    def test_admin_can_approve_admin_required_action_without_execution(self):
        remediation_action = action(RemediationActionType.BLOCK_IP)
        request = RemediationApprovalRequest(
            request_id="req-1",
            plan_id="plan-1",
            action_id=remediation_action.action_id,
            incident_id=1,
            decision=RemediationApprovalDecision.APPROVE,
            actor=actor("ADMIN"),
            rationale="Admin reviewed evidence, risk and rollback notes.",
        )
        record = create_approval_record(request, action=remediation_action)
        validation = validate_approval_record(record)

        self.assertEqual(record.status, RemediationApprovalStatus.APPROVED)
        self.assertFalse(record.execution_triggered)
        self.assertEqual(validation.issues, [])

    def test_forbidden_action_cannot_be_approved(self):
        remediation_action = action(RemediationActionType.KILL_PROCESS)
        result = evaluate_action_approval(
            actor("ADMIN"),
            remediation_action,
            RemediationApprovalDecision.APPROVE,
            rationale="Attempted approval for destructive action.",
        )

        self.assertFalse(result.allowed)
        self.assertEqual(result.status, RemediationApprovalStatus.FORBIDDEN)
        self.assertEqual(
            remediation_action.approval_requirement,
            RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT,
        )

    def test_approval_requires_rationale(self):
        result = evaluate_action_approval(
            actor("ADMIN"),
            action(RemediationActionType.CREATE_TICKET),
            RemediationApprovalDecision.APPROVE,
            rationale="",
        )

        self.assertFalse(result.allowed)
        self.assertIn("APPROVAL_REQUIRES_RATIONALE", result.issues)


if __name__ == "__main__":
    unittest.main()
