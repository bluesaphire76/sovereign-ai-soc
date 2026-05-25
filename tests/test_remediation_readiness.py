import unittest

from investigation_ai.models import EvidenceReference, InvestigationEvidenceType
from remediation.approvals import (
    RemediationApprovalActor,
    RemediationApprovalDecision,
    RemediationApprovalRequest,
    create_approval_record,
)
from remediation.dry_run import generate_action_dry_run
from remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationImpactAssessment,
    RemediationTarget,
    RemediationTargetCriticality,
    RemediationTargetType,
)
from remediation.readiness import (
    RemediationExecutionAuditStatus,
    assess_action_execution_readiness,
)
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan
from remediation.validators import validate_execution_readiness_assessment


def evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Evidence supports future readiness review.",
    )


def action(
    action_type: RemediationActionType = RemediationActionType.BLOCK_IP,
    *,
    include_evidence: bool = True,
    include_rollback: bool = True,
    command_preview: str | None = "PREVIEW ONLY: block traffic for IP 10.0.0.5",
) -> RemediationAction:
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
        criticality=RemediationTargetCriticality.LOW,
    )
    rollback = build_rollback_plan(action_type, action_id=f"readiness-{action_type.value.lower()}")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=90,
        evidence_count=1 if include_evidence else 0,
    )
    return RemediationAction(
        action_id=f"readiness-{action_type.value.lower()}",
        action_type=action_type,
        title="Review remediation readiness",
        description="Assess future readiness without execution.",
        target=target,
        reason="Evidence indicates readiness can be evaluated.",
        evidence=[evidence()] if include_evidence else [],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="Readiness-only action."),
        rollback_steps=rollback.steps if include_rollback else [],
        command_preview=command_preview,
    )


def approved_record(remediation_action: RemediationAction):
    request = RemediationApprovalRequest(
        request_id=f"request-{remediation_action.action_id}",
        plan_id="plan-1",
        action_id=remediation_action.action_id,
        incident_id=1,
        decision=RemediationApprovalDecision.APPROVE,
        actor=RemediationApprovalActor(username="admin-user", role="ADMIN"),
        rationale="Admin reviewed evidence, risk and rollback readiness.",
    )
    return create_approval_record(request, action=remediation_action)


class RemediationReadinessTests(unittest.TestCase):
    def test_readiness_blocked_without_required_approval(self):
        remediation_action = action()
        assessment = assess_action_execution_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
        )

        self.assertEqual(
            assessment.execution_status,
            RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_APPROVAL,
        )
        self.assertFalse(assessment.execution_supported)

    def test_readiness_blocked_for_forbidden_action(self):
        remediation_action = action(RemediationActionType.KILL_PROCESS)
        assessment = assess_action_execution_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
        )

        self.assertEqual(
            assessment.execution_status,
            RemediationExecutionAuditStatus.BLOCKED_BY_POLICY,
        )

    def test_readiness_blocked_without_rollback_for_operational_action(self):
        remediation_action = action(include_rollback=False)
        approval = approved_record(remediation_action)
        dry_run = generate_action_dry_run(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
        )
        assessment = assess_action_execution_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
            dry_run_result=dry_run,
        )

        self.assertEqual(
            assessment.execution_status,
            RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_ROLLBACK,
        )

    def test_readiness_blocked_for_shell_like_preview(self):
        remediation_action = action(command_preview="PREVIEW ONLY: iptables -A INPUT; rm -rf /tmp/x")
        approval = approved_record(remediation_action)
        dry_run = generate_action_dry_run(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
        )
        assessment = assess_action_execution_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
            dry_run_result=dry_run,
        )

        self.assertEqual(
            assessment.execution_status,
            RemediationExecutionAuditStatus.BLOCKED_BY_VALIDATION,
        )

    def test_readiness_can_reach_future_executor_state_without_execution(self):
        remediation_action = action()
        approval = approved_record(remediation_action)
        dry_run = generate_action_dry_run(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
        )
        assessment = assess_action_execution_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
            dry_run_result=dry_run,
        )
        validation = validate_execution_readiness_assessment(assessment)

        self.assertEqual(
            assessment.execution_status,
            RemediationExecutionAuditStatus.READY_FOR_FUTURE_EXECUTOR,
        )
        self.assertFalse(assessment.execution_supported)
        self.assertFalse(assessment.execution_attempted)
        self.assertEqual(assessment.blockers, [])
        self.assertEqual(validation.issues, [])

    def test_readiness_repeatability_for_stable_fields(self):
        remediation_action = action()
        approval = approved_record(remediation_action)
        first = assess_action_execution_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
        )
        second = assess_action_execution_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
        )

        self.assertEqual(first.readiness_id, second.readiness_id)
        self.assertEqual(first.execution_status, second.execution_status)
        self.assertEqual(
            [precondition.precondition_id for precondition in first.preconditions],
            [precondition.precondition_id for precondition in second.preconditions],
        )


if __name__ == "__main__":
    unittest.main()
