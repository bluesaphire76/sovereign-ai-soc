import unittest

from investigation_ai.models import EvidenceReference, InvestigationEvidenceType
from remediation.approvals import (
    RemediationApprovalActor,
    RemediationApprovalDecision,
    RemediationApprovalRequest,
    RemediationApprovalStatus,
    create_approval_record,
)
from remediation.dry_run import (
    RemediationDryRunStatus,
    RemediationExecutionReadiness,
    generate_action_dry_run,
    generate_plan_dry_run,
)
from remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationImpactAssessment,
    RemediationPlan,
    RemediationTarget,
    RemediationTargetCriticality,
    RemediationTargetType,
)
from remediation.planner import create_fallback_remediation_plan
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan
from remediation.validators import validate_dry_run_result


def evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Evidence supports remediation dry-run review.",
    )


def action(action_type: RemediationActionType = RemediationActionType.CREATE_TICKET) -> RemediationAction:
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
        criticality=RemediationTargetCriticality.LOW,
    )
    rollback = build_rollback_plan(action_type, action_id=f"dry-run-{action_type.value.lower()}")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=90,
        evidence_count=1,
    )
    return RemediationAction(
        action_id=f"dry-run-{action_type.value.lower()}",
        action_type=action_type,
        title="Review remediation action",
        description="Review remediation action in dry-run mode.",
        target=target,
        reason="Evidence indicates a governed review is warranted.",
        evidence=[evidence()],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="Planning-only action."),
        rollback_steps=rollback.steps,
    )


class RemediationDryRunTests(unittest.TestCase):
    def test_dry_run_does_not_mutate_plan_state(self):
        plan = create_fallback_remediation_plan(7)
        before = plan.model_dump(mode="json")

        result = generate_plan_dry_run(plan)
        after = plan.model_dump(mode="json")
        validation = validate_dry_run_result(result)

        self.assertEqual(before, after)
        self.assertFalse(result.state_mutated)
        self.assertFalse(result.execution_supported)
        self.assertEqual(validation.issues, [])

    def test_dry_run_flags_missing_rollback(self):
        remediation_action = action().model_copy(update={"rollback_steps": []})
        result = generate_action_dry_run(remediation_action, plan_id="plan-1", incident_id=1)

        self.assertEqual(result.status, RemediationDryRunStatus.MISSING_ROLLBACK)
        self.assertIn(
            RemediationDryRunStatus.MISSING_ROLLBACK,
            {finding.status for finding in result.findings},
        )

    def test_dry_run_flags_missing_evidence(self):
        remediation_action = action().model_copy(update={"evidence": []})
        result = generate_action_dry_run(remediation_action, plan_id="plan-1", incident_id=1)

        self.assertEqual(result.status, RemediationDryRunStatus.MISSING_EVIDENCE)
        self.assertIn(
            RemediationDryRunStatus.MISSING_EVIDENCE,
            {finding.status for finding in result.findings},
        )

    def test_forbidden_action_is_blocked_in_dry_run(self):
        result = generate_action_dry_run(
            action(RemediationActionType.KILL_PROCESS),
            plan_id="plan-1",
            incident_id=1,
        )

        self.assertEqual(result.status, RemediationDryRunStatus.FORBIDDEN)
        self.assertEqual(result.readiness, RemediationExecutionReadiness.BLOCKED)

    def test_approval_record_satisfies_dry_run_approval_requirement(self):
        remediation_action = action(RemediationActionType.BLOCK_IP)
        request = RemediationApprovalRequest(
            request_id="req-1",
            plan_id="plan-1",
            action_id=remediation_action.action_id,
            incident_id=1,
            decision=RemediationApprovalDecision.APPROVE,
            actor=RemediationApprovalActor(username="admin-user", role="ADMIN"),
            rationale="Admin reviewed evidence, risk and rollback.",
        )
        approval = create_approval_record(request, action=remediation_action)
        self.assertEqual(approval.status, RemediationApprovalStatus.APPROVED)

        result = generate_action_dry_run(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
            approval_record=approval,
        )

        self.assertNotIn(
            RemediationDryRunStatus.MISSING_APPROVAL,
            {finding.status for finding in result.findings},
        )
        self.assertEqual(result.status, RemediationDryRunStatus.NOT_SUPPORTED)
        self.assertFalse(result.execution_supported)

    def test_plan_dry_run_is_deterministic_for_stable_fields(self):
        plan: RemediationPlan = create_fallback_remediation_plan(9)
        first = generate_plan_dry_run(plan)
        second = generate_plan_dry_run(plan)

        self.assertEqual(first.dry_run_id, second.dry_run_id)
        self.assertEqual(first.status, second.status)
        self.assertEqual(first.readiness, second.readiness)
        self.assertEqual(
            [finding.finding_id for finding in first.findings],
            [finding.finding_id for finding in second.findings],
        )


if __name__ == "__main__":
    unittest.main()
