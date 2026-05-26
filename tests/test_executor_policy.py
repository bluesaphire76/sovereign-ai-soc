import unittest

from executor.models import ExecutorMode, executor_action_from_remediation
from executor.policy import evaluate_executor_policy
from executor.validators import validate_executor_action
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
from remediation.readiness import assess_action_execution_readiness
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan
from remediation.rollback_readiness import assess_action_rollback_readiness


def evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Evidence supports controlled executor validation.",
    )


def remediation_action(
    action_type: RemediationActionType = RemediationActionType.BLOCK_IP,
) -> RemediationAction:
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
        criticality=RemediationTargetCriticality.LOW,
    )
    rollback = build_rollback_plan(action_type, action_id=f"executor-{action_type.value.lower()}")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=90,
        evidence_count=1,
    )
    return RemediationAction(
        action_id=f"executor-{action_type.value.lower()}",
        action_type=action_type,
        title="Review controlled executor action",
        description="Prepare a controlled executor action without real execution.",
        target=target,
        reason="Evidence indicates a governed action can be evaluated.",
        evidence=[evidence()],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="No production impact."),
        rollback_steps=rollback.steps,
        command_preview="PREVIEW ONLY: block traffic for IP 10.0.0.5",
    )


def approved_record(action: RemediationAction):
    request = RemediationApprovalRequest(
        request_id=f"request-{action.action_id}",
        plan_id="plan-1",
        action_id=action.action_id,
        incident_id=1,
        decision=RemediationApprovalDecision.APPROVE,
        actor=RemediationApprovalActor(username="admin-user", role="ADMIN"),
        rationale="Admin reviewed approval, rollback and dry-run context.",
    )
    return create_approval_record(request, action=action)


def executor_context(action: RemediationAction, *, mode: ExecutorMode = ExecutorMode.NOOP):
    approval = approved_record(action)
    dry_run = generate_action_dry_run(
        action,
        plan_id="plan-1",
        incident_id=1,
        approval_record=approval,
    )
    rollback = assess_action_rollback_readiness(action, plan_id="plan-1", incident_id=1)
    readiness = assess_action_execution_readiness(
        action,
        plan_id="plan-1",
        incident_id=1,
        approval_record=approval,
        dry_run_result=dry_run,
        rollback_readiness=rollback,
    )
    executor_action = executor_action_from_remediation(
        action,
        approval_record=approval,
        dry_run_result=dry_run,
        readiness=readiness,
        rollback_readiness=rollback,
        mode=mode,
    )
    return executor_action, approval, dry_run, rollback, readiness


class ExecutorPolicyTests(unittest.TestCase):
    def test_policy_allows_validated_noop_whitelisted_action(self):
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

        self.assertTrue(decision.allowed)
        self.assertEqual(decision.status.value, "ALLOWED_FOR_NOOP")
        self.assertFalse(decision.execution_supported)
        self.assertFalse(decision.production_impact_allowed)

    def test_policy_blocks_missing_approval(self):
        executor_action, _approval, dry_run, rollback, readiness = executor_context(
            remediation_action()
        )

        decision = evaluate_executor_policy(
            executor_action,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )

        self.assertFalse(decision.allowed)
        self.assertIn("EXECUTOR_APPROVAL_NOT_SATISFIED", decision.blockers)

    def test_policy_blocks_missing_whitelist_entry(self):
        executor_action, approval, dry_run, rollback, readiness = executor_context(
            remediation_action()
        )

        decision = evaluate_executor_policy(
            executor_action,
            approval_record=approval,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
            whitelist={},
        )

        self.assertFalse(decision.allowed)
        self.assertIn("EXECUTOR_ACTION_NOT_ENABLED_IN_WHITELIST", decision.blockers)

    def test_arbitrary_command_parameters_are_blocked(self):
        executor_action, approval, dry_run, rollback, readiness = executor_context(
            remediation_action()
        )
        executor_action = executor_action.model_copy(
            update={"parameters": {"command": "rm -rf /tmp/anything"}}
        )
        validation = validate_executor_action(executor_action)
        decision = evaluate_executor_policy(
            executor_action,
            approval_record=approval,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )

        self.assertFalse(validation.valid)
        self.assertFalse(decision.allowed)
        self.assertTrue(any("FORBIDDEN_PARAMETER" in issue for issue in validation.issues))

    def test_non_executor_remediation_action_is_rejected_by_adapter(self):
        with self.assertRaises(ValueError):
            executor_action_from_remediation(remediation_action(RemediationActionType.KILL_PROCESS))


if __name__ == "__main__":
    unittest.main()
