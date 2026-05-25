import unittest

from investigation_ai.models import EvidenceReference, InvestigationEvidenceType
from remediation.approvals import (
    RemediationApprovalActor,
    RemediationApprovalDecision,
    RemediationApprovalRequest,
    create_approval_record,
)
from remediation.audit import (
    RemediationAuditEventType,
    audit_event_from_execution_audit_record,
    audit_event_from_readiness_assessment,
    audit_event_from_rollback_readiness,
)
from remediation.dry_run import generate_action_dry_run
from remediation.execution_audit import (
    build_chain_of_custody,
    prepare_execution_audit_record,
)
from remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationImpactAssessment,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationTarget,
    RemediationTargetCriticality,
    RemediationTargetType,
    RollbackAvailability,
    RollbackPlan,
)
from remediation.readiness import (
    RemediationExecutionAuditStatus,
    assess_action_execution_readiness,
)
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan
from remediation.rollback_readiness import assess_action_rollback_readiness
from remediation.validators import validate_execution_audit_record


def evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Evidence supports execution audit readiness.",
    )


def action() -> RemediationAction:
    action_type = RemediationActionType.BLOCK_IP
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
        criticality=RemediationTargetCriticality.LOW,
    )
    rollback = build_rollback_plan(action_type, action_id="audit-action")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=90,
        evidence_count=1,
    )
    return RemediationAction(
        action_id="audit-action",
        action_type=action_type,
        title="Block suspicious source IP",
        description="Assess future block readiness without execution.",
        target=target,
        reason="Evidence indicates source IP review is warranted.",
        evidence=[evidence()],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="Readiness-only action."),
        rollback_steps=rollback.steps,
        command_preview="PREVIEW ONLY: block traffic for IP 10.0.0.5",
    )


def plan(remediation_action: RemediationAction) -> RemediationPlan:
    return RemediationPlan(
        plan_id="plan-1",
        incident_id=1,
        status=RemediationPlanStatus.PROPOSED,
        summary="Remediation plan ready for governance review.",
        rationale="Readiness assessment only.",
        actions=[remediation_action],
        overall_risk=remediation_action.risk,
        rollback_plan=RollbackPlan(
            rollback_id="plan-rollback",
            availability=RollbackAvailability.FULL,
            steps=remediation_action.rollback_steps,
            validation_steps=["Validate rollback state."],
            recovery_notes="Rollback is available for review.",
        ),
        evidence_used=[evidence()],
    )


def approved_record(remediation_action: RemediationAction):
    request = RemediationApprovalRequest(
        request_id="request-1",
        plan_id="plan-1",
        action_id=remediation_action.action_id,
        incident_id=1,
        decision=RemediationApprovalDecision.APPROVE,
        actor=RemediationApprovalActor(username="admin-user", role="ADMIN"),
        rationale="Admin reviewed evidence, approval and rollback.",
    )
    return create_approval_record(request, action=remediation_action)


class RemediationExecutionAuditTests(unittest.TestCase):
    def test_execution_audit_record_does_not_imply_execution(self):
        remediation_action = action()
        remediation_plan = plan(remediation_action)
        approval = approved_record(remediation_action)
        dry_run = generate_action_dry_run(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
            approval_record=approval,
        )
        rollback = assess_action_rollback_readiness(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
        )
        readiness = assess_action_execution_readiness(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
            approval_record=approval,
            dry_run_result=dry_run,
            rollback_readiness=rollback,
        )
        record = prepare_execution_audit_record(
            remediation_plan,
            remediation_action,
            approval_record=approval,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )
        validation = validate_execution_audit_record(record)

        self.assertEqual(
            record.execution_status,
            RemediationExecutionAuditStatus.READY_FOR_FUTURE_EXECUTOR,
        )
        self.assertFalse(record.execution_supported)
        self.assertFalse(record.execution_attempted)
        self.assertEqual(validation.issues, [])

    def test_chain_of_custody_links_required_artifacts(self):
        remediation_action = action()
        remediation_plan = plan(remediation_action)
        approval = approved_record(remediation_action)
        dry_run = generate_action_dry_run(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
            approval_record=approval,
        )
        rollback = assess_action_rollback_readiness(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
        )
        readiness = assess_action_execution_readiness(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
            approval_record=approval,
            dry_run_result=dry_run,
            rollback_readiness=rollback,
        )
        chain = build_chain_of_custody(
            remediation_plan,
            remediation_action,
            approval_record=approval,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )

        self.assertTrue(chain.custody_complete)
        self.assertEqual(chain.plan_id, remediation_plan.plan_id)
        self.assertEqual(chain.action_id, remediation_action.action_id)
        self.assertEqual(chain.approval_id, approval.approval_id)
        self.assertEqual(chain.dry_run_id, dry_run.dry_run_id)
        self.assertEqual(chain.readiness_id, readiness.readiness_id)
        self.assertEqual(chain.rollback_readiness_id, rollback.rollback_readiness_id)

    def test_readiness_and_rollback_audit_events_do_not_claim_execution(self):
        remediation_action = action()
        remediation_plan = plan(remediation_action)
        approval = approved_record(remediation_action)
        dry_run = generate_action_dry_run(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
            approval_record=approval,
        )
        rollback = assess_action_rollback_readiness(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
        )
        readiness = assess_action_execution_readiness(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
            approval_record=approval,
            dry_run_result=dry_run,
            rollback_readiness=rollback,
        )
        record = prepare_execution_audit_record(
            remediation_plan,
            remediation_action,
            approval_record=approval,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )

        readiness_event = audit_event_from_readiness_assessment(readiness)
        rollback_event = audit_event_from_rollback_readiness(rollback)
        record_event = audit_event_from_execution_audit_record(record)

        self.assertEqual(
            readiness_event.event_type,
            RemediationAuditEventType.REMEDIATION_EXECUTION_READINESS_ASSESSED,
        )
        self.assertEqual(
            rollback_event.event_type,
            RemediationAuditEventType.REMEDIATION_ROLLBACK_READINESS_ASSESSED,
        )
        self.assertEqual(
            record_event.event_type,
            RemediationAuditEventType.REMEDIATION_CHAIN_OF_CUSTODY_PREPARED,
        )
        self.assertFalse(record_event.details["execution_supported"])
        self.assertFalse(record_event.details["execution_attempted"])

    def test_no_execution_path_exists_on_audit_record(self):
        remediation_action = action()
        remediation_plan = plan(remediation_action)
        approval = approved_record(remediation_action)
        dry_run = generate_action_dry_run(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
            approval_record=approval,
        )
        rollback = assess_action_rollback_readiness(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
        )
        readiness = assess_action_execution_readiness(
            remediation_action,
            plan_id=remediation_plan.plan_id,
            incident_id=remediation_plan.incident_id,
            approval_record=approval,
            dry_run_result=dry_run,
            rollback_readiness=rollback,
        )
        record = prepare_execution_audit_record(
            remediation_plan,
            remediation_action,
            approval_record=approval,
            dry_run_result=dry_run,
            readiness=readiness,
            rollback_readiness=rollback,
        )

        self.assertFalse(hasattr(record, "execute"))
        self.assertFalse(record.execution_supported)
        self.assertFalse(record.execution_attempted)


if __name__ == "__main__":
    unittest.main()
