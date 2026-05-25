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
    audit_event_from_approval,
    audit_event_from_dry_run,
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
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan


def evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Evidence supports remediation audit review.",
    )


def action() -> RemediationAction:
    action_type = RemediationActionType.CREATE_TICKET
    target = RemediationTarget(
        target_type=RemediationTargetType.TICKET,
        value="incident:1",
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
        title="Create review ticket",
        description="Create a governed review ticket.",
        target=target,
        reason="Low-risk governance tracking.",
        evidence=[evidence()],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="Planning-only action."),
        rollback_steps=rollback.steps,
    )


class RemediationAuditTests(unittest.TestCase):
    def test_approval_record_produces_audit_friendly_event(self):
        remediation_action = action()
        request = RemediationApprovalRequest(
            request_id="req-audit-1",
            plan_id="plan-1",
            action_id=remediation_action.action_id,
            incident_id=1,
            decision=RemediationApprovalDecision.APPROVE,
            actor=RemediationApprovalActor(username="analyst-user", role="ANALYST"),
            rationale="Analyst reviewed low-risk action.",
        )
        record = create_approval_record(request, action=remediation_action)

        event = audit_event_from_approval(record)

        self.assertEqual(event.event_type, RemediationAuditEventType.REMEDIATION_APPROVED)
        self.assertFalse(event.details["execution_triggered"])
        self.assertNotIn("command_preview", event.details)

    def test_dry_run_audit_event_omits_command_preview(self):
        remediation_action = action()
        object.__setattr__(
            remediation_action,
            "command_preview",
            "PREVIEW ONLY: review-only content",
        )
        result = generate_action_dry_run(remediation_action, plan_id="plan-1", incident_id=1)

        event = audit_event_from_dry_run(result)

        self.assertEqual(event.event_type, RemediationAuditEventType.REMEDIATION_DRY_RUN_GENERATED)
        self.assertFalse(event.details["state_mutated"])
        self.assertFalse(event.details["execution_supported"])
        self.assertNotIn("command_preview", event.details)


if __name__ == "__main__":
    unittest.main()
