from __future__ import annotations

from investigation_ai.models import EvidenceReference, InvestigationEvidenceType
from remediation.approvals import (
    RemediationApprovalActor,
    RemediationApprovalDecision,
    RemediationApprovalRequest,
    create_approval_record,
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
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan


def evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Evidence supports remediation governance workflow review.",
    )


def remediation_action(
    action_type: RemediationActionType = RemediationActionType.BLOCK_IP,
    *,
    include_evidence: bool = True,
    include_rollback: bool = True,
    command_preview: str | None = "PREVIEW ONLY: review block-list intent for IP 10.0.0.5",
) -> RemediationAction:
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
        criticality=RemediationTargetCriticality.LOW,
    )
    rollback = build_rollback_plan(action_type, action_id=f"workflow-{action_type.value.lower()}")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=90,
        evidence_count=1 if include_evidence else 0,
    )
    return RemediationAction(
        action_id=f"workflow-{action_type.value.lower()}",
        action_type=action_type,
        title="Review governed remediation workflow",
        description="Evaluate remediation governance without production execution.",
        target=target,
        reason="Evidence indicates the action can be reviewed through governance gates.",
        evidence=[evidence()] if include_evidence else [],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="Governance-only review."),
        rollback_steps=rollback.steps if include_rollback else [],
        command_preview=command_preview,
    )


def remediation_plan(action: RemediationAction) -> RemediationPlan:
    return RemediationPlan(
        plan_id="plan-1",
        incident_id=1,
        status=RemediationPlanStatus.PROPOSED,
        summary="Governed remediation plan for Step 12 workflow validation.",
        rationale="The plan is used to validate approval, dry-run, readiness, policy and mock dispatch.",
        actions=[action],
        overall_risk=action.risk,
        rollback_plan=RollbackPlan(
            rollback_id="plan-rollback",
            availability=RollbackAvailability.FULL if action.rollback_steps else RollbackAvailability.UNAVAILABLE,
            steps=action.rollback_steps,
            validation_steps=["Validate rollback state remains review-only."],
            recovery_notes="Rollback metadata is present for governance review.",
        ),
        evidence_used=[evidence()],
    )


def approval_record(
    action: RemediationAction,
    *,
    decision: RemediationApprovalDecision = RemediationApprovalDecision.APPROVE,
):
    request = RemediationApprovalRequest(
        request_id=f"request-{decision.value.lower()}-{action.action_id}",
        plan_id="plan-1",
        action_id=action.action_id,
        incident_id=1,
        decision=decision,
        actor=RemediationApprovalActor(username="admin-user", role="ADMIN"),
        rationale="Admin reviewed evidence, dry-run, rollback and governance requirements.",
    )
    return create_approval_record(request, action=action)
