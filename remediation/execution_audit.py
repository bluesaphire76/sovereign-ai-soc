from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field

from .approvals import RemediationApprovalRecord
from .dry_run import RemediationDryRunResult
from .models import (
    RemediationAction,
    RemediationApprovalRequirement,
    RemediationBaseModel,
    RemediationPlan,
    RemediationRiskLevel,
)
from .readiness import (
    RemediationExecutionAuditStatus,
    RemediationExecutionReadinessAssessment,
)
from .rollback_readiness import (
    RemediationRollbackReadiness,
    RemediationRollbackReadinessStatus,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationExecutionChainOfCustody(RemediationBaseModel):
    chain_id: str
    incident_id: int | None = None
    evidence_reference_ids: list[str] = Field(default_factory=list)
    plan_id: str
    action_id: str
    approval_id: str | None = None
    dry_run_id: str | None = None
    readiness_id: str | None = None
    rollback_readiness_id: str | None = None
    prepared_at: datetime = Field(default_factory=utc_now)
    custody_complete: bool = False
    gaps: list[str] = Field(default_factory=list)


class RemediationExecutionAuditRecord(RemediationBaseModel):
    execution_audit_id: str
    plan_id: str
    action_id: str
    incident_id: int | None = None
    approval_id: str | None = None
    dry_run_id: str | None = None
    requested_by: str | None = None
    approved_by: str | None = None
    requested_at: datetime = Field(default_factory=utc_now)
    approved_at: datetime | None = None
    readiness_checked_at: datetime = Field(default_factory=utc_now)
    execution_status: RemediationExecutionAuditStatus = (
        RemediationExecutionAuditStatus.EXECUTION_NOT_IMPLEMENTED
    )
    execution_supported: bool = False
    execution_attempted: bool = False
    execution_blocked_reason: str | None = None
    action_type: str
    target_summary: str
    risk_level: RemediationRiskLevel
    approval_requirement: RemediationApprovalRequirement
    rollback_available: bool = False
    rollback_readiness_status: RemediationRollbackReadinessStatus
    evidence_references: list[str] = Field(default_factory=list)
    policy_checks: list[str] = Field(default_factory=list)
    validation_results: list[str] = Field(default_factory=list)
    audit_notes: list[str] = Field(default_factory=list)
    chain_of_custody: RemediationExecutionChainOfCustody


def _target_summary(action: RemediationAction) -> str:
    target = action.target
    value = target.value or target.host or target.user or target.ip_address or "unspecified target"
    return f"{target.target_type.value}: {value}"


def build_chain_of_custody(
    plan: RemediationPlan,
    action: RemediationAction,
    *,
    approval_record: RemediationApprovalRecord | None = None,
    dry_run_result: RemediationDryRunResult | None = None,
    readiness: RemediationExecutionReadinessAssessment | None = None,
    rollback_readiness: RemediationRollbackReadiness | None = None,
) -> RemediationExecutionChainOfCustody:
    gaps: list[str] = []
    if action.approval_requirement != RemediationApprovalRequirement.NONE and not approval_record:
        gaps.append("missing_approval_record")
    if not dry_run_result:
        gaps.append("missing_dry_run_result")
    if not readiness:
        gaps.append("missing_readiness_assessment")
    if not rollback_readiness:
        gaps.append("missing_rollback_readiness")
    if not action.evidence:
        gaps.append("missing_evidence_references")

    return RemediationExecutionChainOfCustody(
        chain_id=f"chain:{plan.plan_id}:{action.action_id}",
        incident_id=plan.incident_id,
        evidence_reference_ids=[evidence.evidence_id for evidence in action.evidence],
        plan_id=plan.plan_id,
        action_id=action.action_id,
        approval_id=approval_record.approval_id if approval_record else None,
        dry_run_id=dry_run_result.dry_run_id if dry_run_result else None,
        readiness_id=readiness.readiness_id if readiness else None,
        rollback_readiness_id=(
            rollback_readiness.rollback_readiness_id if rollback_readiness else None
        ),
        custody_complete=not gaps,
        gaps=gaps,
    )


def prepare_execution_audit_record(
    plan: RemediationPlan,
    action: RemediationAction,
    *,
    approval_record: RemediationApprovalRecord | None,
    dry_run_result: RemediationDryRunResult | None,
    readiness: RemediationExecutionReadinessAssessment,
    rollback_readiness: RemediationRollbackReadiness,
    requested_by: str | None = None,
) -> RemediationExecutionAuditRecord:
    chain = build_chain_of_custody(
        plan,
        action,
        approval_record=approval_record,
        dry_run_result=dry_run_result,
        readiness=readiness,
        rollback_readiness=rollback_readiness,
    )
    blocked_reason = "; ".join(blocker.reason for blocker in readiness.blockers) or None

    return RemediationExecutionAuditRecord(
        execution_audit_id=f"execution-audit:{plan.plan_id}:{action.action_id}",
        plan_id=plan.plan_id,
        action_id=action.action_id,
        incident_id=plan.incident_id,
        approval_id=approval_record.approval_id if approval_record else None,
        dry_run_id=dry_run_result.dry_run_id if dry_run_result else None,
        requested_by=requested_by or plan.generated_by,
        approved_by=approval_record.decided_by if approval_record else None,
        requested_at=plan.generated_at,
        approved_at=approval_record.decided_at if approval_record else None,
        readiness_checked_at=readiness.assessed_at,
        execution_status=readiness.execution_status,
        execution_supported=False,
        execution_attempted=False,
        execution_blocked_reason=blocked_reason,
        action_type=action.action_type.value,
        target_summary=_target_summary(action),
        risk_level=action.risk.level,
        approval_requirement=action.approval_requirement,
        rollback_available=rollback_readiness.rollback_available,
        rollback_readiness_status=rollback_readiness.status,
        evidence_references=[evidence.evidence_id for evidence in action.evidence],
        policy_checks=list(readiness.policy_checks),
        validation_results=list(readiness.validation_results),
        audit_notes=[
            "Execution audit record is prepared for governance only.",
            "No system state was changed in Step 10.",
            *readiness.audit_notes,
        ],
        chain_of_custody=chain,
    )
