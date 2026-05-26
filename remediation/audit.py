from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field

from .approvals import (
    RemediationApprovalActor,
    RemediationApprovalRecord,
    RemediationApprovalStatus,
)
from .dry_run import RemediationDryRunResult, RemediationDryRunStatus
from .execution_audit import RemediationExecutionAuditRecord
from .models import RemediationBaseModel
from .readiness import (
    RemediationExecutionAuditStatus,
    RemediationExecutionReadinessAssessment,
)
from .rollback_readiness import RemediationRollbackReadiness


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationAuditEventType(str, Enum):
    REMEDIATION_APPROVAL_REQUESTED = "REMEDIATION_APPROVAL_REQUESTED"
    REMEDIATION_APPROVED = "REMEDIATION_APPROVED"
    REMEDIATION_REJECTED = "REMEDIATION_REJECTED"
    REMEDIATION_DEFERRED = "REMEDIATION_DEFERRED"
    REMEDIATION_ADMIN_REVIEW_REQUESTED = "REMEDIATION_ADMIN_REVIEW_REQUESTED"
    REMEDIATION_FORBIDDEN_APPROVAL_ATTEMPTED = "REMEDIATION_FORBIDDEN_APPROVAL_ATTEMPTED"
    REMEDIATION_DRY_RUN_GENERATED = "REMEDIATION_DRY_RUN_GENERATED"
    REMEDIATION_DRY_RUN_BLOCKED_BY_POLICY = "REMEDIATION_DRY_RUN_BLOCKED_BY_POLICY"
    REMEDIATION_EXECUTION_READINESS_ASSESSED = "REMEDIATION_EXECUTION_READINESS_ASSESSED"
    REMEDIATION_EXECUTION_BLOCKED_BY_POLICY = "REMEDIATION_EXECUTION_BLOCKED_BY_POLICY"
    REMEDIATION_EXECUTION_BLOCKED_BY_MISSING_APPROVAL = (
        "REMEDIATION_EXECUTION_BLOCKED_BY_MISSING_APPROVAL"
    )
    REMEDIATION_EXECUTION_BLOCKED_BY_MISSING_ROLLBACK = (
        "REMEDIATION_EXECUTION_BLOCKED_BY_MISSING_ROLLBACK"
    )
    REMEDIATION_ROLLBACK_READINESS_ASSESSED = "REMEDIATION_ROLLBACK_READINESS_ASSESSED"
    REMEDIATION_CHAIN_OF_CUSTODY_PREPARED = "REMEDIATION_CHAIN_OF_CUSTODY_PREPARED"
    REMEDIATION_UNSUPPORTED_EXECUTION_REQUESTED = "REMEDIATION_UNSUPPORTED_EXECUTION_REQUESTED"
    REMEDIATION_GOVERNANCE_STATE_EVALUATED = "REMEDIATION_GOVERNANCE_STATE_EVALUATED"
    REMEDIATION_WORKFLOW_ADVANCED = "REMEDIATION_WORKFLOW_ADVANCED"
    REMEDIATION_WORKFLOW_BLOCKED_BY_POLICY = "REMEDIATION_WORKFLOW_BLOCKED_BY_POLICY"
    REMEDIATION_WORKFLOW_BLOCKED_BY_ROLLBACK = "REMEDIATION_WORKFLOW_BLOCKED_BY_ROLLBACK"
    REMEDIATION_WORKFLOW_BLOCKED_BY_MISSING_APPROVAL = (
        "REMEDIATION_WORKFLOW_BLOCKED_BY_MISSING_APPROVAL"
    )
    REMEDIATION_MOCK_DISPATCH_REQUESTED = "REMEDIATION_MOCK_DISPATCH_REQUESTED"
    REMEDIATION_MOCK_DISPATCH_COMPLETED = "REMEDIATION_MOCK_DISPATCH_COMPLETED"
    REMEDIATION_NOOP_DISPATCH_COMPLETED = "REMEDIATION_NOOP_DISPATCH_COMPLETED"


class RemediationAuditEvent(RemediationBaseModel):
    event_type: RemediationAuditEventType
    outcome: str
    actor_username: str | None = None
    actor_role: str | None = None
    target_type: str
    target_id: str
    incident_id: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


def _approval_event_type(record: RemediationApprovalRecord) -> RemediationAuditEventType:
    if record.status == RemediationApprovalStatus.APPROVED:
        return RemediationAuditEventType.REMEDIATION_APPROVED
    if record.status == RemediationApprovalStatus.REJECTED:
        return RemediationAuditEventType.REMEDIATION_REJECTED
    if record.status == RemediationApprovalStatus.DEFERRED:
        return RemediationAuditEventType.REMEDIATION_DEFERRED
    if record.status == RemediationApprovalStatus.REQUIRES_ADMIN:
        return RemediationAuditEventType.REMEDIATION_ADMIN_REVIEW_REQUESTED
    if record.status == RemediationApprovalStatus.FORBIDDEN:
        return RemediationAuditEventType.REMEDIATION_FORBIDDEN_APPROVAL_ATTEMPTED
    return RemediationAuditEventType.REMEDIATION_APPROVAL_REQUESTED


def audit_event_from_approval(record: RemediationApprovalRecord) -> RemediationAuditEvent:
    return RemediationAuditEvent(
        event_type=_approval_event_type(record),
        outcome=record.status.value,
        actor_username=record.decided_by,
        actor_role=record.role_at_decision,
        target_type="remediation_action" if record.action_id else "remediation_plan",
        target_id=record.action_id or record.plan_id,
        incident_id=record.incident_id,
        details={
            "plan_id": record.plan_id,
            "action_id": record.action_id,
            "decision": record.decision.value,
            "approval_requirement": record.approval_requirement.value,
            "risk_level": record.risk_level.value if record.risk_level else None,
            "policy_issues": list(record.policy_issues),
            "execution_triggered": False,
        },
    )


def audit_event_from_dry_run(
    result: RemediationDryRunResult,
    *,
    actor: RemediationApprovalActor | None = None,
) -> RemediationAuditEvent:
    blocked = result.status in {
        RemediationDryRunStatus.BLOCKED_BY_POLICY,
        RemediationDryRunStatus.FORBIDDEN,
    }
    return RemediationAuditEvent(
        event_type=(
            RemediationAuditEventType.REMEDIATION_DRY_RUN_BLOCKED_BY_POLICY
            if blocked
            else RemediationAuditEventType.REMEDIATION_DRY_RUN_GENERATED
        ),
        outcome=result.status.value,
        actor_username=actor.username if actor else None,
        actor_role=actor.role if actor else None,
        target_type="remediation_action" if result.action_id else "remediation_plan",
        target_id=result.action_id or result.plan_id or result.dry_run_id,
        incident_id=result.incident_id,
        details={
            "dry_run_id": result.dry_run_id,
            "plan_id": result.plan_id,
            "action_id": result.action_id,
            "readiness": result.readiness.value,
            "finding_count": len(result.findings),
            "state_mutated": False,
            "execution_supported": False,
        },
    )


def _readiness_event_type(
    assessment: RemediationExecutionReadinessAssessment,
) -> RemediationAuditEventType:
    if assessment.execution_status == RemediationExecutionAuditStatus.BLOCKED_BY_POLICY:
        return RemediationAuditEventType.REMEDIATION_EXECUTION_BLOCKED_BY_POLICY
    if assessment.execution_status == RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_APPROVAL:
        return RemediationAuditEventType.REMEDIATION_EXECUTION_BLOCKED_BY_MISSING_APPROVAL
    if assessment.execution_status == RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_ROLLBACK:
        return RemediationAuditEventType.REMEDIATION_EXECUTION_BLOCKED_BY_MISSING_ROLLBACK
    if assessment.execution_status in {
        RemediationExecutionAuditStatus.NOT_SUPPORTED,
        RemediationExecutionAuditStatus.EXECUTION_NOT_IMPLEMENTED,
    }:
        return RemediationAuditEventType.REMEDIATION_UNSUPPORTED_EXECUTION_REQUESTED
    return RemediationAuditEventType.REMEDIATION_EXECUTION_READINESS_ASSESSED


def audit_event_from_readiness_assessment(
    assessment: RemediationExecutionReadinessAssessment,
    *,
    actor: RemediationApprovalActor | None = None,
) -> RemediationAuditEvent:
    return RemediationAuditEvent(
        event_type=_readiness_event_type(assessment),
        outcome=assessment.execution_status.value,
        actor_username=actor.username if actor else None,
        actor_role=actor.role if actor else None,
        target_type="remediation_action",
        target_id=assessment.action_id,
        incident_id=assessment.incident_id,
        details={
            "readiness_id": assessment.readiness_id,
            "plan_id": assessment.plan_id,
            "action_id": assessment.action_id,
            "approval_id": assessment.approval_id,
            "dry_run_id": assessment.dry_run_id,
            "rollback_readiness_id": assessment.rollback_readiness_id,
            "blocker_count": len(assessment.blockers),
            "execution_supported": False,
            "execution_attempted": False,
        },
    )


def audit_event_from_rollback_readiness(
    rollback_readiness: RemediationRollbackReadiness,
    *,
    actor: RemediationApprovalActor | None = None,
) -> RemediationAuditEvent:
    return RemediationAuditEvent(
        event_type=RemediationAuditEventType.REMEDIATION_ROLLBACK_READINESS_ASSESSED,
        outcome=rollback_readiness.status.value,
        actor_username=actor.username if actor else None,
        actor_role=actor.role if actor else None,
        target_type="remediation_action" if rollback_readiness.action_id else "remediation_plan",
        target_id=rollback_readiness.action_id
        or rollback_readiness.plan_id
        or rollback_readiness.rollback_readiness_id,
        incident_id=rollback_readiness.incident_id,
        details={
            "rollback_readiness_id": rollback_readiness.rollback_readiness_id,
            "plan_id": rollback_readiness.plan_id,
            "action_id": rollback_readiness.action_id,
            "rollback_available": rollback_readiness.rollback_available,
            "blocker_count": len(rollback_readiness.blockers),
            "execution_supported": False,
        },
    )


def audit_event_from_execution_audit_record(
    record: RemediationExecutionAuditRecord,
    *,
    actor: RemediationApprovalActor | None = None,
) -> RemediationAuditEvent:
    return RemediationAuditEvent(
        event_type=RemediationAuditEventType.REMEDIATION_CHAIN_OF_CUSTODY_PREPARED,
        outcome=record.execution_status.value,
        actor_username=actor.username if actor else record.requested_by,
        actor_role=actor.role if actor else None,
        target_type="remediation_action",
        target_id=record.action_id,
        incident_id=record.incident_id,
        details={
            "execution_audit_id": record.execution_audit_id,
            "plan_id": record.plan_id,
            "action_id": record.action_id,
            "approval_id": record.approval_id,
            "dry_run_id": record.dry_run_id,
            "chain_id": record.chain_of_custody.chain_id,
            "custody_complete": record.chain_of_custody.custody_complete,
            "execution_supported": False,
            "execution_attempted": False,
        },
    )


def audit_event_from_workflow_state(
    state: Any,
    *,
    actor: RemediationApprovalActor | None = None,
) -> RemediationAuditEvent:
    status = getattr(state, "status")
    status_value = status.value if hasattr(status, "value") else str(status)
    event_type = _workflow_event_type(status_value)
    return RemediationAuditEvent(
        event_type=event_type,
        outcome=status_value,
        actor_username=actor.username if actor else None,
        actor_role=actor.role if actor else None,
        target_type="remediation_action",
        target_id=getattr(state, "action_id", None) or getattr(state, "plan_id", "unknown"),
        incident_id=getattr(state, "incident_id", None),
        details={
            "plan_id": getattr(state, "plan_id", None),
            "action_id": getattr(state, "action_id", None),
            "approval_id": getattr(state, "approval_id", None),
            "dry_run_id": getattr(state, "dry_run_id", None),
            "rollback_readiness_id": getattr(state, "rollback_readiness_id", None),
            "readiness_id": getattr(state, "readiness_id", None),
            "policy_decision_id": getattr(state, "policy_decision_id", None),
            "dispatch_id": getattr(state, "dispatch_id", None),
            "execution_audit_id": getattr(state, "execution_audit_id", None),
            "blocker_count": len(getattr(state, "blockers", [])),
            "timeline_count": len(getattr(state, "timeline", [])),
            "execution_supported": False,
            "execution_disabled": True,
            "production_impact": False,
        },
    )


def _workflow_event_type(status_value: str) -> RemediationAuditEventType:
    if status_value == "BLOCKED_BY_POLICY":
        return RemediationAuditEventType.REMEDIATION_WORKFLOW_BLOCKED_BY_POLICY
    if status_value == "BLOCKED_BY_ROLLBACK":
        return RemediationAuditEventType.REMEDIATION_WORKFLOW_BLOCKED_BY_ROLLBACK
    if status_value == "AWAITING_APPROVAL":
        return RemediationAuditEventType.REMEDIATION_WORKFLOW_BLOCKED_BY_MISSING_APPROVAL
    if status_value == "MOCK_DISPATCH_COMPLETED":
        return RemediationAuditEventType.REMEDIATION_MOCK_DISPATCH_COMPLETED
    if status_value == "NOOP_DISPATCH_COMPLETED":
        return RemediationAuditEventType.REMEDIATION_NOOP_DISPATCH_COMPLETED
    if status_value in {"DRY_RUN_READY", "READINESS_READY", "READY_FOR_MOCK_DISPATCH"}:
        return RemediationAuditEventType.REMEDIATION_WORKFLOW_ADVANCED
    return RemediationAuditEventType.REMEDIATION_GOVERNANCE_STATE_EVALUATED
