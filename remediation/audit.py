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
from .models import RemediationBaseModel


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
