from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from remediation.approvals import RemediationApprovalRecord
from remediation.dry_run import RemediationDryRunResult
from remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationRiskLevel,
    RemediationTargetType,
)
from remediation.readiness import RemediationExecutionReadinessAssessment
from remediation.rollback_readiness import RemediationRollbackReadiness


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExecutorBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ExecutorMode(str, Enum):
    NOOP = "NOOP"
    MOCK = "MOCK"


class ExecutorActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"
    CREATE_TICKET = "CREATE_TICKET"
    NOTIFY_OWNER = "NOTIFY_OWNER"
    ESCALATE_CASE = "ESCALATE_CASE"
    COLLECT_FORENSIC_EVIDENCE = "COLLECT_FORENSIC_EVIDENCE"


class ExecutorTarget(ExecutorBaseModel):
    target_type: RemediationTargetType = RemediationTargetType.UNKNOWN
    value: str | None = None
    host: str | None = None
    user: str | None = None
    ip_address: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExecutorAction(ExecutorBaseModel):
    action_id: str
    action_type: ExecutorActionType
    target: ExecutorTarget = Field(default_factory=ExecutorTarget)
    plan_id: str | None = None
    incident_id: int | None = None
    approval_id: str | None = None
    dry_run_id: str | None = None
    readiness_id: str | None = None
    rollback_readiness_id: str | None = None
    risk_level: RemediationRiskLevel
    approval_requirement: RemediationApprovalRequirement
    evidence_references: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    command_preview: str | None = None
    command_preview_is_executable: bool = False
    mode: ExecutorMode = ExecutorMode.NOOP
    production_impact_allowed: bool = False
    execution_supported: bool = False

    @model_validator(mode="after")
    def enforce_non_executing_boundary(self) -> "ExecutorAction":
        object.__setattr__(self, "production_impact_allowed", False)
        object.__setattr__(self, "execution_supported", False)
        object.__setattr__(self, "command_preview_is_executable", False)
        return self


class ExecutorPolicyStatus(str, Enum):
    ALLOWED_FOR_NOOP = "ALLOWED_FOR_NOOP"
    ALLOWED_FOR_MOCK = "ALLOWED_FOR_MOCK"
    BLOCKED_BY_WHITELIST = "BLOCKED_BY_WHITELIST"
    BLOCKED_BY_APPROVAL = "BLOCKED_BY_APPROVAL"
    BLOCKED_BY_ROLLBACK = "BLOCKED_BY_ROLLBACK"
    BLOCKED_BY_READINESS = "BLOCKED_BY_READINESS"
    BLOCKED_BY_VALIDATION = "BLOCKED_BY_VALIDATION"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


class ExecutorPolicyDecision(ExecutorBaseModel):
    decision_id: str
    action_id: str
    allowed: bool = False
    status: ExecutorPolicyStatus
    mode: ExecutorMode = ExecutorMode.NOOP
    reasons: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    whitelist_entry_id: str | None = None
    evaluated_at: datetime = Field(default_factory=utc_now)
    execution_supported: bool = False
    production_impact_allowed: bool = False


class ExecutorDispatchStatus(str, Enum):
    NOOP_RECORDED = "NOOP_RECORDED"
    MOCK_RECORDED = "MOCK_RECORDED"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    BLOCKED_BY_VALIDATION = "BLOCKED_BY_VALIDATION"
    UNSUPPORTED = "UNSUPPORTED"


class ExecutorDispatchResult(ExecutorBaseModel):
    dispatch_id: str
    action_id: str
    plan_id: str | None = None
    incident_id: int | None = None
    status: ExecutorDispatchStatus
    mode: ExecutorMode
    message: str
    policy_decision_id: str | None = None
    validation_issues: list[str] = Field(default_factory=list)
    audit_notes: list[str] = Field(default_factory=list)
    dispatched_at: datetime = Field(default_factory=utc_now)
    state_mutated: bool = False
    production_impact: bool = False
    execution_supported: bool = False


REMEDIATION_TO_EXECUTOR_ACTION = {
    RemediationActionType.BLOCK_IP: ExecutorActionType.BLOCK_IP,
    RemediationActionType.UNBLOCK_IP: ExecutorActionType.UNBLOCK_IP,
    RemediationActionType.CREATE_TICKET: ExecutorActionType.CREATE_TICKET,
    RemediationActionType.NOTIFY_OWNER: ExecutorActionType.NOTIFY_OWNER,
    RemediationActionType.ESCALATE_CASE: ExecutorActionType.ESCALATE_CASE,
    RemediationActionType.COLLECT_FORENSIC_EVIDENCE: ExecutorActionType.COLLECT_FORENSIC_EVIDENCE,
}


def executor_action_from_remediation(
    action: RemediationAction,
    *,
    approval_record: RemediationApprovalRecord | None = None,
    dry_run_result: RemediationDryRunResult | None = None,
    readiness: RemediationExecutionReadinessAssessment | None = None,
    rollback_readiness: RemediationRollbackReadiness | None = None,
    mode: ExecutorMode = ExecutorMode.NOOP,
    parameters: dict[str, Any] | None = None,
) -> ExecutorAction:
    if action.action_type not in REMEDIATION_TO_EXECUTOR_ACTION:
        raise ValueError(f"Remediation action type is not executor-whitelisted: {action.action_type}")

    target = ExecutorTarget(
        target_type=action.target.target_type,
        value=action.target.value,
        host=action.target.host,
        user=action.target.user,
        ip_address=action.target.ip_address,
        metadata=dict(action.target.metadata),
    )
    return ExecutorAction(
        action_id=action.action_id,
        action_type=REMEDIATION_TO_EXECUTOR_ACTION[action.action_type],
        target=target,
        plan_id=readiness.plan_id if readiness else dry_run_result.plan_id if dry_run_result else None,
        incident_id=readiness.incident_id if readiness else dry_run_result.incident_id if dry_run_result else None,
        approval_id=approval_record.approval_id if approval_record else None,
        dry_run_id=dry_run_result.dry_run_id if dry_run_result else None,
        readiness_id=readiness.readiness_id if readiness else None,
        rollback_readiness_id=(
            rollback_readiness.rollback_readiness_id if rollback_readiness else None
        ),
        risk_level=action.risk.level,
        approval_requirement=action.approval_requirement,
        evidence_references=[evidence.evidence_id for evidence in action.evidence],
        parameters=parameters or {},
        command_preview=action.command_preview,
        command_preview_is_executable=False,
        mode=mode,
        production_impact_allowed=False,
        execution_supported=False,
    )
