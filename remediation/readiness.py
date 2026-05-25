from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re

from pydantic import Field

from .approvals import RemediationApprovalRecord, RemediationApprovalStatus
from .dry_run import RemediationDryRunResult, generate_action_dry_run
from .models import (
    RemediationAction,
    RemediationActionStatus,
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationBaseModel,
    RemediationPlan,
    RemediationRiskLevel,
)
from .rollback_readiness import (
    RemediationRollbackReadiness,
    RemediationRollbackReadinessStatus,
    assess_action_rollback_readiness,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


SHELL_OPERATOR_RE = re.compile(r"(\||&&|;|`|\$\(|>\s*[^ ]|<\s*[^ ])")


class RemediationExecutionAuditStatus(str, Enum):
    NOT_SUPPORTED = "NOT_SUPPORTED"
    READY_FOR_FUTURE_EXECUTOR = "READY_FOR_FUTURE_EXECUTOR"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    BLOCKED_BY_MISSING_APPROVAL = "BLOCKED_BY_MISSING_APPROVAL"
    BLOCKED_BY_MISSING_ROLLBACK = "BLOCKED_BY_MISSING_ROLLBACK"
    BLOCKED_BY_VALIDATION = "BLOCKED_BY_VALIDATION"
    EXECUTION_NOT_IMPLEMENTED = "EXECUTION_NOT_IMPLEMENTED"


class RemediationExecutionPrecondition(RemediationBaseModel):
    precondition_id: str
    title: str
    satisfied: bool
    required: bool = True
    details: str | None = None


class RemediationExecutionBlocker(RemediationBaseModel):
    blocker_id: str
    reason: str
    severity: str = "HIGH"
    source: str = "readiness"


class RemediationExecutionReadinessAssessment(RemediationBaseModel):
    readiness_id: str
    plan_id: str | None = None
    action_id: str
    incident_id: int | None = None
    assessed_at: datetime = Field(default_factory=utc_now)
    execution_status: RemediationExecutionAuditStatus = (
        RemediationExecutionAuditStatus.EXECUTION_NOT_IMPLEMENTED
    )
    execution_supported: bool = False
    execution_attempted: bool = False
    action_type: RemediationActionType
    target_summary: str
    risk_level: RemediationRiskLevel
    approval_requirement: RemediationApprovalRequirement
    approval_id: str | None = None
    dry_run_id: str | None = None
    rollback_readiness_id: str | None = None
    rollback_readiness_status: RemediationRollbackReadinessStatus | None = None
    evidence_references: list[str] = Field(default_factory=list)
    preconditions: list[RemediationExecutionPrecondition] = Field(default_factory=list)
    blockers: list[RemediationExecutionBlocker] = Field(default_factory=list)
    policy_checks: list[str] = Field(default_factory=list)
    validation_results: list[str] = Field(default_factory=list)
    audit_notes: list[str] = Field(default_factory=list)


FUTURE_EXECUTOR_WHITELIST = {
    RemediationActionType.BLOCK_IP,
    RemediationActionType.UNBLOCK_IP,
    RemediationActionType.CREATE_TICKET,
    RemediationActionType.NOTIFY_OWNER,
    RemediationActionType.ESCALATE_CASE,
    RemediationActionType.COLLECT_FORENSIC_EVIDENCE,
}


def _target_summary(action: RemediationAction) -> str:
    target = action.target
    value = target.value or target.host or target.user or target.ip_address or "unspecified target"
    return f"{target.target_type.value}: {value}"


def _approval_satisfied(
    action: RemediationAction,
    approval_record: RemediationApprovalRecord | None,
) -> bool:
    if action.approval_requirement == RemediationApprovalRequirement.NONE:
        return True
    return bool(
        approval_record
        and approval_record.status == RemediationApprovalStatus.APPROVED
        and not approval_record.policy_issues
    )


def _blocker(
    blocker_id: str,
    reason: str,
    *,
    severity: str = "HIGH",
    source: str = "readiness",
) -> RemediationExecutionBlocker:
    return RemediationExecutionBlocker(
        blocker_id=blocker_id,
        reason=reason,
        severity=severity,
        source=source,
    )


def _precondition(
    precondition_id: str,
    title: str,
    satisfied: bool,
    details: str | None = None,
) -> RemediationExecutionPrecondition:
    return RemediationExecutionPrecondition(
        precondition_id=precondition_id,
        title=title,
        satisfied=satisfied,
        details=details,
    )


def _status_from_blockers(
    blockers: list[RemediationExecutionBlocker],
) -> RemediationExecutionAuditStatus:
    blocker_ids = {blocker.blocker_id for blocker in blockers}
    if any("policy" in blocker_id or "forbidden" in blocker_id for blocker_id in blocker_ids):
        return RemediationExecutionAuditStatus.BLOCKED_BY_POLICY
    if any("approval" in blocker_id for blocker_id in blocker_ids):
        return RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_APPROVAL
    if any("rollback" in blocker_id for blocker_id in blocker_ids):
        return RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_ROLLBACK
    if blockers:
        return RemediationExecutionAuditStatus.BLOCKED_BY_VALIDATION
    return RemediationExecutionAuditStatus.READY_FOR_FUTURE_EXECUTOR


def assess_action_execution_readiness(
    action: RemediationAction,
    *,
    plan_id: str | None = None,
    incident_id: int | None = None,
    approval_record: RemediationApprovalRecord | None = None,
    dry_run_result: RemediationDryRunResult | None = None,
    rollback_readiness: RemediationRollbackReadiness | None = None,
) -> RemediationExecutionReadinessAssessment:
    rollback_readiness = rollback_readiness or assess_action_rollback_readiness(
        action,
        plan_id=plan_id,
        incident_id=incident_id,
    )
    dry_run_result = dry_run_result or generate_action_dry_run(
        action,
        plan_id=plan_id,
        incident_id=incident_id,
        approval_record=approval_record,
    )
    blockers: list[RemediationExecutionBlocker] = []
    policy_checks: list[str] = [
        "Execution readiness is a governance assessment only.",
        "Step 10 does not implement a remediation executor.",
    ]

    forbidden = (
        action.approval_requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
        or action.status == RemediationActionStatus.BLOCKED
    )
    if forbidden:
        blockers.append(
            _blocker(
                f"{action.action_id}-forbidden-policy",
                "Action is forbidden by default and cannot be marked ready for future execution.",
                severity="CRITICAL",
                source="policy",
            )
        )

    if not _approval_satisfied(action, approval_record):
        blockers.append(
            _blocker(
                f"{action.action_id}-missing-approval",
                "Required approval is missing or contains policy issues.",
                severity="HIGH",
                source="approval",
            )
        )

    if rollback_readiness.status in {
        RemediationRollbackReadinessStatus.MISSING,
        RemediationRollbackReadinessStatus.BLOCKED,
        RemediationRollbackReadinessStatus.UNKNOWN,
    }:
        blockers.append(
            _blocker(
                f"{action.action_id}-rollback-not-ready",
                "Rollback readiness is missing, blocked or unknown.",
                severity="HIGH",
                source="rollback",
            )
        )

    if not action.evidence:
        blockers.append(
            _blocker(
                f"{action.action_id}-missing-evidence",
                "Supporting evidence is required before future execution readiness.",
                severity="MEDIUM",
                source="evidence",
            )
        )

    if action.action_type not in FUTURE_EXECUTOR_WHITELIST:
        blockers.append(
            _blocker(
                f"{action.action_id}-action-not-whitelisted",
                "Action type is not whitelisted for future executor compatibility.",
                severity="HIGH",
                source="policy",
            )
        )

    if action.execution_supported:
        blockers.append(
            _blocker(
                f"{action.action_id}-execution-flag-set",
                "Action unexpectedly advertises execution support.",
                severity="CRITICAL",
                source="validation",
            )
        )

    if action.command_preview_is_executable:
        blockers.append(
            _blocker(
                f"{action.action_id}-executable-command-preview",
                "Command preview must remain non-executable review content.",
                severity="CRITICAL",
                source="validation",
            )
        )

    if action.command_preview and SHELL_OPERATOR_RE.search(action.command_preview):
        blockers.append(
            _blocker(
                f"{action.action_id}-shell-like-command-preview",
                "Command preview contains shell-like operators and is not eligible for future readiness.",
                severity="HIGH",
                source="validation",
            )
        )

    preconditions = [
        _precondition(
            f"{action.action_id}-plan-exists",
            "Plan/action context exists",
            bool(plan_id and action.action_id),
            details=plan_id,
        ),
        _precondition(
            f"{action.action_id}-approval",
            "Approval requirement satisfied",
            _approval_satisfied(action, approval_record),
            details=approval_record.approval_id if approval_record else None,
        ),
        _precondition(
            f"{action.action_id}-dry-run",
            "Dry-run is available",
            bool(dry_run_result.dry_run_id),
            details=dry_run_result.dry_run_id,
        ),
        _precondition(
            f"{action.action_id}-rollback",
            "Rollback readiness is acceptable",
            rollback_readiness.status
            in {
                RemediationRollbackReadinessStatus.READY,
                RemediationRollbackReadinessStatus.PARTIAL,
                RemediationRollbackReadinessStatus.NOT_APPLICABLE,
            },
            details=rollback_readiness.status.value,
        ),
        _precondition(
            f"{action.action_id}-future-whitelist",
            "Action type is whitelisted for future executor compatibility",
            action.action_type in FUTURE_EXECUTOR_WHITELIST,
            details=action.action_type.value,
        ),
    ]

    status = _status_from_blockers(blockers)
    return RemediationExecutionReadinessAssessment(
        readiness_id=f"execution-readiness:{plan_id or 'plan'}:{action.action_id}",
        plan_id=plan_id,
        action_id=action.action_id,
        incident_id=incident_id,
        execution_status=status,
        execution_supported=False,
        execution_attempted=False,
        action_type=action.action_type,
        target_summary=_target_summary(action),
        risk_level=action.risk.level,
        approval_requirement=action.approval_requirement,
        approval_id=approval_record.approval_id if approval_record else None,
        dry_run_id=dry_run_result.dry_run_id,
        rollback_readiness_id=rollback_readiness.rollback_readiness_id,
        rollback_readiness_status=rollback_readiness.status,
        evidence_references=[evidence.evidence_id for evidence in action.evidence],
        preconditions=preconditions,
        blockers=blockers,
        policy_checks=policy_checks,
        validation_results=[
            f"{blocker.source}:{blocker.reason}" for blocker in blockers
        ],
        audit_notes=[
            "No remediation action was run.",
            "Readiness does not imply execution support in Step 10.",
        ],
    )


def assess_plan_execution_readiness(
    plan: RemediationPlan,
    *,
    approval_records: list[RemediationApprovalRecord] | None = None,
    dry_run_results: list[RemediationDryRunResult] | None = None,
) -> list[RemediationExecutionReadinessAssessment]:
    approval_records = approval_records or []
    dry_run_results = dry_run_results or []
    approvals_by_action = {
        record.action_id: record
        for record in approval_records
        if record.action_id
    }
    dry_runs_by_action = {
        result.action_id: result
        for result in dry_run_results
        if result.action_id
    }
    return [
        assess_action_execution_readiness(
            action,
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
            approval_record=approvals_by_action.get(action.action_id),
            dry_run_result=dry_runs_by_action.get(action.action_id),
        )
        for action in plan.actions
    ]
