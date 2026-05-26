from __future__ import annotations

from remediation.approvals import RemediationApprovalRecord, RemediationApprovalStatus
from remediation.dry_run import RemediationDryRunResult
from remediation.models import RemediationApprovalRequirement
from remediation.readiness import (
    RemediationExecutionAuditStatus,
    RemediationExecutionReadinessAssessment,
)
from remediation.rollback_readiness import (
    RemediationRollbackReadiness,
    RemediationRollbackReadinessStatus,
)

from .models import (
    ExecutorAction,
    ExecutorMode,
    ExecutorPolicyDecision,
    ExecutorPolicyStatus,
)
from .validators import validate_executor_action
from .whitelist import ExecutorWhitelistEntry, get_whitelist_entry


def _approval_satisfied(
    action: ExecutorAction,
    approval_record: RemediationApprovalRecord | None,
    entry: ExecutorWhitelistEntry | None,
) -> bool:
    if action.approval_requirement == RemediationApprovalRequirement.NONE and not (
        entry and entry.requires_approval
    ):
        return True
    return bool(
        approval_record
        and approval_record.status == RemediationApprovalStatus.APPROVED
        and not approval_record.policy_issues
        and approval_record.approval_id == action.approval_id
    )


def evaluate_executor_policy(
    action: ExecutorAction,
    *,
    approval_record: RemediationApprovalRecord | None = None,
    dry_run_result: RemediationDryRunResult | None = None,
    readiness: RemediationExecutionReadinessAssessment | None = None,
    rollback_readiness: RemediationRollbackReadiness | None = None,
    whitelist: dict | None = None,
) -> ExecutorPolicyDecision:
    reasons: list[str] = [
        "Executor framework is restricted to NOOP/MOCK dispatch in Step 11.",
    ]
    blockers: list[str] = []
    validation = validate_executor_action(action, whitelist=whitelist)
    entry = get_whitelist_entry(action.action_type, whitelist)

    if not validation.valid:
        blockers.extend(validation.issues)

    if entry is None or not entry.enabled:
        blockers.append("EXECUTOR_ACTION_NOT_ENABLED_IN_WHITELIST")
    else:
        if entry.production_impact_allowed:
            blockers.append("EXECUTOR_WHITELIST_PRODUCTION_IMPACT_FORBIDDEN")
        if action.mode not in entry.allowed_modes:
            blockers.append("EXECUTOR_MODE_NOT_ALLOWED_BY_WHITELIST")

    if action.mode not in {ExecutorMode.NOOP, ExecutorMode.MOCK}:
        blockers.append("EXECUTOR_REAL_MODE_NOT_SUPPORTED")

    if not _approval_satisfied(action, approval_record, entry):
        blockers.append("EXECUTOR_APPROVAL_NOT_SATISFIED")

    if dry_run_result is None or dry_run_result.dry_run_id != action.dry_run_id:
        blockers.append("EXECUTOR_DRY_RUN_REFERENCE_NOT_VERIFIED")

    if readiness is None or readiness.readiness_id != action.readiness_id:
        blockers.append("EXECUTOR_READINESS_REFERENCE_NOT_VERIFIED")
    elif readiness.execution_status != RemediationExecutionAuditStatus.READY_FOR_FUTURE_EXECUTOR:
        blockers.append("EXECUTOR_READINESS_NOT_READY_FOR_FUTURE_EXECUTOR")

    if entry and entry.requires_rollback_readiness:
        if rollback_readiness is None or (
            rollback_readiness.rollback_readiness_id != action.rollback_readiness_id
        ):
            blockers.append("EXECUTOR_ROLLBACK_READINESS_REFERENCE_NOT_VERIFIED")
        elif rollback_readiness.status not in {
            RemediationRollbackReadinessStatus.READY,
            RemediationRollbackReadinessStatus.PARTIAL,
            RemediationRollbackReadinessStatus.NOT_APPLICABLE,
        }:
            blockers.append("EXECUTOR_ROLLBACK_READINESS_NOT_ACCEPTABLE")

    status = _status_from_blockers(blockers)
    allowed = not blockers
    if allowed:
        status = (
            ExecutorPolicyStatus.ALLOWED_FOR_MOCK
            if action.mode == ExecutorMode.MOCK
            else ExecutorPolicyStatus.ALLOWED_FOR_NOOP
        )
        reasons.append("Action is allowed only for controlled NOOP/MOCK dispatch.")

    return ExecutorPolicyDecision(
        decision_id=f"executor-policy:{action.action_id}:{action.mode.value.lower()}",
        action_id=action.action_id,
        allowed=allowed,
        status=status,
        mode=action.mode,
        reasons=reasons,
        blockers=blockers,
        whitelist_entry_id=entry.whitelist_entry_id if entry else None,
        execution_supported=False,
        production_impact_allowed=False,
    )


def _status_from_blockers(blockers: list[str]) -> ExecutorPolicyStatus:
    if any("WHITELIST" in blocker or "NOT_ENABLED" in blocker for blocker in blockers):
        return ExecutorPolicyStatus.BLOCKED_BY_WHITELIST
    if any("APPROVAL" in blocker for blocker in blockers):
        return ExecutorPolicyStatus.BLOCKED_BY_APPROVAL
    if any("ROLLBACK" in blocker for blocker in blockers):
        return ExecutorPolicyStatus.BLOCKED_BY_ROLLBACK
    if any("READINESS" in blocker or "DRY_RUN" in blocker for blocker in blockers):
        return ExecutorPolicyStatus.BLOCKED_BY_READINESS
    if any("VALIDATION" in blocker or "COMMAND" in blocker or "PARAMETER" in blocker for blocker in blockers):
        return ExecutorPolicyStatus.BLOCKED_BY_VALIDATION
    if blockers:
        return ExecutorPolicyStatus.BLOCKED_BY_POLICY
    return ExecutorPolicyStatus.ALLOWED_FOR_NOOP
