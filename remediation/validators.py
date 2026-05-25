from __future__ import annotations

import re

from .models import (
    RemediationAction,
    RemediationActionStatus,
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationPlan,
    RemediationValidationResult,
    RollbackAvailability,
)
from .risk import FORBIDDEN_ACTION_TYPES
from .approvals import RemediationApprovalRecord, RemediationApprovalStatus, normalize_role
from .dry_run import RemediationDryRunResult, RemediationDryRunStatus


SHELL_OPERATOR_RE = re.compile(r"(\||&&|;|`|\$\(|>\s*[^ ]|<\s*[^ ])")

OPERATIONAL_ACTION_TYPES = {
    RemediationActionType.BLOCK_IP,
    RemediationActionType.UNBLOCK_IP,
    RemediationActionType.DISABLE_USER,
    RemediationActionType.ENABLE_USER,
    RemediationActionType.STOP_SERVICE,
    RemediationActionType.RESTART_SERVICE,
    RemediationActionType.QUARANTINE_FILE,
    RemediationActionType.RESTORE_FILE,
    RemediationActionType.KILL_PROCESS,
    RemediationActionType.ISOLATE_HOST,
    RemediationActionType.RELEASE_HOST,
    RemediationActionType.ADD_FIREWALL_RULE,
    RemediationActionType.REMOVE_FIREWALL_RULE,
    RemediationActionType.COLLECT_FORENSIC_EVIDENCE,
}


def validate_remediation_action(action: RemediationAction) -> RemediationValidationResult:
    issues: list[str] = []
    warnings: list[str] = []

    if action.execution_supported:
        issues.append("EXECUTION_NOT_SUPPORTED_IN_STEP_8")

    if action.command_preview_is_executable:
        issues.append("COMMAND_PREVIEW_MUST_BE_NON_EXECUTABLE")

    if action.command_preview and SHELL_OPERATOR_RE.search(action.command_preview):
        warnings.append("COMMAND_PREVIEW_CONTAINS_SHELL_OPERATORS_FOR_REVIEW_ONLY")

    if (
        action.action_type in OPERATIONAL_ACTION_TYPES
        and action.approval_requirement == RemediationApprovalRequirement.NONE
    ):
        issues.append("OPERATIONAL_ACTION_REQUIRES_APPROVAL")

    if (
        action.action_type in FORBIDDEN_ACTION_TYPES
        and action.approval_requirement != RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
    ):
        issues.append("DESTRUCTIVE_ACTION_MUST_BE_FORBIDDEN_BY_DEFAULT")

    if action.action_type in FORBIDDEN_ACTION_TYPES and action.status != RemediationActionStatus.BLOCKED:
        issues.append("FORBIDDEN_ACTION_MUST_BE_BLOCKED")

    if not action.risk:
        issues.append("ACTION_REQUIRES_RISK_ASSESSMENT")

    if not action.rollback_steps:
        warnings.append("ACTION_HAS_NO_INLINE_ROLLBACK_STEPS")

    if not action.evidence:
        warnings.append("ACTION_HAS_NO_SUPPORTING_EVIDENCE")

    return RemediationValidationResult(
        valid=not issues,
        issues=issues,
        warnings=warnings,
    )


def validate_remediation_plan(plan: RemediationPlan) -> RemediationValidationResult:
    issues: list[str] = []
    warnings: list[str] = []

    if plan.execution_supported:
        issues.append("PLAN_EXECUTION_NOT_SUPPORTED_IN_STEP_8")

    if plan.status.value == "APPROVED_FOR_FUTURE_EXECUTION":
        warnings.append("PLAN_APPROVAL_IS_METADATA_ONLY_NO_EXECUTION_AVAILABLE")

    if not plan.rollback_plan:
        issues.append("PLAN_REQUIRES_ROLLBACK_PLAN")
    elif (
        plan.rollback_plan.availability == RollbackAvailability.UNAVAILABLE
        and not plan.rollback_plan.limitations
    ):
        issues.append("UNAVAILABLE_ROLLBACK_REQUIRES_LIMITATION")

    if not plan.actions:
        warnings.append("PLAN_HAS_NO_REMEDIATION_ACTIONS")

    for action in plan.actions:
        result = validate_remediation_action(action)
        issues.extend(f"{action.action_id}:{issue}" for issue in result.issues)
        warnings.extend(f"{action.action_id}:{warning}" for warning in result.warnings)

    if not plan.evidence_used:
        warnings.append("PLAN_HAS_NO_SUPPORTING_EVIDENCE")

    return RemediationValidationResult(
        valid=not issues,
        issues=issues,
        warnings=warnings,
    )


def validate_approval_record(record: RemediationApprovalRecord) -> RemediationValidationResult:
    issues: list[str] = []
    warnings: list[str] = []

    if record.execution_triggered:
        issues.append("APPROVAL_MUST_NOT_TRIGGER_EXECUTION_IN_STEP_9")

    if not (record.rationale or "").strip():
        issues.append("APPROVAL_REQUIRES_RATIONALE")

    if (
        record.status == RemediationApprovalStatus.APPROVED
        and normalize_role(record.role_at_decision) == "VIEWER"
    ):
        issues.append("VIEWER_CANNOT_APPROVE_REMEDIATION")

    if (
        record.status == RemediationApprovalStatus.APPROVED
        and record.approval_requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
    ):
        issues.append("FORBIDDEN_ACTION_CANNOT_BE_APPROVED")

    if record.status == RemediationApprovalStatus.APPROVED and record.policy_issues:
        issues.append("APPROVED_RECORD_HAS_POLICY_ISSUES")

    if record.status in {
        RemediationApprovalStatus.REQUIRES_ADMIN,
        RemediationApprovalStatus.FORBIDDEN,
        RemediationApprovalStatus.PENDING_REVIEW,
    }:
        warnings.extend(record.policy_issues)

    return RemediationValidationResult(
        valid=not issues,
        issues=issues,
        warnings=warnings,
    )


def validate_dry_run_result(result: RemediationDryRunResult) -> RemediationValidationResult:
    issues: list[str] = []
    warnings: list[str] = []
    finding_statuses = {finding.status for finding in result.findings}

    if result.state_mutated:
        issues.append("DRY_RUN_MUST_NOT_MUTATE_STATE")

    if result.execution_supported:
        issues.append("DRY_RUN_MUST_NOT_SUPPORT_EXECUTION_IN_STEP_9")

    if result.status == RemediationDryRunStatus.MISSING_ROLLBACK and (
        RemediationDryRunStatus.MISSING_ROLLBACK not in finding_statuses
    ):
        issues.append("DRY_RUN_MISSING_ROLLBACK_REQUIRES_FINDING")

    if result.status == RemediationDryRunStatus.MISSING_EVIDENCE and (
        RemediationDryRunStatus.MISSING_EVIDENCE not in finding_statuses
    ):
        issues.append("DRY_RUN_MISSING_EVIDENCE_REQUIRES_FINDING")

    if result.status in {
        RemediationDryRunStatus.FORBIDDEN,
        RemediationDryRunStatus.BLOCKED_BY_POLICY,
        RemediationDryRunStatus.MISSING_APPROVAL,
        RemediationDryRunStatus.MISSING_ROLLBACK,
        RemediationDryRunStatus.MISSING_EVIDENCE,
        RemediationDryRunStatus.NOT_SUPPORTED,
    }:
        warnings.extend(finding.title for finding in result.findings)

    return RemediationValidationResult(
        valid=not issues,
        issues=issues,
        warnings=warnings,
    )
