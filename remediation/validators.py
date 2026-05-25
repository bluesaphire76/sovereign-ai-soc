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
