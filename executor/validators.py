from __future__ import annotations

import re
from typing import Any

from .models import ExecutorAction, ExecutorPolicyDecision
from .whitelist import ExecutorWhitelistEntry, get_whitelist_entry


SHELL_OPERATOR_RE = re.compile(r"(\||&&|;|`|\$\(|>\s*[^ ]|<\s*[^ ])")
FORBIDDEN_PARAMETER_KEYS = {
    "cmd",
    "command",
    "raw_command",
    "shell",
    "shell_command",
    "script",
    "subprocess",
    "ssh",
}


class ExecutorValidationResult:
    def __init__(
        self,
        *,
        valid: bool,
        issues: list[str] | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        self.valid = valid
        self.issues = issues or []
        self.warnings = warnings or []


def _contains_forbidden_value(value: Any) -> bool:
    if isinstance(value, str):
        lowered = value.lower()
        return bool(SHELL_OPERATOR_RE.search(value)) or any(
            keyword in lowered
            for keyword in ("subprocess", "shell=true", "/bin/sh", "powershell", "cmd.exe")
        )
    if isinstance(value, dict):
        return any(_contains_forbidden_value(item) for item in value.values())
    if isinstance(value, list | tuple | set):
        return any(_contains_forbidden_value(item) for item in value)
    return False


def validate_executor_action(
    action: ExecutorAction,
    *,
    whitelist: dict | None = None,
) -> ExecutorValidationResult:
    issues: list[str] = []
    warnings: list[str] = []
    entry: ExecutorWhitelistEntry | None = get_whitelist_entry(action.action_type, whitelist)

    if entry is None:
        issues.append("EXECUTOR_ACTION_NOT_WHITELISTED")
    elif not entry.enabled:
        issues.append("EXECUTOR_WHITELIST_ENTRY_DISABLED")
    else:
        if action.target.target_type not in entry.allowed_target_types:
            issues.append("EXECUTOR_TARGET_TYPE_NOT_ALLOWED")
        if action.mode not in entry.allowed_modes:
            issues.append("EXECUTOR_MODE_NOT_ALLOWED")
        if entry.production_impact_allowed:
            issues.append("EXECUTOR_WHITELIST_ENTRY_MUST_NOT_ALLOW_PRODUCTION_IMPACT")

    if action.execution_supported:
        issues.append("EXECUTOR_ACTION_MUST_NOT_SUPPORT_REAL_EXECUTION")

    if action.production_impact_allowed:
        issues.append("EXECUTOR_ACTION_MUST_NOT_ALLOW_PRODUCTION_IMPACT")

    if action.command_preview_is_executable:
        issues.append("EXECUTOR_COMMAND_PREVIEW_MUST_NOT_BE_EXECUTABLE")

    if action.command_preview and SHELL_OPERATOR_RE.search(action.command_preview):
        issues.append("EXECUTOR_COMMAND_PREVIEW_CONTAINS_SHELL_OPERATORS")

    forbidden_keys = sorted(
        key for key in action.parameters if str(key).lower() in FORBIDDEN_PARAMETER_KEYS
    )
    if forbidden_keys:
        issues.append(f"EXECUTOR_FORBIDDEN_PARAMETER_KEYS:{','.join(forbidden_keys)}")

    if _contains_forbidden_value(action.parameters):
        issues.append("EXECUTOR_FORBIDDEN_PARAMETER_VALUE")

    if not action.dry_run_id:
        warnings.append("EXECUTOR_ACTION_HAS_NO_DRY_RUN_REFERENCE")

    if not action.readiness_id:
        warnings.append("EXECUTOR_ACTION_HAS_NO_READINESS_REFERENCE")

    return ExecutorValidationResult(valid=not issues, issues=issues, warnings=warnings)


def validate_policy_decision(decision: ExecutorPolicyDecision) -> ExecutorValidationResult:
    issues: list[str] = []
    warnings: list[str] = []

    if decision.execution_supported:
        issues.append("EXECUTOR_POLICY_MUST_NOT_SUPPORT_REAL_EXECUTION")

    if decision.production_impact_allowed:
        issues.append("EXECUTOR_POLICY_MUST_NOT_ALLOW_PRODUCTION_IMPACT")

    if decision.allowed and decision.blockers:
        issues.append("EXECUTOR_ALLOWED_POLICY_MUST_NOT_HAVE_BLOCKERS")

    if not decision.allowed and not decision.blockers:
        warnings.append("EXECUTOR_BLOCKED_POLICY_HAS_NO_BLOCKER_DETAILS")

    return ExecutorValidationResult(valid=not issues, issues=issues, warnings=warnings)
