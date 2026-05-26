from __future__ import annotations

from .mock_executor import MockExecutor
from .models import (
    ExecutorAction,
    ExecutorDispatchResult,
    ExecutorDispatchStatus,
    ExecutorMode,
    ExecutorPolicyDecision,
)
from .noop_executor import NoopExecutor
from .validators import validate_executor_action, validate_policy_decision


def dispatch_executor_action(
    action: ExecutorAction,
    policy_decision: ExecutorPolicyDecision,
) -> ExecutorDispatchResult:
    action_validation = validate_executor_action(action)
    policy_validation = validate_policy_decision(policy_decision)
    validation_issues = action_validation.issues + policy_validation.issues

    if validation_issues:
        return ExecutorDispatchResult(
            dispatch_id=f"executor-blocked-validation:{action.action_id}",
            action_id=action.action_id,
            plan_id=action.plan_id,
            incident_id=action.incident_id,
            status=ExecutorDispatchStatus.BLOCKED_BY_VALIDATION,
            mode=action.mode,
            message="Executor dispatch blocked by validation.",
            policy_decision_id=policy_decision.decision_id,
            validation_issues=validation_issues,
            state_mutated=False,
            production_impact=False,
            execution_supported=False,
        )

    if not policy_decision.allowed:
        return ExecutorDispatchResult(
            dispatch_id=f"executor-blocked-policy:{action.action_id}",
            action_id=action.action_id,
            plan_id=action.plan_id,
            incident_id=action.incident_id,
            status=ExecutorDispatchStatus.BLOCKED_BY_POLICY,
            mode=action.mode,
            message="Executor dispatch blocked by policy.",
            policy_decision_id=policy_decision.decision_id,
            validation_issues=list(policy_decision.blockers),
            state_mutated=False,
            production_impact=False,
            execution_supported=False,
        )

    backend = MockExecutor() if action.mode == ExecutorMode.MOCK else NoopExecutor()
    result = backend.dispatch(action)
    return result.model_copy(update={"policy_decision_id": policy_decision.decision_id})
