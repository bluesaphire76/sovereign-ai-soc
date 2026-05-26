from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field

from .models import ExecutorBaseModel, ExecutorDispatchResult, ExecutorPolicyDecision


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExecutorAuditEventType(str, Enum):
    EXECUTOR_POLICY_EVALUATED = "EXECUTOR_POLICY_EVALUATED"
    EXECUTOR_ACTION_BLOCKED = "EXECUTOR_ACTION_BLOCKED"
    EXECUTOR_ACTION_DISPATCHED_NOOP = "EXECUTOR_ACTION_DISPATCHED_NOOP"
    EXECUTOR_ACTION_DISPATCHED_MOCK = "EXECUTOR_ACTION_DISPATCHED_MOCK"
    EXECUTOR_VALIDATION_FAILED = "EXECUTOR_VALIDATION_FAILED"
    EXECUTOR_UNSUPPORTED_REAL_EXECUTION_BLOCKED = "EXECUTOR_UNSUPPORTED_REAL_EXECUTION_BLOCKED"


class ExecutorAuditEvent(ExecutorBaseModel):
    event_type: ExecutorAuditEventType
    outcome: str
    action_id: str
    plan_id: str | None = None
    incident_id: int | None = None
    policy_decision_id: str | None = None
    dispatch_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


def audit_event_from_policy_decision(
    decision: ExecutorPolicyDecision,
) -> ExecutorAuditEvent:
    return ExecutorAuditEvent(
        event_type=(
            ExecutorAuditEventType.EXECUTOR_POLICY_EVALUATED
            if decision.allowed
            else ExecutorAuditEventType.EXECUTOR_ACTION_BLOCKED
        ),
        outcome=decision.status.value,
        action_id=decision.action_id,
        policy_decision_id=decision.decision_id,
        details={
            "mode": decision.mode.value,
            "allowed": decision.allowed,
            "blocker_count": len(decision.blockers),
            "whitelist_entry_id": decision.whitelist_entry_id,
            "execution_supported": False,
            "production_impact_allowed": False,
        },
    )


def audit_event_from_dispatch_result(
    result: ExecutorDispatchResult,
) -> ExecutorAuditEvent:
    if result.status.value.endswith("VALIDATION"):
        event_type = ExecutorAuditEventType.EXECUTOR_VALIDATION_FAILED
    elif result.status.value.endswith("POLICY"):
        event_type = ExecutorAuditEventType.EXECUTOR_ACTION_BLOCKED
    elif result.status.value.startswith("MOCK"):
        event_type = ExecutorAuditEventType.EXECUTOR_ACTION_DISPATCHED_MOCK
    elif result.status.value.startswith("NOOP"):
        event_type = ExecutorAuditEventType.EXECUTOR_ACTION_DISPATCHED_NOOP
    else:
        event_type = ExecutorAuditEventType.EXECUTOR_UNSUPPORTED_REAL_EXECUTION_BLOCKED

    return ExecutorAuditEvent(
        event_type=event_type,
        outcome=result.status.value,
        action_id=result.action_id,
        plan_id=result.plan_id,
        incident_id=result.incident_id,
        policy_decision_id=result.policy_decision_id,
        dispatch_id=result.dispatch_id,
        details={
            "mode": result.mode.value,
            "state_mutated": False,
            "production_impact": False,
            "execution_supported": False,
            "validation_issue_count": len(result.validation_issues),
        },
    )
