from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import Field

from .intelligence import generate_remediation_intelligence
from .models import (
    RemediationAction,
    RemediationBaseModel,
    RemediationPlan,
    RemediationRiskLevel,
)
from .rollback_readiness import (
    RemediationRollbackReadinessStatus,
    assess_action_rollback_readiness,
    assess_plan_rollback_readiness,
)
from .simulation import build_remediation_plan_from_intelligence


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RollbackEngineOverallStatus(str, Enum):
    READY = "READY"
    CONDITIONAL = "CONDITIONAL"
    NOT_READY = "NOT_READY"
    UNKNOWN = "UNKNOWN"


class RollbackActionReadiness(RemediationBaseModel):
    action_id: str
    action_type: str
    title: str
    rollback_available: bool
    rollback_status: RollbackEngineOverallStatus
    rollback_risk: RemediationRiskLevel
    approval_required: bool = True
    preconditions: list[str] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RollbackEngineResponse(RemediationBaseModel):
    incident_id: int
    generated_at: datetime = Field(default_factory=utc_now)
    source: str = "rollback_engine"
    remediation_source: str | None = None
    execution_supported: bool = False
    rollback_execution_supported: bool = False
    human_approval_required: bool = True
    overall_status: RollbackEngineOverallStatus
    summary: str
    actions: list[RollbackActionReadiness] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


ROLLBACK_NOTES = [
    "Planning only.",
    "No rollback execution is available.",
    "Human approval is required before any operational change.",
]


def _status_from_readiness(
    status: RemediationRollbackReadinessStatus,
) -> RollbackEngineOverallStatus:
    if status == RemediationRollbackReadinessStatus.READY:
        return RollbackEngineOverallStatus.READY
    if status in {
        RemediationRollbackReadinessStatus.PARTIAL,
        RemediationRollbackReadinessStatus.NOT_APPLICABLE,
    }:
        return RollbackEngineOverallStatus.CONDITIONAL
    if status in {
        RemediationRollbackReadinessStatus.MISSING,
        RemediationRollbackReadinessStatus.BLOCKED,
    }:
        return RollbackEngineOverallStatus.NOT_READY
    return RollbackEngineOverallStatus.UNKNOWN


def _overall_status(actions: list[RollbackActionReadiness]) -> RollbackEngineOverallStatus:
    if not actions:
        return RollbackEngineOverallStatus.UNKNOWN

    statuses = {action.rollback_status for action in actions}
    if RollbackEngineOverallStatus.NOT_READY in statuses:
        return RollbackEngineOverallStatus.NOT_READY
    if RollbackEngineOverallStatus.UNKNOWN in statuses:
        return RollbackEngineOverallStatus.UNKNOWN
    if RollbackEngineOverallStatus.CONDITIONAL in statuses:
        return RollbackEngineOverallStatus.CONDITIONAL
    return RollbackEngineOverallStatus.READY


def _preconditions(action: RemediationAction) -> list[str]:
    values = [
        f"{check.title}: {check.description}" for check in action.pre_checks
    ]
    values.append("Human approval must be recorded before any future operational change.")
    values.append("Rollback plan must be reviewed by the responsible analyst or owner.")
    return values


def _validation_steps(action: RemediationAction) -> list[str]:
    validations = [
        step.validation
        for step in action.rollback_steps
        if step.validation
    ]
    validations.extend(
        f"{check.title}: {check.description}" for check in action.post_checks
    )
    if not validations:
        validations.append("Validate rollback outcome and residual operational risk.")
    return validations


def _rollback_steps(action: RemediationAction) -> list[str]:
    return [
        f"{step.title}: {step.description}" for step in action.rollback_steps
    ]


def _action_readiness(plan: RemediationPlan, action: RemediationAction) -> RollbackActionReadiness:
    readiness = assess_action_rollback_readiness(
        action,
        plan_id=plan.plan_id,
        incident_id=plan.incident_id,
    )
    rollback_status = _status_from_readiness(readiness.status)
    limitations = list(readiness.limitations)
    limitations.extend(action.possible_side_effects[:3])
    if not action.rollback_steps:
        limitations.append("Rollback steps are not defined for this action.")

    return RollbackActionReadiness(
        action_id=action.action_id,
        action_type=action.action_type.value,
        title=action.title,
        rollback_available=readiness.rollback_available,
        rollback_status=rollback_status,
        rollback_risk=action.risk.level,
        approval_required=True,
        preconditions=_preconditions(action),
        rollback_steps=_rollback_steps(action),
        validation_steps=_validation_steps(action),
        limitations=limitations,
    )


def build_rollback_engine_response(
    plan: RemediationPlan,
    *,
    remediation_source: str | None = None,
) -> RollbackEngineResponse:
    actions = [_action_readiness(plan, action) for action in plan.actions]
    plan_readiness = assess_plan_rollback_readiness(plan)
    blockers = [blocker.reason for blocker in plan_readiness.blockers]
    warnings = list(plan_readiness.limitations)

    if not actions:
        warnings.append("No remediation actions were available for rollback readiness assessment.")
    if plan_readiness.recovery_notes:
        warnings.append(plan_readiness.recovery_notes)

    overall_status = _overall_status(actions)
    summary = (
        "Rollback readiness was assessed from the current remediation plan. "
        "This is planning-only and does not execute rollback or remediation actions."
    )
    if overall_status == RollbackEngineOverallStatus.NOT_READY:
        summary = (
            "Rollback readiness is not ready for one or more proposed remediation actions. "
            "Resolve blockers before any future operational approval."
        )
    elif overall_status == RollbackEngineOverallStatus.CONDITIONAL:
        summary = (
            "Rollback readiness is conditional and requires owner or analyst validation before approval."
        )

    return RollbackEngineResponse(
        incident_id=plan.incident_id,
        remediation_source=remediation_source,
        execution_supported=False,
        rollback_execution_supported=False,
        human_approval_required=True,
        overall_status=overall_status,
        summary=summary,
        actions=actions,
        blockers=blockers,
        warnings=warnings,
        notes=ROLLBACK_NOTES,
    )


def generate_incident_remediation_rollback_readiness(incident_id: int) -> RollbackEngineResponse:
    intelligence = generate_remediation_intelligence(incident_id)
    plan = build_remediation_plan_from_intelligence(intelligence)
    return build_rollback_engine_response(
        plan,
        remediation_source=str(intelligence.get("source") or "unknown"),
    )
