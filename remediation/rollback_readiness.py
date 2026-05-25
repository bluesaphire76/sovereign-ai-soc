from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import Field

from .models import (
    RemediationAction,
    RemediationActionStatus,
    RemediationApprovalRequirement,
    RemediationBaseModel,
    RemediationPlan,
    RollbackAvailability,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationRollbackReadinessStatus(str, Enum):
    READY = "READY"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class RemediationRollbackBlocker(RemediationBaseModel):
    blocker_id: str
    reason: str
    severity: str = "HIGH"


class RemediationRollbackValidation(RemediationBaseModel):
    validation_id: str
    description: str
    status: RemediationRollbackReadinessStatus
    details: str | None = None


class RemediationRollbackReadiness(RemediationBaseModel):
    rollback_readiness_id: str
    plan_id: str | None = None
    action_id: str | None = None
    incident_id: int | None = None
    assessed_at: datetime = Field(default_factory=utc_now)
    status: RemediationRollbackReadinessStatus
    rollback_available: bool = False
    rollback_availability: RollbackAvailability | None = None
    steps_count: int = 0
    validation_count: int = 0
    limitations: list[str] = Field(default_factory=list)
    blockers: list[RemediationRollbackBlocker] = Field(default_factory=list)
    validations: list[RemediationRollbackValidation] = Field(default_factory=list)
    recovery_notes: str | None = None
    approval_required: bool = True
    risk_summary: str | None = None


def _status_from_action(action: RemediationAction) -> RemediationRollbackReadinessStatus:
    if (
        action.approval_requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
        or action.status == RemediationActionStatus.BLOCKED
    ):
        return RemediationRollbackReadinessStatus.BLOCKED
    if not action.rollback_steps:
        return RemediationRollbackReadinessStatus.MISSING
    if "rollback_partial" in action.risk.risk_factors:
        return RemediationRollbackReadinessStatus.PARTIAL
    if "rollback_unavailable" in action.risk.risk_factors:
        return RemediationRollbackReadinessStatus.BLOCKED
    if "rollback_available" in action.risk.risk_factors:
        return RemediationRollbackReadinessStatus.READY
    return RemediationRollbackReadinessStatus.UNKNOWN


def assess_action_rollback_readiness(
    action: RemediationAction,
    *,
    plan_id: str | None = None,
    incident_id: int | None = None,
) -> RemediationRollbackReadiness:
    status = _status_from_action(action)
    blockers: list[RemediationRollbackBlocker] = []
    limitations: list[str] = []

    if status == RemediationRollbackReadinessStatus.BLOCKED:
        blockers.append(
            RemediationRollbackBlocker(
                blocker_id=f"{action.action_id}-rollback-policy-blocked",
                reason="Rollback readiness is blocked by forbidden action policy or unavailable rollback risk.",
                severity="CRITICAL",
            )
        )
    elif status == RemediationRollbackReadinessStatus.MISSING:
        blockers.append(
            RemediationRollbackBlocker(
                blocker_id=f"{action.action_id}-rollback-missing",
                reason="Rollback steps are missing for the remediation action.",
                severity="HIGH",
            )
        )
    elif status == RemediationRollbackReadinessStatus.PARTIAL:
        limitations.append("Rollback is partial and requires owner validation before future execution review.")
    elif status == RemediationRollbackReadinessStatus.UNKNOWN:
        limitations.append("Rollback readiness could not be fully determined from current action metadata.")

    validations = [
        RemediationRollbackValidation(
            validation_id=f"{step.step_id}-validation",
            description=step.validation or f"Validate rollback step: {step.title}",
            status=(
                RemediationRollbackReadinessStatus.READY
                if step.validation
                else RemediationRollbackReadinessStatus.PARTIAL
            ),
            details=step.description,
        )
        for step in action.rollback_steps
    ]

    return RemediationRollbackReadiness(
        rollback_readiness_id=f"rollback-readiness:{plan_id or 'plan'}:{action.action_id}",
        plan_id=plan_id,
        action_id=action.action_id,
        incident_id=incident_id,
        status=status,
        rollback_available=status in {
            RemediationRollbackReadinessStatus.READY,
            RemediationRollbackReadinessStatus.PARTIAL,
        },
        rollback_availability=None,
        steps_count=len(action.rollback_steps),
        validation_count=len(validations),
        limitations=limitations,
        blockers=blockers,
        validations=validations,
        recovery_notes=(
            "Rollback steps are present for future governance review."
            if action.rollback_steps
            else "Rollback readiness cannot be established without rollback steps."
        ),
        approval_required=action.approval_requirement != RemediationApprovalRequirement.NONE,
        risk_summary=f"{action.risk.level.value} risk, score {action.risk.score}.",
    )


def assess_plan_rollback_readiness(plan: RemediationPlan) -> RemediationRollbackReadiness:
    action_assessments = [
        assess_action_rollback_readiness(
            action,
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
        )
        for action in plan.actions
    ]
    blockers = [blocker for assessment in action_assessments for blocker in assessment.blockers]
    validations = [
        validation for assessment in action_assessments for validation in assessment.validations
    ]
    limitations = list(plan.rollback_plan.limitations)
    limitations.extend(
        limitation for assessment in action_assessments for limitation in assessment.limitations
    )

    if blockers:
        status = RemediationRollbackReadinessStatus.BLOCKED
    elif plan.rollback_plan.availability == RollbackAvailability.NOT_APPLICABLE:
        status = RemediationRollbackReadinessStatus.NOT_APPLICABLE
    elif plan.rollback_plan.availability == RollbackAvailability.UNAVAILABLE:
        status = RemediationRollbackReadinessStatus.MISSING
        blockers.append(
            RemediationRollbackBlocker(
                blocker_id=f"{plan.plan_id}-rollback-unavailable",
                reason="Plan-level rollback is unavailable.",
                severity="HIGH",
            )
        )
    elif plan.rollback_plan.availability == RollbackAvailability.PARTIAL:
        status = RemediationRollbackReadinessStatus.PARTIAL
    elif plan.rollback_plan.availability == RollbackAvailability.FULL:
        status = RemediationRollbackReadinessStatus.READY
    else:
        status = RemediationRollbackReadinessStatus.UNKNOWN

    return RemediationRollbackReadiness(
        rollback_readiness_id=f"rollback-readiness:{plan.plan_id}",
        plan_id=plan.plan_id,
        incident_id=plan.incident_id,
        status=status,
        rollback_available=status in {
            RemediationRollbackReadinessStatus.READY,
            RemediationRollbackReadinessStatus.PARTIAL,
            RemediationRollbackReadinessStatus.NOT_APPLICABLE,
        },
        rollback_availability=plan.rollback_plan.availability,
        steps_count=len(plan.rollback_plan.steps),
        validation_count=len(plan.rollback_plan.validation_steps) + len(validations),
        limitations=limitations,
        blockers=blockers,
        validations=validations,
        recovery_notes=plan.rollback_plan.recovery_notes,
        approval_required=plan.approval_required,
        risk_summary=f"{plan.overall_risk.level.value} risk, score {plan.overall_risk.score}.",
    )
