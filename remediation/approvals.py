from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import Field, model_validator

from .models import (
    RemediationAction,
    RemediationActionStatus,
    RemediationApprovalRequirement,
    RemediationBaseModel,
    RemediationPlan,
    RemediationRiskLevel,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationApprovalStatus(str, Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    REQUIRES_ADMIN = "REQUIRES_ADMIN"
    FORBIDDEN = "FORBIDDEN"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class RemediationApprovalDecision(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    DEFER = "DEFER"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
    MARK_FOR_ADMIN_REVIEW = "MARK_FOR_ADMIN_REVIEW"


class RemediationApprovalActor(RemediationBaseModel):
    username: str
    role: str
    actor_id: str | None = None

    @model_validator(mode="after")
    def normalize_role(self) -> "RemediationApprovalActor":
        object.__setattr__(self, "role", normalize_role(self.role))
        return self


class RemediationApprovalPolicy(RemediationBaseModel):
    required_approval: RemediationApprovalRequirement
    allowed_roles: list[str] = Field(default_factory=list)
    requires_rationale: bool = True
    no_execution: bool = True
    notes: list[str] = Field(default_factory=list)


class RemediationReviewOutcome(RemediationBaseModel):
    allowed: bool = False
    status: RemediationApprovalStatus = RemediationApprovalStatus.PENDING_REVIEW
    reason: str
    required_approval: RemediationApprovalRequirement
    issues: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    execution_triggered: bool = False


class RemediationApprovalRequest(RemediationBaseModel):
    request_id: str
    plan_id: str
    action_id: str | None = None
    incident_id: int | None = None
    decision: RemediationApprovalDecision
    actor: RemediationApprovalActor
    rationale: str
    requested_by: str | None = None
    requested_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None


class RemediationApprovalRecord(RemediationBaseModel):
    approval_id: str
    plan_id: str
    action_id: str | None = None
    incident_id: int | None = None
    requested_by: str | None = None
    requested_at: datetime = Field(default_factory=utc_now)
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision: RemediationApprovalDecision
    status: RemediationApprovalStatus
    role_at_decision: str | None = None
    approval_requirement: RemediationApprovalRequirement
    risk_level: RemediationRiskLevel | None = None
    rationale: str
    rejection_reason: str | None = None
    expires_at: datetime | None = None
    audit_reference: str | None = None
    policy_issues: list[str] = Field(default_factory=list)
    policy_warnings: list[str] = Field(default_factory=list)
    execution_triggered: bool = False


ADMIN_ROLES = {"ADMIN"}
ANALYST_ROLES = {"ANALYST"}
SECURITY_LEAD_ROLES = {"SECURITY_LEAD"}
VIEWER_ROLES = {"VIEWER"}
REVIEW_ROLES = ADMIN_ROLES | ANALYST_ROLES | SECURITY_LEAD_ROLES


def normalize_role(role: str | None) -> str:
    return (role or "VIEWER").strip().upper()


def _rationale_missing(rationale: str | None) -> bool:
    return not (rationale or "").strip()


def _decision_status(decision: RemediationApprovalDecision) -> RemediationApprovalStatus:
    if decision == RemediationApprovalDecision.APPROVE:
        return RemediationApprovalStatus.APPROVED
    if decision == RemediationApprovalDecision.REJECT:
        return RemediationApprovalStatus.REJECTED
    if decision in {
        RemediationApprovalDecision.DEFER,
        RemediationApprovalDecision.REQUEST_MORE_EVIDENCE,
    }:
        return RemediationApprovalStatus.DEFERRED
    return RemediationApprovalStatus.REQUIRES_ADMIN


def _required_approval_for_plan(plan: RemediationPlan) -> RemediationApprovalRequirement:
    requirements = {action.approval_requirement for action in plan.actions}
    if RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT in requirements:
        return RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
    if RemediationApprovalRequirement.SECURITY_LEAD_APPROVAL in requirements:
        return RemediationApprovalRequirement.SECURITY_LEAD_APPROVAL
    if RemediationApprovalRequirement.ADMIN_APPROVAL in requirements:
        return RemediationApprovalRequirement.ADMIN_APPROVAL
    if RemediationApprovalRequirement.ANALYST_APPROVAL in requirements:
        return RemediationApprovalRequirement.ANALYST_APPROVAL
    return RemediationApprovalRequirement.NONE


def approval_policy_for_requirement(
    requirement: RemediationApprovalRequirement,
) -> RemediationApprovalPolicy:
    if requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT:
        return RemediationApprovalPolicy(
            required_approval=requirement,
            allowed_roles=[],
            notes=["Forbidden actions cannot be approved in Step 9."],
        )
    if requirement == RemediationApprovalRequirement.SECURITY_LEAD_APPROVAL:
        return RemediationApprovalPolicy(
            required_approval=requirement,
            allowed_roles=sorted(ADMIN_ROLES | SECURITY_LEAD_ROLES),
            notes=["Security-lead-level approval is represented by ADMIN in this release."],
        )
    if requirement == RemediationApprovalRequirement.ADMIN_APPROVAL:
        return RemediationApprovalPolicy(
            required_approval=requirement,
            allowed_roles=sorted(ADMIN_ROLES),
        )
    if requirement == RemediationApprovalRequirement.ANALYST_APPROVAL:
        return RemediationApprovalPolicy(
            required_approval=requirement,
            allowed_roles=sorted(ADMIN_ROLES | ANALYST_ROLES),
        )
    return RemediationApprovalPolicy(
        required_approval=requirement,
        allowed_roles=sorted(ADMIN_ROLES | ANALYST_ROLES),
        notes=["Informational approval records remain review-only and do not trigger execution."],
    )


def evaluate_action_approval(
    actor: RemediationApprovalActor,
    action: RemediationAction,
    decision: RemediationApprovalDecision,
    *,
    rationale: str,
    now: datetime | None = None,
    expires_at: datetime | None = None,
) -> RemediationReviewOutcome:
    now = now or utc_now()
    role = normalize_role(actor.role)
    required = action.approval_requirement
    policy = approval_policy_for_requirement(required)
    issues: list[str] = []
    warnings = list(policy.notes)

    if expires_at is not None and expires_at <= now:
        return RemediationReviewOutcome(
            allowed=False,
            status=RemediationApprovalStatus.EXPIRED,
            reason="The approval request has expired.",
            required_approval=required,
            issues=["APPROVAL_REQUEST_EXPIRED"],
            warnings=warnings,
        )

    if _rationale_missing(rationale):
        issues.append("APPROVAL_REQUIRES_RATIONALE")

    if role in VIEWER_ROLES:
        issues.append("VIEWER_CANNOT_APPROVE_REMEDIATION")
        return RemediationReviewOutcome(
            allowed=False,
            status=RemediationApprovalStatus.FORBIDDEN,
            reason="Viewer role cannot make remediation approval decisions.",
            required_approval=required,
            issues=issues,
            warnings=warnings,
        )

    if role not in REVIEW_ROLES:
        issues.append("ROLE_NOT_ALLOWED_FOR_REMEDIATION_APPROVAL")

    if (
        decision == RemediationApprovalDecision.APPROVE
        and (
            required == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
            or action.status == RemediationActionStatus.BLOCKED
        )
    ):
        issues.append("FORBIDDEN_ACTION_CANNOT_BE_APPROVED")
        return RemediationReviewOutcome(
            allowed=False,
            status=RemediationApprovalStatus.FORBIDDEN,
            reason="Forbidden remediation actions cannot be approved in Step 9.",
            required_approval=required,
            issues=issues,
            warnings=warnings,
        )

    if decision != RemediationApprovalDecision.APPROVE:
        status = _decision_status(decision)
        return RemediationReviewOutcome(
            allowed=not issues,
            status=status if not issues else RemediationApprovalStatus.PENDING_REVIEW,
            reason="Remediation decision recorded for governance review.",
            required_approval=required,
            issues=issues,
            warnings=warnings,
        )

    if required == RemediationApprovalRequirement.ADMIN_APPROVAL and role not in ADMIN_ROLES:
        issues.append("ADMIN_APPROVAL_REQUIRED")
        return RemediationReviewOutcome(
            allowed=False,
            status=RemediationApprovalStatus.REQUIRES_ADMIN,
            reason="This remediation action requires admin approval.",
            required_approval=required,
            issues=issues,
            warnings=warnings,
        )

    if (
        required == RemediationApprovalRequirement.SECURITY_LEAD_APPROVAL
        and role not in ADMIN_ROLES | SECURITY_LEAD_ROLES
    ):
        issues.append("SECURITY_LEAD_APPROVAL_REQUIRED")
        return RemediationReviewOutcome(
            allowed=False,
            status=RemediationApprovalStatus.REQUIRES_ADMIN,
            reason="This high-risk remediation action requires elevated approval.",
            required_approval=required,
            issues=issues,
            warnings=warnings,
        )

    if role not in policy.allowed_roles:
        issues.append("ROLE_NOT_ALLOWED_FOR_APPROVAL_REQUIREMENT")

    return RemediationReviewOutcome(
        allowed=not issues,
        status=(
            RemediationApprovalStatus.APPROVED
            if not issues
            else RemediationApprovalStatus.PENDING_REVIEW
        ),
        reason="Approval decision is governance metadata only and does not trigger execution.",
        required_approval=required,
        issues=issues,
        warnings=warnings,
    )


def evaluate_plan_approval(
    actor: RemediationApprovalActor,
    plan: RemediationPlan,
    decision: RemediationApprovalDecision,
    *,
    rationale: str,
    now: datetime | None = None,
    expires_at: datetime | None = None,
) -> RemediationReviewOutcome:
    now = now or utc_now()
    required = _required_approval_for_plan(plan)
    if not plan.actions:
        return RemediationReviewOutcome(
            allowed=False,
            status=RemediationApprovalStatus.PENDING_REVIEW,
            reason="The remediation plan has no actions to review.",
            required_approval=required,
            issues=["PLAN_HAS_NO_REMEDIATION_ACTIONS"],
        )

    outcomes = [
        evaluate_action_approval(
            actor,
            action,
            decision,
            rationale=rationale,
            now=now,
            expires_at=expires_at,
        )
        for action in plan.actions
    ]
    issues = [issue for outcome in outcomes for issue in outcome.issues]
    warnings = [warning for outcome in outcomes for warning in outcome.warnings]

    if any(outcome.status == RemediationApprovalStatus.FORBIDDEN for outcome in outcomes):
        status = RemediationApprovalStatus.FORBIDDEN
    elif any(outcome.status == RemediationApprovalStatus.REQUIRES_ADMIN for outcome in outcomes):
        status = RemediationApprovalStatus.REQUIRES_ADMIN
    elif any(outcome.status == RemediationApprovalStatus.EXPIRED for outcome in outcomes):
        status = RemediationApprovalStatus.EXPIRED
    elif all(outcome.allowed for outcome in outcomes):
        status = _decision_status(decision)
    else:
        status = RemediationApprovalStatus.PENDING_REVIEW

    return RemediationReviewOutcome(
        allowed=all(outcome.allowed for outcome in outcomes),
        status=status,
        reason="Plan-level decision evaluated across all remediation actions.",
        required_approval=required,
        issues=issues,
        warnings=warnings,
    )


def create_approval_record(
    request: RemediationApprovalRequest,
    *,
    plan: RemediationPlan | None = None,
    action: RemediationAction | None = None,
    now: datetime | None = None,
) -> RemediationApprovalRecord:
    now = now or utc_now()
    if plan is None and action is None:
        raise ValueError("Either plan or action is required to create an approval record.")

    if action is not None:
        outcome = evaluate_action_approval(
            request.actor,
            action,
            request.decision,
            rationale=request.rationale,
            now=now,
            expires_at=request.expires_at,
        )
        requirement = action.approval_requirement
        risk_level = action.risk.level
    else:
        assert plan is not None
        outcome = evaluate_plan_approval(
            request.actor,
            plan,
            request.decision,
            rationale=request.rationale,
            now=now,
            expires_at=request.expires_at,
        )
        requirement = outcome.required_approval
        risk_level = plan.overall_risk.level

    return RemediationApprovalRecord(
        approval_id=f"approval-{request.request_id}",
        plan_id=request.plan_id,
        action_id=request.action_id if action is not None else None,
        incident_id=request.incident_id or (plan.incident_id if plan is not None else None),
        requested_by=request.requested_by or request.actor.username,
        requested_at=request.requested_at,
        decided_by=request.actor.username,
        decided_at=now,
        decision=request.decision,
        status=outcome.status,
        role_at_decision=normalize_role(request.actor.role),
        approval_requirement=requirement,
        risk_level=risk_level,
        rationale=request.rationale,
        rejection_reason=(
            outcome.reason
            if outcome.status in {RemediationApprovalStatus.REJECTED, RemediationApprovalStatus.FORBIDDEN}
            else None
        ),
        expires_at=request.expires_at,
        audit_reference=f"remediation-approval:{request.request_id}",
        policy_issues=outcome.issues,
        policy_warnings=outcome.warnings,
        execution_triggered=False,
    )
