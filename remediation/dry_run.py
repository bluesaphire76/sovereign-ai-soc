from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import Field

from .approvals import RemediationApprovalRecord, RemediationApprovalStatus
from .models import (
    RemediationAction,
    RemediationActionStatus,
    RemediationApprovalRequirement,
    RemediationBaseModel,
    RemediationPlan,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationDryRunStatus(str, Enum):
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    MISSING_APPROVAL = "MISSING_APPROVAL"
    MISSING_ROLLBACK = "MISSING_ROLLBACK"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    FORBIDDEN = "FORBIDDEN"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class RemediationExecutionReadiness(str, Enum):
    READY_FOR_FUTURE_REVIEW = "READY_FOR_FUTURE_REVIEW"
    BLOCKED = "BLOCKED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    REQUIRES_EVIDENCE = "REQUIRES_EVIDENCE"
    REQUIRES_ROLLBACK = "REQUIRES_ROLLBACK"


class RemediationDryRunStep(RemediationBaseModel):
    step_id: str
    title: str
    description: str
    target_summary: str | None = None
    would_change_state: bool = False


class RemediationDryRunFinding(RemediationBaseModel):
    finding_id: str
    status: RemediationDryRunStatus
    title: str
    description: str
    severity: str = "INFO"


class RemediationDryRunResult(RemediationBaseModel):
    dry_run_id: str
    generated_at: datetime = Field(default_factory=utc_now)
    plan_id: str | None = None
    action_id: str | None = None
    incident_id: int | None = None
    status: RemediationDryRunStatus
    readiness: RemediationExecutionReadiness
    action_summary: str
    target_summary: str | None = None
    expected_impact: str | None = None
    affected_systems: list[str] = Field(default_factory=list)
    prerequisites: list[str] = Field(default_factory=list)
    pre_checks: list[str] = Field(default_factory=list)
    post_checks: list[str] = Field(default_factory=list)
    rollback_readiness: str | None = None
    risk_summary: str | None = None
    steps: list[RemediationDryRunStep] = Field(default_factory=list)
    findings: list[RemediationDryRunFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    state_mutated: bool = False
    execution_supported: bool = False


DRY_RUN_LIMITATION = (
    "Step 9 dry-run is simulation only. It does not execute remediation actions or modify systems."
)


def _target_summary(action: RemediationAction) -> str:
    target = action.target
    value = target.value or target.host or target.user or target.ip_address or "unspecified target"
    return f"{target.target_type.value}: {value}"


def _approval_is_satisfied(
    action: RemediationAction,
    approval_record: RemediationApprovalRecord | None,
) -> bool:
    if action.approval_requirement == RemediationApprovalRequirement.NONE:
        return True
    return bool(approval_record and approval_record.status == RemediationApprovalStatus.APPROVED)


def _finding(
    finding_id: str,
    status: RemediationDryRunStatus,
    title: str,
    description: str,
    *,
    severity: str = "INFO",
) -> RemediationDryRunFinding:
    return RemediationDryRunFinding(
        finding_id=finding_id,
        status=status,
        title=title,
        description=description,
        severity=severity,
    )


def _status_from_findings(
    findings: list[RemediationDryRunFinding],
) -> tuple[RemediationDryRunStatus, RemediationExecutionReadiness]:
    priority = [
        (
            RemediationDryRunStatus.FORBIDDEN,
            RemediationExecutionReadiness.BLOCKED,
        ),
        (
            RemediationDryRunStatus.BLOCKED_BY_POLICY,
            RemediationExecutionReadiness.BLOCKED,
        ),
        (
            RemediationDryRunStatus.MISSING_APPROVAL,
            RemediationExecutionReadiness.REQUIRES_APPROVAL,
        ),
        (
            RemediationDryRunStatus.MISSING_ROLLBACK,
            RemediationExecutionReadiness.REQUIRES_ROLLBACK,
        ),
        (
            RemediationDryRunStatus.MISSING_EVIDENCE,
            RemediationExecutionReadiness.REQUIRES_EVIDENCE,
        ),
        (
            RemediationDryRunStatus.NOT_SUPPORTED,
            RemediationExecutionReadiness.NOT_SUPPORTED,
        ),
    ]
    statuses = {finding.status for finding in findings}
    for status, readiness in priority:
        if status in statuses:
            return status, readiness
    return RemediationDryRunStatus.READY_FOR_REVIEW, RemediationExecutionReadiness.READY_FOR_FUTURE_REVIEW


def generate_action_dry_run(
    action: RemediationAction,
    *,
    plan_id: str | None = None,
    incident_id: int | None = None,
    approval_record: RemediationApprovalRecord | None = None,
) -> RemediationDryRunResult:
    findings: list[RemediationDryRunFinding] = []

    if (
        action.approval_requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
        or action.status == RemediationActionStatus.BLOCKED
    ):
        findings.append(
            _finding(
                f"{action.action_id}-forbidden",
                RemediationDryRunStatus.FORBIDDEN,
                "Action blocked by remediation policy",
                "The action is forbidden by default and cannot proceed to future execution review in Step 9.",
                severity="CRITICAL",
            )
        )

    if not _approval_is_satisfied(action, approval_record):
        findings.append(
            _finding(
                f"{action.action_id}-approval",
                RemediationDryRunStatus.MISSING_APPROVAL,
                "Approval is required",
                "A matching approval record is required before any future execution layer could evaluate this action.",
                severity="HIGH",
            )
        )

    if not action.rollback_steps:
        findings.append(
            _finding(
                f"{action.action_id}-rollback",
                RemediationDryRunStatus.MISSING_ROLLBACK,
                "Rollback steps are missing",
                "The action lacks rollback steps and must remain blocked until rollback readiness is reviewed.",
                severity="HIGH",
            )
        )

    if not action.evidence:
        findings.append(
            _finding(
                f"{action.action_id}-evidence",
                RemediationDryRunStatus.MISSING_EVIDENCE,
                "Supporting evidence is missing",
                "The action needs evidence or an explicit limitation before governance approval.",
                severity="MEDIUM",
            )
        )

    findings.append(
        _finding(
            f"{action.action_id}-execution-not-supported",
            RemediationDryRunStatus.NOT_SUPPORTED,
            "Execution is not supported",
            "Step 9 only simulates remediation impact. No executor, shell command or target-system mutation exists.",
        )
    )

    status, readiness = _status_from_findings(findings)
    target_summary = _target_summary(action)
    steps = [
        RemediationDryRunStep(
            step_id=f"{action.action_id}-review-target",
            title="Review target and scope",
            description="Validate that the remediation target matches the incident and investigation evidence.",
            target_summary=target_summary,
        ),
        RemediationDryRunStep(
            step_id=f"{action.action_id}-review-risk",
            title="Review operational risk",
            description="Review risk, approval requirement, rollback readiness and potential side effects.",
            target_summary=target_summary,
        ),
        RemediationDryRunStep(
            step_id=f"{action.action_id}-future-validation",
            title="Future post-action validation",
            description="If a later approved execution layer exists, validate expected telemetry and service health.",
            target_summary=target_summary,
        ),
    ]

    return RemediationDryRunResult(
        dry_run_id=f"dry-run:{plan_id or 'plan'}:{action.action_id}",
        plan_id=plan_id,
        action_id=action.action_id,
        incident_id=incident_id,
        status=status,
        readiness=readiness,
        action_summary=f"{action.title}: {action.description}",
        target_summary=target_summary,
        expected_impact=action.expected_impact.technical_impact or action.risk.blast_radius,
        affected_systems=[
            value
            for value in [
                action.target.host,
                action.target.user,
                action.target.ip_address,
                action.target.value,
            ]
            if value
        ],
        prerequisites=[
            "Human approval must be recorded where required.",
            "Supporting evidence and rollback readiness must be reviewed.",
        ],
        pre_checks=[
            f"{check.title}: {check.description}" for check in action.pre_checks
        ],
        post_checks=[
            f"{check.title}: {check.description}" for check in action.post_checks
        ],
        rollback_readiness=(
            "Rollback steps are available for review."
            if action.rollback_steps
            else "Rollback steps are missing."
        ),
        risk_summary=f"{action.risk.level.value} risk, score {action.risk.score}. {action.risk.rationale}",
        steps=steps,
        findings=findings,
        limitations=[DRY_RUN_LIMITATION],
        state_mutated=False,
        execution_supported=False,
    )


def generate_plan_dry_run(
    plan: RemediationPlan,
    *,
    approval_records: list[RemediationApprovalRecord] | None = None,
) -> RemediationDryRunResult:
    approval_records = approval_records or []
    approvals_by_action = {
        record.action_id: record
        for record in approval_records
        if record.action_id and record.status == RemediationApprovalStatus.APPROVED
    }
    action_results = [
        generate_action_dry_run(
            action,
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
            approval_record=approvals_by_action.get(action.action_id),
        )
        for action in plan.actions
    ]
    findings = [finding for result in action_results for finding in result.findings]
    status, readiness = _status_from_findings(findings)

    return RemediationDryRunResult(
        dry_run_id=f"dry-run:{plan.plan_id}",
        plan_id=plan.plan_id,
        incident_id=plan.incident_id,
        status=status,
        readiness=readiness,
        action_summary=plan.summary,
        target_summary=f"{len(plan.actions)} remediation action(s) proposed for review",
        expected_impact=plan.technical_impact or plan.business_impact,
        affected_systems=[
            action.target.value
            for action in plan.actions
            if action.target.value
        ],
        prerequisites=plan.prerequisites
        or [
            "Review plan evidence, approval requirements and rollback readiness before any future execution design.",
        ],
        pre_checks=[f"{check.title}: {check.description}" for check in plan.pre_checks],
        post_checks=[f"{check.title}: {check.description}" for check in plan.post_checks],
        rollback_readiness=(
            f"{plan.rollback_plan.availability.value}: {plan.rollback_plan.recovery_notes or 'Rollback readiness requires analyst review.'}"
        ),
        risk_summary=f"{plan.overall_risk.level.value} risk, score {plan.overall_risk.score}. {plan.overall_risk.rationale}",
        steps=[
            RemediationDryRunStep(
                step_id=f"{plan.plan_id}-plan-review",
                title="Review remediation plan",
                description="Review all proposed actions, approvals, risks and rollback notes.",
            ),
            RemediationDryRunStep(
                step_id=f"{plan.plan_id}-decision-record",
                title="Record analyst decision",
                description="Record approval, rejection, deferral or request for additional evidence.",
            ),
        ],
        findings=findings,
        limitations=[
            DRY_RUN_LIMITATION,
            "Plan-level dry-run aggregates action readiness and does not indicate execution availability.",
        ],
        state_mutated=False,
        execution_supported=False,
    )
