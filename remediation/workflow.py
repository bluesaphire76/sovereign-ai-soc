from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field

from executor.audit import (
    ExecutorAuditEvent,
    audit_event_from_dispatch_result,
    audit_event_from_policy_decision,
)
from executor.dispatcher import dispatch_executor_action
from executor.models import (
    ExecutorDispatchResult,
    ExecutorDispatchStatus,
    ExecutorMode,
    ExecutorPolicyDecision,
    executor_action_from_remediation,
)
from executor.policy import evaluate_executor_policy

from .approvals import RemediationApprovalRecord, RemediationApprovalStatus
from .audit import (
    RemediationAuditEvent,
    audit_event_from_dry_run,
    audit_event_from_execution_audit_record,
    audit_event_from_readiness_assessment,
    audit_event_from_rollback_readiness,
    audit_event_from_workflow_state,
)
from .dry_run import RemediationDryRunResult, generate_action_dry_run
from .execution_audit import (
    RemediationExecutionAuditRecord,
    prepare_execution_audit_record,
)
from .models import (
    RemediationAction,
    RemediationActionStatus,
    RemediationApprovalRequirement,
    RemediationBaseModel,
    RemediationPlan,
)
from .readiness import (
    RemediationExecutionAuditStatus,
    RemediationExecutionReadinessAssessment,
    assess_action_execution_readiness,
)
from .rollback_readiness import (
    RemediationRollbackReadiness,
    RemediationRollbackReadinessStatus,
    assess_action_rollback_readiness,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationWorkflowStatus(str, Enum):
    PLAN_AVAILABLE = "PLAN_AVAILABLE"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DRY_RUN_READY = "DRY_RUN_READY"
    READINESS_READY = "READINESS_READY"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    BLOCKED_BY_ROLLBACK = "BLOCKED_BY_ROLLBACK"
    READY_FOR_MOCK_DISPATCH = "READY_FOR_MOCK_DISPATCH"
    MOCK_DISPATCH_COMPLETED = "MOCK_DISPATCH_COMPLETED"
    NOOP_DISPATCH_COMPLETED = "NOOP_DISPATCH_COMPLETED"
    EXECUTION_DISABLED = "EXECUTION_DISABLED"
    FAILED_VALIDATION = "FAILED_VALIDATION"


class RemediationWorkflowStep(str, Enum):
    PLAN = "PLAN"
    APPROVAL = "APPROVAL"
    DRY_RUN = "DRY_RUN"
    ROLLBACK_READINESS = "ROLLBACK_READINESS"
    EXECUTION_READINESS = "EXECUTION_READINESS"
    EXECUTOR_POLICY = "EXECUTOR_POLICY"
    MOCK_NOOP_DISPATCH = "MOCK_NOOP_DISPATCH"
    AUDIT = "AUDIT"


class RemediationWorkflowBlocker(RemediationBaseModel):
    blocker_id: str
    step: RemediationWorkflowStep
    reason: str
    severity: str = "HIGH"
    source: str = "workflow"


class RemediationGovernanceTimelineEntry(RemediationBaseModel):
    entry_id: str
    sequence: int
    step: RemediationWorkflowStep
    status: RemediationWorkflowStatus
    title: str
    description: str
    reference_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    production_impact: bool = False


class RemediationWorkflowState(RemediationBaseModel):
    plan_id: str | None = None
    action_id: str | None = None
    incident_id: int | None = None
    status: RemediationWorkflowStatus
    evaluated_at: datetime = Field(default_factory=utc_now)
    blockers: list[RemediationWorkflowBlocker] = Field(default_factory=list)
    timeline: list[RemediationGovernanceTimelineEntry] = Field(default_factory=list)
    approval_id: str | None = None
    dry_run_id: str | None = None
    rollback_readiness_id: str | None = None
    readiness_id: str | None = None
    policy_decision_id: str | None = None
    dispatch_id: str | None = None
    execution_audit_id: str | None = None
    execution_disabled: bool = True
    production_impact: bool = False


class RemediationWorkflowResult(RemediationBaseModel):
    state: RemediationWorkflowState
    dry_run_result: RemediationDryRunResult | None = None
    rollback_readiness: RemediationRollbackReadiness | None = None
    readiness: RemediationExecutionReadinessAssessment | None = None
    policy_decision: ExecutorPolicyDecision | None = None
    dispatch_result: ExecutorDispatchResult | None = None
    execution_audit_record: RemediationExecutionAuditRecord | None = None
    remediation_audit_events: list[RemediationAuditEvent] = Field(default_factory=list)
    executor_audit_events: list[ExecutorAuditEvent] = Field(default_factory=list)


class RemediationGovernanceSummary(RemediationBaseModel):
    plan_id: str | None = None
    action_id: str | None = None
    incident_id: int | None = None
    status: RemediationWorkflowStatus
    summary: str
    blocker_count: int = 0
    timeline_count: int = 0
    production_execution_enabled: bool = False
    next_steps: list[str] = Field(default_factory=list)


def _find_action(plan: RemediationPlan, action_id: str) -> RemediationAction | None:
    return next((action for action in plan.actions if action.action_id == action_id), None)


def _blocker(
    blocker_id: str,
    step: RemediationWorkflowStep,
    reason: str,
    *,
    severity: str = "HIGH",
    source: str = "workflow",
) -> RemediationWorkflowBlocker:
    return RemediationWorkflowBlocker(
        blocker_id=blocker_id,
        step=step,
        reason=reason,
        severity=severity,
        source=source,
    )


def _entry(
    sequence: int,
    step: RemediationWorkflowStep,
    status: RemediationWorkflowStatus,
    title: str,
    description: str,
    *,
    reference_id: str | None = None,
) -> RemediationGovernanceTimelineEntry:
    return RemediationGovernanceTimelineEntry(
        entry_id=f"workflow:{sequence}:{step.value.lower()}:{status.value.lower()}",
        sequence=sequence,
        step=step,
        status=status,
        title=title,
        description=description,
        reference_id=reference_id,
        production_impact=False,
    )


def _approval_satisfied(
    action: RemediationAction,
    approval_record: RemediationApprovalRecord | None,
) -> bool:
    if action.approval_requirement == RemediationApprovalRequirement.NONE:
        return True
    return bool(
        approval_record
        and approval_record.status == RemediationApprovalStatus.APPROVED
        and not approval_record.policy_issues
        and approval_record.action_id == action.action_id
    )


def _forbidden_action(action: RemediationAction) -> bool:
    return (
        action.approval_requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
        or action.status == RemediationActionStatus.BLOCKED
    )


def _status_from_dispatch(result: ExecutorDispatchResult) -> RemediationWorkflowStatus:
    if result.status == ExecutorDispatchStatus.MOCK_RECORDED:
        return RemediationWorkflowStatus.MOCK_DISPATCH_COMPLETED
    if result.status == ExecutorDispatchStatus.NOOP_RECORDED:
        return RemediationWorkflowStatus.NOOP_DISPATCH_COMPLETED
    if result.status == ExecutorDispatchStatus.BLOCKED_BY_POLICY:
        return RemediationWorkflowStatus.BLOCKED_BY_POLICY
    return RemediationWorkflowStatus.FAILED_VALIDATION


def get_workflow_state(
    plan: RemediationPlan | None,
    action_id: str,
    *,
    approval_record: RemediationApprovalRecord | None = None,
    dry_run_result: RemediationDryRunResult | None = None,
    rollback_readiness: RemediationRollbackReadiness | None = None,
    readiness: RemediationExecutionReadinessAssessment | None = None,
    policy_decision: ExecutorPolicyDecision | None = None,
    dispatch_result: ExecutorDispatchResult | None = None,
    execution_audit_record: RemediationExecutionAuditRecord | None = None,
) -> RemediationWorkflowState:
    blockers: list[RemediationWorkflowBlocker] = []
    timeline: list[RemediationGovernanceTimelineEntry] = []
    status = RemediationWorkflowStatus.EXECUTION_DISABLED

    if plan is None:
        blockers.append(
            _blocker(
                "plan-missing",
                RemediationWorkflowStep.PLAN,
                "Remediation plan is required before governance workflow evaluation.",
            )
        )
        timeline.append(
            _entry(
                1,
                RemediationWorkflowStep.PLAN,
                RemediationWorkflowStatus.FAILED_VALIDATION,
                "Plan missing",
                "Workflow evaluation stopped because no remediation plan was provided.",
            )
        )
        return RemediationWorkflowState(
            action_id=action_id,
            status=RemediationWorkflowStatus.FAILED_VALIDATION,
            blockers=blockers,
            timeline=timeline,
        )

    action = _find_action(plan, action_id)
    timeline.append(
        _entry(
            1,
            RemediationWorkflowStep.PLAN,
            RemediationWorkflowStatus.PLAN_AVAILABLE,
            "Plan available",
            "Remediation plan and action context are available for governance review.",
            reference_id=plan.plan_id,
        )
    )
    if action is None:
        blockers.append(
            _blocker(
                "action-missing",
                RemediationWorkflowStep.PLAN,
                "Requested remediation action is not present in the plan.",
            )
        )
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action_id,
            incident_id=plan.incident_id,
            status=RemediationWorkflowStatus.FAILED_VALIDATION,
            blockers=blockers,
            timeline=timeline,
        )

    if _forbidden_action(action):
        blockers.append(
            _blocker(
                f"{action.action_id}-forbidden",
                RemediationWorkflowStep.APPROVAL,
                "Action is forbidden by remediation policy and cannot enter dispatch review.",
                severity="CRITICAL",
                source="policy",
            )
        )
        status = RemediationWorkflowStatus.BLOCKED_BY_POLICY
        timeline.append(
            _entry(
                2,
                RemediationWorkflowStep.APPROVAL,
                status,
                "Action blocked by policy",
                "Forbidden actions cannot be approved or dispatched in Step 12.",
                reference_id=action.action_id,
            )
        )
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=status,
            blockers=blockers,
            timeline=timeline,
        )

    if approval_record and approval_record.status == RemediationApprovalStatus.REJECTED:
        blockers.append(
            _blocker(
                f"{action.action_id}-approval-rejected",
                RemediationWorkflowStep.APPROVAL,
                "Approval decision rejected this remediation action.",
                source="approval",
            )
        )
        status = RemediationWorkflowStatus.REJECTED
        timeline.append(
            _entry(
                2,
                RemediationWorkflowStep.APPROVAL,
                status,
                "Action rejected",
                "A reviewer rejected this remediation action.",
                reference_id=approval_record.approval_id,
            )
        )
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=status,
            blockers=blockers,
            timeline=timeline,
            approval_id=approval_record.approval_id,
        )

    if not _approval_satisfied(action, approval_record):
        blockers.append(
            _blocker(
                f"{action.action_id}-approval-required",
                RemediationWorkflowStep.APPROVAL,
                "Required human approval is missing or contains policy issues.",
                source="approval",
            )
        )
        status = RemediationWorkflowStatus.AWAITING_APPROVAL
        timeline.append(
            _entry(
                2,
                RemediationWorkflowStep.APPROVAL,
                status,
                "Awaiting approval",
                "Human approval is required before readiness or dispatch review can proceed.",
                reference_id=approval_record.approval_id if approval_record else None,
            )
        )
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=status,
            blockers=blockers,
            timeline=timeline,
            approval_id=approval_record.approval_id if approval_record else None,
        )

    timeline.append(
        _entry(
            2,
            RemediationWorkflowStep.APPROVAL,
            RemediationWorkflowStatus.APPROVED,
            "Approval recorded",
            "Approval metadata is present. It does not trigger execution.",
            reference_id=approval_record.approval_id if approval_record else None,
        )
    )

    if dry_run_result is None:
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=RemediationWorkflowStatus.APPROVED,
            blockers=blockers,
            timeline=timeline,
            approval_id=approval_record.approval_id if approval_record else None,
        )

    timeline.append(
        _entry(
            3,
            RemediationWorkflowStep.DRY_RUN,
            RemediationWorkflowStatus.DRY_RUN_READY,
            "Dry-run generated",
            "Simulation output is available. No system state was changed.",
            reference_id=dry_run_result.dry_run_id,
        )
    )

    if rollback_readiness is not None:
        rollback_status = (
            RemediationWorkflowStatus.BLOCKED_BY_ROLLBACK
            if rollback_readiness.status
            in {
                RemediationRollbackReadinessStatus.MISSING,
                RemediationRollbackReadinessStatus.BLOCKED,
                RemediationRollbackReadinessStatus.UNKNOWN,
            }
            else RemediationWorkflowStatus.READINESS_READY
        )
        timeline.append(
            _entry(
                4,
                RemediationWorkflowStep.ROLLBACK_READINESS,
                rollback_status,
                "Rollback readiness checked",
                f"Rollback readiness status: {rollback_readiness.status.value}.",
                reference_id=rollback_readiness.rollback_readiness_id,
            )
        )
        if rollback_status == RemediationWorkflowStatus.BLOCKED_BY_ROLLBACK:
            blockers.append(
                _blocker(
                    f"{action.action_id}-rollback-blocked",
                    RemediationWorkflowStep.ROLLBACK_READINESS,
                    "Rollback readiness is missing, blocked or unknown.",
                    source="rollback",
                )
            )
            return RemediationWorkflowState(
                plan_id=plan.plan_id,
                action_id=action.action_id,
                incident_id=plan.incident_id,
                status=rollback_status,
                blockers=blockers,
                timeline=timeline,
                approval_id=approval_record.approval_id if approval_record else None,
                dry_run_id=dry_run_result.dry_run_id,
                rollback_readiness_id=rollback_readiness.rollback_readiness_id,
            )

    if readiness is None:
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=RemediationWorkflowStatus.DRY_RUN_READY,
            blockers=blockers,
            timeline=timeline,
            approval_id=approval_record.approval_id if approval_record else None,
            dry_run_id=dry_run_result.dry_run_id,
            rollback_readiness_id=(
                rollback_readiness.rollback_readiness_id if rollback_readiness else None
            ),
        )

    readiness_status = (
        RemediationWorkflowStatus.READINESS_READY
        if readiness.execution_status == RemediationExecutionAuditStatus.READY_FOR_FUTURE_EXECUTOR
        else RemediationWorkflowStatus.BLOCKED_BY_POLICY
    )
    if readiness.execution_status == RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_ROLLBACK:
        readiness_status = RemediationWorkflowStatus.BLOCKED_BY_ROLLBACK
    elif readiness.execution_status == RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_APPROVAL:
        readiness_status = RemediationWorkflowStatus.AWAITING_APPROVAL
    timeline.append(
        _entry(
            5,
            RemediationWorkflowStep.EXECUTION_READINESS,
            readiness_status,
            "Execution readiness assessed",
            f"Governance readiness status: {readiness.execution_status.value}.",
            reference_id=readiness.readiness_id,
        )
    )
    if readiness_status != RemediationWorkflowStatus.READINESS_READY:
        blockers.extend(
            _blocker(
                blocker.blocker_id,
                RemediationWorkflowStep.EXECUTION_READINESS,
                blocker.reason,
                severity=blocker.severity,
                source=blocker.source,
            )
            for blocker in readiness.blockers
        )
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=readiness_status,
            blockers=blockers,
            timeline=timeline,
            approval_id=approval_record.approval_id if approval_record else None,
            dry_run_id=dry_run_result.dry_run_id,
            rollback_readiness_id=(
                rollback_readiness.rollback_readiness_id if rollback_readiness else None
            ),
            readiness_id=readiness.readiness_id,
        )

    if policy_decision is None:
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=RemediationWorkflowStatus.READINESS_READY,
            blockers=blockers,
            timeline=timeline,
            approval_id=approval_record.approval_id if approval_record else None,
            dry_run_id=dry_run_result.dry_run_id,
            rollback_readiness_id=(
                rollback_readiness.rollback_readiness_id if rollback_readiness else None
            ),
            readiness_id=readiness.readiness_id,
        )

    policy_status = (
        RemediationWorkflowStatus.READY_FOR_MOCK_DISPATCH
        if policy_decision.allowed
        else RemediationWorkflowStatus.BLOCKED_BY_POLICY
    )
    timeline.append(
        _entry(
            6,
            RemediationWorkflowStep.EXECUTOR_POLICY,
            policy_status,
            "Executor policy evaluated",
            f"Executor policy status: {policy_decision.status.value}.",
            reference_id=policy_decision.decision_id,
        )
    )
    if not policy_decision.allowed:
        blockers.extend(
            _blocker(
                f"{action.action_id}-policy-{index}",
                RemediationWorkflowStep.EXECUTOR_POLICY,
                blocker,
                source="executor_policy",
            )
            for index, blocker in enumerate(policy_decision.blockers, start=1)
        )
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=policy_status,
            blockers=blockers,
            timeline=timeline,
            approval_id=approval_record.approval_id if approval_record else None,
            dry_run_id=dry_run_result.dry_run_id,
            rollback_readiness_id=(
                rollback_readiness.rollback_readiness_id if rollback_readiness else None
            ),
            readiness_id=readiness.readiness_id,
            policy_decision_id=policy_decision.decision_id,
        )

    if dispatch_result is None:
        return RemediationWorkflowState(
            plan_id=plan.plan_id,
            action_id=action.action_id,
            incident_id=plan.incident_id,
            status=RemediationWorkflowStatus.READY_FOR_MOCK_DISPATCH,
            blockers=blockers,
            timeline=timeline,
            approval_id=approval_record.approval_id if approval_record else None,
            dry_run_id=dry_run_result.dry_run_id,
            rollback_readiness_id=(
                rollback_readiness.rollback_readiness_id if rollback_readiness else None
            ),
            readiness_id=readiness.readiness_id,
            policy_decision_id=policy_decision.decision_id,
        )

    status = _status_from_dispatch(dispatch_result)
    timeline.append(
        _entry(
            7,
            RemediationWorkflowStep.MOCK_NOOP_DISPATCH,
            status,
            "Mock/no-op dispatch recorded",
            "Dispatcher recorded mock/no-op metadata only. No production system was changed.",
            reference_id=dispatch_result.dispatch_id,
        )
    )
    if execution_audit_record is not None:
        timeline.append(
            _entry(
                8,
                RemediationWorkflowStep.AUDIT,
                status,
                "Governance audit prepared",
                "Chain-of-custody audit metadata is available for review.",
                reference_id=execution_audit_record.execution_audit_id,
            )
        )

    return RemediationWorkflowState(
        plan_id=plan.plan_id,
        action_id=action.action_id,
        incident_id=plan.incident_id,
        status=status,
        blockers=blockers,
        timeline=timeline,
        approval_id=approval_record.approval_id if approval_record else None,
        dry_run_id=dry_run_result.dry_run_id,
        rollback_readiness_id=(
            rollback_readiness.rollback_readiness_id if rollback_readiness else None
        ),
        readiness_id=readiness.readiness_id,
        policy_decision_id=policy_decision.decision_id,
        dispatch_id=dispatch_result.dispatch_id,
        execution_audit_id=(
            execution_audit_record.execution_audit_id if execution_audit_record else None
        ),
    )


def advance_to_dry_run(
    plan: RemediationPlan,
    action_id: str,
    *,
    approval_record: RemediationApprovalRecord | None = None,
) -> RemediationWorkflowResult:
    action = _find_action(plan, action_id)
    if action is None:
        state = get_workflow_state(plan, action_id, approval_record=approval_record)
        return RemediationWorkflowResult(
            state=state,
            remediation_audit_events=[audit_event_from_workflow_state(state)],
        )

    dry_run = generate_action_dry_run(
        action,
        plan_id=plan.plan_id,
        incident_id=plan.incident_id,
        approval_record=approval_record,
    )
    state = get_workflow_state(
        plan,
        action_id,
        approval_record=approval_record,
        dry_run_result=dry_run,
    )
    return RemediationWorkflowResult(
        state=state,
        dry_run_result=dry_run,
        remediation_audit_events=[
            audit_event_from_dry_run(dry_run),
            audit_event_from_workflow_state(state),
        ],
    )


def advance_to_readiness_check(
    plan: RemediationPlan,
    action_id: str,
    *,
    approval_record: RemediationApprovalRecord | None = None,
    dry_run_result: RemediationDryRunResult | None = None,
) -> RemediationWorkflowResult:
    action = _find_action(plan, action_id)
    if action is None:
        state = get_workflow_state(plan, action_id, approval_record=approval_record)
        return RemediationWorkflowResult(
            state=state,
            remediation_audit_events=[audit_event_from_workflow_state(state)],
        )

    dry_run = dry_run_result or generate_action_dry_run(
        action,
        plan_id=plan.plan_id,
        incident_id=plan.incident_id,
        approval_record=approval_record,
    )
    rollback = assess_action_rollback_readiness(
        action,
        plan_id=plan.plan_id,
        incident_id=plan.incident_id,
    )
    readiness = assess_action_execution_readiness(
        action,
        plan_id=plan.plan_id,
        incident_id=plan.incident_id,
        approval_record=approval_record,
        dry_run_result=dry_run,
        rollback_readiness=rollback,
    )
    state = get_workflow_state(
        plan,
        action_id,
        approval_record=approval_record,
        dry_run_result=dry_run,
        rollback_readiness=rollback,
        readiness=readiness,
    )
    return RemediationWorkflowResult(
        state=state,
        dry_run_result=dry_run,
        rollback_readiness=rollback,
        readiness=readiness,
        remediation_audit_events=[
            audit_event_from_dry_run(dry_run),
            audit_event_from_rollback_readiness(rollback),
            audit_event_from_readiness_assessment(readiness),
            audit_event_from_workflow_state(state),
        ],
    )


def advance_to_policy_check(
    plan: RemediationPlan,
    action_id: str,
    *,
    approval_record: RemediationApprovalRecord | None = None,
    dry_run_result: RemediationDryRunResult | None = None,
    rollback_readiness: RemediationRollbackReadiness | None = None,
    readiness: RemediationExecutionReadinessAssessment | None = None,
    mode: ExecutorMode = ExecutorMode.NOOP,
    parameters: dict[str, Any] | None = None,
) -> RemediationWorkflowResult:
    readiness_result = advance_to_readiness_check(
        plan,
        action_id,
        approval_record=approval_record,
        dry_run_result=dry_run_result,
    )
    action = _find_action(plan, action_id)
    if action is None or readiness_result.state.blockers:
        return readiness_result

    dry_run = dry_run_result or readiness_result.dry_run_result
    rollback = rollback_readiness or readiness_result.rollback_readiness
    readiness_assessment = readiness or readiness_result.readiness
    if dry_run is None or rollback is None or readiness_assessment is None:
        return readiness_result

    try:
        executor_action = executor_action_from_remediation(
            action,
            approval_record=approval_record,
            dry_run_result=dry_run,
            readiness=readiness_assessment,
            rollback_readiness=rollback,
            mode=mode,
            parameters=parameters,
        )
        policy = evaluate_executor_policy(
            executor_action,
            approval_record=approval_record,
            dry_run_result=dry_run,
            readiness=readiness_assessment,
            rollback_readiness=rollback,
        )
        executor_events = [audit_event_from_policy_decision(policy)]
    except ValueError as exc:
        state = get_workflow_state(
            plan,
            action_id,
            approval_record=approval_record,
            dry_run_result=dry_run,
            rollback_readiness=rollback,
            readiness=readiness_assessment,
        )
        state = state.model_copy(
            update={
                "status": RemediationWorkflowStatus.BLOCKED_BY_POLICY,
                "blockers": [
                    *state.blockers,
                    _blocker(
                        f"{action.action_id}-executor-adapter",
                        RemediationWorkflowStep.EXECUTOR_POLICY,
                        str(exc),
                        source="executor_policy",
                    ),
                ],
            }
        )
        return RemediationWorkflowResult(
            state=state,
            dry_run_result=dry_run,
            rollback_readiness=rollback,
            readiness=readiness_assessment,
            remediation_audit_events=[audit_event_from_workflow_state(state)],
        )

    state = get_workflow_state(
        plan,
        action_id,
        approval_record=approval_record,
        dry_run_result=dry_run,
        rollback_readiness=rollback,
        readiness=readiness_assessment,
        policy_decision=policy,
    )
    return RemediationWorkflowResult(
        state=state,
        dry_run_result=dry_run,
        rollback_readiness=rollback,
        readiness=readiness_assessment,
        policy_decision=policy,
        remediation_audit_events=[
            *readiness_result.remediation_audit_events,
            audit_event_from_workflow_state(state),
        ],
        executor_audit_events=executor_events,
    )


def advance_to_mock_dispatch(
    plan: RemediationPlan,
    action_id: str,
    *,
    approval_record: RemediationApprovalRecord | None = None,
    mode: ExecutorMode = ExecutorMode.MOCK,
    parameters: dict[str, Any] | None = None,
) -> RemediationWorkflowResult:
    if mode not in {ExecutorMode.MOCK, ExecutorMode.NOOP}:
        raise ValueError("Step 12 supports only MOCK or NOOP dispatch modes.")

    policy_result = advance_to_policy_check(
        plan,
        action_id,
        approval_record=approval_record,
        mode=mode,
        parameters=parameters,
    )
    action = _find_action(plan, action_id)
    if (
        action is None
        or policy_result.policy_decision is None
        or policy_result.dry_run_result is None
        or policy_result.rollback_readiness is None
        or policy_result.readiness is None
    ):
        return policy_result

    if not policy_result.policy_decision.allowed:
        return policy_result

    executor_action = executor_action_from_remediation(
        action,
        approval_record=approval_record,
        dry_run_result=policy_result.dry_run_result,
        readiness=policy_result.readiness,
        rollback_readiness=policy_result.rollback_readiness,
        mode=mode,
        parameters=parameters,
    )
    dispatch = dispatch_executor_action(executor_action, policy_result.policy_decision)
    audit_record = prepare_execution_audit_record(
        plan,
        action,
        approval_record=approval_record,
        dry_run_result=policy_result.dry_run_result,
        readiness=policy_result.readiness,
        rollback_readiness=policy_result.rollback_readiness,
    )
    state = get_workflow_state(
        plan,
        action_id,
        approval_record=approval_record,
        dry_run_result=policy_result.dry_run_result,
        rollback_readiness=policy_result.rollback_readiness,
        readiness=policy_result.readiness,
        policy_decision=policy_result.policy_decision,
        dispatch_result=dispatch,
        execution_audit_record=audit_record,
    )
    return RemediationWorkflowResult(
        state=state,
        dry_run_result=policy_result.dry_run_result,
        rollback_readiness=policy_result.rollback_readiness,
        readiness=policy_result.readiness,
        policy_decision=policy_result.policy_decision,
        dispatch_result=dispatch,
        execution_audit_record=audit_record,
        remediation_audit_events=[
            *policy_result.remediation_audit_events,
            audit_event_from_execution_audit_record(audit_record),
            audit_event_from_workflow_state(state),
        ],
        executor_audit_events=[
            *policy_result.executor_audit_events,
            audit_event_from_dispatch_result(dispatch),
        ],
    )


def build_governance_summary(
    state: RemediationWorkflowState | RemediationWorkflowResult,
) -> RemediationGovernanceSummary:
    workflow_state = state.state if isinstance(state, RemediationWorkflowResult) else state
    if workflow_state.blockers:
        next_steps = [blocker.reason for blocker in workflow_state.blockers]
    elif workflow_state.status == RemediationWorkflowStatus.READY_FOR_MOCK_DISPATCH:
        next_steps = ["Mock/no-op dispatch may be requested explicitly for governance validation."]
    elif workflow_state.status in {
        RemediationWorkflowStatus.MOCK_DISPATCH_COMPLETED,
        RemediationWorkflowStatus.NOOP_DISPATCH_COMPLETED,
    }:
        next_steps = ["Review audit trail and governance timeline. Production execution remains disabled."]
    else:
        next_steps = ["Continue the next explicit remediation governance step."]

    return RemediationGovernanceSummary(
        plan_id=workflow_state.plan_id,
        action_id=workflow_state.action_id,
        incident_id=workflow_state.incident_id,
        status=workflow_state.status,
        summary=(
            "Production execution is disabled. This workflow evaluates governance readiness "
            "and records mock/no-op dispatch metadata only."
        ),
        blocker_count=len(workflow_state.blockers),
        timeline_count=len(workflow_state.timeline),
        production_execution_enabled=False,
        next_steps=next_steps,
    )
