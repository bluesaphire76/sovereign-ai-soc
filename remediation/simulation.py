from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field

from investigation_ai.models import (
    EvidenceReference,
    InvestigationEvidenceStrength,
    InvestigationEvidenceType,
)

from .dry_run import RemediationDryRunStatus, generate_plan_dry_run
from .intelligence import generate_remediation_intelligence
from .models import (
    RemediationAction,
    RemediationActionStatus,
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationBaseModel,
    RemediationImpactAssessment,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPostCheck,
    RemediationPreCheck,
    RemediationRiskAssessment,
    RemediationRiskLevel,
    RemediationTarget,
    RemediationTargetCriticality,
    RemediationTargetType,
    RollbackAvailability,
    RollbackPlan,
)
from .readiness import RemediationExecutionAuditStatus, assess_action_execution_readiness
from .risk import approval_for_action, assess_action_risk
from .rollback import build_rollback_plan
from .rollback_readiness import (
    RemediationRollbackReadinessStatus,
    assess_plan_rollback_readiness,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationSimulationStatus(str, Enum):
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    MISSING_APPROVAL = "MISSING_APPROVAL"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    MISSING_ROLLBACK = "MISSING_ROLLBACK"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class RemediationDryRunFindingPreview(RemediationBaseModel):
    title: str
    description: str
    severity: str = "INFO"
    status: str
    recommendation: str | None = None


class RemediationApprovalGatePreview(RemediationBaseModel):
    action_id: str
    action_title: str
    approval_requirement: RemediationApprovalRequirement
    current_state: str
    reason: str


class RemediationRollbackReadinessPreview(RemediationBaseModel):
    status: str
    blockers: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RemediationDryRunSimulationResponse(RemediationBaseModel):
    incident_id: int
    generated_at: datetime = Field(default_factory=utc_now)
    source: str = "dry_run_simulation"
    remediation_source: str | None = None
    execution_supported: bool = False
    state_mutated: bool = False
    human_approval_required: bool = True
    summary: str
    status: RemediationSimulationStatus
    findings: list[RemediationDryRunFindingPreview] = Field(default_factory=list)
    approval_gates: list[RemediationApprovalGatePreview] = Field(default_factory=list)
    rollback_readiness: RemediationRollbackReadinessPreview
    next_safe_steps: list[str] = Field(default_factory=list)


APPROVAL_STRENGTH = {
    RemediationApprovalRequirement.NONE: 0,
    RemediationApprovalRequirement.ANALYST_APPROVAL: 1,
    RemediationApprovalRequirement.ADMIN_APPROVAL: 2,
    RemediationApprovalRequirement.SECURITY_LEAD_APPROVAL: 3,
    RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT: 4,
}

FINDING_RECOMMENDATIONS = {
    RemediationDryRunStatus.FORBIDDEN.value: "Do not approve this action in the current governance model.",
    RemediationDryRunStatus.BLOCKED_BY_POLICY.value: "Resolve the policy blocker before review continues.",
    RemediationDryRunStatus.MISSING_APPROVAL.value: "Record the required human approval before future execution review.",
    RemediationDryRunStatus.MISSING_ROLLBACK.value: "Define rollback steps and validation before approval.",
    RemediationDryRunStatus.MISSING_EVIDENCE.value: "Attach supporting evidence or document an explicit limitation.",
    RemediationDryRunStatus.NOT_SUPPORTED.value: "Treat this as simulation output only; no remediation was executed.",
}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _as_text(value: Any, fallback: str) -> str:
    text = str(value).strip() if value is not None else ""
    return text or fallback


def _enum_value(enum_type: type[Enum], value: Any, fallback: Enum) -> Enum:
    try:
        return enum_type(str(value))
    except Exception:
        return fallback


def _approval_from_action(
    action_type: RemediationActionType,
    raw_approval: Any,
    risk_score: int,
) -> RemediationApprovalRequirement:
    requested = _enum_value(
        RemediationApprovalRequirement,
        raw_approval,
        RemediationApprovalRequirement.ANALYST_APPROVAL,
    )
    deterministic = approval_for_action(action_type, risk_score=risk_score)
    return max(
        [requested, deterministic],
        key=lambda item: APPROVAL_STRENGTH[item],
    )


def _evidence_from_action(action_id: str, action: dict[str, Any]) -> list[EvidenceReference]:
    evidence: list[EvidenceReference] = []
    for index, item in enumerate(_as_list(action.get("evidence_basis"))[:8], start=1):
        summary = _as_text(item, "")
        if not summary:
            continue
        evidence.append(
            EvidenceReference(
                evidence_id=f"{action_id}-evidence-{index}",
                evidence_type=InvestigationEvidenceType.INCIDENT,
                source_system="remediation_intelligence",
                source_reference=action_id,
                summary=summary,
                strength=InvestigationEvidenceStrength.CONTEXTUAL,
            )
        )
    return evidence


def _risk_from_action(
    action_type: RemediationActionType,
    target: RemediationTarget,
    rollback_plan: RollbackPlan,
    evidence_count: int,
) -> RemediationRiskAssessment:
    return assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback_plan,
        confidence_score=60 if evidence_count else 25,
        evidence_count=evidence_count,
    )


def _action_from_plan_action(
    incident_id: int,
    index: int,
    action: dict[str, Any],
) -> RemediationAction:
    action_type = _enum_value(
        RemediationActionType,
        action.get("action_type"),
        RemediationActionType.COLLECT_FORENSIC_EVIDENCE,
    )
    assert isinstance(action_type, RemediationActionType)

    action_id = f"incident-{incident_id}-dry-run-action-{index}"
    target = RemediationTarget(
        target_type=RemediationTargetType.UNKNOWN,
        value=f"incident:{incident_id}",
        criticality=RemediationTargetCriticality.UNKNOWN,
    )
    rollback_plan = build_rollback_plan(action_type, action_id=action_id)
    if action.get("rollback_possible") is False:
        rollback_plan = RollbackPlan(
            rollback_id=f"rollback-{action_id}",
            availability=RollbackAvailability.UNAVAILABLE,
            steps=[],
            validation_steps=[
                "Document why rollback is unavailable before future approval review."
            ],
            recovery_notes="Rollback was not confirmed by remediation intelligence.",
            limitations=["Rollback readiness is missing for this proposed action."],
        )
    evidence = _evidence_from_action(action_id, action)
    risk = _risk_from_action(action_type, target, rollback_plan, len(evidence))
    approval = _approval_from_action(action_type, action.get("approval_requirement"), risk.score)

    return RemediationAction(
        action_id=action_id,
        action_type=action_type,
        title=_as_text(action.get("title"), action_type.value.replace("_", " ").title()),
        description=_as_text(
            action.get("description"),
            "Review this proposed remediation action in simulation mode.",
        ),
        target=target,
        reason="Proposed by remediation intelligence and converted to dry-run governance model.",
        evidence=evidence,
        approval_requirement=approval,
        risk=risk,
        expected_impact=RemediationImpactAssessment(
            business_impact="Business impact requires analyst and owner review.",
            technical_impact="Dry-run only. No production system state is changed.",
            service_availability_impact="No availability impact occurs during simulation.",
            blast_radius=risk.blast_radius,
        ),
        possible_side_effects=[
            "Future operational execution could affect availability or user productivity.",
            "Approval and rollback readiness must be reviewed before any future executor can act.",
        ],
        rollback_steps=rollback_plan.steps,
        pre_checks=[
            RemediationPreCheck(
                check_id=f"{action_id}-precheck-evidence",
                title="Review evidence basis",
                description="Confirm evidence supports the proposed remediation action.",
                expected_result="Analyst confirms evidence is sufficient or records missing evidence.",
            )
        ],
        post_checks=[
            RemediationPostCheck(
                check_id=f"{action_id}-postcheck-no-execution",
                title="Confirm no execution occurred",
                description="Confirm this dry-run did not mutate target systems.",
                expected_result="No users, services, files, firewall rules or hosts were changed.",
            )
        ],
        command_preview=None,
        command_preview_is_executable=False,
        execution_supported=False,
        simulation_supported=True,
        status=(
            RemediationActionStatus.BLOCKED
            if approval == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
            else RemediationActionStatus.PROPOSED
        ),
    )


def _fallback_action(incident_id: int) -> dict[str, Any]:
    return {
        "action_type": RemediationActionType.COLLECT_FORENSIC_EVIDENCE.value,
        "title": "Collect additional evidence before remediation",
        "description": "Gather supporting host, identity and network evidence before selecting an operational action.",
        "approval_requirement": RemediationApprovalRequirement.ANALYST_APPROVAL.value,
        "risk_level": RemediationRiskLevel.LOW.value,
        "rollback_possible": True,
        "evidence_basis": [],
    }


def _plan_from_intelligence(intelligence: dict[str, Any]) -> RemediationPlan:
    incident_id = int(intelligence.get("incident_id") or 0)
    raw_plan = intelligence.get("plan") if isinstance(intelligence.get("plan"), dict) else {}
    raw_actions = [
        item
        for item in _as_list(raw_plan.get("recommended_actions"))
        if isinstance(item, dict)
    ]
    if not raw_actions:
        raw_actions = [_fallback_action(incident_id)]

    actions = [
        _action_from_plan_action(incident_id, index, action)
        for index, action in enumerate(raw_actions[:8], start=1)
    ]
    overall_risk = max(actions, key=lambda item: item.risk.score).risk
    action_steps = [step for action in actions for step in action.rollback_steps[:2]]
    rollback_availability = (
        RollbackAvailability.UNAVAILABLE
        if not action_steps
        else RollbackAvailability.PARTIAL
    )

    return RemediationPlan(
        plan_id=f"dry-run-plan-{incident_id}",
        incident_id=incident_id,
        generated_by="remediation_dry_run_simulation",
        status=RemediationPlanStatus.UNDER_REVIEW,
        summary=_as_text(
            raw_plan.get("remediation_objective") or raw_plan.get("executive_summary"),
            "Remediation dry-run simulation is available for analyst review.",
        ),
        rationale=(
            "The simulation adapts remediation intelligence into governance checks. "
            "It does not execute actions or mutate state."
        ),
        actions=actions,
        overall_risk=overall_risk,
        expected_benefit="Improved review quality before any future remediation executor can act.",
        business_impact="No business impact occurs during dry-run simulation.",
        technical_impact="No technical state changes occur during dry-run simulation.",
        prerequisites=[
            "Human approval remains mandatory for operational remediation.",
            "Dry-run, rollback readiness and evidence blockers must be reviewed.",
        ],
        pre_checks=[
            RemediationPreCheck(
                check_id=f"incident-{incident_id}-dry-run-precheck",
                title="Validate dry-run scope",
                description="Confirm the remediation simulation is scoped to the selected incident.",
                expected_result="Analyst confirms the dry-run is review-only.",
            )
        ],
        post_checks=[
            RemediationPostCheck(
                check_id=f"incident-{incident_id}-dry-run-postcheck",
                title="Confirm no state mutation",
                description="Confirm the simulation did not change target systems or configurations.",
                expected_result="No remediation action was executed.",
            )
        ],
        rollback_plan=RollbackPlan(
            rollback_id=f"dry-run-plan-{incident_id}-rollback",
            availability=rollback_availability,
            steps=action_steps,
            validation_steps=[
                "Review rollback readiness per action before approval.",
                "Record limitations where rollback is partial or unavailable.",
            ],
            recovery_notes="Rollback readiness is advisory in Step 14 simulation.",
            limitations=list(_as_list(raw_plan.get("rollback_considerations"))[:6]),
        ),
        approval_required=True,
        evidence_used=[evidence for action in actions for evidence in action.evidence],
        limitations=list(_as_list(raw_plan.get("limitations"))[:8]),
        execution_supported=False,
        simulation_supported=True,
    )


def build_remediation_plan_from_intelligence(intelligence: dict[str, Any]) -> RemediationPlan:
    return _plan_from_intelligence(intelligence)


def _approval_gates(plan: RemediationPlan) -> list[RemediationApprovalGatePreview]:
    gates: list[RemediationApprovalGatePreview] = []
    for action in plan.actions:
        if action.approval_requirement == RemediationApprovalRequirement.NONE:
            current_state = "NOT_REQUIRED"
            reason = "The action is informational and does not require approval metadata."
        elif action.approval_requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT:
            current_state = "FORBIDDEN"
            reason = "The action is forbidden by default and cannot be approved in this dry-run."
        else:
            current_state = "MISSING"
            reason = "No approval record is evaluated by the read-only dry-run endpoint."

        gates.append(
            RemediationApprovalGatePreview(
                action_id=action.action_id,
                action_title=action.title,
                approval_requirement=action.approval_requirement,
                current_state=current_state,
                reason=reason,
            )
        )
    return gates


def _finding_previews(plan: RemediationPlan) -> list[RemediationDryRunFindingPreview]:
    findings: list[RemediationDryRunFindingPreview] = []
    dry_run = generate_plan_dry_run(plan)
    for finding in dry_run.findings:
        findings.append(
            RemediationDryRunFindingPreview(
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                status=finding.status.value,
                recommendation=FINDING_RECOMMENDATIONS.get(finding.status.value),
            )
        )

    for action in plan.actions:
        readiness = assess_action_execution_readiness(action, plan_id=plan.plan_id, incident_id=plan.incident_id)
        for blocker in readiness.blockers:
            findings.append(
                RemediationDryRunFindingPreview(
                    title="Execution readiness blocker",
                    description=blocker.reason,
                    severity=blocker.severity,
                    status=readiness.execution_status.value,
                    recommendation="Resolve this governance blocker before any future executor can act.",
                )
            )

    if not findings:
        findings.append(
            RemediationDryRunFindingPreview(
                title="Dry-run completed",
                description="No blockers were identified by the current simulation metadata.",
                severity="INFO",
                status=RemediationSimulationStatus.READY_FOR_REVIEW.value,
                recommendation="Review the plan with a human analyst before any future approval workflow.",
            )
        )
    return findings


def _rollup_status(
    findings: list[RemediationDryRunFindingPreview],
    rollback_status: RemediationRollbackReadinessStatus,
) -> RemediationSimulationStatus:
    statuses = {finding.status for finding in findings}
    if (
        RemediationDryRunStatus.FORBIDDEN.value in statuses
        or RemediationDryRunStatus.BLOCKED_BY_POLICY.value in statuses
        or RemediationExecutionAuditStatus.BLOCKED_BY_POLICY.value in statuses
    ):
        return RemediationSimulationStatus.BLOCKED_BY_POLICY
    if (
        RemediationDryRunStatus.MISSING_APPROVAL.value in statuses
        or RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_APPROVAL.value in statuses
    ):
        return RemediationSimulationStatus.MISSING_APPROVAL
    if rollback_status in {
        RemediationRollbackReadinessStatus.MISSING,
        RemediationRollbackReadinessStatus.BLOCKED,
        RemediationRollbackReadinessStatus.UNKNOWN,
    } or (
        RemediationDryRunStatus.MISSING_ROLLBACK.value in statuses
        or RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_ROLLBACK.value in statuses
    ):
        return RemediationSimulationStatus.MISSING_ROLLBACK
    if (
        RemediationDryRunStatus.MISSING_EVIDENCE.value in statuses
        or RemediationExecutionAuditStatus.BLOCKED_BY_VALIDATION.value in statuses
    ):
        return RemediationSimulationStatus.MISSING_EVIDENCE
    if RemediationDryRunStatus.NOT_SUPPORTED.value in statuses:
        return RemediationSimulationStatus.READY_FOR_REVIEW
    return RemediationSimulationStatus.NOT_SUPPORTED


def _next_safe_steps(status: RemediationSimulationStatus) -> list[str]:
    steps = [
        "Review dry-run findings with an analyst.",
        "Record the required human approval before any future execution layer can act.",
        "Confirm rollback readiness and evidence coverage before approval.",
        "No remediation action was executed or dispatched.",
    ]
    if status == RemediationSimulationStatus.MISSING_APPROVAL:
        steps.insert(1, "Capture analyst, admin or security lead approval according to the action risk.")
    elif status == RemediationSimulationStatus.MISSING_ROLLBACK:
        steps.insert(1, "Define rollback steps and validation criteria before approval.")
    elif status == RemediationSimulationStatus.MISSING_EVIDENCE:
        steps.insert(1, "Attach supporting incident evidence or document an explicit limitation.")
    elif status == RemediationSimulationStatus.BLOCKED_BY_POLICY:
        steps.insert(1, "Remove or replace forbidden actions before continuing remediation review.")
    return steps


def generate_incident_remediation_dry_run(
    incident_id: int,
) -> RemediationDryRunSimulationResponse:
    intelligence = generate_remediation_intelligence(incident_id)
    plan = _plan_from_intelligence(intelligence)
    findings = _finding_previews(plan)
    rollback = assess_plan_rollback_readiness(plan)
    status = _rollup_status(findings, rollback.status)

    return RemediationDryRunSimulationResponse(
        incident_id=incident_id,
        remediation_source=str(intelligence.get("source") or "unknown"),
        execution_supported=False,
        state_mutated=False,
        human_approval_required=True,
        summary=(
            "Dry-run simulation evaluated remediation governance gates. "
            "No action was executed and no target system state was changed."
        ),
        status=status,
        findings=findings[:12],
        approval_gates=_approval_gates(plan),
        rollback_readiness=RemediationRollbackReadinessPreview(
            status=rollback.status.value,
            blockers=[blocker.reason for blocker in rollback.blockers],
            limitations=rollback.limitations,
        ),
        next_safe_steps=_next_safe_steps(status),
    )
