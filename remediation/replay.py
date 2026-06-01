from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field, model_validator

from .audit_trail import build_remediation_audit_trail
from .dry_run import (
    RemediationDryRunStatus,
    generate_action_dry_run,
    generate_plan_dry_run,
)
from .intelligence import generate_remediation_intelligence
from .models import (
    RemediationAction,
    RemediationApprovalRequirement,
    RemediationBaseModel,
    RemediationPlan,
)
from .rollback_engine import (
    RollbackEngineOverallStatus,
    build_rollback_engine_response,
)
from .simulation import build_remediation_plan_from_intelligence


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationReplayMode(str, Enum):
    READ_ONLY = "READ_ONLY"


class RemediationReplayPhase(str, Enum):
    PLAN_GENERATION = "PLAN_GENERATION"
    GOVERNANCE_CHECK = "GOVERNANCE_CHECK"
    APPROVAL_GATE = "APPROVAL_GATE"
    DRY_RUN = "DRY_RUN"
    ROLLBACK_READINESS = "ROLLBACK_READINESS"
    AUDIT_TRAIL = "AUDIT_TRAIL"
    FINAL_DECISION = "FINAL_DECISION"


class RemediationReplayStepStatus(str, Enum):
    PASSED = "PASSED"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RemediationReplayDryRunStatus(str, Enum):
    PASSED = "PASSED"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


class RemediationReplayTimelineEntry(RemediationBaseModel):
    step: int
    phase: RemediationReplayPhase
    status: RemediationReplayStepStatus
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    policy_notes: list[str] = Field(default_factory=list)


class RemediationReplayProposedAction(RemediationBaseModel):
    action_type: str
    title: str
    approval_required: bool = True
    dry_run_status: RemediationReplayDryRunStatus = RemediationReplayDryRunStatus.UNKNOWN
    rollback_status: str = "UNKNOWN"
    governance_status: str = "REQUIRES_REVIEW"


class RemediationReplayResponse(RemediationBaseModel):
    incident_id: int
    generated_at: datetime = Field(default_factory=utc_now)
    source: str = "remediation_replay_engine"
    remediation_source: str | None = None
    execution_supported: bool = False
    state_mutated: bool = False
    replay_mode: RemediationReplayMode = RemediationReplayMode.READ_ONLY
    summary: str
    timeline: list[RemediationReplayTimelineEntry] = Field(default_factory=list)
    proposed_actions: list[RemediationReplayProposedAction] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    human_decision_required: bool = True
    final_recommendation: str
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_read_only_boundary(self) -> "RemediationReplayResponse":
        object.__setattr__(self, "execution_supported", False)
        object.__setattr__(self, "state_mutated", False)
        object.__setattr__(self, "replay_mode", RemediationReplayMode.READ_ONLY)
        object.__setattr__(self, "human_decision_required", True)
        return self


REPLAY_NOTES = [
    "Replay is read-only.",
    "No remediation was executed.",
    "No rollback was executed.",
    "Human approval remains mandatory.",
]


def _safe_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _governance_status(governance: dict[str, Any] | None) -> str:
    return str((governance or {}).get("status") or "REQUIRES_REVIEW")


def _timeline_status_from_governance(status: str) -> RemediationReplayStepStatus:
    if status == "PASSED":
        return RemediationReplayStepStatus.PASSED
    if status == "BLOCKED":
        return RemediationReplayStepStatus.BLOCKED
    if status in {"REQUIRES_REVIEW", "NEEDS_HUMAN_REVIEW"}:
        return RemediationReplayStepStatus.REQUIRES_REVIEW
    return RemediationReplayStepStatus.WARNING


def _timeline_status_from_dry_run(status: RemediationDryRunStatus | None) -> RemediationReplayStepStatus:
    if status == RemediationDryRunStatus.READY_FOR_REVIEW:
        return RemediationReplayStepStatus.WARNING
    if status in {
        RemediationDryRunStatus.FORBIDDEN,
        RemediationDryRunStatus.BLOCKED_BY_POLICY,
    }:
        return RemediationReplayStepStatus.BLOCKED
    if status in {
        RemediationDryRunStatus.MISSING_APPROVAL,
        RemediationDryRunStatus.MISSING_ROLLBACK,
        RemediationDryRunStatus.MISSING_EVIDENCE,
    }:
        return RemediationReplayStepStatus.REQUIRES_REVIEW
    if status == RemediationDryRunStatus.NOT_SUPPORTED:
        return RemediationReplayStepStatus.WARNING
    return RemediationReplayStepStatus.NOT_APPLICABLE


def _proposed_dry_run_status(status: RemediationDryRunStatus | None) -> RemediationReplayDryRunStatus:
    if status == RemediationDryRunStatus.READY_FOR_REVIEW:
        return RemediationReplayDryRunStatus.PASSED
    if status == RemediationDryRunStatus.NOT_SUPPORTED:
        return RemediationReplayDryRunStatus.NOT_SUPPORTED
    if status in {
        RemediationDryRunStatus.FORBIDDEN,
        RemediationDryRunStatus.BLOCKED_BY_POLICY,
    }:
        return RemediationReplayDryRunStatus.BLOCKED
    if status in {
        RemediationDryRunStatus.MISSING_APPROVAL,
        RemediationDryRunStatus.MISSING_ROLLBACK,
        RemediationDryRunStatus.MISSING_EVIDENCE,
    }:
        return RemediationReplayDryRunStatus.WARNING
    return RemediationReplayDryRunStatus.UNKNOWN


def _timeline_status_from_rollback(status: RollbackEngineOverallStatus | None) -> RemediationReplayStepStatus:
    if status == RollbackEngineOverallStatus.READY:
        return RemediationReplayStepStatus.PASSED
    if status == RollbackEngineOverallStatus.CONDITIONAL:
        return RemediationReplayStepStatus.WARNING
    if status == RollbackEngineOverallStatus.NOT_READY:
        return RemediationReplayStepStatus.BLOCKED
    return RemediationReplayStepStatus.REQUIRES_REVIEW


def _approval_required(action: RemediationAction) -> bool:
    return action.approval_requirement != RemediationApprovalRequirement.NONE


def _action_evidence(action: RemediationAction) -> list[str]:
    return [evidence.summary for evidence in action.evidence if evidence.summary][:4]


def _blocked_or_warning_values(*values: list[str]) -> tuple[list[str], list[str]]:
    blockers: list[str] = []
    warnings: list[str] = []
    for items in values:
        for item in items:
            lowered = item.lower()
            if "blocked" in lowered or "forbidden" in lowered or "not ready" in lowered:
                blockers.append(item)
            else:
                warnings.append(item)
    return list(dict.fromkeys(blockers)), list(dict.fromkeys(warnings))


def _timeline_entry(
    step: int,
    phase: RemediationReplayPhase,
    status: RemediationReplayStepStatus,
    title: str,
    description: str,
    *,
    evidence: list[str] | None = None,
    policy_notes: list[str] | None = None,
) -> RemediationReplayTimelineEntry:
    return RemediationReplayTimelineEntry(
        step=step,
        phase=phase,
        status=status,
        title=title,
        description=description,
        evidence=evidence or [],
        policy_notes=policy_notes or [],
    )


def _partial_replay(
    incident_id: int,
    *,
    remediation_source: str | None,
    plan: RemediationPlan | None,
    timeline: list[RemediationReplayTimelineEntry],
    proposed_actions: list[RemediationReplayProposedAction],
    blockers: list[str],
    warnings: list[str],
) -> RemediationReplayResponse:
    if not timeline:
        timeline.append(
            _timeline_entry(
                1,
                RemediationReplayPhase.FINAL_DECISION,
                RemediationReplayStepStatus.REQUIRES_REVIEW,
                "Replay incomplete",
                "Replay could not compose every remediation subsystem. Review available warnings.",
                policy_notes=warnings,
            )
        )

    return RemediationReplayResponse(
        incident_id=incident_id,
        remediation_source=remediation_source,
        summary=(
            "Replay simulation completed with partial data. "
            "No remediation, rollback or target-system mutation was performed."
        ),
        timeline=timeline,
        proposed_actions=proposed_actions,
        blockers=blockers,
        warnings=warnings,
        final_recommendation=(
            "Review missing replay components before using remediation guidance."
            if warnings or blockers
            else "Review replay output with a human analyst before any future approval."
        ),
        notes=REPLAY_NOTES,
    )


def build_remediation_replay_response(
    *,
    incident_id: int,
    intelligence: dict[str, Any],
    plan: RemediationPlan,
) -> RemediationReplayResponse:
    remediation_source = str(intelligence.get("source") or "unknown")
    governance = intelligence.get("governance") if isinstance(intelligence.get("governance"), dict) else {}
    governance_status = _governance_status(governance)
    governance_warnings = _safe_strings(governance.get("policy_warnings"))
    governance_limitations = _safe_strings(governance.get("limitations"))
    timeline: list[RemediationReplayTimelineEntry] = [
        _timeline_entry(
            1,
            RemediationReplayPhase.PLAN_GENERATION,
            RemediationReplayStepStatus.PASSED,
            "Remediation plan prepared",
            "Replay loaded the current remediation plan as read-only simulation input.",
            evidence=[evidence.evidence_id for evidence in plan.evidence_used[:6]],
            policy_notes=["Plan replay does not mutate incident, case or target-system state."],
        ),
        _timeline_entry(
            2,
            RemediationReplayPhase.GOVERNANCE_CHECK,
            _timeline_status_from_governance(governance_status),
            "AI governance assessed",
            "Governance labels, evidence coverage, limitations and policy warnings were evaluated.",
            policy_notes=[*governance_warnings[:4], *governance_limitations[:2]],
        ),
    ]
    warnings = [*governance_warnings, *governance_limitations]
    blockers: list[str] = []
    proposed_actions: list[RemediationReplayProposedAction] = []

    approval_notes = [
        f"{action.title}: {action.approval_requirement.value}"
        for action in plan.actions
        if _approval_required(action)
    ]
    timeline.append(
        _timeline_entry(
            3,
            RemediationReplayPhase.APPROVAL_GATE,
            RemediationReplayStepStatus.REQUIRES_REVIEW if approval_notes else RemediationReplayStepStatus.PASSED,
            "Approval gates evaluated",
            "Replay identified human approval requirements for proposed remediation actions.",
            policy_notes=approval_notes[:6] or ["No approval gate was required by current action metadata."],
        )
    )

    try:
        plan_dry_run = generate_plan_dry_run(plan)
        timeline.append(
            _timeline_entry(
                4,
                RemediationReplayPhase.DRY_RUN,
                _timeline_status_from_dry_run(plan_dry_run.status),
                "Dry-run simulated",
                "Read-only dry-run findings were generated without changing system state.",
                policy_notes=[finding.description for finding in plan_dry_run.findings[:5]],
            )
        )
        warnings.extend(finding.description for finding in plan_dry_run.findings)
    except Exception as exc:
        plan_dry_run = None
        warning = f"Dry-run subsystem unavailable during replay: {type(exc).__name__}"
        warnings.append(warning)
        timeline.append(
            _timeline_entry(
                4,
                RemediationReplayPhase.DRY_RUN,
                RemediationReplayStepStatus.NOT_APPLICABLE,
                "Dry-run unavailable",
                "Replay continued with partial data because dry-run output was unavailable.",
                policy_notes=[warning],
            )
        )

    try:
        rollback = build_rollback_engine_response(plan, remediation_source=remediation_source)
        rollback_by_action = {action.action_id: action for action in rollback.actions}
        timeline.append(
            _timeline_entry(
                5,
                RemediationReplayPhase.ROLLBACK_READINESS,
                _timeline_status_from_rollback(rollback.overall_status),
                "Rollback readiness simulated",
                "Rollback feasibility and blockers were assessed from the proposed plan.",
                policy_notes=[*rollback.blockers[:4], *rollback.warnings[:3]],
            )
        )
        rb_blockers, rb_warnings = _blocked_or_warning_values(rollback.blockers, rollback.warnings)
        blockers.extend(rb_blockers)
        warnings.extend(rb_warnings)
    except Exception as exc:
        rollback = None
        rollback_by_action = {}
        warning = f"Rollback readiness subsystem unavailable during replay: {type(exc).__name__}"
        warnings.append(warning)
        timeline.append(
            _timeline_entry(
                5,
                RemediationReplayPhase.ROLLBACK_READINESS,
                RemediationReplayStepStatus.NOT_APPLICABLE,
                "Rollback readiness unavailable",
                "Replay continued with partial data because rollback readiness output was unavailable.",
                policy_notes=[warning],
            )
        )

    for action in plan.actions:
        try:
            action_dry_run = generate_action_dry_run(
                action,
                plan_id=plan.plan_id,
                incident_id=plan.incident_id,
            )
            dry_status = _proposed_dry_run_status(action_dry_run.status)
        except Exception as exc:
            dry_status = RemediationReplayDryRunStatus.UNKNOWN
            warnings.append(f"Action dry-run unavailable for {action.title}: {type(exc).__name__}")

        proposed_actions.append(
            RemediationReplayProposedAction(
                action_type=action.action_type.value,
                title=action.title,
                approval_required=_approval_required(action),
                dry_run_status=dry_status,
                rollback_status=rollback_by_action.get(action.action_id).rollback_status.value
                if action.action_id in rollback_by_action
                else "UNKNOWN",
                governance_status=governance_status,
            )
        )
        if not action.evidence:
            warnings.append(f"Proposed action '{action.title}' has no linked evidence.")
        if action.approval_requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT:
            blockers.append(f"Proposed action '{action.title}' is forbidden by default.")

    try:
        audit_trail = build_remediation_audit_trail(plan, remediation_source=remediation_source)
        timeline.append(
            _timeline_entry(
                6,
                RemediationReplayPhase.AUDIT_TRAIL,
                RemediationReplayStepStatus.PASSED,
                "Audit trail preview composed",
                "Replay projected read-only governance audit records for the remediation workflow.",
                policy_notes=[
                    f"{len(audit_trail.records)} audit records projected.",
                    "Audit trail preview does not record production execution.",
                ],
            )
        )
    except Exception as exc:
        warning = f"Audit trail subsystem unavailable during replay: {type(exc).__name__}"
        warnings.append(warning)
        timeline.append(
            _timeline_entry(
                6,
                RemediationReplayPhase.AUDIT_TRAIL,
                RemediationReplayStepStatus.NOT_APPLICABLE,
                "Audit trail unavailable",
                "Replay continued with partial data because audit trail output was unavailable.",
                policy_notes=[warning],
            )
        )

    blockers = list(dict.fromkeys(blockers))
    warnings = list(dict.fromkeys(warnings))
    final_status = (
        RemediationReplayStepStatus.BLOCKED
        if blockers
        else RemediationReplayStepStatus.REQUIRES_REVIEW
    )
    timeline.append(
        _timeline_entry(
            7,
            RemediationReplayPhase.FINAL_DECISION,
            final_status,
            "Human decision required",
            "Replay completed as advisory simulation output. Human approval remains mandatory and execution is disabled.",
            policy_notes=blockers[:4] or warnings[:4] or ["No execution is available from replay output."],
        )
    )

    return RemediationReplayResponse(
        incident_id=incident_id,
        remediation_source=remediation_source,
        summary=(
            "Replay simulated the remediation workflow from plan generation through governance, "
            "approval gates, dry-run, rollback readiness and audit preview. No state was changed."
        ),
        timeline=timeline,
        proposed_actions=proposed_actions,
        blockers=blockers,
        warnings=warnings,
        final_recommendation=(
            "Resolve blockers before future approval review."
            if blockers
            else "Review warnings and obtain the required human approval before any future operational workflow."
        ),
        notes=REPLAY_NOTES,
    )


def generate_incident_remediation_replay(incident_id: int) -> RemediationReplayResponse:
    intelligence = generate_remediation_intelligence(incident_id)
    plan = build_remediation_plan_from_intelligence(intelligence)

    try:
        return build_remediation_replay_response(
            incident_id=incident_id,
            intelligence=intelligence,
            plan=plan,
        )
    except Exception as exc:
        return _partial_replay(
            incident_id,
            remediation_source=str(intelligence.get("source") or "unknown"),
            plan=plan,
            timeline=[],
            proposed_actions=[],
            blockers=[],
            warnings=[f"Replay engine completed with partial output: {type(exc).__name__}"],
        )
