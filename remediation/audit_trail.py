from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import Field

from .dry_run import generate_plan_dry_run
from .intelligence import generate_remediation_intelligence
from .models import RemediationBaseModel, RemediationPlan
from .readiness import (
    RemediationExecutionAuditStatus,
    assess_action_execution_readiness,
)
from .rollback_readiness import assess_action_rollback_readiness, assess_plan_rollback_readiness
from .simulation import build_remediation_plan_from_intelligence


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RemediationAuditTrailEventType(str, Enum):
    PLAN_GENERATED = "PLAN_GENERATED"
    AI_REMEDIATION_INTELLIGENCE_USED = "AI_REMEDIATION_INTELLIGENCE_USED"
    DETERMINISTIC_FALLBACK_USED = "DETERMINISTIC_FALLBACK_USED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    DRY_RUN_REQUIRED = "DRY_RUN_REQUIRED"
    DRY_RUN_COMPLETED = "DRY_RUN_COMPLETED"
    ROLLBACK_READINESS_REQUIRED = "ROLLBACK_READINESS_REQUIRED"
    ROLLBACK_READINESS_CHECKED = "ROLLBACK_READINESS_CHECKED"
    EXECUTION_BLOCKED_BY_POLICY = "EXECUTION_BLOCKED_BY_POLICY"
    EXECUTION_NOT_SUPPORTED = "EXECUTION_NOT_SUPPORTED"
    HUMAN_VALIDATION_REQUIRED = "HUMAN_VALIDATION_REQUIRED"


class RemediationAuditPolicyStatus(str, Enum):
    PASSED = "PASSED"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RemediationAuditTrailRecord(RemediationBaseModel):
    event_id: str
    event_type: RemediationAuditTrailEventType
    timestamp: datetime = Field(default_factory=utc_now)
    actor: str = "system"
    actor_role: str = "SYSTEM"
    summary: str
    decision: str | None = None
    policy_status: RemediationAuditPolicyStatus = RemediationAuditPolicyStatus.NOT_APPLICABLE
    evidence_refs: list[str] = Field(default_factory=list)
    rationale: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RemediationAuditTrailSummary(RemediationBaseModel):
    plan_generated: bool = True
    approval_required: bool = True
    dry_run_completed: bool = True
    rollback_readiness_checked: bool = True
    execution_attempted: bool = False
    execution_blocked: bool = True


class RemediationAuditTrailResponse(RemediationBaseModel):
    incident_id: int
    generated_at: datetime = Field(default_factory=utc_now)
    source: str = "remediation_audit_trail"
    remediation_source: str | None = None
    execution_supported: bool = False
    records: list[RemediationAuditTrailRecord] = Field(default_factory=list)
    summary: RemediationAuditTrailSummary = Field(default_factory=RemediationAuditTrailSummary)
    notes: list[str] = Field(default_factory=list)


AUDIT_TRAIL_NOTES = [
    "Audit trail is read-only.",
    "No remediation execution is supported.",
    "Human approval remains mandatory before any future operational action.",
]


def _actor_for_source(source: str | None) -> tuple[str, str]:
    if source == "local_ai":
        return ("local_ai", "SYSTEM")
    return ("system", "SYSTEM")


def _source_event_type(source: str | None) -> RemediationAuditTrailEventType:
    if source == "local_ai":
        return RemediationAuditTrailEventType.AI_REMEDIATION_INTELLIGENCE_USED
    return RemediationAuditTrailEventType.DETERMINISTIC_FALLBACK_USED


def _evidence_refs(plan: RemediationPlan) -> list[str]:
    refs = [evidence.evidence_id for evidence in plan.evidence_used]
    if refs:
        return refs[:12]
    action_refs = [
        evidence.evidence_id
        for action in plan.actions
        for evidence in action.evidence
    ]
    return action_refs[:12]


def _record(
    event_id: str,
    event_type: RemediationAuditTrailEventType,
    *,
    actor: str = "system",
    actor_role: str = "SYSTEM",
    summary: str,
    decision: str | None = None,
    policy_status: RemediationAuditPolicyStatus = RemediationAuditPolicyStatus.NOT_APPLICABLE,
    evidence_refs: list[str] | None = None,
    rationale: str,
    metadata: dict[str, Any] | None = None,
    timestamp: datetime | None = None,
) -> RemediationAuditTrailRecord:
    return RemediationAuditTrailRecord(
        event_id=event_id,
        event_type=event_type,
        timestamp=timestamp or utc_now(),
        actor=actor,
        actor_role=actor_role,
        summary=summary,
        decision=decision,
        policy_status=policy_status,
        evidence_refs=evidence_refs or [],
        rationale=rationale,
        metadata=metadata or {},
    )


def _readiness_events(plan: RemediationPlan) -> list[RemediationAuditTrailRecord]:
    records: list[RemediationAuditTrailRecord] = []
    for action in plan.actions:
        dry_run = generate_plan_dry_run(plan)
        rollback = assess_action_rollback_readiness(
            action,
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
        )
        readiness = assess_action_execution_readiness(
            action,
            plan_id=plan.plan_id,
            incident_id=plan.incident_id,
            dry_run_result=dry_run,
            rollback_readiness=rollback,
        )
        policy_status = RemediationAuditPolicyStatus.WARNING
        if readiness.execution_status in {
            RemediationExecutionAuditStatus.BLOCKED_BY_POLICY,
            RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_APPROVAL,
            RemediationExecutionAuditStatus.BLOCKED_BY_MISSING_ROLLBACK,
            RemediationExecutionAuditStatus.BLOCKED_BY_VALIDATION,
        }:
            policy_status = RemediationAuditPolicyStatus.BLOCKED

        blockers = [blocker.reason for blocker in readiness.blockers]
        records.append(
            _record(
                f"{action.action_id}-execution-boundary",
                RemediationAuditTrailEventType.EXECUTION_NOT_SUPPORTED,
                summary=f"Execution remains unsupported for {action.title}.",
                decision=readiness.execution_status.value,
                policy_status=policy_status,
                evidence_refs=[evidence.evidence_id for evidence in action.evidence],
                rationale=(
                    "Step 16 prepares an audit trail only. No executor is available from this view."
                ),
                metadata={
                    "plan_id": plan.plan_id,
                    "action_id": action.action_id,
                    "action_type": action.action_type.value,
                    "execution_supported": False,
                    "execution_attempted": False,
                    "blockers": blockers,
                },
            )
        )

        if readiness.execution_status == RemediationExecutionAuditStatus.BLOCKED_BY_POLICY:
            records.append(
                _record(
                    f"{action.action_id}-policy-block",
                    RemediationAuditTrailEventType.EXECUTION_BLOCKED_BY_POLICY,
                    summary=f"Policy blocked future execution review for {action.title}.",
                    decision=readiness.execution_status.value,
                    policy_status=RemediationAuditPolicyStatus.BLOCKED,
                    evidence_refs=[evidence.evidence_id for evidence in action.evidence],
                    rationale="Policy blockers must be resolved before future execution readiness can be considered.",
                    metadata={
                        "plan_id": plan.plan_id,
                        "action_id": action.action_id,
                        "blocker_count": len(readiness.blockers),
                    },
                )
            )

    return records


def build_remediation_audit_trail(
    plan: RemediationPlan,
    *,
    remediation_source: str | None = None,
) -> RemediationAuditTrailResponse:
    actor, actor_role = _actor_for_source(remediation_source)
    evidence_refs = _evidence_refs(plan)
    dry_run = generate_plan_dry_run(plan)
    rollback = assess_plan_rollback_readiness(plan)
    records = [
        _record(
            f"{plan.plan_id}-plan-generated",
            RemediationAuditTrailEventType.PLAN_GENERATED,
            actor=actor,
            actor_role=actor_role,
            summary="Remediation plan was generated for analyst review.",
            decision=plan.status.value,
            policy_status=RemediationAuditPolicyStatus.PASSED,
            evidence_refs=evidence_refs,
            rationale=plan.rationale,
            metadata={
                "plan_id": plan.plan_id,
                "action_count": len(plan.actions),
                "execution_supported": False,
            },
            timestamp=plan.generated_at,
        ),
        _record(
            f"{plan.plan_id}-source",
            _source_event_type(remediation_source),
            actor=actor,
            actor_role=actor_role,
            summary="Remediation intelligence source was recorded.",
            decision=remediation_source or "unknown",
            policy_status=RemediationAuditPolicyStatus.NOT_APPLICABLE,
            evidence_refs=evidence_refs,
            rationale="The audit trail records whether local AI or deterministic fallback supplied the plan.",
            metadata={"remediation_source": remediation_source},
            timestamp=plan.generated_at,
        ),
        _record(
            f"{plan.plan_id}-approval-required",
            RemediationAuditTrailEventType.APPROVAL_REQUIRED,
            summary="Human approval is required before any future operational action.",
            decision="REQUIRED" if plan.approval_required else "NOT_REQUIRED",
            policy_status=(
                RemediationAuditPolicyStatus.WARNING
                if plan.approval_required
                else RemediationAuditPolicyStatus.NOT_APPLICABLE
            ),
            evidence_refs=evidence_refs,
            rationale="Remediation planning is human-in-the-loop and cannot bypass approval.",
            metadata={"approval_required": plan.approval_required},
        ),
        _record(
            f"{plan.plan_id}-dry-run-required",
            RemediationAuditTrailEventType.DRY_RUN_REQUIRED,
            summary="Dry-run review is required before any future execution decision.",
            decision="REQUIRED",
            policy_status=RemediationAuditPolicyStatus.WARNING,
            evidence_refs=evidence_refs,
            rationale="Simulation must be reviewed before operational approval.",
            metadata={"plan_id": plan.plan_id},
        ),
        _record(
            f"{plan.plan_id}-dry-run-completed",
            RemediationAuditTrailEventType.DRY_RUN_COMPLETED,
            summary="Dry-run simulation was computed as read-only metadata.",
            decision=dry_run.status.value,
            policy_status=RemediationAuditPolicyStatus.PASSED,
            evidence_refs=evidence_refs,
            rationale="Dry-run completed without mutating system state.",
            metadata={
                "dry_run_id": dry_run.dry_run_id,
                "state_mutated": False,
                "execution_supported": False,
                "finding_count": len(dry_run.findings),
            },
        ),
        _record(
            f"{plan.plan_id}-rollback-required",
            RemediationAuditTrailEventType.ROLLBACK_READINESS_REQUIRED,
            summary="Rollback readiness must be reviewed before future execution readiness.",
            decision="REQUIRED",
            policy_status=RemediationAuditPolicyStatus.WARNING,
            evidence_refs=evidence_refs,
            rationale="Rollback planning is part of the remediation governance boundary.",
            metadata={"plan_id": plan.plan_id},
        ),
        _record(
            f"{plan.plan_id}-rollback-checked",
            RemediationAuditTrailEventType.ROLLBACK_READINESS_CHECKED,
            summary="Rollback readiness was assessed from the remediation plan.",
            decision=rollback.status.value,
            policy_status=(
                RemediationAuditPolicyStatus.BLOCKED
                if rollback.blockers
                else RemediationAuditPolicyStatus.WARNING
            ),
            evidence_refs=evidence_refs,
            rationale=rollback.recovery_notes
            or "Rollback readiness was normalized into governance metadata.",
            metadata={
                "rollback_readiness_id": rollback.rollback_readiness_id,
                "rollback_available": rollback.rollback_available,
                "blocker_count": len(rollback.blockers),
                "limitation_count": len(rollback.limitations),
            },
        ),
        _record(
            f"{plan.plan_id}-human-validation",
            RemediationAuditTrailEventType.HUMAN_VALIDATION_REQUIRED,
            summary="Human validation remains mandatory.",
            decision="REQUIRED",
            policy_status=RemediationAuditPolicyStatus.WARNING,
            evidence_refs=evidence_refs,
            rationale="AI can propose and summarize, but the analyst remains responsible for approval.",
            metadata={"human_approval_required": True},
        ),
    ]
    records.extend(_readiness_events(plan))
    records.append(
        _record(
            f"{plan.plan_id}-execution-not-supported",
            RemediationAuditTrailEventType.EXECUTION_NOT_SUPPORTED,
            summary="Execution was not attempted and is not supported by this endpoint.",
            decision="NOT_SUPPORTED",
            policy_status=RemediationAuditPolicyStatus.BLOCKED,
            evidence_refs=evidence_refs,
            rationale="Step 16 exposes an audit trail only. It does not execute remediation or rollback.",
            metadata={
                "execution_supported": False,
                "execution_attempted": False,
                "rollback_execution_supported": False,
            },
        )
    )

    return RemediationAuditTrailResponse(
        incident_id=plan.incident_id,
        remediation_source=remediation_source,
        execution_supported=False,
        records=records,
        summary=RemediationAuditTrailSummary(
            plan_generated=True,
            approval_required=plan.approval_required,
            dry_run_completed=True,
            rollback_readiness_checked=True,
            execution_attempted=False,
            execution_blocked=True,
        ),
        notes=AUDIT_TRAIL_NOTES,
    )


def generate_incident_remediation_audit_trail(incident_id: int) -> RemediationAuditTrailResponse:
    intelligence = generate_remediation_intelligence(incident_id)
    plan = build_remediation_plan_from_intelligence(intelligence)
    return build_remediation_audit_trail(
        plan,
        remediation_source=str(intelligence.get("source") or "unknown"),
    )
