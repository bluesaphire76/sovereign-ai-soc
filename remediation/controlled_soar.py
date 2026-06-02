from __future__ import annotations

import json
from enum import Enum
from typing import Any

from pydantic import Field, model_validator
from sqlalchemy.exc import SQLAlchemyError

from database import SessionLocal
from models import (
    CaseAction,
    CaseAudit,
    CaseIncident,
    Incident,
    IncidentAudit,
    IncidentCase,
    IncidentNote,
    SecurityAuditEvent,
    utc_now,
)

from .approvals import (
    RemediationApprovalActor,
    RemediationApprovalDecision,
    RemediationApprovalRequest,
    RemediationApprovalStatus,
    create_approval_record,
)
from .dry_run import RemediationDryRunStatus, generate_action_dry_run
from .intelligence import generate_remediation_intelligence
from .models import (
    RemediationAction,
    RemediationActionType,
    RemediationBaseModel,
)
from .rollback_readiness import (
    RemediationRollbackReadinessStatus,
    assess_action_rollback_readiness,
)
from .simulation import build_remediation_plan_from_intelligence


class ControlledSoarActionType(str, Enum):
    CREATE_CASE_ACTION = "CREATE_CASE_ACTION"
    CREATE_REMEDIATION_TASK = "CREATE_REMEDIATION_TASK"
    MARK_CONTAINMENT_REQUIRED = "MARK_CONTAINMENT_REQUIRED"
    NOTIFY_OWNER_MANUAL_TASK = "NOTIFY_OWNER_MANUAL_TASK"
    GENERATE_OPERATOR_CHECKLIST = "GENERATE_OPERATOR_CHECKLIST"
    CREATE_AUDIT_NOTE = "CREATE_AUDIT_NOTE"


class ControlledSoarExecutionStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    FAILED = "FAILED"


class ControlledSoarPolicyCheckStatus(str, Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ControlledSoarActor(RemediationBaseModel):
    username: str = "unknown"
    role: str = "VIEWER"
    actor_id: str | None = None

    @model_validator(mode="after")
    def normalize_role(self) -> "ControlledSoarActor":
        object.__setattr__(self, "role", (self.role or "VIEWER").strip().upper())
        object.__setattr__(self, "username", (self.username or "unknown").strip() or "unknown")
        return self


class ControlledSoarExecutionRequest(RemediationBaseModel):
    approval_confirmed: bool = False
    approval_rationale: str | None = Field(default=None, max_length=500)


class ControlledSoarPolicyCheck(RemediationBaseModel):
    check: str
    status: ControlledSoarPolicyCheckStatus
    detail: str


class ControlledSoarCreatedRecord(RemediationBaseModel):
    record_type: str
    record_id: str


class ControlledSoarAuditReference(RemediationBaseModel):
    before_event_id: str | None = None
    after_event_id: str | None = None


class ControlledSoarSupport(RemediationBaseModel):
    action_type: str
    controlled_action_type: ControlledSoarActionType | None = None
    execution_supported: bool = False
    execution_label: str | None = None
    unsupported_reason: str | None = None


class ControlledSoarExecutionResult(RemediationBaseModel):
    incident_id: int
    action_id: str
    action_type: str
    source: str = "controlled_soar_executor"
    execution_supported: bool
    external_system_mutated: bool = False
    target_system_mutated: bool = False
    product_workflow_mutated: bool = False
    status: ControlledSoarExecutionStatus
    summary: str
    policy_checks: list[ControlledSoarPolicyCheck] = Field(default_factory=list)
    created_records: list[ControlledSoarCreatedRecord] = Field(default_factory=list)
    audit: ControlledSoarAuditReference = Field(default_factory=ControlledSoarAuditReference)
    notes: list[str] = Field(default_factory=list)


SAFE_INTERNAL_ACTIONS: dict[RemediationActionType, ControlledSoarActionType] = {
    RemediationActionType.CREATE_TICKET: ControlledSoarActionType.CREATE_REMEDIATION_TASK,
    RemediationActionType.NOTIFY_OWNER: ControlledSoarActionType.NOTIFY_OWNER_MANUAL_TASK,
    RemediationActionType.ESCALATE_CASE: ControlledSoarActionType.CREATE_CASE_ACTION,
    RemediationActionType.COLLECT_FORENSIC_EVIDENCE: ControlledSoarActionType.GENERATE_OPERATOR_CHECKLIST,
}

UNSUPPORTED_ACTION_REASONS: dict[RemediationActionType, str] = {
    RemediationActionType.BLOCK_IP: "Blocking IPs requires an external connector or playbook integration.",
    RemediationActionType.UNBLOCK_IP: "Unblocking IPs requires an external connector or playbook integration.",
    RemediationActionType.DISABLE_USER: "User account changes are not supported by the current executor.",
    RemediationActionType.ENABLE_USER: "User account changes are not supported by the current executor.",
    RemediationActionType.STOP_SERVICE: "Service control requires a governed host executor that is not available in this release.",
    RemediationActionType.RESTART_SERVICE: "Service control requires a governed host executor that is not available in this release.",
    RemediationActionType.QUARANTINE_FILE: "File quarantine requires a governed endpoint connector that is not available in this release.",
    RemediationActionType.RESTORE_FILE: "File restore requires a governed endpoint connector that is not available in this release.",
    RemediationActionType.KILL_PROCESS: "Process control requires a governed endpoint connector that is not available in this release.",
    RemediationActionType.ISOLATE_HOST: "Host isolation requires a governed endpoint connector that is not available in this release.",
    RemediationActionType.RELEASE_HOST: "Host release requires a governed endpoint connector that is not available in this release.",
    RemediationActionType.ADD_FIREWALL_RULE: "Firewall rule changes require an external connector or playbook integration.",
    RemediationActionType.REMOVE_FIREWALL_RULE: "Firewall rule changes require an external connector or playbook integration.",
}

EXECUTION_LABELS = {
    ControlledSoarActionType.CREATE_CASE_ACTION: "Create case action",
    ControlledSoarActionType.CREATE_REMEDIATION_TASK: "Create remediation task",
    ControlledSoarActionType.MARK_CONTAINMENT_REQUIRED: "Record containment review",
    ControlledSoarActionType.NOTIFY_OWNER_MANUAL_TASK: "Create owner notification task",
    ControlledSoarActionType.GENERATE_OPERATOR_CHECKLIST: "Create operator checklist",
    ControlledSoarActionType.CREATE_AUDIT_NOTE: "Create audit note",
}

EXECUTION_NOTES = [
    "Only product workflow records were changed.",
    "No endpoint, identity, firewall or host action was executed.",
    "LLM output is never converted into a shell command or free-form execution payload.",
]


def actor_from_current_user(current_user: dict[str, Any] | None) -> ControlledSoarActor:
    current_user = current_user or {}
    return ControlledSoarActor(
        username=str(current_user.get("username") or "unknown"),
        role=str(current_user.get("role") or "VIEWER"),
        actor_id=str(current_user.get("id")) if current_user.get("id") is not None else None,
    )


def controlled_soar_support_for_action_type(
    action_type: RemediationActionType | str | None,
) -> ControlledSoarSupport:
    try:
        normalized = (
            action_type
            if isinstance(action_type, RemediationActionType)
            else RemediationActionType(str(action_type))
        )
    except Exception:
        return ControlledSoarSupport(
            action_type=str(action_type or "UNKNOWN"),
            execution_supported=False,
            unsupported_reason="Action type is not recognized by the controlled SOAR executor.",
        )

    controlled_type = SAFE_INTERNAL_ACTIONS.get(normalized)
    if controlled_type is not None:
        return ControlledSoarSupport(
            action_type=normalized.value,
            controlled_action_type=controlled_type,
            execution_supported=True,
            execution_label=EXECUTION_LABELS[controlled_type],
        )

    return ControlledSoarSupport(
        action_type=normalized.value,
        execution_supported=False,
        unsupported_reason=UNSUPPORTED_ACTION_REASONS.get(
            normalized,
            "This action is not supported by the current controlled SOAR executor.",
        ),
    )


def controlled_soar_support_for_action(action: RemediationAction) -> ControlledSoarSupport:
    return controlled_soar_support_for_action_type(action.action_type)


def _policy_check(
    check: str,
    status: ControlledSoarPolicyCheckStatus,
    detail: str,
) -> ControlledSoarPolicyCheck:
    return ControlledSoarPolicyCheck(check=check, status=status, detail=detail)


def _details_json(details: dict[str, Any]) -> str:
    return json.dumps(details, default=str, sort_keys=True)


def _add_incident_audit(
    db,
    *,
    incident_id: int,
    event_type: str,
    created_by: str,
    comment: str,
    old_value: str | None = None,
    new_value: str | None = None,
) -> IncidentAudit:
    row = IncidentAudit(
        incident_id=incident_id,
        event_type=event_type,
        old_value=old_value,
        new_value=new_value,
        comment=comment,
        created_by=created_by,
    )
    db.add(row)
    db.flush()
    return row


def _add_security_audit(
    db,
    *,
    event_type: str,
    outcome: str,
    actor: ControlledSoarActor,
    incident_id: int,
    action_id: str,
    details: dict[str, Any],
) -> SecurityAuditEvent:
    row = SecurityAuditEvent(
        event_type=event_type,
        outcome=outcome,
        actor_user_id=int(actor.actor_id) if actor.actor_id and actor.actor_id.isdigit() else None,
        actor_username=actor.username,
        actor_role=actor.role,
        target_type="INCIDENT_REMEDIATION_ACTION",
        target_id=f"{incident_id}:{action_id}",
        details_json=_details_json(details),
    )
    db.add(row)
    db.flush()
    return row


def _find_case_for_incident(db, incident_id: int) -> IncidentCase | None:
    return (
        db.query(IncidentCase)
        .join(CaseIncident, CaseIncident.case_id == IncidentCase.id)
        .filter(CaseIncident.incident_id == incident_id)
        .order_by(IncidentCase.updated_at.desc().nullslast(), IncidentCase.id.desc())
        .first()
    )


def _priority_for_action(action: RemediationAction) -> str:
    risk = action.risk.level.value
    if risk in {"CRITICAL", "HIGH"}:
        return "HIGH"
    if risk in {"LOW", "INFORMATIONAL"}:
        return "LOW"
    return "MEDIUM"


def _category_for_template(template: ControlledSoarActionType) -> str:
    if template == ControlledSoarActionType.NOTIFY_OWNER_MANUAL_TASK:
        return "COMMUNICATION"
    if template == ControlledSoarActionType.GENERATE_OPERATOR_CHECKLIST:
        return "INVESTIGATION"
    if template == ControlledSoarActionType.MARK_CONTAINMENT_REQUIRED:
        return "CONTAINMENT"
    return "REMEDIATION"


def _workflow_description(
    *,
    template: ControlledSoarActionType,
    action: RemediationAction,
    incident_id: int,
    actor: ControlledSoarActor,
) -> str:
    return (
        f"Controlled SOAR workflow action recorded for incident {incident_id}. "
        f"Template={template.value}; remediation_action_type={action.action_type.value}; "
        f"approved_by={actor.username}; risk={action.risk.level.value}. "
        "This created product workflow metadata only. No endpoint, identity, firewall, "
        "service, process, file or host action was executed."
    )


def _apply_internal_template(
    db,
    *,
    incident: Incident,
    action: RemediationAction,
    template: ControlledSoarActionType,
    actor: ControlledSoarActor,
) -> tuple[list[ControlledSoarCreatedRecord], bool]:
    records: list[ControlledSoarCreatedRecord] = []
    description = _workflow_description(
        template=template,
        action=action,
        incident_id=int(incident.id),
        actor=actor,
    )
    case = _find_case_for_incident(db, int(incident.id))

    if case is not None and template != ControlledSoarActionType.CREATE_AUDIT_NOTE:
        case_action = CaseAction(
            case_id=case.id,
            title=action.title[:240],
            description=description,
            category=_category_for_template(template),
            priority=_priority_for_action(action),
            status="OPEN",
            created_by=actor.username,
            updated_at=utc_now(),
        )
        db.add(case_action)
        db.flush()
        records.append(
            ControlledSoarCreatedRecord(
                record_type="CASE_ACTION",
                record_id=str(case_action.id),
            )
        )

        case.updated_at = utc_now()
        case_audit = CaseAudit(
            case_id=case.id,
            event_type="CONTROLLED_SOAR_CASE_ACTION_CREATED",
            old_value=None,
            new_value=f"action:{case_action.id}:{case_action.title}",
            comment=description,
            created_by=actor.username,
        )
        db.add(case_audit)
        db.flush()
        records.append(
            ControlledSoarCreatedRecord(
                record_type="CASE_AUDIT",
                record_id=str(case_audit.id),
            )
        )
        return records, True

    note = IncidentNote(
        incident_id=incident.id,
        note=description,
        created_by=actor.username,
    )
    db.add(note)
    db.flush()
    records.append(
        ControlledSoarCreatedRecord(
            record_type="INCIDENT_NOTE",
            record_id=str(note.id),
        )
    )
    return records, True


def execute_approved_controlled_soar_action(
    *,
    incident_id: int,
    action_id: str,
    actor: ControlledSoarActor,
    approval_confirmed: bool,
    approval_rationale: str | None = None,
) -> ControlledSoarExecutionResult:
    policy_checks: list[ControlledSoarPolicyCheck] = []
    created_records: list[ControlledSoarCreatedRecord] = []
    before_audit: IncidentAudit | None = None
    after_audit: IncidentAudit | None = None
    db = SessionLocal()

    rationale = (
        (approval_rationale or "").strip()
        or "Operator confirmed approved product-only workflow action from Incident Command Room."
    )

    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        before_audit = _add_incident_audit(
            db,
            incident_id=incident_id,
            event_type="CONTROLLED_SOAR_ACTION_REQUESTED",
            old_value=None,
            new_value=action_id,
            comment=(
                f"Controlled SOAR action requested by {actor.username}. "
                "Policy gates will be evaluated before any internal workflow record is created."
            ),
            created_by=actor.username,
        )
        created_records.append(
            ControlledSoarCreatedRecord(
                record_type="AUDIT_EVENT",
                record_id=str(before_audit.id),
            )
        )

        _add_security_audit(
            db,
            event_type="CONTROLLED_SOAR_ACTION_REQUESTED",
            outcome="REQUESTED",
            actor=actor,
            incident_id=incident_id,
            action_id=action_id,
            details={
                "approval_confirmed": approval_confirmed,
                "target_system_mutated": False,
                "external_system_mutated": False,
            },
        )

        if actor.role not in {"ADMIN", "ANALYST"}:
            policy_checks.append(
                _policy_check(
                    "ROLE_ALLOWED",
                    ControlledSoarPolicyCheckStatus.FAILED,
                    "Only ADMIN or ANALYST can execute approved internal workflow actions.",
                )
            )
            status = ControlledSoarExecutionStatus.REJECTED
            summary = "Viewer or unsupported role cannot execute remediation workflow actions."
            return _finalize_blocked(
                db,
                incident_id=incident_id,
                action_id=action_id,
                action_type="UNKNOWN",
                actor=actor,
                status=status,
                summary=summary,
                policy_checks=policy_checks,
                created_records=created_records,
                before_event_id=str(before_audit.id),
                execution_supported=False,
            )
        policy_checks.append(
            _policy_check(
                "ROLE_ALLOWED",
                ControlledSoarPolicyCheckStatus.PASSED,
                f"Actor role {actor.role} is allowed by RBAC.",
            )
        )

        intelligence = generate_remediation_intelligence(incident_id)
        plan = build_remediation_plan_from_intelligence(intelligence)
        action = next((item for item in plan.actions if item.action_id == action_id), None)
        if action is None:
            policy_checks.append(
                _policy_check(
                    "ACTION_EXISTS",
                    ControlledSoarPolicyCheckStatus.FAILED,
                    "Action id is not present in the current remediation plan.",
                )
            )
            return _finalize_result(
                db,
                incident_id=incident_id,
                action_id=action_id,
                action_type="UNKNOWN",
                actor=actor,
                status=ControlledSoarExecutionStatus.FAILED,
                summary="Requested remediation action was not found in the current remediation plan.",
                policy_checks=policy_checks,
                created_records=created_records,
                before_event_id=str(before_audit.id),
                execution_supported=False,
                product_workflow_mutated=False,
            )
        policy_checks.append(
            _policy_check(
                "ACTION_EXISTS",
                ControlledSoarPolicyCheckStatus.PASSED,
                "Action exists in the current remediation plan.",
            )
        )

        support = controlled_soar_support_for_action(action)
        if not support.execution_supported or support.controlled_action_type is None:
            policy_checks.append(
                _policy_check(
                    "ACTION_ALLOWLISTED",
                    ControlledSoarPolicyCheckStatus.FAILED,
                    support.unsupported_reason
                    or "Action is not allowlisted for controlled SOAR workflow execution.",
                )
            )
            return _finalize_result(
                db,
                incident_id=incident_id,
                action_id=action.action_id,
                action_type=action.action_type.value,
                actor=actor,
                status=ControlledSoarExecutionStatus.NOT_SUPPORTED,
                summary=(
                    support.unsupported_reason
                    or "This action requires an external connector/playbook and is not supported by the current executor."
                ),
                policy_checks=policy_checks,
                created_records=created_records,
                before_event_id=str(before_audit.id),
                execution_supported=False,
                product_workflow_mutated=False,
            )
        policy_checks.append(
            _policy_check(
                "ACTION_ALLOWLISTED",
                ControlledSoarPolicyCheckStatus.PASSED,
                f"Action maps to safe internal template {support.controlled_action_type.value}.",
            )
        )

        if not approval_confirmed:
            policy_checks.append(
                _policy_check(
                    "HUMAN_APPROVAL_CONFIRMED",
                    ControlledSoarPolicyCheckStatus.FAILED,
                    "Explicit human approval confirmation is required before creating internal workflow records.",
                )
            )
            return _finalize_result(
                db,
                incident_id=incident_id,
                action_id=action.action_id,
                action_type=action.action_type.value,
                actor=actor,
                status=ControlledSoarExecutionStatus.BLOCKED,
                summary="Controlled SOAR action is blocked until human approval is confirmed.",
                policy_checks=policy_checks,
                created_records=created_records,
                before_event_id=str(before_audit.id),
                execution_supported=True,
                product_workflow_mutated=False,
            )
        policy_checks.append(
            _policy_check(
                "HUMAN_APPROVAL_CONFIRMED",
                ControlledSoarPolicyCheckStatus.PASSED,
                "Explicit human approval confirmation was supplied for this product-only action.",
            )
        )

        approval_record = create_approval_record(
            RemediationApprovalRequest(
                request_id=f"controlled-soar-{incident_id}-{action.action_id}",
                plan_id=plan.plan_id,
                action_id=action.action_id,
                incident_id=incident_id,
                decision=RemediationApprovalDecision.APPROVE,
                actor=RemediationApprovalActor(
                    username=actor.username,
                    role=actor.role,
                    actor_id=actor.actor_id,
                ),
                rationale=rationale,
                requested_by=actor.username,
            ),
            plan=plan,
            action=action,
        )
        if approval_record.status != RemediationApprovalStatus.APPROVED:
            policy_checks.append(
                _policy_check(
                    "APPROVAL_POLICY",
                    ControlledSoarPolicyCheckStatus.FAILED,
                    "; ".join(approval_record.policy_issues)
                    or f"Approval policy returned {approval_record.status.value}.",
                )
            )
            return _finalize_result(
                db,
                incident_id=incident_id,
                action_id=action.action_id,
                action_type=action.action_type.value,
                actor=actor,
                status=ControlledSoarExecutionStatus.BLOCKED,
                summary="Controlled SOAR action is blocked by approval policy.",
                policy_checks=policy_checks,
                created_records=created_records,
                before_event_id=str(before_audit.id),
                execution_supported=True,
                product_workflow_mutated=False,
            )
        policy_checks.append(
            _policy_check(
                "APPROVAL_POLICY",
                ControlledSoarPolicyCheckStatus.PASSED,
                f"Approval policy accepted actor role {actor.role}.",
            )
        )

        governance = intelligence.get("governance") if isinstance(intelligence.get("governance"), dict) else {}
        governance_status = str(governance.get("status") or "REQUIRES_REVIEW")
        if governance_status == "BLOCKED":
            policy_checks.append(
                _policy_check(
                    "AI_GOVERNANCE",
                    ControlledSoarPolicyCheckStatus.FAILED,
                    "AI governance classified the remediation output as blocked.",
                )
            )
            return _finalize_result(
                db,
                incident_id=incident_id,
                action_id=action.action_id,
                action_type=action.action_type.value,
                actor=actor,
                status=ControlledSoarExecutionStatus.BLOCKED,
                summary="Controlled SOAR action is blocked by AI governance policy.",
                policy_checks=policy_checks,
                created_records=created_records,
                before_event_id=str(before_audit.id),
                execution_supported=True,
                product_workflow_mutated=False,
            )
        policy_checks.append(
            _policy_check(
                "AI_GOVERNANCE",
                ControlledSoarPolicyCheckStatus.PASSED
                if governance_status == "PASSED"
                else ControlledSoarPolicyCheckStatus.WARNING,
                f"Governance status is {governance_status}; human approval remains authoritative.",
            )
        )

        dry_run = generate_action_dry_run(
            action,
            plan_id=plan.plan_id,
            incident_id=incident_id,
            approval_record=approval_record,
        )
        blocking_dry_run_statuses = {
            RemediationDryRunStatus.FORBIDDEN,
            RemediationDryRunStatus.BLOCKED_BY_POLICY,
            RemediationDryRunStatus.MISSING_ROLLBACK,
            RemediationDryRunStatus.MISSING_EVIDENCE,
        }
        if dry_run.status in blocking_dry_run_statuses:
            policy_checks.append(
                _policy_check(
                    "DRY_RUN",
                    ControlledSoarPolicyCheckStatus.FAILED,
                    f"Dry-run status {dry_run.status.value} blocks workflow action creation.",
                )
            )
            return _finalize_result(
                db,
                incident_id=incident_id,
                action_id=action.action_id,
                action_type=action.action_type.value,
                actor=actor,
                status=ControlledSoarExecutionStatus.BLOCKED,
                summary="Controlled SOAR action is blocked by dry-run findings.",
                policy_checks=policy_checks,
                created_records=created_records,
                before_event_id=str(before_audit.id),
                execution_supported=True,
                product_workflow_mutated=False,
            )
        policy_checks.append(
            _policy_check(
                "DRY_RUN",
                ControlledSoarPolicyCheckStatus.WARNING
                if dry_run.status == RemediationDryRunStatus.NOT_SUPPORTED
                else ControlledSoarPolicyCheckStatus.PASSED,
                (
                    "Dry-run remains simulation-only; safe internal workflow creation can continue."
                    if dry_run.status == RemediationDryRunStatus.NOT_SUPPORTED
                    else f"Dry-run status {dry_run.status.value} is acceptable."
                ),
            )
        )

        rollback = assess_action_rollback_readiness(
            action,
            plan_id=plan.plan_id,
            incident_id=incident_id,
        )
        if rollback.status not in {
            RemediationRollbackReadinessStatus.READY,
            RemediationRollbackReadinessStatus.PARTIAL,
            RemediationRollbackReadinessStatus.NOT_APPLICABLE,
        }:
            policy_checks.append(
                _policy_check(
                    "ROLLBACK_READINESS",
                    ControlledSoarPolicyCheckStatus.FAILED,
                    f"Rollback readiness {rollback.status.value} blocks this workflow action.",
                )
            )
            return _finalize_result(
                db,
                incident_id=incident_id,
                action_id=action.action_id,
                action_type=action.action_type.value,
                actor=actor,
                status=ControlledSoarExecutionStatus.BLOCKED,
                summary="Controlled SOAR action is blocked by rollback readiness.",
                policy_checks=policy_checks,
                created_records=created_records,
                before_event_id=str(before_audit.id),
                execution_supported=True,
                product_workflow_mutated=False,
            )
        policy_checks.append(
            _policy_check(
                "ROLLBACK_READINESS",
                ControlledSoarPolicyCheckStatus.PASSED,
                f"Rollback readiness {rollback.status.value} is acceptable for product-only workflow mutation.",
            )
        )

        workflow_records, workflow_mutated = _apply_internal_template(
            db,
            incident=incident,
            action=action,
            template=support.controlled_action_type,
            actor=actor,
        )
        created_records.extend(workflow_records)

        return _finalize_result(
            db,
            incident_id=incident_id,
            action_id=action.action_id,
            action_type=action.action_type.value,
            actor=actor,
            status=ControlledSoarExecutionStatus.SUCCEEDED,
            summary=(
                f"{EXECUTION_LABELS[support.controlled_action_type]} completed as an internal "
                "product workflow action. No target system was changed."
            ),
            policy_checks=policy_checks,
            created_records=created_records,
            before_event_id=str(before_audit.id),
            execution_supported=True,
            product_workflow_mutated=workflow_mutated,
        )

    except SQLAlchemyError:
        db.rollback()
        raise
    finally:
        db.close()


def _finalize_blocked(
    db,
    *,
    incident_id: int,
    action_id: str,
    action_type: str,
    actor: ControlledSoarActor,
    status: ControlledSoarExecutionStatus,
    summary: str,
    policy_checks: list[ControlledSoarPolicyCheck],
    created_records: list[ControlledSoarCreatedRecord],
    before_event_id: str,
    execution_supported: bool,
) -> ControlledSoarExecutionResult:
    return _finalize_result(
        db,
        incident_id=incident_id,
        action_id=action_id,
        action_type=action_type,
        actor=actor,
        status=status,
        summary=summary,
        policy_checks=policy_checks,
        created_records=created_records,
        before_event_id=before_event_id,
        execution_supported=execution_supported,
        product_workflow_mutated=False,
    )


def _finalize_result(
    db,
    *,
    incident_id: int,
    action_id: str,
    action_type: str,
    actor: ControlledSoarActor,
    status: ControlledSoarExecutionStatus,
    summary: str,
    policy_checks: list[ControlledSoarPolicyCheck],
    created_records: list[ControlledSoarCreatedRecord],
    before_event_id: str | None,
    execution_supported: bool,
    product_workflow_mutated: bool,
) -> ControlledSoarExecutionResult:
    after_audit = _add_incident_audit(
        db,
        incident_id=incident_id,
        event_type="CONTROLLED_SOAR_ACTION_RESULT",
        old_value=action_id,
        new_value=status.value,
        comment=summary,
        created_by=actor.username,
    )
    created_records.append(
        ControlledSoarCreatedRecord(
            record_type="AUDIT_EVENT",
            record_id=str(after_audit.id),
        )
    )
    _add_security_audit(
        db,
        event_type="CONTROLLED_SOAR_ACTION_RESULT",
        outcome=status.value,
        actor=actor,
        incident_id=incident_id,
        action_id=action_id,
        details={
            "action_type": action_type,
            "policy_checks": [check.model_dump(mode="json") for check in policy_checks],
            "execution_supported": execution_supported,
            "external_system_mutated": False,
            "target_system_mutated": False,
            "product_workflow_mutated": product_workflow_mutated,
        },
    )
    db.commit()

    return ControlledSoarExecutionResult(
        incident_id=incident_id,
        action_id=action_id,
        action_type=action_type,
        execution_supported=execution_supported,
        status=status,
        summary=summary,
        policy_checks=policy_checks,
        created_records=created_records,
        audit=ControlledSoarAuditReference(
            before_event_id=before_event_id,
            after_event_id=str(after_audit.id),
        ),
        product_workflow_mutated=product_workflow_mutated,
        notes=EXECUTION_NOTES,
    )
