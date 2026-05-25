from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from investigation_ai.models import EvidenceReference


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_score(value: object) -> int:
    try:
        numeric = int(round(float(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    return min(100, max(0, numeric))


class RemediationBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class RemediationActionType(str, Enum):
    BLOCK_IP = "BLOCK_IP"
    UNBLOCK_IP = "UNBLOCK_IP"
    DISABLE_USER = "DISABLE_USER"
    ENABLE_USER = "ENABLE_USER"
    STOP_SERVICE = "STOP_SERVICE"
    RESTART_SERVICE = "RESTART_SERVICE"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    RESTORE_FILE = "RESTORE_FILE"
    KILL_PROCESS = "KILL_PROCESS"
    ISOLATE_HOST = "ISOLATE_HOST"
    RELEASE_HOST = "RELEASE_HOST"
    ADD_FIREWALL_RULE = "ADD_FIREWALL_RULE"
    REMOVE_FIREWALL_RULE = "REMOVE_FIREWALL_RULE"
    CREATE_TICKET = "CREATE_TICKET"
    NOTIFY_OWNER = "NOTIFY_OWNER"
    ESCALATE_CASE = "ESCALATE_CASE"
    COLLECT_FORENSIC_EVIDENCE = "COLLECT_FORENSIC_EVIDENCE"


class RemediationApprovalRequirement(str, Enum):
    NONE = "NONE"
    ANALYST_APPROVAL = "ANALYST_APPROVAL"
    ADMIN_APPROVAL = "ADMIN_APPROVAL"
    SECURITY_LEAD_APPROVAL = "SECURITY_LEAD_APPROVAL"
    FORBIDDEN_BY_DEFAULT = "FORBIDDEN_BY_DEFAULT"


class RemediationPlanStatus(str, Enum):
    DRAFT = "DRAFT"
    PROPOSED = "PROPOSED"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED_FOR_FUTURE_EXECUTION = "APPROVED_FOR_FUTURE_EXECUTION"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class RemediationActionStatus(str, Enum):
    PROPOSED = "PROPOSED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    APPROVED_FOR_FUTURE_EXECUTION = "APPROVED_FOR_FUTURE_EXECUTION"
    REJECTED = "REJECTED"
    BLOCKED = "BLOCKED"


class RemediationTargetType(str, Enum):
    HOST = "HOST"
    USER = "USER"
    IP_ADDRESS = "IP_ADDRESS"
    FILE = "FILE"
    PROCESS = "PROCESS"
    SERVICE = "SERVICE"
    CASE = "CASE"
    TICKET = "TICKET"
    UNKNOWN = "UNKNOWN"


class RemediationTargetCriticality(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class RemediationRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RollbackAvailability(str, Enum):
    FULL = "FULL"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RemediationTarget(RemediationBaseModel):
    target_type: RemediationTargetType = RemediationTargetType.UNKNOWN
    value: str | None = None
    host: str | None = None
    user: str | None = None
    ip_address: str | None = None
    file_path: str | None = None
    process_name: str | None = None
    service_name: str | None = None
    criticality: RemediationTargetCriticality = RemediationTargetCriticality.UNKNOWN
    metadata: dict[str, Any] = Field(default_factory=dict)


class RemediationRiskAssessment(RemediationBaseModel):
    score: int = 0
    level: RemediationRiskLevel = RemediationRiskLevel.INFORMATIONAL
    rationale: str
    risk_factors: list[str] = Field(default_factory=list)
    blast_radius: str | None = None
    approval_requirement: RemediationApprovalRequirement = (
        RemediationApprovalRequirement.ANALYST_APPROVAL
    )

    @field_validator("score", mode="before")
    @classmethod
    def normalize_score(cls, value: object) -> int:
        return _normalize_score(value)


class RemediationImpactAssessment(RemediationBaseModel):
    business_impact: str | None = None
    technical_impact: str | None = None
    service_availability_impact: str | None = None
    identity_impact: str | None = None
    data_integrity_impact: str | None = None
    blast_radius: str | None = None


class RollbackStep(RemediationBaseModel):
    step_id: str
    title: str
    description: str
    validation: str | None = None
    requires_approval: bool = True


class RollbackPlan(RemediationBaseModel):
    rollback_id: str
    availability: RollbackAvailability = RollbackAvailability.PARTIAL
    steps: list[RollbackStep] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    recovery_notes: str | None = None
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_unavailable_limitations(self) -> "RollbackPlan":
        if self.availability == RollbackAvailability.UNAVAILABLE and not self.limitations:
            object.__setattr__(
                self,
                "limitations",
                ["Rollback is unavailable and must be treated as a high-risk remediation condition."],
            )
        return self


class RemediationPreCheck(RemediationBaseModel):
    check_id: str
    title: str
    description: str
    expected_result: str | None = None
    required: bool = True


class RemediationPostCheck(RemediationBaseModel):
    check_id: str
    title: str
    description: str
    expected_result: str | None = None
    required: bool = True


class RemediationValidationResult(RemediationBaseModel):
    valid: bool = True
    issues: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RemediationAction(RemediationBaseModel):
    action_id: str
    action_type: RemediationActionType
    title: str
    description: str
    target: RemediationTarget = Field(default_factory=RemediationTarget)
    reason: str
    evidence: list[EvidenceReference] = Field(default_factory=list)
    approval_requirement: RemediationApprovalRequirement = (
        RemediationApprovalRequirement.ANALYST_APPROVAL
    )
    risk: RemediationRiskAssessment
    expected_impact: RemediationImpactAssessment = Field(default_factory=RemediationImpactAssessment)
    possible_side_effects: list[str] = Field(default_factory=list)
    rollback_steps: list[RollbackStep] = Field(default_factory=list)
    pre_checks: list[RemediationPreCheck] = Field(default_factory=list)
    post_checks: list[RemediationPostCheck] = Field(default_factory=list)
    command_preview: str | None = None
    command_preview_is_executable: bool = False
    execution_supported: bool = False
    simulation_supported: bool = False
    status: RemediationActionStatus = RemediationActionStatus.PROPOSED

    @model_validator(mode="after")
    def enforce_non_executable_boundary(self) -> "RemediationAction":
        object.__setattr__(self, "execution_supported", False)
        object.__setattr__(self, "command_preview_is_executable", False)
        if self.approval_requirement == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT:
            object.__setattr__(self, "status", RemediationActionStatus.BLOCKED)
        return self


class RemediationPlanningContext(RemediationBaseModel):
    incident_id: int
    investigation_session_id: str | None = None
    incident: dict[str, Any] = Field(default_factory=dict)
    investigation_brief: Any | None = None
    evidence: list[EvidenceReference] = Field(default_factory=list)
    recommended_actions: list[Any] = Field(default_factory=list)
    detection_engineering_recommendations: list[Any] = Field(default_factory=list)
    generated_by: str = "system"


class RemediationPlan(RemediationBaseModel):
    plan_id: str
    incident_id: int
    investigation_session_id: str | None = None
    generated_at: datetime = Field(default_factory=utc_now)
    generated_by: str = "system"
    status: RemediationPlanStatus = RemediationPlanStatus.PROPOSED
    summary: str
    rationale: str
    actions: list[RemediationAction] = Field(default_factory=list)
    overall_risk: RemediationRiskAssessment
    expected_benefit: str | None = None
    business_impact: str | None = None
    technical_impact: str | None = None
    prerequisites: list[str] = Field(default_factory=list)
    pre_checks: list[RemediationPreCheck] = Field(default_factory=list)
    post_checks: list[RemediationPostCheck] = Field(default_factory=list)
    rollback_plan: RollbackPlan
    approval_required: bool = True
    evidence_used: list[EvidenceReference] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    execution_supported: bool = False
    simulation_supported: bool = False

    @model_validator(mode="after")
    def enforce_plan_boundary(self) -> "RemediationPlan":
        object.__setattr__(self, "execution_supported", False)
        object.__setattr__(
            self,
            "approval_required",
            any(
                action.approval_requirement != RemediationApprovalRequirement.NONE
                for action in self.actions
            ),
        )
        return self
