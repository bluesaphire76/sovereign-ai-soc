from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_confidence_score(value: object) -> int:
    try:
        numeric_value = int(round(float(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0

    return min(100, max(0, numeric_value))


class InvestigationSessionStatus(str, Enum):
    INITIAL_ANALYSIS = "INITIAL_ANALYSIS"
    EVIDENCE_EXPANSION = "EVIDENCE_EXPANSION"
    HYPOTHESIS_REFINEMENT = "HYPOTHESIS_REFINEMENT"
    READY_FOR_ANALYST = "READY_FOR_ANALYST"
    NEEDS_HUMAN_INPUT = "NEEDS_HUMAN_INPUT"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    CLOSED = "CLOSED"


class InvestigationFindingType(str, Enum):
    INDICATOR = "INDICATOR"
    BEHAVIOR = "BEHAVIOR"
    IMPACT = "IMPACT"
    ROOT_CAUSE_CANDIDATE = "ROOT_CAUSE_CANDIDATE"
    POLICY_GAP = "POLICY_GAP"
    CONTROL_GAP = "CONTROL_GAP"
    TIMELINE_OBSERVATION = "TIMELINE_OBSERVATION"
    UNKNOWN = "UNKNOWN"


class InvestigationConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class InvestigationEvidenceType(str, Enum):
    RAW_EVENT = "RAW_EVENT"
    SECURITY_ALERT = "SECURITY_ALERT"
    INCIDENT = "INCIDENT"
    CASE = "CASE"
    NETWORK_EVENT = "NETWORK_EVENT"
    DNS_CONTEXT = "DNS_CONTEXT"
    CORRELATION_SUMMARY = "CORRELATION_SUMMARY"
    MITRE_METADATA = "MITRE_METADATA"
    ANALYST_NOTE = "ANALYST_NOTE"
    AUDIT_EVENT = "AUDIT_EVENT"
    REPORT = "REPORT"
    OTHER = "OTHER"


class InvestigationEvidenceStrength(str, Enum):
    STRONG = "STRONG"
    MODERATE = "MODERATE"
    WEAK = "WEAK"
    CONTEXTUAL = "CONTEXTUAL"
    UNKNOWN = "UNKNOWN"


class InvestigationHypothesisStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DISCARDED = "DISCARDED"
    CONFIRMED = "CONFIRMED"
    WEAKENED = "WEAKENED"
    NEEDS_EVIDENCE = "NEEDS_EVIDENCE"


class RecommendedCheckPriority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RecommendedActionCategory(str, Enum):
    INVESTIGATION = "INVESTIGATION"
    CONTAINMENT = "CONTAINMENT"
    ERADICATION = "ERADICATION"
    RECOVERY = "RECOVERY"
    MONITORING = "MONITORING"
    COMMUNICATION = "COMMUNICATION"
    GOVERNANCE = "GOVERNANCE"
    DETECTION_TUNING = "DETECTION_TUNING"
    DOCUMENTATION = "DOCUMENTATION"


class RecommendedActionApprovalRequirement(str, Enum):
    NONE = "NONE"
    ANALYST_APPROVAL = "ANALYST_APPROVAL"
    ADMIN_APPROVAL = "ADMIN_APPROVAL"
    FORBIDDEN_BY_DEFAULT = "FORBIDDEN_BY_DEFAULT"


class InvestigationClaimClassification(str, Enum):
    EVIDENCE_BACKED = "EVIDENCE_BACKED"
    INFERRED = "INFERRED"
    SPECULATIVE = "SPECULATIVE"
    UNSUPPORTED = "UNSUPPORTED"


class InvestigationBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class EvidenceReference(InvestigationBaseModel):
    evidence_id: str
    evidence_type: InvestigationEvidenceType = InvestigationEvidenceType.OTHER
    source_system: str | None = None
    source_table: str | None = None
    source_reference: str | None = None
    timestamp: datetime | None = None
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    rule_id: str | None = None
    mitre_technique: str | None = None
    summary: str | None = None
    raw_reference: str | None = None
    strength: InvestigationEvidenceStrength = InvestigationEvidenceStrength.UNKNOWN
    claim_classification: InvestigationClaimClassification = (
        InvestigationClaimClassification.EVIDENCE_BACKED
    )


class ConfidenceAssessment(InvestigationBaseModel):
    score: int = Field(default=0, description="Normalized confidence score from 0 to 100.")
    level: InvestigationConfidenceLevel = InvestigationConfidenceLevel.UNKNOWN
    rationale: str | None = None
    positive_signals: list[str] = Field(default_factory=list)
    negative_signals: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    contradictory_evidence: list[str] = Field(default_factory=list)

    @field_validator("score", mode="before")
    @classmethod
    def normalize_score(cls, value: object) -> int:
        return _normalize_confidence_score(value)

    @model_validator(mode="after")
    def infer_level(self) -> "ConfidenceAssessment":
        if self.level != InvestigationConfidenceLevel.UNKNOWN:
            return self

        if self.score >= 75:
            self.level = InvestigationConfidenceLevel.HIGH
        elif self.score >= 40:
            self.level = InvestigationConfidenceLevel.MEDIUM
        elif self.score > 0:
            self.level = InvestigationConfidenceLevel.LOW

        return self


class InvestigationHypothesis(InvestigationBaseModel):
    hypothesis_id: str
    title: str
    statement: str
    status: InvestigationHypothesisStatus = InvestigationHypothesisStatus.ACTIVE
    confidence: ConfidenceAssessment = Field(default_factory=ConfidenceAssessment)
    supporting_evidence: list[EvidenceReference] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[EvidenceReference] = Field(default_factory=list)
    rationale: str | None = None
    related_mitre_techniques: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class RecommendedCheck(InvestigationBaseModel):
    check_id: str
    title: str
    description: str
    priority: RecommendedCheckPriority = RecommendedCheckPriority.MEDIUM
    reason: str | None = None
    expected_evidence: list[str] = Field(default_factory=list)
    related_hypothesis_ids: list[str] = Field(default_factory=list)
    suggested_query: str | None = None
    source_system: str | None = None
    requires_human_input: bool = True


class RecommendedAction(InvestigationBaseModel):
    action_id: str
    title: str
    description: str
    category: RecommendedActionCategory = RecommendedActionCategory.INVESTIGATION
    approval_requirement: RecommendedActionApprovalRequirement = (
        RecommendedActionApprovalRequirement.ANALYST_APPROVAL
    )
    reason: str | None = None
    expected_impact: str | None = None
    risk: str | None = None
    rollback_notes: str | None = None
    related_hypothesis_ids: list[str] = Field(default_factory=list)
    related_evidence_ids: list[str] = Field(default_factory=list)
    execution_supported: bool = False


class InvestigationFinding(InvestigationBaseModel):
    finding_id: str
    finding_type: InvestigationFindingType = InvestigationFindingType.UNKNOWN
    title: str
    description: str
    claim_classification: InvestigationClaimClassification = (
        InvestigationClaimClassification.INFERRED
    )
    confidence: ConfidenceAssessment = Field(default_factory=ConfidenceAssessment)
    evidence: list[EvidenceReference] = Field(default_factory=list)
    business_impact: str | None = None
    technical_impact: str | None = None


class InvestigationLimitation(InvestigationBaseModel):
    limitation_id: str
    description: str
    impact: str | None = None
    missing_data: list[str] = Field(default_factory=list)
    suggested_resolution: str | None = None


class InvestigationBrief(InvestigationBaseModel):
    incident_id: int
    session_id: str
    generated_at: datetime = Field(default_factory=utc_now)
    status: InvestigationSessionStatus = InvestigationSessionStatus.INITIAL_ANALYSIS
    summary: str
    risk_assessment: str | None = None
    hypotheses: list[InvestigationHypothesis] = Field(default_factory=list)
    findings: list[InvestigationFinding] = Field(default_factory=list)
    recommended_checks: list[RecommendedCheck] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    evidence_used: list[EvidenceReference] = Field(default_factory=list)
    confidence: ConfidenceAssessment = Field(default_factory=ConfidenceAssessment)
    limitations: list[InvestigationLimitation] = Field(default_factory=list)
    next_investigation_steps: list[str] = Field(default_factory=list)


class InvestigationSession(InvestigationBaseModel):
    session_id: str
    incident_id: int
    status: InvestigationSessionStatus = InvestigationSessionStatus.INITIAL_ANALYSIS
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    generated_by: str = "system"
    model_name: str | None = None
    brief: InvestigationBrief | None = None
    analyst_feedback: list[str] = Field(default_factory=list)
    previous_session_id: str | None = None
