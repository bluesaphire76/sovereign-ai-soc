from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_score(value: object) -> int:
    try:
        numeric = int(round(float(value)))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0
    return min(100, max(0, numeric))


class DetectionEngineeringBaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class DetectionEngineeringCategory(str, Enum):
    NOISE_REDUCTION = "NOISE_REDUCTION"
    THRESHOLD_TUNING = "THRESHOLD_TUNING"
    SUPPRESSION_CANDIDATE = "SUPPRESSION_CANDIDATE"
    CORRELATION_IMPROVEMENT = "CORRELATION_IMPROVEMENT"
    DETECTION_GAP = "DETECTION_GAP"
    MITRE_ENRICHMENT = "MITRE_ENRICHMENT"
    RULE_DEDUPLICATION = "RULE_DEDUPLICATION"
    RULE_QUALITY = "RULE_QUALITY"
    FALSE_POSITIVE_REDUCTION = "FALSE_POSITIVE_REDUCTION"
    COVERAGE_IMPROVEMENT = "COVERAGE_IMPROVEMENT"


class DetectionEngineeringSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DetectionEngineeringConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SPECULATIVE = "SPECULATIVE"


class DetectionRecommendationStatus(str, Enum):
    PROPOSED = "PROPOSED"
    REVIEWED = "REVIEWED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    IMPLEMENTED_EXTERNALLY = "IMPLEMENTED_EXTERNALLY"


class DetectionEngineeringSignal(DetectionEngineeringBaseModel):
    signal_id: str
    source_type: str
    source_system: str | None = None
    source_reference: str | None = None
    rule_id: str | None = None
    rule_description: str | None = None
    timestamp: str | None = None
    host: str | None = None
    severity: str | None = None
    count: int = 1
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("count", mode="before")
    @classmethod
    def normalize_count(cls, value: object) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0


class DetectionRuleAssessment(DetectionEngineeringBaseModel):
    rule_id: str
    source_system: str = "unknown"
    rule_description: str | None = None
    alert_count: int = 0
    incident_count: int = 0
    suppressed_count: int = 0
    false_positive_count: int = 0
    low_severity_count: int = 0
    mitre_techniques: list[str] = Field(default_factory=list)
    noise_score: int = 0
    recurrence_score: int = 0
    quality_score: int = 100
    evidence: list[DetectionEngineeringSignal] = Field(default_factory=list)
    rationale: str | None = None

    @field_validator(
        "alert_count",
        "incident_count",
        "suppressed_count",
        "false_positive_count",
        "low_severity_count",
        "noise_score",
        "recurrence_score",
        "quality_score",
        mode="before",
    )
    @classmethod
    def normalize_numeric_fields(cls, value: object) -> int:
        try:
            numeric = int(round(float(value or 0)))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0
        return max(0, numeric)

    @field_validator("mitre_techniques", mode="before")
    @classmethod
    def normalize_mitre(cls, values: object) -> list[str]:
        if not values:
            return []
        if isinstance(values, str):
            values = [values]
        return sorted({str(value).strip() for value in values if str(value).strip()})


class DetectionEngineeringFinding(DetectionEngineeringBaseModel):
    finding_id: str
    title: str
    description: str
    category: DetectionEngineeringCategory
    severity: DetectionEngineeringSeverity = DetectionEngineeringSeverity.MEDIUM
    confidence: DetectionEngineeringConfidence = DetectionEngineeringConfidence.MEDIUM
    evidence: list[DetectionEngineeringSignal] = Field(default_factory=list)
    rationale: str
    rule_id: str | None = None
    source_system: str | None = None
    unsupported: bool = False


class DetectionGap(DetectionEngineeringBaseModel):
    gap_id: str
    title: str
    description: str
    affected_rule_ids: list[str] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    evidence: list[DetectionEngineeringSignal] = Field(default_factory=list)
    severity: DetectionEngineeringSeverity = DetectionEngineeringSeverity.MEDIUM
    confidence: DetectionEngineeringConfidence = DetectionEngineeringConfidence.MEDIUM


class SuppressionCandidate(DetectionEngineeringBaseModel):
    candidate_id: str
    rule_id: str
    source_system: str = "unknown"
    reason: str
    evidence: list[DetectionEngineeringSignal] = Field(default_factory=list)
    risk: str
    approval_required: bool = True

    @model_validator(mode="after")
    def require_approval(self) -> "SuppressionCandidate":
        object.__setattr__(self, "approval_required", True)
        return self


class ThresholdTuningRecommendation(DetectionEngineeringBaseModel):
    tuning_id: str
    rule_id: str
    source_system: str = "unknown"
    current_behavior: str
    suggested_review: str
    evidence: list[DetectionEngineeringSignal] = Field(default_factory=list)
    expected_benefit: str
    operational_risk: str
    approval_required: bool = True

    @model_validator(mode="after")
    def require_approval(self) -> "ThresholdTuningRecommendation":
        object.__setattr__(self, "approval_required", True)
        return self


class CorrelationOpportunity(DetectionEngineeringBaseModel):
    opportunity_id: str
    title: str
    description: str
    related_rule_ids: list[str] = Field(default_factory=list)
    recurring_entities: list[str] = Field(default_factory=list)
    evidence: list[DetectionEngineeringSignal] = Field(default_factory=list)
    expected_benefit: str
    approval_required: bool = True


class DetectionEngineeringRecommendation(DetectionEngineeringBaseModel):
    recommendation_id: str
    title: str
    description: str
    category: DetectionEngineeringCategory
    severity: DetectionEngineeringSeverity = DetectionEngineeringSeverity.MEDIUM
    confidence: DetectionEngineeringConfidence = DetectionEngineeringConfidence.MEDIUM
    evidence: list[DetectionEngineeringSignal] = Field(default_factory=list)
    rationale: str
    expected_benefit: str
    operational_risk: str
    implementation_notes: str
    approval_required: bool = True
    status: DetectionRecommendationStatus = DetectionRecommendationStatus.PROPOSED
    validation_suggestion: str | None = None
    rollback_considerations: str | None = None
    production_rule_change_supported: bool = False

    @model_validator(mode="after")
    def enforce_governance(self) -> "DetectionEngineeringRecommendation":
        object.__setattr__(self, "production_rule_change_supported", False)
        if self.category in {
            DetectionEngineeringCategory.NOISE_REDUCTION,
            DetectionEngineeringCategory.THRESHOLD_TUNING,
            DetectionEngineeringCategory.SUPPRESSION_CANDIDATE,
            DetectionEngineeringCategory.CORRELATION_IMPROVEMENT,
            DetectionEngineeringCategory.RULE_DEDUPLICATION,
            DetectionEngineeringCategory.FALSE_POSITIVE_REDUCTION,
        }:
            object.__setattr__(self, "approval_required", True)
        return self


class DetectionEngineeringReport(DetectionEngineeringBaseModel):
    report_id: str
    generated_at: datetime = Field(default_factory=utc_now)
    summary: str
    rule_assessments: list[DetectionRuleAssessment] = Field(default_factory=list)
    findings: list[DetectionEngineeringFinding] = Field(default_factory=list)
    gaps: list[DetectionGap] = Field(default_factory=list)
    suppression_candidates: list[SuppressionCandidate] = Field(default_factory=list)
    threshold_tuning: list[ThresholdTuningRecommendation] = Field(default_factory=list)
    correlation_opportunities: list[CorrelationOpportunity] = Field(default_factory=list)
    recommendations: list[DetectionEngineeringRecommendation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    source_counts: dict[str, int] = Field(default_factory=dict)
    no_production_rule_changes: bool = True

    @model_validator(mode="after")
    def enforce_report_boundary(self) -> "DetectionEngineeringReport":
        object.__setattr__(self, "no_production_rule_changes", True)
        return self
