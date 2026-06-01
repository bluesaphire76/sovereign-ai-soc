from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AIClaimClassification(str, Enum):
    EVIDENCE_BACKED = "EVIDENCE_BACKED"
    INFERRED = "INFERRED"
    SPECULATIVE = "SPECULATIVE"
    UNSUPPORTED = "UNSUPPORTED"


class AIGovernanceSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AIPresentationSafetyLabel(str, Enum):
    AI_GENERATED = "AI_GENERATED"
    EVIDENCE_BACKED = "EVIDENCE_BACKED"
    INFERRED = "INFERRED"
    SPECULATIVE = "SPECULATIVE"
    UNSUPPORTED = "UNSUPPORTED"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"
    NO_EXECUTION = "NO_EXECUTION"
    SIMULATION_ONLY = "SIMULATION_ONLY"
    EXECUTION_DISABLED = "EXECUTION_DISABLED"
    MOCK_ONLY = "MOCK_ONLY"
    FALLBACK_GENERATED = "FALLBACK_GENERATED"
    POLICY_BLOCKED = "POLICY_BLOCKED"


class AIGovernanceStatus(str, Enum):
    PASSED = "PASSED"
    PASSED_WITH_WARNINGS = "PASSED_WITH_WARNINGS"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"
    BLOCKED = "BLOCKED"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"


class AIEvidenceCoverage(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


@dataclass(slots=True)
class AIGovernanceAssessment:
    classification: AIClaimClassification = AIClaimClassification.INFERRED
    status: AIGovernanceStatus = AIGovernanceStatus.PASSED_WITH_WARNINGS
    severity: AIGovernanceSeverity = AIGovernanceSeverity.LOW

    confidence_score: int = 0
    confidence_level: Optional[str] = None

    evidence_count: int = 0
    unsupported_claims: list[str] = field(default_factory=list)
    speculative_claims: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    requires_human_review: bool = True
    fallback_used: bool = False
    presentation_labels: list[AIPresentationSafetyLabel] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence_score = max(0, min(100, int(self.confidence_score)))
        self.evidence_count = max(0, int(self.evidence_count))


@dataclass(slots=True)
class AIRemediationGovernanceAssessment:
    status: AIGovernanceStatus = AIGovernanceStatus.REQUIRES_REVIEW
    confidence_score: int = 0
    evidence_coverage: AIEvidenceCoverage = AIEvidenceCoverage.NONE
    human_review_required: bool = True
    unsupported_claims: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    policy_warnings: list[str] = field(default_factory=list)
    safety_labels: list[AIPresentationSafetyLabel] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence_score = max(0, min(100, int(self.confidence_score)))
        self.human_review_required = True
        base_labels = [
            AIPresentationSafetyLabel.AI_GENERATED,
            AIPresentationSafetyLabel.HUMAN_REVIEW_REQUIRED,
            AIPresentationSafetyLabel.REQUIRES_HUMAN_REVIEW,
            AIPresentationSafetyLabel.NO_EXECUTION,
            AIPresentationSafetyLabel.EXECUTION_DISABLED,
        ]
        self.safety_labels = list(dict.fromkeys([*base_labels, *self.safety_labels]))

    def to_payload(self) -> dict[str, object]:
        return {
            "status": self.status.value,
            "confidence_score": self.confidence_score,
            "evidence_coverage": self.evidence_coverage.value,
            "human_review_required": self.human_review_required,
            "unsupported_claims": list(self.unsupported_claims),
            "assumptions": list(self.assumptions),
            "limitations": list(self.limitations),
            "policy_warnings": list(self.policy_warnings),
            "safety_labels": [label.value for label in self.safety_labels],
        }
