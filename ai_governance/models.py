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
    EVIDENCE_BACKED = "EVIDENCE_BACKED"
    INFERRED = "INFERRED"
    SPECULATIVE = "SPECULATIVE"
    UNSUPPORTED = "UNSUPPORTED"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"
    SIMULATION_ONLY = "SIMULATION_ONLY"
    EXECUTION_DISABLED = "EXECUTION_DISABLED"
    MOCK_ONLY = "MOCK_ONLY"
    FALLBACK_GENERATED = "FALLBACK_GENERATED"


class AIGovernanceStatus(str, Enum):
    PASSED = "PASSED"
    PASSED_WITH_WARNINGS = "PASSED_WITH_WARNINGS"
    BLOCKED = "BLOCKED"
    NEEDS_HUMAN_REVIEW = "NEEDS_HUMAN_REVIEW"


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
