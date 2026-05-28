from __future__ import annotations

from ai_governance.models import (
    AIGovernanceAssessment,
    AIGovernanceStatus,
    AIPresentationSafetyLabel,
    AIClaimClassification,
)
from ai_governance.validators import assess_claim_governance


def assess_output_governance(
    *,
    classification: str,
    confidence_score: int,
    evidence_count: int = 0,
    unsupported_claims: list[str] | None = None,
    speculative_claims: list[str] | None = None,
    limitations: list[str] | None = None,
    fallback_used: bool = False,
) -> AIGovernanceAssessment:
    normalized = classification.upper().strip()

    try:
        claim_classification = AIClaimClassification(normalized)
    except ValueError:
        claim_classification = AIClaimClassification.UNSUPPORTED
        unsupported_claims = list(unsupported_claims or [])
        unsupported_claims.append(f"Unknown claim classification: {classification}")

    return assess_claim_governance(
        classification=claim_classification,
        confidence_score=confidence_score,
        evidence_count=evidence_count,
        unsupported_claims=unsupported_claims,
        speculative_claims=speculative_claims,
        limitations=limitations,
        fallback_used=fallback_used,
    )


def should_block_as_fact(assessment: AIGovernanceAssessment) -> bool:
    return (
        assessment.classification == AIClaimClassification.UNSUPPORTED
        or assessment.status == AIGovernanceStatus.BLOCKED
    )


def requires_visible_human_review(assessment: AIGovernanceAssessment) -> bool:
    return (
        assessment.requires_human_review
        or AIPresentationSafetyLabel.REQUIRES_HUMAN_REVIEW in assessment.presentation_labels
    )


def is_safe_to_present_as_evidence_backed(assessment: AIGovernanceAssessment) -> bool:
    return (
        assessment.classification == AIClaimClassification.EVIDENCE_BACKED
        and assessment.evidence_count > 0
        and not assessment.unsupported_claims
        and assessment.confidence_score >= 70
    )
