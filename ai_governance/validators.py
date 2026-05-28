from __future__ import annotations

from ai_governance.models import (
    AIGovernanceAssessment,
    AIGovernanceSeverity,
    AIGovernanceStatus,
    AIPresentationSafetyLabel,
    AIClaimClassification,
)


def assess_claim_governance(
    *,
    classification: AIClaimClassification,
    confidence_score: int,
    evidence_count: int = 0,
    unsupported_claims: list[str] | None = None,
    speculative_claims: list[str] | None = None,
    limitations: list[str] | None = None,
    fallback_used: bool = False,
) -> AIGovernanceAssessment:
    unsupported_claims = unsupported_claims or []
    speculative_claims = speculative_claims or []
    limitations = limitations or []

    labels: list[AIPresentationSafetyLabel] = []

    if classification == AIClaimClassification.EVIDENCE_BACKED:
        labels.append(AIPresentationSafetyLabel.EVIDENCE_BACKED)
    elif classification == AIClaimClassification.INFERRED:
        labels.append(AIPresentationSafetyLabel.INFERRED)
    elif classification == AIClaimClassification.SPECULATIVE:
        labels.append(AIPresentationSafetyLabel.SPECULATIVE)
    elif classification == AIClaimClassification.UNSUPPORTED:
        labels.append(AIPresentationSafetyLabel.UNSUPPORTED)

    if confidence_score < 50:
        labels.append(AIPresentationSafetyLabel.LOW_CONFIDENCE)

    if fallback_used:
        labels.append(AIPresentationSafetyLabel.FALLBACK_GENERATED)

    requires_human_review = (
        classification in {
            AIClaimClassification.INFERRED,
            AIClaimClassification.SPECULATIVE,
            AIClaimClassification.UNSUPPORTED,
        }
        or confidence_score < 70
        or bool(unsupported_claims)
        or bool(speculative_claims)
        or fallback_used
    )

    if requires_human_review:
        labels.append(AIPresentationSafetyLabel.REQUIRES_HUMAN_REVIEW)

    if classification == AIClaimClassification.UNSUPPORTED or unsupported_claims:
        status = AIGovernanceStatus.NEEDS_HUMAN_REVIEW
        severity = AIGovernanceSeverity.HIGH
    elif classification == AIClaimClassification.SPECULATIVE or speculative_claims:
        status = AIGovernanceStatus.PASSED_WITH_WARNINGS
        severity = AIGovernanceSeverity.MEDIUM
    elif confidence_score < 50:
        status = AIGovernanceStatus.PASSED_WITH_WARNINGS
        severity = AIGovernanceSeverity.MEDIUM
    else:
        status = AIGovernanceStatus.PASSED
        severity = AIGovernanceSeverity.LOW

    if classification == AIClaimClassification.EVIDENCE_BACKED and evidence_count <= 0:
        status = AIGovernanceStatus.PASSED_WITH_WARNINGS
        severity = AIGovernanceSeverity.MEDIUM
        requires_human_review = True
        labels.append(AIPresentationSafetyLabel.REQUIRES_HUMAN_REVIEW)
        limitations.append("Evidence-backed classification has no linked evidence references.")

    return AIGovernanceAssessment(
        classification=classification,
        status=status,
        severity=severity,
        confidence_score=confidence_score,
        evidence_count=evidence_count,
        unsupported_claims=unsupported_claims,
        speculative_claims=speculative_claims,
        limitations=limitations,
        requires_human_review=requires_human_review,
        fallback_used=fallback_used,
        presentation_labels=list(dict.fromkeys(labels)),
    )
