from ai_governance.models import (
    AIGovernanceSeverity,
    AIGovernanceStatus,
    AIPresentationSafetyLabel,
    AIClaimClassification,
)
from ai_governance.validators import assess_claim_governance


def test_evidence_backed_claim_with_evidence_passes():
    result = assess_claim_governance(
        classification=AIClaimClassification.EVIDENCE_BACKED,
        confidence_score=82,
        evidence_count=2,
    )

    assert result.status == AIGovernanceStatus.PASSED
    assert result.severity == AIGovernanceSeverity.LOW
    assert AIPresentationSafetyLabel.EVIDENCE_BACKED in result.presentation_labels


def test_evidence_backed_claim_without_evidence_warns():
    result = assess_claim_governance(
        classification=AIClaimClassification.EVIDENCE_BACKED,
        confidence_score=80,
        evidence_count=0,
    )

    assert result.status == AIGovernanceStatus.PASSED_WITH_WARNINGS
    assert result.severity == AIGovernanceSeverity.MEDIUM
    assert result.requires_human_review is True
    assert result.limitations


def test_unsupported_claim_needs_human_review():
    result = assess_claim_governance(
        classification=AIClaimClassification.UNSUPPORTED,
        confidence_score=75,
        evidence_count=0,
        unsupported_claims=["unsupported attribution"],
    )

    assert result.status == AIGovernanceStatus.NEEDS_HUMAN_REVIEW
    assert result.severity == AIGovernanceSeverity.HIGH
    assert AIPresentationSafetyLabel.UNSUPPORTED in result.presentation_labels
    assert AIPresentationSafetyLabel.REQUIRES_HUMAN_REVIEW in result.presentation_labels


def test_low_confidence_adds_low_confidence_label():
    result = assess_claim_governance(
        classification=AIClaimClassification.INFERRED,
        confidence_score=35,
        evidence_count=1,
    )

    assert result.status == AIGovernanceStatus.PASSED_WITH_WARNINGS
    assert AIPresentationSafetyLabel.LOW_CONFIDENCE in result.presentation_labels


def test_fallback_adds_fallback_label():
    result = assess_claim_governance(
        classification=AIClaimClassification.INFERRED,
        confidence_score=65,
        evidence_count=1,
        fallback_used=True,
    )

    assert AIPresentationSafetyLabel.FALLBACK_GENERATED in result.presentation_labels
    assert result.requires_human_review is True
