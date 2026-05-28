from ai_governance.models import (
    AIGovernanceAssessment,
    AIGovernanceSeverity,
    AIGovernanceStatus,
    AIClaimClassification,
    AIPresentationSafetyLabel,
)


def test_claim_classification_values():
    assert AIClaimClassification.EVIDENCE_BACKED == "EVIDENCE_BACKED"
    assert AIClaimClassification.INFERRED == "INFERRED"
    assert AIClaimClassification.SPECULATIVE == "SPECULATIVE"
    assert AIClaimClassification.UNSUPPORTED == "UNSUPPORTED"


def test_governance_assessment_defaults_are_safe():
    assessment = AIGovernanceAssessment()

    assert assessment.classification == AIClaimClassification.INFERRED
    assert assessment.status == AIGovernanceStatus.PASSED_WITH_WARNINGS
    assert assessment.severity == AIGovernanceSeverity.LOW
    assert assessment.confidence_score == 0
    assert assessment.evidence_count == 0
    assert assessment.requires_human_review is True
    assert assessment.fallback_used is False
    assert assessment.unsupported_claims == []
    assert assessment.speculative_claims == []
    assert assessment.limitations == []
    assert assessment.presentation_labels == []


def test_governance_assessment_accepts_labels_and_claims():
    assessment = AIGovernanceAssessment(
        classification=AIClaimClassification.SPECULATIVE,
        status=AIGovernanceStatus.NEEDS_HUMAN_REVIEW,
        severity=AIGovernanceSeverity.MEDIUM,
        confidence_score=42,
        evidence_count=1,
        unsupported_claims=["unsupported operational conclusion"],
        speculative_claims=["possible lateral movement"],
        limitations=["missing endpoint telemetry"],
        fallback_used=True,
        presentation_labels=[
            AIPresentationSafetyLabel.SPECULATIVE,
            AIPresentationSafetyLabel.REQUIRES_HUMAN_REVIEW,
            AIPresentationSafetyLabel.FALLBACK_GENERATED,
        ],
    )

    assert assessment.classification == AIClaimClassification.SPECULATIVE
    assert assessment.status == AIGovernanceStatus.NEEDS_HUMAN_REVIEW
    assert assessment.confidence_score == 42
    assert assessment.evidence_count == 1
    assert assessment.requires_human_review is True
    assert AIPresentationSafetyLabel.FALLBACK_GENERATED in assessment.presentation_labels
