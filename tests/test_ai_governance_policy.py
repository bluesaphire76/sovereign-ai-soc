from ai_governance.models import AIClaimClassification
from ai_governance.policy import (
    assess_output_governance,
    is_safe_to_present_as_evidence_backed,
    requires_visible_human_review,
    should_block_as_fact,
)


def test_assess_output_governance_accepts_string_classification():
    result = assess_output_governance(
        classification="EVIDENCE_BACKED",
        confidence_score=88,
        evidence_count=2,
    )

    assert result.classification == AIClaimClassification.EVIDENCE_BACKED
    assert is_safe_to_present_as_evidence_backed(result) is True


def test_unknown_classification_becomes_unsupported():
    result = assess_output_governance(
        classification="CERTAINLY_TRUE",
        confidence_score=90,
        evidence_count=0,
    )

    assert result.classification == AIClaimClassification.UNSUPPORTED
    assert result.unsupported_claims
    assert should_block_as_fact(result) is True


def test_requires_visible_human_review_for_speculative_output():
    result = assess_output_governance(
        classification="SPECULATIVE",
        confidence_score=55,
        evidence_count=1,
        speculative_claims=["possible credential abuse"],
    )

    assert requires_visible_human_review(result) is True
    assert is_safe_to_present_as_evidence_backed(result) is False


def test_evidence_backed_without_evidence_is_not_safe_as_fact():
    result = assess_output_governance(
        classification="EVIDENCE_BACKED",
        confidence_score=90,
        evidence_count=0,
    )

    assert is_safe_to_present_as_evidence_backed(result) is False
    assert requires_visible_human_review(result) is True
