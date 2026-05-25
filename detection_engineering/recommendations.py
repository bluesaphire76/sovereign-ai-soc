from __future__ import annotations

import logging
from collections.abc import Sequence

from .models import (
    DetectionEngineeringCategory,
    DetectionEngineeringConfidence,
    DetectionEngineeringFinding,
    DetectionEngineeringRecommendation,
    DetectionEngineeringSeverity,
)
from .scoring import calculate_expected_benefit, calculate_operational_risk


logger = logging.getLogger(__name__)


IMPLEMENTATION_CATEGORIES = {
    DetectionEngineeringCategory.NOISE_REDUCTION,
    DetectionEngineeringCategory.THRESHOLD_TUNING,
    DetectionEngineeringCategory.SUPPRESSION_CANDIDATE,
    DetectionEngineeringCategory.CORRELATION_IMPROVEMENT,
    DetectionEngineeringCategory.RULE_DEDUPLICATION,
    DetectionEngineeringCategory.FALSE_POSITIVE_REDUCTION,
}


def _recommendation_title(finding: DetectionEngineeringFinding) -> str:
    if finding.category == DetectionEngineeringCategory.SUPPRESSION_CANDIDATE:
        return f"Review suppression candidate for rule {finding.rule_id or 'unknown'}"
    if finding.category == DetectionEngineeringCategory.THRESHOLD_TUNING:
        return f"Review threshold tuning for rule {finding.rule_id or 'unknown'}"
    if finding.category == DetectionEngineeringCategory.MITRE_ENRICHMENT:
        return f"Review MITRE enrichment for rule {finding.rule_id or 'unknown'}"
    if finding.category == DetectionEngineeringCategory.CORRELATION_IMPROVEMENT:
        return "Review correlation improvement opportunity"
    return finding.title


def recommendation_from_finding(
    finding: DetectionEngineeringFinding,
) -> DetectionEngineeringRecommendation:
    evidence = list(finding.evidence)
    confidence = finding.confidence
    unsupported = finding.unsupported or not evidence

    if unsupported:
        confidence = DetectionEngineeringConfidence.SPECULATIVE
        logger.info(
            "detection_engineering_recommendation_downgraded",
            extra={"finding_id": finding.finding_id, "reason": "missing_evidence"},
        )

    category = finding.category
    approval_required = category in IMPLEMENTATION_CATEGORIES or unsupported

    return DetectionEngineeringRecommendation(
        recommendation_id=f"rec-{finding.finding_id}",
        title=_recommendation_title(finding),
        description=finding.description,
        category=category,
        severity=finding.severity,
        confidence=confidence,
        evidence=evidence,
        rationale=(
            finding.rationale
            if not unsupported
            else (
                f"{finding.rationale} Additional evidence is required before this "
                "recommendation can be treated as implementation-ready."
            )
        ),
        expected_benefit=calculate_expected_benefit(
            category.value,
            evidence_count=len(evidence),
            recurrence_score=sum(signal.count for signal in evidence),
        ),
        operational_risk=calculate_operational_risk(category.value, confidence=confidence),
        implementation_notes=(
            "Use this as an analyst-reviewed detection engineering proposal only. "
            "Validate against historical events and synthetic scenarios before any production change."
        ),
        approval_required=approval_required,
        validation_suggestion=(
            "Replay representative historical events and synthetic scenarios before changing "
            "rules, thresholds, suppression policy or correlation logic."
        ),
        rollback_considerations=(
            "Keep the previous detection rule, threshold or suppression policy available for rollback."
        ),
        production_rule_change_supported=False,
    )


def generate_recommendations(
    findings: Sequence[DetectionEngineeringFinding],
) -> list[DetectionEngineeringRecommendation]:
    recommendations = [recommendation_from_finding(finding) for finding in findings]
    severity_order = {
        DetectionEngineeringSeverity.CRITICAL: 0,
        DetectionEngineeringSeverity.HIGH: 1,
        DetectionEngineeringSeverity.MEDIUM: 2,
        DetectionEngineeringSeverity.LOW: 3,
        DetectionEngineeringSeverity.INFO: 4,
    }
    confidence_order = {
        DetectionEngineeringConfidence.HIGH: 0,
        DetectionEngineeringConfidence.MEDIUM: 1,
        DetectionEngineeringConfidence.LOW: 2,
        DetectionEngineeringConfidence.SPECULATIVE: 3,
    }
    return sorted(
        recommendations,
        key=lambda item: (
            severity_order.get(item.severity, 9),
            confidence_order.get(item.confidence, 9),
            item.recommendation_id,
        ),
    )
