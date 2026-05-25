from __future__ import annotations

from .models import (
    DetectionEngineeringBaseModel,
    DetectionEngineeringCategory,
    DetectionEngineeringConfidence,
    DetectionEngineeringRecommendation,
    DetectionEngineeringReport,
)


class DetectionEngineeringValidationIssue(DetectionEngineeringBaseModel):
    code: str
    message: str
    reference: str | None = None
    severity: str = "WARNING"


IMPLEMENTATION_IMPACTING_CATEGORIES = {
    DetectionEngineeringCategory.NOISE_REDUCTION,
    DetectionEngineeringCategory.THRESHOLD_TUNING,
    DetectionEngineeringCategory.SUPPRESSION_CANDIDATE,
    DetectionEngineeringCategory.CORRELATION_IMPROVEMENT,
    DetectionEngineeringCategory.RULE_DEDUPLICATION,
    DetectionEngineeringCategory.FALSE_POSITIVE_REDUCTION,
}


def validate_recommendation(
    recommendation: DetectionEngineeringRecommendation,
) -> list[DetectionEngineeringValidationIssue]:
    issues: list[DetectionEngineeringValidationIssue] = []

    if not recommendation.evidence and recommendation.confidence != DetectionEngineeringConfidence.SPECULATIVE:
        issues.append(
            DetectionEngineeringValidationIssue(
                code="RECOMMENDATION_REQUIRES_EVIDENCE",
                message="Evidence-backed detection engineering recommendations require supporting evidence.",
                reference=recommendation.recommendation_id,
            )
        )

    if (
        recommendation.category in IMPLEMENTATION_IMPACTING_CATEGORIES
        and not recommendation.approval_required
    ):
        issues.append(
            DetectionEngineeringValidationIssue(
                code="IMPLEMENTATION_RECOMMENDATION_REQUIRES_APPROVAL",
                message="Implementation-impacting detection engineering recommendations require human approval.",
                reference=recommendation.recommendation_id,
                severity="ERROR",
            )
        )

    if recommendation.production_rule_change_supported:
        issues.append(
            DetectionEngineeringValidationIssue(
                code="PRODUCTION_RULE_CHANGE_NOT_SUPPORTED",
                message="Step 7 recommendations must not support direct production rule modification.",
                reference=recommendation.recommendation_id,
                severity="ERROR",
            )
        )

    return issues


def validate_detection_engineering_report(
    report: DetectionEngineeringReport,
) -> list[DetectionEngineeringValidationIssue]:
    issues: list[DetectionEngineeringValidationIssue] = []

    if not report.no_production_rule_changes:
        issues.append(
            DetectionEngineeringValidationIssue(
                code="REPORT_BOUNDARY_VIOLATION",
                message="Detection engineering reports must not modify production rules.",
                reference=report.report_id,
                severity="ERROR",
            )
        )

    for recommendation in report.recommendations:
        issues.extend(validate_recommendation(recommendation))

    return issues
