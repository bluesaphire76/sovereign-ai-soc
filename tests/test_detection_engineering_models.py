import unittest

from detection_engineering.models import (
    DetectionEngineeringCategory,
    DetectionEngineeringConfidence,
    DetectionEngineeringFinding,
    DetectionEngineeringRecommendation,
    DetectionEngineeringSeverity,
    DetectionEngineeringSignal,
    DetectionRecommendationStatus,
)
from detection_engineering.recommendations import recommendation_from_finding
from detection_engineering.validators import validate_recommendation


class DetectionEngineeringModelTests(unittest.TestCase):
    def test_recommendation_model_enforces_governance(self):
        recommendation = DetectionEngineeringRecommendation(
            recommendation_id="rec-1",
            title="Review suppression policy",
            description="Review noisy rule behavior before any change.",
            category=DetectionEngineeringCategory.SUPPRESSION_CANDIDATE,
            severity=DetectionEngineeringSeverity.MEDIUM,
            confidence=DetectionEngineeringConfidence.MEDIUM,
            rationale="Repeated low-value evidence is present.",
            expected_benefit="Reduced alert fatigue after validation.",
            operational_risk="Suppression may hide relevant signals.",
            implementation_notes="Validate with historical data before implementation.",
            approval_required=False,
            production_rule_change_supported=True,
        )

        self.assertTrue(recommendation.approval_required)
        self.assertFalse(recommendation.production_rule_change_supported)
        self.assertEqual(recommendation.status, DetectionRecommendationStatus.PROPOSED)

    def test_unsupported_finding_is_downgraded_to_speculative_recommendation(self):
        finding = DetectionEngineeringFinding(
            finding_id="finding-unsupported",
            title="Potential tuning issue",
            description="The rule may require review.",
            category=DetectionEngineeringCategory.THRESHOLD_TUNING,
            severity=DetectionEngineeringSeverity.LOW,
            confidence=DetectionEngineeringConfidence.HIGH,
            rationale="The claim lacks supporting evidence.",
            unsupported=True,
        )

        recommendation = recommendation_from_finding(finding)

        self.assertEqual(recommendation.confidence, DetectionEngineeringConfidence.SPECULATIVE)
        self.assertTrue(recommendation.approval_required)
        self.assertFalse(recommendation.production_rule_change_supported)

    def test_evidence_backed_recommendation_validates(self):
        signal = DetectionEngineeringSignal(
            signal_id="signal-1",
            source_type="security_alert",
            source_system="wazuh",
            rule_id="5710",
            count=5,
        )
        recommendation = DetectionEngineeringRecommendation(
            recommendation_id="rec-2",
            title="Review rule quality",
            description="Rule shows repeated behavior.",
            category=DetectionEngineeringCategory.RULE_QUALITY,
            severity=DetectionEngineeringSeverity.LOW,
            confidence=DetectionEngineeringConfidence.MEDIUM,
            evidence=[signal],
            rationale="Evidence exists.",
            expected_benefit="Improved detection quality.",
            operational_risk="Low risk.",
            implementation_notes="Review only.",
        )

        self.assertEqual(validate_recommendation(recommendation), [])


if __name__ == "__main__":
    unittest.main()
