import unittest

from detection_engineering.analyzer import analyze_detection_engineering, normalize_detection_engineering_context
from detection_engineering.scoring import calculate_noise_score, calculate_recurrence_score
from detection_engineering.validators import validate_detection_engineering_report


class DetectionEngineeringRecommendationTests(unittest.TestCase):
    def test_deterministic_scoring_repeatability(self):
        first = calculate_noise_score(
            alert_count=50,
            incident_count=1,
            suppressed_count=60,
            false_positive_count=3,
            low_severity_count=45,
        )
        second = calculate_noise_score(
            alert_count=50,
            incident_count=1,
            suppressed_count=60,
            false_positive_count=3,
            low_severity_count=45,
        )

        self.assertEqual(first, second)
        self.assertEqual(
            calculate_recurrence_score(alert_count=50, incident_count=1),
            calculate_recurrence_score(alert_count=50, incident_count=1),
        )

    def test_report_recommendations_are_evidence_backed_or_speculative(self):
        context = normalize_detection_engineering_context(
            event_aggregates=[
                {
                    "id": "agg-1",
                    "source": "wazuh",
                    "rule_id": "100900",
                    "rule_description": "Repeated rule without MITRE",
                    "level": 8,
                    "count": 30,
                }
            ]
        )
        report = analyze_detection_engineering(context)

        self.assertEqual(validate_detection_engineering_report(report), [])
        self.assertTrue(
            all(recommendation.evidence or recommendation.confidence.value == "SPECULATIVE" for recommendation in report.recommendations)
        )

    def test_no_production_rule_modification_occurs(self):
        context = normalize_detection_engineering_context(
            event_aggregates=[
                {
                    "id": "agg-2",
                    "source": "wazuh",
                    "rule_id": "100901",
                    "rule_description": "High volume rule",
                    "level": 3,
                    "severity_bucket": "LOW",
                    "count": 80,
                }
            ]
        )
        report = analyze_detection_engineering(context)

        self.assertTrue(report.no_production_rule_changes)
        self.assertTrue(
            all(not recommendation.production_rule_change_supported for recommendation in report.recommendations)
        )


if __name__ == "__main__":
    unittest.main()
