import unittest

from detection_engineering.analyzer import (
    analyze_detection_engineering,
    normalize_detection_engineering_context,
)
from detection_engineering.models import DetectionEngineeringCategory


def aggregate(rule_id="100213", count=40, level=3, description="Noisy operational baseline"):
    return {
        "id": f"agg-{rule_id}",
        "source": "wazuh",
        "rule_id": rule_id,
        "rule_description": description,
        "level": level,
        "severity_bucket": "LOW" if level <= 3 else "MEDIUM",
        "count": count,
        "agent": "endpoint-01",
    }


def incident(rule_id="100210", status="OPEN", mitre=None, description="Synthetic brute force"):
    return {
        "id": f"incident-{rule_id}",
        "source": "wazuh",
        "rule_id": rule_id,
        "rule_description": description,
        "status": status,
        "mitre": mitre,
        "agent": "endpoint-01",
    }


class DetectionEngineeringAnalyzerTests(unittest.TestCase):
    def test_noise_reduction_candidate_generation(self):
        context = normalize_detection_engineering_context(
            event_aggregates=[aggregate(count=30)],
            suppression_outcomes=[
                {
                    "id": "noise-1",
                    "source": "wazuh",
                    "rule_id": "100213",
                    "rule_description": "Noisy operational baseline",
                    "decision": "SUPPRESS",
                    "policy_id": "LOW_VALUE_OPERATIONAL_NOISE",
                    "count": 80,
                }
            ],
        )

        report = analyze_detection_engineering(context)
        categories = {recommendation.category for recommendation in report.recommendations}

        self.assertIn(DetectionEngineeringCategory.SUPPRESSION_CANDIDATE, categories)
        self.assertTrue(report.no_production_rule_changes)

    def test_threshold_tuning_candidate_generation(self):
        context = normalize_detection_engineering_context(
            event_aggregates=[aggregate(rule_id="100300", count=60, description="High volume login noise")],
            incidents=[incident(rule_id="100300", description="High volume login noise")],
        )

        report = analyze_detection_engineering(context)
        categories = {recommendation.category for recommendation in report.recommendations}

        self.assertIn(DetectionEngineeringCategory.THRESHOLD_TUNING, categories)

    def test_detection_gap_candidate_generation(self):
        context = normalize_detection_engineering_context(
            event_aggregates=[
                aggregate(rule_id="100400", count=35, level=8, description="Recurring suspicious activity")
            ],
        )

        report = analyze_detection_engineering(context)
        categories = {recommendation.category for recommendation in report.recommendations}

        self.assertIn(DetectionEngineeringCategory.MITRE_ENRICHMENT, categories)
        self.assertTrue(report.gaps)

    def test_correlation_opportunity_generation(self):
        context = normalize_detection_engineering_context(
            event_aggregates=[aggregate(rule_id="100500", count=25, level=8, description="Repeated auth chain")],
            incidents=[
                incident(rule_id="100500", description="Repeated auth chain", mitre="T1110"),
                incident(rule_id="100500", description="Repeated auth chain", mitre="T1110"),
            ],
        )

        report = analyze_detection_engineering(context)
        categories = {recommendation.category for recommendation in report.recommendations}

        self.assertIn(DetectionEngineeringCategory.CORRELATION_IMPROVEMENT, categories)
        self.assertTrue(report.correlation_opportunities)

    def test_analyzer_handles_missing_data(self):
        context = normalize_detection_engineering_context()
        report = analyze_detection_engineering(context)

        self.assertEqual(report.rule_assessments, [])
        self.assertEqual(report.recommendations, [])
        self.assertTrue(report.no_production_rule_changes)


if __name__ == "__main__":
    unittest.main()
