import unittest

from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.confidence import calculate_confidence
from investigation_ai.evidence import normalize_evidence_references
from investigation_ai.models import EvidenceReference, InvestigationEvidenceStrength


def correlated_context():
    return normalize_investigation_context(
        incident={
            "id": 44,
            "agent": "endpoint-44",
            "rule": "Repeated authentication failures",
            "mitre": "T1110",
            "correlation_score": 80,
        },
        raw_events=[
            {
                "id": 1,
                "agent": "endpoint-44",
                "rule_description": "Repeated authentication failures from 10.0.0.15",
            }
        ],
        security_alerts=[
            {
                "id": 2,
                "agent": "endpoint-44",
                "rule_description": "Repeated authentication failures from 10.0.0.15",
            }
        ],
        correlation_summary={
            "related_events": 4,
            "matched_patterns": ["authentication_failure_pattern"],
        },
        timeline=[
            {"timestamp": "2026-05-20T10:00:00+00:00"},
            {"timestamp": "2026-05-20T10:03:00+00:00"},
        ],
    )


class ConfidenceEngineTests(unittest.TestCase):
    def test_confidence_uses_positive_signals(self):
        context = correlated_context()
        evidence = normalize_evidence_references(context)

        confidence = calculate_confidence(
            context=context,
            supporting_evidence=evidence,
            missing_evidence=[],
            contradictory_evidence=[],
        )

        self.assertGreaterEqual(confidence.score, 75)
        self.assertIn("Multiple correlated events are present.", confidence.positive_signals)
        self.assertTrue(confidence.scoring_factors)

    def test_missing_and_contradictory_evidence_reduce_confidence(self):
        context = correlated_context()
        evidence = normalize_evidence_references(context)
        baseline = calculate_confidence(context=context, supporting_evidence=evidence)
        contradiction = EvidenceReference(
            evidence_id="contradiction-1",
            summary="False positive context requires analyst review.",
            strength=InvestigationEvidenceStrength.CONTEXTUAL,
        )

        reduced = calculate_confidence(
            context=context,
            supporting_evidence=evidence,
            missing_evidence=["successful login verification", "process tree"],
            contradictory_evidence=[contradiction],
        )

        self.assertLess(reduced.score, baseline.score)
        self.assertIn("Contradictory evidence reduces confidence.", reduced.negative_signals)

    def test_unsupported_claims_apply_strong_penalty(self):
        context = correlated_context()
        evidence = normalize_evidence_references(context)

        baseline = calculate_confidence(context=context, supporting_evidence=evidence)
        penalized = calculate_confidence(
            context=context,
            supporting_evidence=evidence,
            unsupported_claim_count=2,
        )

        self.assertLess(penalized.score, baseline.score)
        self.assertIn("Unsupported claims were downgraded.", penalized.negative_signals)

    def test_scoring_is_deterministic(self):
        context = correlated_context()
        evidence = normalize_evidence_references(context)

        first = calculate_confidence(context=context, supporting_evidence=evidence)
        second = calculate_confidence(context=context, supporting_evidence=evidence)

        self.assertEqual(first.score, second.score)
        self.assertEqual(first.scoring_factors, second.scoring_factors)

    def test_low_evidence_context_stays_low_confidence(self):
        context = normalize_investigation_context(incident_id=77)
        confidence = calculate_confidence(context=context, supporting_evidence=[])

        self.assertLess(confidence.score, 40)
        self.assertEqual(confidence.positive_signals, [])


if __name__ == "__main__":
    unittest.main()
