import unittest

from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.similarity import (
    SimilaritySignalType,
    SimilarityStrength,
    build_similarity_match,
    build_similarity_profile,
    explain_similarity,
)


def context(
    incident_id,
    *,
    host="endpoint-01",
    user="alice",
    source_ip="10.0.0.5",
    rule_id="5710",
    mitre="T1110",
    timestamp="2026-05-20T10:00:00+00:00",
    rule="SSH brute force authentication failures",
):
    return normalize_investigation_context(
        incident={
            "id": incident_id,
            "agent": host,
            "user": user,
            "source_ip": source_ip,
            "rule_id": rule_id,
            "rule": rule,
            "mitre": mitre,
            "timestamp": timestamp,
        },
        raw_events=[
            {
                "id": incident_id * 10,
                "agent": host,
                "rule_id": rule_id,
                "rule_description": rule,
                "event_timestamp": timestamp,
            }
        ],
    )


class SimilarityScoringTests(unittest.TestCase):
    def test_similarity_score_generation(self):
        current = build_similarity_profile(context(1))
        candidate = build_similarity_profile(context(2))

        score = explain_similarity(current, candidate)

        self.assertGreaterEqual(score.score, 70)
        self.assertEqual(score.strength, SimilarityStrength.STRONG)
        self.assertTrue(score.signals)

    def test_mitre_overlap_scoring(self):
        current = build_similarity_profile(context(1, mitre="T1110"))
        candidate = build_similarity_profile(context(2, mitre="T1110", host="endpoint-02", source_ip="10.0.0.99"))

        score = explain_similarity(current, candidate)
        signal_types = {signal.signal_type for signal in score.signals}

        self.assertIn(SimilaritySignalType.MITRE_OVERLAP, signal_types)

    def test_entity_overlap_scoring(self):
        current = build_similarity_profile(context(1, source_ip="10.0.0.10", user="svc-deploy"))
        candidate = build_similarity_profile(context(2, source_ip="10.0.0.10", user="svc-deploy", mitre="T1548"))

        score = explain_similarity(current, candidate)
        signal_types = {signal.signal_type for signal in score.signals}

        self.assertIn(SimilaritySignalType.SAME_SOURCE_IP, signal_types)
        self.assertIn(SimilaritySignalType.SAME_USER, signal_types)

    def test_timeline_similarity_handling(self):
        current = build_similarity_profile(context(1, timestamp="2026-05-20T10:00:00+00:00"))
        candidate = build_similarity_profile(context(2, timestamp="2026-05-20T13:00:00+00:00"))

        score = explain_similarity(current, candidate, max_time_window_days=1)
        signal_types = {signal.signal_type for signal in score.signals}

        self.assertIn(SimilaritySignalType.TIMELINE_PROXIMITY, signal_types)

    def test_similarity_explanation_generation(self):
        current = build_similarity_profile(context(1))
        candidate = build_similarity_profile(context(2))
        match = build_similarity_match(current, candidate)

        self.assertIn("MITRE_OVERLAP", match.rationale)
        self.assertIn("t1110", match.matched_mitre)

    def test_scoring_is_deterministic(self):
        current = build_similarity_profile(context(1))
        candidate = build_similarity_profile(context(2))

        first = explain_similarity(current, candidate)
        second = explain_similarity(current, candidate)

        self.assertEqual(first.score, second.score)
        self.assertEqual(
            [signal.model_dump() for signal in first.signals],
            [signal.model_dump() for signal in second.signals],
        )


if __name__ == "__main__":
    unittest.main()
