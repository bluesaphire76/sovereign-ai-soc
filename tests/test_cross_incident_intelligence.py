import unittest
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.engine import generate_investigation_brief
from investigation_ai.intelligence import (
    SimilarityAnalysisLimits,
    build_historical_investigation_context,
)
from investigation_ai.persistence import InvestigationPersistenceStore
from models import Base, InvestigationSimilarityHistoryRecord


def incident_context(
    incident_id,
    *,
    host="endpoint-01",
    user="alice",
    source_ip="10.0.0.5",
    mitre="T1110",
    rule_id="5710",
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
        correlation_summary={"related_events": 3},
        timeline=[{"timestamp": timestamp, "kind": "incident"}],
    )


class CrossIncidentIntelligenceTests(unittest.TestCase):
    def test_historical_enrichment_stability(self):
        current = incident_context(100)
        historical = [incident_context(90), incident_context(80, mitre="T1548", source_ip="10.0.0.99")]

        context = build_historical_investigation_context(
            current_context=current,
            historical_contexts=historical,
            limits=SimilarityAnalysisLimits(min_score=35),
        )

        self.assertGreaterEqual(len(context.matches), 1)
        self.assertEqual(context.matches[0].incident_id, 90)
        self.assertIn("threshold", context.rationale)

    def test_recurring_entity_tracking(self):
        current = incident_context(100, source_ip="10.0.0.5")
        historical = [
            incident_context(90, source_ip="10.0.0.5"),
            incident_context(91, source_ip="10.0.0.5", host="endpoint-02"),
        ]
        context = build_historical_investigation_context(
            current_context=current,
            historical_contexts=historical,
            limits=SimilarityAnalysisLimits(min_score=35),
        )

        entities = {(entity.entity_type.value, entity.value) for entity in context.recurring_entities}

        self.assertIn(("SOURCE_IP", "10.0.0.5"), entities)

    def test_similarity_boundary_enforcement(self):
        current = incident_context(100)
        historical = [incident_context(index) for index in range(1, 8)]
        context = build_historical_investigation_context(
            current_context=current,
            historical_contexts=historical,
            limits=SimilarityAnalysisLimits(max_related_incidents=2, min_score=35),
        )

        self.assertEqual(len(context.matches), 2)
        self.assertIn("max_related_incidents", context.boundaries_applied)

    def test_similarity_depth_zero_skips_analysis(self):
        current = incident_context(100)
        context = build_historical_investigation_context(
            current_context=current,
            historical_contexts=[incident_context(90)],
            limits=SimilarityAnalysisLimits(max_similarity_depth=0),
        )

        self.assertEqual(context.matches, [])
        self.assertIn("max_similarity_depth", context.boundaries_applied)

    def test_similarity_failure_fallback(self):
        current = incident_context(100)
        with patch("investigation_ai.intelligence.build_similarity_match", side_effect=RuntimeError("boom")):
            context = build_historical_investigation_context(
                current_context=current,
                historical_contexts=[incident_context(90)],
                limits=SimilarityAnalysisLimits(min_score=0),
            )

        self.assertEqual(context.matches, [])
        self.assertIn("RuntimeError", context.failures)

    def test_engine_enriches_brief_with_historical_context(self):
        current = incident_context(100)
        brief = generate_investigation_brief(
            context=current,
            enable_cross_incident_intelligence=True,
            historical_contexts=[incident_context(90)],
            similarity_limits=SimilarityAnalysisLimits(min_score=35),
        )

        self.assertTrue(
            any(finding.finding_id == "finding-cross-incident-context" for finding in brief.findings)
        )
        self.assertTrue(
            any(check.check_id == "check-historical-similarity-context" for check in brief.recommended_checks)
        )
        self.assertTrue(
            any("historical similarity" in factor for factor in brief.confidence.scoring_factors)
        )

    def test_similarity_metadata_persistence(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=engine)
        db = sessionmaker(bind=engine)()
        try:
            current = incident_context(100)
            historical_context = build_historical_investigation_context(
                current_context=current,
                historical_contexts=[incident_context(90)],
                limits=SimilarityAnalysisLimits(min_score=35),
            )
            brief = generate_investigation_brief(context=current, session_id="similarity-session")
            store = InvestigationPersistenceStore(db)

            store.persist_investigation_brief(
                brief,
                historical_context=historical_context,
            )
            rows = db.query(InvestigationSimilarityHistoryRecord).filter_by(session_id=brief.session_id).all()

            self.assertEqual(len(rows), len(historical_context.matches))
            self.assertEqual(rows[0].related_incident_id, 90)
            self.assertGreaterEqual(rows[0].similarity_score, 35)
        finally:
            db.close()

    def test_cross_incident_intelligence_is_repeatable(self):
        current = incident_context(100)
        historical = [incident_context(90), incident_context(91, host="endpoint-02")]

        first = build_historical_investigation_context(
            current_context=current,
            historical_contexts=historical,
            limits=SimilarityAnalysisLimits(min_score=35),
        )
        second = build_historical_investigation_context(
            current_context=current,
            historical_contexts=historical,
            limits=SimilarityAnalysisLimits(min_score=35),
        )

        self.assertEqual(
            [match.model_dump() for match in first.matches],
            [match.model_dump() for match in second.matches],
        )


if __name__ == "__main__":
    unittest.main()
