import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.engine import generate_investigation_brief
from investigation_ai.expansion import run_single_enrichment_pass
from investigation_ai.models import EvidenceReference, InvestigationEvidenceStrength
from investigation_ai.persistence import (
    InvestigationPersistenceStore,
    deserialize_investigation_brief,
    safe_persist_investigation_brief,
    serialize_investigation_brief,
)
from investigation_ai.retrieval import InvestigationRetrievalLimits
from models import (
    Base,
    InvestigationConfidenceHistoryRecord,
    InvestigationFeedbackRecord,
    InvestigationHypothesisHistoryRecord,
    InvestigationRetrievalHistoryRecord,
    InvestigationSessionRecord,
    InvestigationSnapshotRecord,
)


def sample_context():
    return normalize_investigation_context(
        incident={
            "id": 701,
            "status": "TRIAGED",
            "agent": "endpoint-701",
            "rule": "SSH brute force authentication failures",
            "risk_score": 70,
        }
    )


def retrieved_auth_evidence():
    return EvidenceReference(
        evidence_id="auth-success-endpoint-701",
        source_system="wazuh",
        source_table="raw_events",
        host="endpoint-701",
        summary="Accepted password successful login over ssh on endpoint-701.",
        strength=InvestigationEvidenceStrength.STRONG,
    )


class InvestigationPersistenceTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=engine)
        self.SessionLocal = sessionmaker(bind=engine)
        self.db = self.SessionLocal()
        self.store = InvestigationPersistenceStore(self.db)

    def tearDown(self):
        self.db.close()

    def test_investigation_session_creation(self):
        brief = generate_investigation_brief(context=sample_context(), session_id="session-create")
        result = self.store.persist_investigation_brief(brief, generated_by="unit-test")

        row = self.db.query(InvestigationSessionRecord).filter_by(session_id=brief.session_id).first()
        self.assertTrue(result.success)
        self.assertIsNotNone(row)
        self.assertEqual(row.incident_id, 701)
        self.assertEqual(row.generated_by, "unit-test")
        self.assertEqual(row.investigation_version, 1)

    def test_snapshot_persistence_and_deserialization(self):
        brief = generate_investigation_brief(context=sample_context(), session_id="session-snapshot")
        self.store.persist_investigation_brief(brief)

        snapshot = self.db.query(InvestigationSnapshotRecord).filter_by(session_id=brief.session_id).first()
        restored = deserialize_investigation_brief(snapshot.investigation_payload)

        self.assertEqual(snapshot.evidence_count, len(brief.evidence_used))
        self.assertEqual(restored.session_id, brief.session_id)
        self.assertEqual(restored.incident_id, brief.incident_id)

    def test_hypothesis_history_persistence(self):
        brief = generate_investigation_brief(context=sample_context(), session_id="session-hypothesis")
        self.store.persist_investigation_brief(brief)

        rows = self.db.query(InvestigationHypothesisHistoryRecord).filter_by(session_id=brief.session_id).all()

        self.assertEqual(len(rows), len(brief.hypotheses))
        self.assertEqual(rows[0].investigation_version, 1)
        self.assertGreaterEqual(rows[0].missing_evidence_count, 1)

    def test_confidence_evolution_persistence(self):
        brief = generate_investigation_brief(context=sample_context(), session_id="session-confidence")
        updated_confidence = brief.confidence.model_copy(
            update={"score": min(100, brief.confidence.score + 12)}
        )
        refined = brief.model_copy(update={"confidence": updated_confidence})

        self.store.persist_investigation_brief(brief)
        self.store.persist_investigation_brief(refined)
        rows = (
            self.db.query(InvestigationConfidenceHistoryRecord)
            .filter_by(session_id=brief.session_id)
            .order_by(InvestigationConfidenceHistoryRecord.investigation_version.asc())
            .all()
        )

        self.assertEqual(len(rows), 2)
        self.assertIsNone(rows[0].previous_score)
        self.assertEqual(rows[1].previous_score, brief.confidence.score)
        self.assertEqual(rows[1].new_score, refined.confidence.score)

    def test_retrieval_metadata_persistence(self):
        context = sample_context()
        initial = generate_investigation_brief(context=context, session_id="session-retrieval")
        expansion_result = run_single_enrichment_pass(
            context=context,
            brief=initial,
            retrieval_evidence=[retrieved_auth_evidence()],
            limits=InvestigationRetrievalLimits(max_requests=4),
        )
        refined = generate_investigation_brief(
            context=context,
            session_id=initial.session_id,
            enable_retrieval_enrichment=True,
            retrieval_evidence=[retrieved_auth_evidence()],
            retrieval_limits=InvestigationRetrievalLimits(max_requests=4),
        )

        self.store.persist_investigation_brief(
            refined,
            enrichment_pass_count=1,
            expansion=expansion_result.expansion,
        )
        rows = self.db.query(InvestigationRetrievalHistoryRecord).filter_by(session_id=initial.session_id).all()

        self.assertGreaterEqual(len(rows), 1)
        self.assertEqual(rows[0].enrichment_pass, 1)
        self.assertGreaterEqual(rows[0].evidence_count, 1)

    def test_persistence_fallback_handling(self):
        brief = generate_investigation_brief(context=sample_context(), session_id="session-fallback")
        result = safe_persist_investigation_brief(object(), brief)

        self.assertFalse(result.success)
        self.assertEqual(result.session_id, brief.session_id)
        self.assertIsNotNone(result.error)

    def test_engine_can_persist_session_when_store_session_is_provided(self):
        brief = generate_investigation_brief(
            context=sample_context(),
            session_id="session-engine-integration",
            persistence_session=self.db,
            generated_by="engine-test",
        )

        row = self.db.query(InvestigationSessionRecord).filter_by(session_id=brief.session_id).first()
        snapshot = self.db.query(InvestigationSnapshotRecord).filter_by(session_id=brief.session_id).first()

        self.assertIsNotNone(row)
        self.assertIsNotNone(snapshot)
        self.assertEqual(row.generated_by, "engine-test")

    def test_version_increment_handling(self):
        brief = generate_investigation_brief(context=sample_context(), session_id="session-version")
        first = self.store.persist_investigation_brief(brief)
        second = self.store.persist_investigation_brief(brief)
        snapshots = self.store.list_snapshots(session_id=brief.session_id)

        self.assertEqual(first.investigation_version, 1)
        self.assertEqual(second.investigation_version, 2)
        self.assertEqual([snapshot.investigation_version for snapshot in snapshots], [1, 2])

    def test_snapshot_serialization_round_trip(self):
        brief = generate_investigation_brief(context=sample_context(), session_id="session-round-trip")
        payload = serialize_investigation_brief(brief)
        restored = deserialize_investigation_brief(payload)

        self.assertEqual(restored.session_id, brief.session_id)
        self.assertEqual(restored.confidence.score, brief.confidence.score)

    def test_analyst_feedback_foundation(self):
        brief = generate_investigation_brief(context=sample_context(), session_id="session-feedback")
        self.store.persist_investigation_brief(brief)
        feedback_id = self.store.add_analyst_feedback(
            session_id=brief.session_id,
            analyst="unit_analyst",
            feedback_type="VALIDATION_NOTE",
            feedback_text="Reviewed during unit test.",
            hypothesis_reference=brief.hypotheses[0].hypothesis_id,
        )

        row = self.db.query(InvestigationFeedbackRecord).filter_by(feedback_id=feedback_id).first()
        self.assertIsNotNone(row)
        self.assertEqual(row.analyst, "unit_analyst")


if __name__ == "__main__":
    unittest.main()
