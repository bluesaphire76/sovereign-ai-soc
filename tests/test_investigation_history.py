import unittest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.engine import generate_investigation_brief
from investigation_ai.expansion import run_single_enrichment_pass
from investigation_ai.models import EvidenceReference, InvestigationEvidenceStrength
from investigation_ai.persistence import InvestigationPersistenceStore
from investigation_ai.retrieval import InvestigationRetrievalLimits
from models import Base


def context_for_history(incident_id=801):
    return normalize_investigation_context(
        incident={
            "id": incident_id,
            "status": "TRIAGED",
            "agent": f"endpoint-{incident_id}",
            "rule": "Suspicious authentication pattern",
            "risk_score": 64,
        }
    )


def related_evidence(incident_id=801):
    return EvidenceReference(
        evidence_id=f"history-auth-success-{incident_id}",
        source_system="wazuh",
        source_table="raw_events",
        host=f"endpoint-{incident_id}",
        summary=f"Accepted password successful login over ssh on endpoint-{incident_id}.",
        strength=InvestigationEvidenceStrength.STRONG,
    )


class InvestigationHistoryTests(unittest.TestCase):
    def setUp(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=engine)
        self.SessionLocal = sessionmaker(bind=engine)
        self.db = self.SessionLocal()
        self.store = InvestigationPersistenceStore(self.db)

    def tearDown(self):
        self.db.close()

    def test_history_lists_sessions_for_incident(self):
        first = generate_investigation_brief(
            context=context_for_history(),
            session_id="history-session-1",
        )
        second = generate_investigation_brief(
            context=context_for_history(),
            session_id="history-session-2",
        )
        self.store.persist_investigation_brief(first)
        self.store.persist_investigation_brief(second, enrichment_pass_count=1)

        history = self.store.list_investigation_history(incident_id=801)

        self.assertEqual({item.session_id for item in history}, {"history-session-1", "history-session-2"})
        self.assertTrue(any(item.enrichment_pass_count == 1 for item in history))

    def test_latest_brief_returns_highest_version_snapshot(self):
        brief = generate_investigation_brief(
            context=context_for_history(),
            session_id="history-latest",
        )
        refined = brief.model_copy(
            update={"summary": "Refined investigation summary for replay validation."}
        )
        self.store.persist_investigation_brief(brief)
        self.store.persist_investigation_brief(refined)

        latest = self.store.latest_brief(session_id=brief.session_id)

        self.assertEqual(latest.summary, "Refined investigation summary for replay validation.")

    def test_retrieval_history_order_is_replay_friendly(self):
        context = context_for_history()
        initial = generate_investigation_brief(context=context, session_id="history-retrieval")
        expansion_result = run_single_enrichment_pass(
            context=context,
            brief=initial,
            retrieval_evidence=[related_evidence()],
            limits=InvestigationRetrievalLimits(max_requests=4),
        )
        refined = generate_investigation_brief(
            context=context,
            session_id=initial.session_id,
            enable_retrieval_enrichment=True,
            retrieval_evidence=[related_evidence()],
            retrieval_limits=InvestigationRetrievalLimits(max_requests=4),
        )

        self.store.persist_investigation_brief(initial)
        self.store.persist_investigation_brief(
            refined,
            enrichment_pass_count=1,
            expansion=expansion_result.expansion,
        )
        retrieval_history = self.store.list_retrieval_history(session_id=initial.session_id)

        self.assertTrue(retrieval_history)
        self.assertEqual(
            [row.investigation_version for row in retrieval_history],
            sorted(row.investigation_version for row in retrieval_history),
        )
        self.assertTrue(all(row.retrieval_type for row in retrieval_history))

    def test_persistence_is_deterministic_for_counts(self):
        brief = generate_investigation_brief(
            context=context_for_history(),
            session_id="history-deterministic",
        )
        self.store.persist_investigation_brief(brief)
        self.store.persist_investigation_brief(brief)
        snapshots = self.store.list_snapshots(session_id=brief.session_id)

        self.assertEqual(len(snapshots), 2)
        self.assertEqual(snapshots[0].evidence_count, snapshots[1].evidence_count)
        self.assertEqual(snapshots[0].hypothesis_count, snapshots[1].hypothesis_count)


if __name__ == "__main__":
    unittest.main()
