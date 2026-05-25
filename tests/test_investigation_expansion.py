import unittest

from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.engine import generate_investigation_brief
from investigation_ai.expansion import missing_evidence_from_brief, run_single_enrichment_pass
from investigation_ai.models import EvidenceReference, InvestigationEvidenceStrength
from investigation_ai.retrieval import InvestigationRetrievalLimits


def investigation_context():
    return normalize_investigation_context(
        incident={
            "id": 61,
            "agent": "endpoint-61",
            "rule": "SSH brute force authentication failures",
        }
    )


def retrieved_auth_evidence():
    return EvidenceReference(
        evidence_id="auth-success-endpoint-61",
        source_system="wazuh",
        source_table="raw_events",
        host="endpoint-61",
        summary="Accepted password successful login over ssh on endpoint-61.",
        strength=InvestigationEvidenceStrength.STRONG,
    )


class InvestigationExpansionTests(unittest.TestCase):
    def test_missing_evidence_drives_enrichment_pass(self):
        context = investigation_context()
        brief = generate_investigation_brief(context=context)

        missing = missing_evidence_from_brief(brief)
        expansion = run_single_enrichment_pass(
            context=context,
            brief=brief,
            retrieval_evidence=[retrieved_auth_evidence()],
            limits=InvestigationRetrievalLimits(max_requests=4),
        )

        self.assertIn("successful login verification", missing)
        self.assertTrue(expansion.enrichment_performed)
        self.assertGreaterEqual(len(expansion.retrieved_evidence), 1)

    def test_engine_can_refine_brief_after_bounded_enrichment(self):
        context = investigation_context()
        initial = generate_investigation_brief(context=context)
        refined = generate_investigation_brief(
            context=context,
            enable_retrieval_enrichment=True,
            retrieval_evidence=[retrieved_auth_evidence()],
            retrieval_limits=InvestigationRetrievalLimits(max_requests=4),
        )

        self.assertGreater(len(refined.evidence_used), len(initial.evidence_used))
        self.assertGreaterEqual(refined.confidence.score, initial.confidence.score)
        self.assertTrue(
            any(
                limitation.limitation_id == "investigation-retrieval-enrichment-applied"
                for limitation in refined.limitations
            )
        )
        self.assertTrue(
            any(check.check_id == "check-retrieved-evidence" for check in refined.recommended_checks)
        )

    def test_enrichment_without_candidates_preserves_stable_brief(self):
        context = investigation_context()
        initial = generate_investigation_brief(context=context)
        refined = generate_investigation_brief(
            context=context,
            enable_retrieval_enrichment=True,
            retrieval_evidence=[],
            retrieval_limits=InvestigationRetrievalLimits(max_requests=4),
        )

        self.assertEqual(len(refined.evidence_used), len(initial.evidence_used))
        self.assertEqual(refined.confidence.score, initial.confidence.score)

    def test_single_enrichment_pass_does_not_recurse(self):
        context = investigation_context()
        refined = generate_investigation_brief(
            context=context,
            enable_retrieval_enrichment=True,
            retrieval_evidence=[retrieved_auth_evidence()],
            retrieval_limits=InvestigationRetrievalLimits(max_depth=1, max_requests=4),
        )

        retrieval_checks = [
            check for check in refined.recommended_checks if check.check_id == "check-retrieved-evidence"
        ]
        self.assertEqual(len(retrieval_checks), 1)

    def test_enrichment_is_repeatable(self):
        context = investigation_context()
        first = generate_investigation_brief(
            context=context,
            enable_retrieval_enrichment=True,
            retrieval_evidence=[retrieved_auth_evidence()],
            retrieval_limits=InvestigationRetrievalLimits(max_requests=4),
        )
        second = generate_investigation_brief(
            context=context,
            enable_retrieval_enrichment=True,
            retrieval_evidence=[retrieved_auth_evidence()],
            retrieval_limits=InvestigationRetrievalLimits(max_requests=4),
        )

        self.assertEqual(
            [item.evidence_id for item in first.evidence_used],
            [item.evidence_id for item in second.evidence_used],
        )
        self.assertEqual(first.confidence.score, second.confidence.score)


if __name__ == "__main__":
    unittest.main()
