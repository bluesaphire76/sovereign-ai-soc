import unittest

from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.models import EvidenceReference, InvestigationEvidenceStrength
from investigation_ai.retrieval import (
    InvestigationRetrievalContext,
    InvestigationRetrievalLimits,
    InvestigationRetrievalPriority,
    InvestigationRetrievalStatus,
    InvestigationRetrievalType,
    build_retrieval_requests,
    execute_retrieval_request,
    prioritize_retrieval_requests,
    run_bounded_retrieval,
)


def base_context():
    return normalize_investigation_context(
        incident={
            "id": 51,
            "agent": "endpoint-51",
            "rule": "SSH brute force authentication failures",
        }
    )


def candidate_login_evidence():
    return EvidenceReference(
        evidence_id="raw-event-login-success",
        source_system="wazuh",
        source_table="raw_events",
        host="endpoint-51",
        summary="Accepted password successful login for endpoint-51 over ssh.",
        strength=InvestigationEvidenceStrength.STRONG,
    )


class InvestigationRetrievalTests(unittest.TestCase):
    def test_retrieval_request_generation_from_missing_evidence(self):
        context = base_context()
        requests = build_retrieval_requests(
            context=context,
            missing_evidence=["successful login verification", "event timeline"],
            limits=InvestigationRetrievalLimits(max_requests=4),
        )
        request_types = {request.request_type for request in requests}

        self.assertIn(InvestigationRetrievalType.AUTH_ACTIVITY, request_types)
        self.assertIn(InvestigationRetrievalType.TIMELINE_EXPANSION, request_types)
        self.assertLessEqual(len(requests), 4)

    def test_retrieval_prioritization_is_deterministic(self):
        context = base_context()
        requests = build_retrieval_requests(
            context=context,
            missing_evidence=[
                "DNS and outbound network activity",
                "successful login verification",
            ],
        )
        prioritized = prioritize_retrieval_requests(list(reversed(requests)))

        self.assertEqual(prioritized[0].priority, InvestigationRetrievalPriority.HIGH)
        self.assertEqual(
            [request.request_id for request in prioritized],
            [request.request_id for request in prioritize_retrieval_requests(prioritized)],
        )

    def test_retrieval_boundaries_are_enforced(self):
        context = base_context()
        requests = build_retrieval_requests(
            context=context,
            missing_evidence=[
                "successful login verification",
                "event timeline",
                "DNS and outbound network activity",
                "sudo or privilege escalation logs",
            ],
            limits=InvestigationRetrievalLimits(max_requests=2),
        )

        self.assertLessEqual(len(requests), 2)

    def test_global_object_limit_truncates_result_evidence(self):
        context = base_context()
        candidates = [
            EvidenceReference(
                evidence_id=f"auth-success-{index}",
                source_system="wazuh",
                source_table="raw_events",
                host="endpoint-51",
                summary=f"Accepted password successful login over ssh event {index}.",
                strength=InvestigationEvidenceStrength.STRONG,
            )
            for index in range(4)
        ]
        expansion = run_bounded_retrieval(
            context=context,
            missing_evidence=["successful login verification"],
            candidate_evidence=candidates,
            limits=InvestigationRetrievalLimits(max_objects=2),
        )

        self.assertLessEqual(sum(len(result.evidence) for result in expansion.results), 2)
        self.assertLessEqual(len(expansion.results[0].evidence), 2)
        self.assertIn("max_objects", expansion.limits_applied)

    def test_retrieval_depth_limit_skips_request(self):
        context = base_context()
        request = build_retrieval_requests(
            context=context,
            missing_evidence=["successful login verification"],
        )[0].model_copy(update={"depth": 3})
        result = execute_retrieval_request(
            request,
            InvestigationRetrievalContext(
                base_context=context,
                candidate_evidence=[candidate_login_evidence()],
                limits=InvestigationRetrievalLimits(max_depth=1),
            ),
        )

        self.assertEqual(result.status, InvestigationRetrievalStatus.SKIPPED)
        self.assertEqual(result.skipped_reason, "max_depth_exceeded")

    def test_retrieval_failure_fallback(self):
        context = base_context()
        request = build_retrieval_requests(
            context=context,
            missing_evidence=["successful login verification"],
        )[0]

        def failing_fetcher(_request, _context):
            raise TimeoutError("timeout")

        result = execute_retrieval_request(
            request,
            InvestigationRetrievalContext(base_context=context),
            fetcher=failing_fetcher,
        )

        self.assertEqual(result.status, InvestigationRetrievalStatus.FAILED)
        self.assertIn("timeout", result.failures)

    def test_bounded_retrieval_returns_matching_candidate_evidence(self):
        context = base_context()
        expansion = run_bounded_retrieval(
            context=context,
            missing_evidence=["successful login verification"],
            candidate_evidence=[candidate_login_evidence()],
        )

        self.assertGreaterEqual(len(expansion.results), 1)
        self.assertTrue(any(result.evidence for result in expansion.results))
        self.assertTrue(any(item.evidence_id == "raw-event-login-success" for item in expansion.merged_evidence))

    def test_retrieval_is_repeatable(self):
        context = base_context()
        first = run_bounded_retrieval(
            context=context,
            missing_evidence=["successful login verification"],
            candidate_evidence=[candidate_login_evidence()],
        )
        second = run_bounded_retrieval(
            context=context,
            missing_evidence=["successful login verification"],
            candidate_evidence=[candidate_login_evidence()],
        )

        self.assertEqual(first.audit, second.audit)
        self.assertEqual(
            [item.evidence_id for item in first.merged_evidence],
            [item.evidence_id for item in second.merged_evidence],
        )


if __name__ == "__main__":
    unittest.main()
