import unittest

from investigation_ai.adapters import normalize_investigation_context
from investigation_ai.engine import generate_investigation_brief
from investigation_ai.evidence import has_ioc_evidence, normalize_evidence
from investigation_ai.reasoning import (
    analyze_reasoning_context,
    classify_hypothesis_claim,
    detect_contradictions,
    identify_missing_evidence,
)
from investigation_ai.models import InvestigationClaimClassification


class EvidenceReasoningTests(unittest.TestCase):
    def test_evidence_normalization_includes_contextual_ai_analysis(self):
        context = normalize_investigation_context(
            incident={"id": 12, "agent": "endpoint-12", "rule": "Suspicious DNS query"},
            existing_ai_analysis="Review DNS context and host activity.",
        )

        result = normalize_evidence(context)

        self.assertGreaterEqual(len(result.evidence), 2)
        self.assertIn("INCIDENT", result.source_counts)
        self.assertTrue(any(item.evidence_id == "existing-ai-analysis-12" for item in result.evidence))

    def test_ioc_evidence_detection(self):
        context = normalize_investigation_context(
            raw_events=[
                {
                    "id": 1,
                    "rule_description": "Outbound connection to 10.10.10.10 for suspicious.example.com",
                }
            ]
        )
        result = normalize_evidence(context)

        self.assertTrue(has_ioc_evidence(result.evidence))

    def test_contradiction_detection_for_noisy_context(self):
        context = normalize_investigation_context(
            incident={
                "id": 13,
                "rule": "Known noisy package inventory finding",
                "escalation_reason": "suppressed false positive context",
            }
        )
        evidence = normalize_evidence(context).evidence

        contradictions = detect_contradictions(context, evidence)

        self.assertGreaterEqual(len(contradictions), 1)
        self.assertEqual(contradictions[0].evidence_id, "contradiction-noisy-or-benign-context")

    def test_contradiction_detection_for_authentication_without_success(self):
        context = normalize_investigation_context(
            incident={
                "id": 131,
                "rule": "SSH brute force authentication failures",
                "escalation_reason": "No successful login was observed after the failures.",
            }
        )
        evidence = normalize_evidence(context).evidence

        contradictions = detect_contradictions(context, evidence)
        ids = {item.evidence_id for item in contradictions}

        self.assertIn("contradiction-no-successful-login-after-authentication-failure", ids)

    def test_missing_evidence_suggestions_are_contextual(self):
        context = normalize_investigation_context(
            incident={"id": 14, "rule": "SSH brute force authentication failures"}
        )
        evidence = normalize_evidence(context).evidence

        missing = identify_missing_evidence(context, evidence)

        self.assertIn("successful login verification", missing)
        self.assertIn("event timeline", missing)

    def test_reasoning_assessment_summarizes_uncertainty(self):
        context = normalize_investigation_context(
            incident={"id": 15, "rule": "Malware process persistence"},
            raw_events=[{"id": 3, "rule_description": "Malware process persistence"}],
        )
        evidence = normalize_evidence(context).evidence

        assessment = analyze_reasoning_context(context, evidence)

        self.assertIn("process tree and file hash evidence", assessment.missing_evidence)
        self.assertIn("Required evidence is missing for stronger conclusions.", assessment.negative_signals)

    def test_hypothesis_classification_uses_evidence_state(self):
        context = normalize_investigation_context(incident={"id": 16, "rule": "Suspicious activity"})
        evidence = normalize_evidence(context).evidence

        backed = classify_hypothesis_claim(evidence, [], [])
        speculative = classify_hypothesis_claim([], ["process tree"], [])

        self.assertEqual(backed, InvestigationClaimClassification.EVIDENCE_BACKED)
        self.assertEqual(speculative, InvestigationClaimClassification.SPECULATIVE)

    def test_engine_links_hypotheses_to_evidence_and_missing_evidence(self):
        brief = generate_investigation_brief(
            incident={"id": 17, "rule": "SSH brute force authentication failures"}
        )

        self.assertGreaterEqual(len(brief.hypotheses[0].supporting_evidence), 1)
        self.assertIn("successful login verification", brief.hypotheses[0].missing_evidence)
        self.assertNotEqual(
            brief.hypotheses[0].claim_classification,
            InvestigationClaimClassification.UNSUPPORTED,
        )


if __name__ == "__main__":
    unittest.main()
