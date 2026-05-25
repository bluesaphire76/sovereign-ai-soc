import unittest

from investigation_ai.factory import (
    create_empty_investigation_brief,
    create_fallback_investigation_brief,
)
from investigation_ai.models import (
    ConfidenceAssessment,
    EvidenceReference,
    InvestigationBrief,
    InvestigationClaimClassification,
    InvestigationEvidenceType,
    InvestigationFinding,
    InvestigationFindingType,
    InvestigationHypothesis,
    RecommendedAction,
    RecommendedActionApprovalRequirement,
    RecommendedActionCategory,
)
from investigation_ai.validators import (
    normalize_confidence_score,
    validate_investigation_brief,
    validate_recommended_action,
)


class InvestigationModelTests(unittest.TestCase):
    def test_investigation_brief_can_be_instantiated(self):
        brief = InvestigationBrief(
            incident_id=123,
            session_id="session-123",
            summary="Structured investigation is available for analyst review.",
        )

        self.assertEqual(brief.incident_id, 123)
        self.assertEqual(brief.session_id, "session-123")
        self.assertEqual(brief.recommended_actions, [])

    def test_confidence_score_normalization(self):
        self.assertEqual(ConfidenceAssessment(score=150).score, 100)
        self.assertEqual(ConfidenceAssessment(score=-10).score, 0)
        self.assertEqual(normalize_confidence_score(42.4), 42)

    def test_unsupported_findings_are_detected(self):
        finding = InvestigationFinding(
            finding_id="finding-1",
            finding_type=InvestigationFindingType.BEHAVIOR,
            title="Unsupported lateral movement finding",
            description="The investigation cannot support this claim with evidence.",
            claim_classification=InvestigationClaimClassification.UNSUPPORTED,
        )
        brief = InvestigationBrief(
            incident_id=123,
            session_id="session-123",
            summary="Brief with unsupported finding.",
            findings=[finding],
        )

        issue_codes = {issue.code for issue in validate_investigation_brief(brief)}
        self.assertIn("UNSUPPORTED_FINDING_CLAIM", issue_codes)

    def test_recommended_actions_default_to_non_executable(self):
        action = RecommendedAction(
            action_id="action-1",
            title="Review affected host",
            description="Review available host evidence before taking action.",
        )

        self.assertFalse(action.execution_supported)

    def test_operational_actions_require_approval(self):
        action = RecommendedAction(
            action_id="action-2",
            title="Isolate affected host",
            description="Isolate the endpoint from the network.",
            category=RecommendedActionCategory.CONTAINMENT,
            approval_requirement=RecommendedActionApprovalRequirement.NONE,
        )

        issue_codes = {issue.code for issue in validate_recommended_action(action)}
        self.assertIn("OPERATIONAL_ACTION_REQUIRES_APPROVAL", issue_codes)

    def test_hypothesis_requires_evidence_or_explicit_gap(self):
        hypothesis = InvestigationHypothesis(
            hypothesis_id="hypothesis-1",
            title="Credential misuse",
            statement="The activity may represent credential misuse.",
        )
        brief = InvestigationBrief(
            incident_id=123,
            session_id="session-123",
            summary="Brief with an incomplete hypothesis.",
            hypotheses=[hypothesis],
        )

        issue_codes = {issue.code for issue in validate_investigation_brief(brief)}
        self.assertIn("HYPOTHESIS_REQUIRES_EVIDENCE_OR_GAP", issue_codes)

    def test_evidence_backed_finding_requires_evidence_reference(self):
        evidence = EvidenceReference(
            evidence_id="raw-event-1",
            evidence_type=InvestigationEvidenceType.RAW_EVENT,
            source_system="wazuh",
            summary="Source alert supports the finding.",
        )
        finding = InvestigationFinding(
            finding_id="finding-2",
            finding_type=InvestigationFindingType.INDICATOR,
            title="Validated source alert",
            description="The source alert supports investigation review.",
            claim_classification=InvestigationClaimClassification.EVIDENCE_BACKED,
            evidence=[evidence],
        )
        brief = InvestigationBrief(
            incident_id=123,
            session_id="session-123",
            summary="Brief with evidence-backed finding.",
            findings=[finding],
        )

        self.assertEqual(validate_investigation_brief(brief), [])

    def test_factories_return_valid_structured_output(self):
        empty = create_empty_investigation_brief(incident_id=123)
        fallback = create_fallback_investigation_brief(incident_id=123)

        self.assertEqual(validate_investigation_brief(empty), [])
        self.assertEqual(validate_investigation_brief(fallback), [])
        self.assertGreaterEqual(len(fallback.recommended_checks), 1)


if __name__ == "__main__":
    unittest.main()
