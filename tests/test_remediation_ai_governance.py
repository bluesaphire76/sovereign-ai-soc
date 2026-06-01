from ai_governance.models import AIEvidenceCoverage, AIGovernanceStatus
from ai_governance.policy import assess_remediation_output_governance


def _plan_with_evidence():
    return {
        "recommended_actions": [
            {
                "action_type": "COLLECT_FORENSIC_EVIDENCE",
                "title": "Collect endpoint evidence",
                "approval_requirement": "ANALYST_APPROVAL",
                "risk_level": "LOW",
                "evidence_basis": ["incident rule", "affected host"],
            }
        ],
        "human_validation_required": True,
        "limitations": ["Operational impact still requires analyst validation."],
        "assumptions": [],
        "unsupported_claims": [],
    }


def test_remediation_governance_requires_human_review_even_when_evidence_backed():
    assessment = assess_remediation_output_governance(
        plan=_plan_with_evidence(),
        source="local_ai",
        execution_supported=False,
    )

    payload = assessment.to_payload()

    assert payload["human_review_required"] is True
    assert payload["evidence_coverage"] == AIEvidenceCoverage.HIGH.value
    assert "AI_GENERATED" in payload["safety_labels"]
    assert "HUMAN_REVIEW_REQUIRED" in payload["safety_labels"]
    assert "NO_EXECUTION" in payload["safety_labels"]


def test_missing_action_evidence_forces_visible_review_warning():
    plan = _plan_with_evidence()
    plan["recommended_actions"][0]["evidence_basis"] = []

    assessment = assess_remediation_output_governance(
        plan=plan,
        source="local_ai",
        execution_supported=False,
    )

    payload = assessment.to_payload()

    assert payload["status"] == AIGovernanceStatus.REQUIRES_REVIEW.value
    assert payload["evidence_coverage"] == AIEvidenceCoverage.NONE.value
    assert any("no evidence_basis" in warning for warning in payload["policy_warnings"])


def test_fallback_output_is_low_confidence_and_review_required():
    assessment = assess_remediation_output_governance(
        plan=_plan_with_evidence(),
        source="deterministic_fallback",
        execution_supported=False,
    )

    payload = assessment.to_payload()

    assert payload["confidence_score"] < 70
    assert payload["evidence_coverage"] == AIEvidenceCoverage.LOW.value
    assert payload["human_review_required"] is True
    assert "FALLBACK_GENERATED" in payload["safety_labels"]


def test_unsupported_claims_are_surfaced_not_suppressed():
    plan = _plan_with_evidence()
    plan["unsupported_claims"] = ["Successful compromise was claimed without evidence."]

    assessment = assess_remediation_output_governance(
        plan=plan,
        source="local_ai",
        execution_supported=False,
    )

    payload = assessment.to_payload()

    assert payload["status"] == AIGovernanceStatus.REQUIRES_REVIEW.value
    assert payload["unsupported_claims"] == ["Successful compromise was claimed without evidence."]
    assert "UNSUPPORTED" in payload["safety_labels"]


def test_execution_supported_blocks_remediation_governance():
    assessment = assess_remediation_output_governance(
        plan=_plan_with_evidence(),
        source="local_ai",
        execution_supported=True,
    )

    payload = assessment.to_payload()

    assert payload["status"] == AIGovernanceStatus.BLOCKED.value
    assert "POLICY_BLOCKED" in payload["safety_labels"]
    assert any("Execution support is not allowed" in warning for warning in payload["policy_warnings"])
