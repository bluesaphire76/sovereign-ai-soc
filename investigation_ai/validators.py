from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .models import (
    ConfidenceAssessment,
    InvestigationBrief,
    InvestigationClaimClassification,
    InvestigationFinding,
    InvestigationHypothesis,
    InvestigationSession,
    RecommendedAction,
    RecommendedActionApprovalRequirement,
    RecommendedActionCategory,
)


OPERATIONAL_ACTION_CATEGORIES = {
    RecommendedActionCategory.CONTAINMENT,
    RecommendedActionCategory.ERADICATION,
    RecommendedActionCategory.RECOVERY,
    RecommendedActionCategory.DETECTION_TUNING,
}

UNQUALIFIED_CERTAINTY_TERMS = (
    "definitely",
    "certainly",
    "without doubt",
    "proves",
    "proven",
    "root cause is",
    "confirmed compromise",
    "confirmed malicious",
)


class InvestigationValidationIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    path: str
    blocking: bool = True


def normalize_confidence_score(value: object) -> int:
    return ConfidenceAssessment(score=value).score


def _issue(code: str, message: str, path: str, blocking: bool = True) -> InvestigationValidationIssue:
    return InvestigationValidationIssue(
        code=code,
        message=message,
        path=path,
        blocking=blocking,
    )


def contains_unqualified_certainty(value: str | None) -> bool:
    if not value:
        return False

    normalized = value.lower()
    return any(term in normalized for term in UNQUALIFIED_CERTAINTY_TERMS)


def validate_hypothesis(
    hypothesis: InvestigationHypothesis,
    *,
    path: str,
) -> list[InvestigationValidationIssue]:
    issues: list[InvestigationValidationIssue] = []

    if not hypothesis.supporting_evidence and not hypothesis.missing_evidence:
        issues.append(
            _issue(
                "HYPOTHESIS_REQUIRES_EVIDENCE_OR_GAP",
                "Hypotheses must include supporting evidence or explicitly document missing evidence.",
                path,
            )
        )

    if hypothesis.claim_classification == InvestigationClaimClassification.UNSUPPORTED:
        issues.append(
            _issue(
                "UNSUPPORTED_HYPOTHESIS_CLAIM",
                "Unsupported factual claims must not be promoted as investigation hypotheses.",
                path,
            )
        )

    if (
        hypothesis.claim_classification == InvestigationClaimClassification.EVIDENCE_BACKED
        and not hypothesis.supporting_evidence
    ):
        issues.append(
            _issue(
                "EVIDENCE_BACKED_HYPOTHESIS_WITHOUT_EVIDENCE",
                "Evidence-backed hypotheses must reference supporting evidence.",
                path,
            )
        )

    if contains_unqualified_certainty(hypothesis.statement) and not hypothesis.supporting_evidence:
        issues.append(
            _issue(
                "UNSUPPORTED_CERTAINTY_LANGUAGE",
                "Hypotheses must avoid certainty language unless directly supported by evidence.",
                path,
            )
        )

    for evidence_index, evidence in enumerate(hypothesis.supporting_evidence):
        if evidence.claim_classification == InvestigationClaimClassification.UNSUPPORTED:
            issues.append(
                _issue(
                    "UNSUPPORTED_EVIDENCE_CLAIM",
                    "Supporting evidence cannot be classified as an unsupported claim.",
                    f"{path}.supporting_evidence[{evidence_index}]",
                )
            )

    return issues


def validate_finding(
    finding: InvestigationFinding,
    *,
    path: str,
) -> list[InvestigationValidationIssue]:
    issues: list[InvestigationValidationIssue] = []

    if finding.claim_classification == InvestigationClaimClassification.UNSUPPORTED:
        issues.append(
            _issue(
                "UNSUPPORTED_FINDING_CLAIM",
                "Unsupported factual claims must not be promoted as investigation findings.",
                path,
            )
        )

    if (
        contains_unqualified_certainty(finding.description)
        and finding.claim_classification != InvestigationClaimClassification.EVIDENCE_BACKED
    ):
        issues.append(
            _issue(
                "UNSUPPORTED_CERTAINTY_LANGUAGE",
                "Findings must avoid certainty language unless classified as evidence-backed.",
                path,
            )
        )

    if (
        finding.claim_classification == InvestigationClaimClassification.EVIDENCE_BACKED
        and not finding.evidence
    ):
        issues.append(
            _issue(
                "EVIDENCE_BACKED_FINDING_WITHOUT_EVIDENCE",
                "Evidence-backed findings must reference at least one evidence item.",
                path,
            )
        )

    return issues


def action_implies_operational_change(action: RecommendedAction) -> bool:
    if action.category in OPERATIONAL_ACTION_CATEGORIES:
        return True

    text = f"{action.title} {action.description}".lower()
    operational_terms = (
        "block",
        "disable",
        "isolate",
        "quarantine",
        "remove",
        "restart",
        "stop service",
        "kill",
        "delete",
        "contain",
        "remediate",
        "eradicate",
        "restore",
        "change firewall",
    )
    return any(term in text for term in operational_terms)


def validate_recommended_action(
    action: RecommendedAction,
    *,
    path: str = "recommended_action",
) -> list[InvestigationValidationIssue]:
    issues: list[InvestigationValidationIssue] = []

    if action.execution_supported:
        issues.append(
            _issue(
                "ACTION_EXECUTION_NOT_SUPPORTED_IN_STEP_1",
                "Recommended actions must remain non-executable in the Step 1 domain model.",
                path,
            )
        )

    if (
        action_implies_operational_change(action)
        and action.approval_requirement == RecommendedActionApprovalRequirement.NONE
    ):
        issues.append(
            _issue(
                "OPERATIONAL_ACTION_REQUIRES_APPROVAL",
                "Operational recommended actions must require analyst or admin approval.",
                path,
            )
        )

    return issues


def validate_investigation_brief(brief: InvestigationBrief) -> list[InvestigationValidationIssue]:
    issues: list[InvestigationValidationIssue] = []

    if brief.confidence.score != normalize_confidence_score(brief.confidence.score):
        issues.append(
            _issue(
                "CONFIDENCE_SCORE_OUT_OF_RANGE",
                "Brief confidence score must be normalized between 0 and 100.",
                "confidence.score",
            )
        )

    for hypothesis_index, hypothesis in enumerate(brief.hypotheses):
        issues.extend(
            validate_hypothesis(
                hypothesis,
                path=f"hypotheses[{hypothesis_index}]",
            )
        )

    for finding_index, finding in enumerate(brief.findings):
        issues.extend(
            validate_finding(
                finding,
                path=f"findings[{finding_index}]",
            )
        )

    for action_index, action in enumerate(brief.recommended_actions):
        issues.extend(
            validate_recommended_action(
                action,
                path=f"recommended_actions[{action_index}]",
            )
        )

    return issues


def validate_investigation_session(session: InvestigationSession) -> list[InvestigationValidationIssue]:
    if session.brief is None:
        return []

    return validate_investigation_brief(session.brief)


def assert_valid_investigation_brief(brief: InvestigationBrief) -> None:
    blocking_issues = [issue for issue in validate_investigation_brief(brief) if issue.blocking]
    if not blocking_issues:
        return

    issue_summary = "; ".join(f"{issue.path}: {issue.message}" for issue in blocking_issues)
    raise ValueError(f"Invalid investigation brief: {issue_summary}")
