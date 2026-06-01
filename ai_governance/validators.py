from __future__ import annotations

from typing import Any

from ai_governance.models import (
    AIEvidenceCoverage,
    AIGovernanceAssessment,
    AIGovernanceSeverity,
    AIGovernanceStatus,
    AIRemediationGovernanceAssessment,
    AIPresentationSafetyLabel,
    AIClaimClassification,
)


def assess_claim_governance(
    *,
    classification: AIClaimClassification,
    confidence_score: int,
    evidence_count: int = 0,
    unsupported_claims: list[str] | None = None,
    speculative_claims: list[str] | None = None,
    limitations: list[str] | None = None,
    fallback_used: bool = False,
) -> AIGovernanceAssessment:
    unsupported_claims = unsupported_claims or []
    speculative_claims = speculative_claims or []
    limitations = limitations or []

    labels: list[AIPresentationSafetyLabel] = []

    if classification == AIClaimClassification.EVIDENCE_BACKED:
        labels.append(AIPresentationSafetyLabel.EVIDENCE_BACKED)
    elif classification == AIClaimClassification.INFERRED:
        labels.append(AIPresentationSafetyLabel.INFERRED)
    elif classification == AIClaimClassification.SPECULATIVE:
        labels.append(AIPresentationSafetyLabel.SPECULATIVE)
    elif classification == AIClaimClassification.UNSUPPORTED:
        labels.append(AIPresentationSafetyLabel.UNSUPPORTED)

    if confidence_score < 50:
        labels.append(AIPresentationSafetyLabel.LOW_CONFIDENCE)

    if fallback_used:
        labels.append(AIPresentationSafetyLabel.FALLBACK_GENERATED)

    requires_human_review = (
        classification in {
            AIClaimClassification.INFERRED,
            AIClaimClassification.SPECULATIVE,
            AIClaimClassification.UNSUPPORTED,
        }
        or confidence_score < 70
        or bool(unsupported_claims)
        or bool(speculative_claims)
        or fallback_used
    )

    if requires_human_review:
        labels.append(AIPresentationSafetyLabel.REQUIRES_HUMAN_REVIEW)

    if classification == AIClaimClassification.UNSUPPORTED or unsupported_claims:
        status = AIGovernanceStatus.NEEDS_HUMAN_REVIEW
        severity = AIGovernanceSeverity.HIGH
    elif classification == AIClaimClassification.SPECULATIVE or speculative_claims:
        status = AIGovernanceStatus.PASSED_WITH_WARNINGS
        severity = AIGovernanceSeverity.MEDIUM
    elif confidence_score < 50:
        status = AIGovernanceStatus.PASSED_WITH_WARNINGS
        severity = AIGovernanceSeverity.MEDIUM
    else:
        status = AIGovernanceStatus.PASSED
        severity = AIGovernanceSeverity.LOW

    if classification == AIClaimClassification.EVIDENCE_BACKED and evidence_count <= 0:
        status = AIGovernanceStatus.PASSED_WITH_WARNINGS
        severity = AIGovernanceSeverity.MEDIUM
        requires_human_review = True
        labels.append(AIPresentationSafetyLabel.REQUIRES_HUMAN_REVIEW)
        limitations.append("Evidence-backed classification has no linked evidence references.")

    return AIGovernanceAssessment(
        classification=classification,
        status=status,
        severity=severity,
        confidence_score=confidence_score,
        evidence_count=evidence_count,
        unsupported_claims=unsupported_claims,
        speculative_claims=speculative_claims,
        limitations=limitations,
        requires_human_review=requires_human_review,
        fallback_used=fallback_used,
        presentation_labels=list(dict.fromkeys(labels)),
    )


_OPERATIONAL_ACTION_TYPES = {
    "BLOCK_IP",
    "UNBLOCK_IP",
    "DISABLE_USER",
    "ENABLE_USER",
    "STOP_SERVICE",
    "RESTART_SERVICE",
    "QUARANTINE_FILE",
    "RESTORE_FILE",
    "KILL_PROCESS",
    "ISOLATE_HOST",
    "RELEASE_HOST",
    "ADD_FIREWALL_RULE",
    "REMOVE_FIREWALL_RULE",
}

_HIGH_IMPACT_ACTION_TYPES = {
    "DISABLE_USER",
    "STOP_SERVICE",
    "RESTART_SERVICE",
    "QUARANTINE_FILE",
    "RESTORE_FILE",
    "KILL_PROCESS",
    "ISOLATE_HOST",
    "RELEASE_HOST",
    "ADD_FIREWALL_RULE",
    "REMOVE_FIREWALL_RULE",
}

_STRONG_APPROVALS = {
    "ADMIN_APPROVAL",
    "SECURITY_LEAD_APPROVAL",
    "FORBIDDEN_BY_DEFAULT",
}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _clean_strings(value: Any) -> list[str]:
    return [str(item).strip() for item in _as_list(value) if str(item).strip()]


def _actions(plan: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in _as_list(plan.get("recommended_actions")) if isinstance(item, dict)]


def _evidence_coverage(actions: list[dict[str, Any]]) -> tuple[AIEvidenceCoverage, int, int]:
    if not actions:
        return AIEvidenceCoverage.NONE, 0, 0

    evidence_counts = [
        len(_clean_strings(action.get("evidence_basis"))) for action in actions
    ]
    actions_with_evidence = sum(1 for count in evidence_counts if count > 0)
    total_evidence = sum(evidence_counts)
    ratio = actions_with_evidence / len(actions)

    if ratio >= 1 and total_evidence >= len(actions):
        return AIEvidenceCoverage.HIGH, actions_with_evidence, total_evidence
    if ratio >= 0.5:
        return AIEvidenceCoverage.MEDIUM, actions_with_evidence, total_evidence
    if total_evidence > 0:
        return AIEvidenceCoverage.LOW, actions_with_evidence, total_evidence
    return AIEvidenceCoverage.NONE, actions_with_evidence, total_evidence


def assess_remediation_plan_governance(
    *,
    plan: dict[str, Any],
    source: str | None = None,
    execution_supported: bool = False,
    fallback_used: bool = False,
) -> AIRemediationGovernanceAssessment:
    actions = _actions(plan)
    limitations = _clean_strings(plan.get("limitations"))
    assumptions = _clean_strings(plan.get("assumptions"))
    unsupported_claims = _clean_strings(plan.get("unsupported_claims"))
    policy_warnings: list[str] = []
    labels: list[AIPresentationSafetyLabel] = []
    blocked = False

    coverage, _, _ = _evidence_coverage(actions)

    if not limitations:
        policy_warnings.append("AI remediation guidance did not provide explicit limitations.")
        limitations.append("Limitations were not supplied by the AI output and require analyst validation.")

    if plan.get("human_validation_required") is not True:
        policy_warnings.append("Human validation was missing or false and was enforced by policy.")

    if execution_supported or plan.get("execution_supported") is True:
        blocked = True
        policy_warnings.append("Execution support is not allowed for AI remediation guidance.")

    if fallback_used or source == "deterministic_fallback":
        policy_warnings.append("Deterministic fallback output requires analyst review before use.")
        if coverage != AIEvidenceCoverage.NONE:
            coverage = AIEvidenceCoverage.LOW
            policy_warnings.append(
                "Fallback evidence coverage is limited to structured incident fields."
            )
        labels.append(AIPresentationSafetyLabel.FALLBACK_GENERATED)

    for index, action in enumerate(actions, start=1):
        title = str(action.get("title") or action.get("action_type") or f"action {index}")
        action_type = str(action.get("action_type") or "").upper()
        approval = str(action.get("approval_requirement") or "").upper()
        risk_level = str(action.get("risk_level") or "").upper()

        if not _clean_strings(action.get("evidence_basis")):
            policy_warnings.append(f"Recommended action '{title}' has no evidence_basis.")

        if action.get("execution_supported") is True:
            blocked = True
            policy_warnings.append(f"Recommended action '{title}' attempted to enable execution.")

        if action.get("command_preview"):
            policy_warnings.append(
                f"Recommended action '{title}' included command preview content; it is non-executable review context only."
            )

        if action_type in _OPERATIONAL_ACTION_TYPES and approval in {"", "NONE"}:
            policy_warnings.append(
                f"Operational action '{title}' requires explicit human approval."
            )

        if action_type in _HIGH_IMPACT_ACTION_TYPES and approval not in _STRONG_APPROVALS:
            policy_warnings.append(
                f"High-impact action '{title}' requires admin, security lead, or forbidden-by-default approval classification."
            )

        if approval == "FORBIDDEN_BY_DEFAULT":
            blocked = True
            policy_warnings.append(f"Recommended action '{title}' is forbidden by default.")

        if risk_level in {"HIGH", "CRITICAL"} and approval in {"", "NONE", "ANALYST_APPROVAL"}:
            policy_warnings.append(
                f"High-risk action '{title}' requires stronger human approval before any future workflow."
            )

        unsupported_claims.extend(_clean_strings(action.get("unsupported_claims")))
        assumptions.extend(_clean_strings(action.get("assumptions")))

    confidence = 75
    if source == "local_ai":
        confidence += 5
    if fallback_used or source == "deterministic_fallback":
        confidence = 45

    if coverage == AIEvidenceCoverage.HIGH:
        confidence += 10
        labels.append(AIPresentationSafetyLabel.EVIDENCE_BACKED)
    elif coverage == AIEvidenceCoverage.MEDIUM:
        confidence += 0
    elif coverage == AIEvidenceCoverage.LOW:
        confidence -= 15
        labels.append(AIPresentationSafetyLabel.LOW_CONFIDENCE)
    else:
        confidence -= 25
        labels.append(AIPresentationSafetyLabel.LOW_CONFIDENCE)

    if unsupported_claims:
        confidence -= min(45, len(unsupported_claims) * 15)
        labels.append(AIPresentationSafetyLabel.UNSUPPORTED)

    if assumptions:
        confidence -= min(20, len(assumptions) * 5)
        labels.append(AIPresentationSafetyLabel.SPECULATIVE)

    if policy_warnings:
        confidence -= min(25, len(policy_warnings) * 3)

    confidence = max(0, min(100, confidence))

    if blocked:
        status = AIGovernanceStatus.BLOCKED
        labels.append(AIPresentationSafetyLabel.POLICY_BLOCKED)
    elif unsupported_claims or coverage in {AIEvidenceCoverage.LOW, AIEvidenceCoverage.NONE}:
        status = AIGovernanceStatus.REQUIRES_REVIEW
    elif policy_warnings or assumptions or coverage == AIEvidenceCoverage.MEDIUM:
        status = AIGovernanceStatus.PASSED_WITH_WARNINGS
    else:
        status = AIGovernanceStatus.PASSED_WITH_WARNINGS
        policy_warnings.append("AI remediation guidance remains advisory and requires human review.")

    policy_warnings.append("No remediation or rollback execution is supported by this AI output.")

    return AIRemediationGovernanceAssessment(
        status=status,
        confidence_score=confidence,
        evidence_coverage=coverage,
        unsupported_claims=list(dict.fromkeys(unsupported_claims)),
        assumptions=list(dict.fromkeys(assumptions)),
        limitations=list(dict.fromkeys(limitations)),
        policy_warnings=list(dict.fromkeys(policy_warnings)),
        safety_labels=list(dict.fromkeys(labels)),
    )
