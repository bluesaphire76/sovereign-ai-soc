from __future__ import annotations

from .models import (
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationRiskAssessment,
    RemediationRiskLevel,
    RemediationTarget,
    RemediationTargetCriticality,
    RollbackAvailability,
    RollbackPlan,
)


FORBIDDEN_ACTION_TYPES = {
    RemediationActionType.DISABLE_USER,
    RemediationActionType.STOP_SERVICE,
    RemediationActionType.QUARANTINE_FILE,
    RemediationActionType.KILL_PROCESS,
    RemediationActionType.ISOLATE_HOST,
}

ADMIN_APPROVAL_ACTION_TYPES = {
    RemediationActionType.BLOCK_IP,
    RemediationActionType.UNBLOCK_IP,
    RemediationActionType.ENABLE_USER,
    RemediationActionType.RESTART_SERVICE,
    RemediationActionType.RESTORE_FILE,
    RemediationActionType.ADD_FIREWALL_RULE,
    RemediationActionType.REMOVE_FIREWALL_RULE,
}

ANALYST_APPROVAL_ACTION_TYPES = {
    RemediationActionType.ESCALATE_CASE,
    RemediationActionType.COLLECT_FORENSIC_EVIDENCE,
}

LOW_RISK_ACTION_TYPES = {
    RemediationActionType.CREATE_TICKET,
    RemediationActionType.NOTIFY_OWNER,
}


BASE_ACTION_RISK = {
    RemediationActionType.BLOCK_IP: 65,
    RemediationActionType.UNBLOCK_IP: 50,
    RemediationActionType.DISABLE_USER: 90,
    RemediationActionType.ENABLE_USER: 70,
    RemediationActionType.STOP_SERVICE: 90,
    RemediationActionType.RESTART_SERVICE: 75,
    RemediationActionType.QUARANTINE_FILE: 90,
    RemediationActionType.RESTORE_FILE: 70,
    RemediationActionType.KILL_PROCESS: 90,
    RemediationActionType.ISOLATE_HOST: 95,
    RemediationActionType.RELEASE_HOST: 70,
    RemediationActionType.ADD_FIREWALL_RULE: 80,
    RemediationActionType.REMOVE_FIREWALL_RULE: 70,
    RemediationActionType.CREATE_TICKET: 15,
    RemediationActionType.NOTIFY_OWNER: 10,
    RemediationActionType.ESCALATE_CASE: 25,
    RemediationActionType.COLLECT_FORENSIC_EVIDENCE: 40,
}


def _clamp(value: int) -> int:
    return min(100, max(0, int(value)))


def risk_level_from_score(score: int) -> RemediationRiskLevel:
    if score >= 85:
        return RemediationRiskLevel.CRITICAL
    if score >= 65:
        return RemediationRiskLevel.HIGH
    if score >= 35:
        return RemediationRiskLevel.MEDIUM
    if score > 0:
        return RemediationRiskLevel.LOW
    return RemediationRiskLevel.INFORMATIONAL


def approval_for_action(
    action_type: RemediationActionType,
    *,
    risk_score: int | None = None,
) -> RemediationApprovalRequirement:
    if action_type in FORBIDDEN_ACTION_TYPES:
        return RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
    if risk_score is not None and risk_score >= 85:
        return RemediationApprovalRequirement.SECURITY_LEAD_APPROVAL
    if action_type in ADMIN_APPROVAL_ACTION_TYPES:
        return RemediationApprovalRequirement.ADMIN_APPROVAL
    if action_type in ANALYST_APPROVAL_ACTION_TYPES:
        return RemediationApprovalRequirement.ANALYST_APPROVAL
    if action_type in LOW_RISK_ACTION_TYPES:
        return RemediationApprovalRequirement.NONE
    return RemediationApprovalRequirement.ANALYST_APPROVAL


def assess_action_risk(
    action_type: RemediationActionType,
    *,
    target: RemediationTarget | None = None,
    rollback_plan: RollbackPlan | None = None,
    confidence_score: int | None = None,
    evidence_count: int = 0,
) -> RemediationRiskAssessment:
    target = target or RemediationTarget()
    score = BASE_ACTION_RISK.get(action_type, 50)
    factors = [f"base_action_risk={score}"]

    if target.criticality == RemediationTargetCriticality.CRITICAL:
        score += 20
        factors.append("critical_target")
    elif target.criticality == RemediationTargetCriticality.HIGH:
        score += 12
        factors.append("high_criticality_target")
    elif target.criticality == RemediationTargetCriticality.UNKNOWN:
        score += 5
        factors.append("target_criticality_unknown")

    if rollback_plan:
        if rollback_plan.availability == RollbackAvailability.UNAVAILABLE:
            score += 25
            factors.append("rollback_unavailable")
        elif rollback_plan.availability == RollbackAvailability.PARTIAL:
            score += 10
            factors.append("rollback_partial")
        elif rollback_plan.availability == RollbackAvailability.FULL:
            score -= 8
            factors.append("rollback_available")
    else:
        score += 15
        factors.append("rollback_not_defined")

    if confidence_score is None:
        score += 8
        factors.append("confidence_unknown")
    elif confidence_score < 40:
        score += 15
        factors.append("low_confidence")
    elif confidence_score >= 75:
        score -= 5
        factors.append("high_confidence")

    if evidence_count <= 0:
        score += 15
        factors.append("no_supporting_evidence")
    elif evidence_count >= 3:
        score -= 5
        factors.append("multiple_evidence_references")

    score = _clamp(score)
    level = risk_level_from_score(score)
    approval = approval_for_action(action_type, risk_score=score)
    return RemediationRiskAssessment(
        score=score,
        level=level,
        rationale=(
            "Risk is calculated deterministically from action type, target criticality, "
            "rollback availability, confidence and evidence coverage."
        ),
        risk_factors=factors,
        blast_radius=(
            "Potentially broad operational impact." if score >= 65 else "Limited expected blast radius."
        ),
        approval_requirement=approval,
    )
