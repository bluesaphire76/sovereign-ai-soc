from __future__ import annotations

import logging
from uuid import uuid4

from investigation_ai.models import (
    EvidenceReference,
    InvestigationBrief,
    RecommendedAction,
    RecommendedActionCategory,
)

from .models import (
    RemediationAction,
    RemediationActionStatus,
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationImpactAssessment,
    RemediationPlan,
    RemediationPlanStatus,
    RemediationPlanningContext,
    RemediationPostCheck,
    RemediationPreCheck,
    RemediationRiskAssessment,
    RemediationRiskLevel,
    RemediationTarget,
    RemediationTargetCriticality,
    RemediationTargetType,
    RollbackAvailability,
    RollbackPlan,
)
from .risk import assess_action_risk, approval_for_action
from .rollback import build_rollback_plan
from .validators import validate_remediation_plan


logger = logging.getLogger(__name__)


def _new_plan_id(incident_id: int | None = None) -> str:
    if incident_id is not None:
        return f"remediation-plan-incident-{incident_id}"
    return f"remediation-plan-{uuid4().hex}"


def _incident_value(context: RemediationPlanningContext, *keys: str) -> str | None:
    for key in keys:
        value = context.incident.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _brief(context: RemediationPlanningContext) -> InvestigationBrief | None:
    brief = context.investigation_brief
    if isinstance(brief, InvestigationBrief):
        return brief
    return None


def _evidence(context: RemediationPlanningContext) -> list[EvidenceReference]:
    evidence = list(context.evidence)
    brief = _brief(context)
    if brief:
        evidence.extend(brief.evidence_used)
    deduped: dict[str, EvidenceReference] = {}
    for item in evidence:
        deduped[item.evidence_id] = item
    return list(deduped.values())


def _confidence_score(context: RemediationPlanningContext) -> int | None:
    brief = _brief(context)
    return brief.confidence.score if brief else None


def _target_from_context(
    context: RemediationPlanningContext,
    *,
    action_type: RemediationActionType,
) -> RemediationTarget:
    agent = _incident_value(context, "agent", "host")
    user = _incident_value(context, "user", "account")
    source_ip = _incident_value(context, "source_ip", "src_ip")

    if action_type in {
        RemediationActionType.BLOCK_IP,
        RemediationActionType.UNBLOCK_IP,
        RemediationActionType.ADD_FIREWALL_RULE,
        RemediationActionType.REMOVE_FIREWALL_RULE,
    }:
        return RemediationTarget(
            target_type=RemediationTargetType.IP_ADDRESS,
            value=source_ip or "unknown-ip",
            ip_address=source_ip,
            criticality=RemediationTargetCriticality.UNKNOWN,
        )

    if action_type in {
        RemediationActionType.DISABLE_USER,
        RemediationActionType.ENABLE_USER,
    }:
        return RemediationTarget(
            target_type=RemediationTargetType.USER,
            value=user or "unknown-user",
            user=user,
            criticality=RemediationTargetCriticality.UNKNOWN,
        )

    if action_type in {
        RemediationActionType.STOP_SERVICE,
        RemediationActionType.RESTART_SERVICE,
    }:
        return RemediationTarget(
            target_type=RemediationTargetType.SERVICE,
            value="service-review-required",
            host=agent,
            criticality=RemediationTargetCriticality.UNKNOWN,
        )

    if action_type in {
        RemediationActionType.ISOLATE_HOST,
        RemediationActionType.RELEASE_HOST,
        RemediationActionType.COLLECT_FORENSIC_EVIDENCE,
    }:
        return RemediationTarget(
            target_type=RemediationTargetType.HOST,
            value=agent or "unknown-host",
            host=agent,
            criticality=RemediationTargetCriticality.UNKNOWN,
        )

    return RemediationTarget(
        target_type=RemediationTargetType.CASE,
        value=f"incident:{context.incident_id}",
        criticality=RemediationTargetCriticality.LOW,
    )


def _action_type_from_recommended_action(action: RecommendedAction) -> RemediationActionType:
    text = " ".join(
        value.lower()
        for value in (action.title, action.description, action.reason or "")
        if value
    )

    if action.category == RecommendedActionCategory.CONTAINMENT:
        if "ip" in text or "block" in text:
            return RemediationActionType.BLOCK_IP
        if "host" in text or "isolate" in text:
            return RemediationActionType.ISOLATE_HOST
        if "user" in text or "account" in text:
            return RemediationActionType.DISABLE_USER
        return RemediationActionType.ESCALATE_CASE

    if action.category == RecommendedActionCategory.ERADICATION:
        if "process" in text:
            return RemediationActionType.KILL_PROCESS
        if "file" in text:
            return RemediationActionType.QUARANTINE_FILE
        return RemediationActionType.ESCALATE_CASE

    if action.category in {
        RecommendedActionCategory.INVESTIGATION,
        RecommendedActionCategory.MONITORING,
    }:
        return RemediationActionType.COLLECT_FORENSIC_EVIDENCE

    if action.category == RecommendedActionCategory.COMMUNICATION:
        return RemediationActionType.NOTIFY_OWNER

    return RemediationActionType.CREATE_TICKET


def _preview_for_action(action_type: RemediationActionType, target: RemediationTarget) -> str | None:
    value = target.value or "target"
    preview = {
        RemediationActionType.BLOCK_IP: f"PREVIEW ONLY: block network traffic for IP {value}",
        RemediationActionType.UNBLOCK_IP: f"PREVIEW ONLY: remove block for IP {value}",
        RemediationActionType.DISABLE_USER: f"PREVIEW ONLY: disable user account {value}",
        RemediationActionType.ENABLE_USER: f"PREVIEW ONLY: enable user account {value}",
        RemediationActionType.STOP_SERVICE: f"PREVIEW ONLY: stop service on {target.host or value}",
        RemediationActionType.RESTART_SERVICE: f"PREVIEW ONLY: restart service on {target.host or value}",
        RemediationActionType.QUARANTINE_FILE: f"PREVIEW ONLY: quarantine file {value}",
        RemediationActionType.RESTORE_FILE: f"PREVIEW ONLY: restore file {value}",
        RemediationActionType.KILL_PROCESS: f"PREVIEW ONLY: terminate process {value}",
        RemediationActionType.ISOLATE_HOST: f"PREVIEW ONLY: isolate host {value}",
        RemediationActionType.RELEASE_HOST: f"PREVIEW ONLY: release host {value} from isolation",
        RemediationActionType.ADD_FIREWALL_RULE: f"PREVIEW ONLY: add firewall rule for {value}",
        RemediationActionType.REMOVE_FIREWALL_RULE: f"PREVIEW ONLY: remove firewall rule for {value}",
    }
    return preview.get(action_type)


def _build_action(
    context: RemediationPlanningContext,
    *,
    action_type: RemediationActionType,
    title: str,
    description: str,
    reason: str,
    evidence: list[EvidenceReference],
) -> RemediationAction:
    action_id = f"remediation-{action_type.value.lower().replace('_', '-')}-{len(evidence)}"
    target = _target_from_context(context, action_type=action_type)
    rollback_plan = build_rollback_plan(action_type, action_id=action_id)
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback_plan,
        confidence_score=_confidence_score(context),
        evidence_count=len(evidence),
    )
    approval = approval_for_action(action_type, risk_score=risk.score)
    return RemediationAction(
        action_id=action_id,
        action_type=action_type,
        title=title,
        description=description,
        target=target,
        reason=reason,
        evidence=evidence[:8],
        approval_requirement=approval,
        risk=risk,
        expected_impact=RemediationImpactAssessment(
            business_impact="Operational impact depends on affected asset criticality and must be reviewed by a human analyst.",
            technical_impact="No technical change is performed in Step 8. This is a proposed planning artifact only.",
            service_availability_impact=(
                "Potential service availability impact requires review."
                if risk.level in {RemediationRiskLevel.HIGH, RemediationRiskLevel.CRITICAL}
                else "No service availability impact occurs because execution is not supported in Step 8."
            ),
            blast_radius=risk.blast_radius,
        ),
        possible_side_effects=[
            "Incorrect remediation selection may disrupt legitimate activity.",
            "Action must be validated against current asset ownership and business context.",
        ],
        rollback_steps=rollback_plan.steps,
        pre_checks=[
            RemediationPreCheck(
                check_id=f"precheck-{action_id}-evidence",
                title="Validate supporting evidence",
                description="Confirm supporting evidence and analyst context before considering approval.",
                expected_result="Evidence supports the proposed remediation and no contradictory evidence blocks review.",
            )
        ],
        post_checks=[
            RemediationPostCheck(
                check_id=f"postcheck-{action_id}-monitor",
                title="Validate outcome after future approved execution",
                description="If a later execution layer performs this action, monitor target telemetry and service health.",
                expected_result="Expected malicious or unwanted activity stops without unacceptable business impact.",
            )
        ],
        command_preview=_preview_for_action(action_type, target),
        command_preview_is_executable=False,
        execution_supported=False,
        simulation_supported=False,
        status=(
            RemediationActionStatus.BLOCKED
            if approval == RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT
            else RemediationActionStatus.PROPOSED
        ),
    )


def _actions_from_recommendations(context: RemediationPlanningContext) -> list[RemediationAction]:
    brief = _brief(context)
    recommended = list(context.recommended_actions)
    if brief:
        recommended.extend(brief.recommended_actions)

    evidence = _evidence(context)
    actions: list[RemediationAction] = []
    seen_titles: set[str] = set()
    for recommended_action in recommended:
        if not isinstance(recommended_action, RecommendedAction):
            continue
        if recommended_action.title in seen_titles:
            continue
        seen_titles.add(recommended_action.title)
        action_type = _action_type_from_recommended_action(recommended_action)
        actions.append(
            _build_action(
                context,
                action_type=action_type,
                title=recommended_action.title,
                description=recommended_action.description,
                reason=recommended_action.reason or "Recommended by structured investigation context.",
                evidence=[
                    item
                    for item in evidence
                    if not recommended_action.related_evidence_ids
                    or item.evidence_id in recommended_action.related_evidence_ids
                ][:8]
                or evidence[:4],
            )
        )
    return actions


def _default_actions(context: RemediationPlanningContext) -> list[RemediationAction]:
    evidence = _evidence(context)
    return [
        _build_action(
            context,
            action_type=RemediationActionType.CREATE_TICKET,
            title="Create remediation review ticket",
            description="Create a governed review ticket for the incident remediation decision.",
            reason="A review ticket preserves accountability without changing production systems.",
            evidence=evidence[:4],
        ),
        _build_action(
            context,
            action_type=RemediationActionType.COLLECT_FORENSIC_EVIDENCE,
            title="Collect additional forensic evidence",
            description="Collect additional host, network or identity evidence before selecting an operational action.",
            reason="Additional evidence reduces the risk of selecting an unsupported remediation.",
            evidence=evidence[:4],
        ),
    ]


def _overall_risk(actions: list[RemediationAction]) -> RemediationRiskAssessment:
    if not actions:
        return RemediationRiskAssessment(
            score=20,
            level=RemediationRiskLevel.LOW,
            rationale="No remediation actions were proposed.",
            risk_factors=["no_actions"],
            approval_requirement=RemediationApprovalRequirement.ANALYST_APPROVAL,
        )
    riskiest = max(actions, key=lambda action: action.risk.score)
    return RemediationRiskAssessment(
        score=riskiest.risk.score,
        level=riskiest.risk.level,
        rationale=f"Overall risk follows the highest-risk proposed action: {riskiest.title}.",
        risk_factors=riskiest.risk.risk_factors,
        blast_radius=riskiest.risk.blast_radius,
        approval_requirement=riskiest.risk.approval_requirement,
    )


def _plan_rollback(actions: list[RemediationAction]) -> RollbackPlan:
    if not actions:
        return RollbackPlan(
            rollback_id="rollback-empty-plan",
            availability=RollbackAvailability.NOT_APPLICABLE,
            steps=[],
            validation_steps=[],
            recovery_notes="No actions are proposed, so no rollback is required.",
        )

    if any(action.risk.approval_requirement.value == "FORBIDDEN_BY_DEFAULT" for action in actions):
        availability = RollbackAvailability.UNAVAILABLE
    elif any(not action.rollback_steps for action in actions):
        availability = RollbackAvailability.PARTIAL
    else:
        availability = RollbackAvailability.PARTIAL

    steps = [step for action in actions for step in action.rollback_steps[:2]]
    return RollbackPlan(
        rollback_id="rollback-remediation-plan",
        availability=availability,
        steps=steps,
        validation_steps=[
            "Validate service health, identity state and security telemetry after any future approved execution.",
            "Document residual risk and analyst sign-off after rollback review.",
        ],
        recovery_notes="Rollback planning is advisory in Step 8; no execution or rollback automation exists.",
        limitations=[
            "Plan-level rollback depends on future approved execution details.",
            "Rollback is not automated in Step 8.",
        ],
    )


def generate_remediation_plan(context: RemediationPlanningContext) -> RemediationPlan:
    logger.info(
        "remediation_plan_generation_started",
        extra={"incident_id": context.incident_id},
    )
    try:
        actions = _actions_from_recommendations(context)
        if not actions:
            actions = _default_actions(context)
        evidence = _evidence(context)
        rollback_plan = _plan_rollback(actions)
        plan = RemediationPlan(
            plan_id=_new_plan_id(context.incident_id),
            incident_id=context.incident_id,
            investigation_session_id=context.investigation_session_id,
            generated_by=context.generated_by,
            status=RemediationPlanStatus.PROPOSED,
            summary="Human-approved remediation plan is available for analyst review.",
            rationale=(
                "The plan is derived from structured investigation context and remains planning-only. "
                "No operational action is executed by this module."
            ),
            actions=actions,
            overall_risk=_overall_risk(actions),
            expected_benefit="Improved containment and recovery decision quality after human validation.",
            business_impact="Business impact must be validated by the asset or service owner before future execution.",
            technical_impact="No technical impact occurs in Step 8 because execution is not supported.",
            prerequisites=[
                "Human analyst review",
                "Evidence validation",
                "Approval according to action risk",
                "Rollback review before future execution",
            ],
            pre_checks=[
                RemediationPreCheck(
                    check_id="plan-precheck-human-review",
                    title="Human review required",
                    description="A human analyst must review the plan before any future execution path is considered.",
                    expected_result="Reviewer confirms evidence, risk, approval and rollback readiness.",
                )
            ],
            post_checks=[
                RemediationPostCheck(
                    check_id="plan-postcheck-no-execution",
                    title="Confirm no execution occurred",
                    description="Confirm Step 8 generated a planning artifact only.",
                    expected_result="No production systems, rules, users, files or services were changed.",
                )
            ],
            rollback_plan=rollback_plan,
            evidence_used=evidence[:12],
            limitations=[
                "Step 8 does not implement remediation execution.",
                "Command previews are non-executable review content only.",
                "Operational actions require human approval before any future execution layer can act.",
            ],
            execution_supported=False,
            simulation_supported=False,
        )
        validation = validate_remediation_plan(plan)
        if not validation.valid:
            logger.warning(
                "remediation_plan_validation_failed",
                extra={"incident_id": context.incident_id, "issues": validation.issues},
            )
        logger.info(
            "remediation_plan_generated",
            extra={"incident_id": context.incident_id, "actions": len(plan.actions)},
        )
        return plan
    except Exception as exc:
        logger.warning(
            "remediation_plan_fallback_used",
            extra={"incident_id": context.incident_id, "reason": exc.__class__.__name__},
        )
        return create_fallback_remediation_plan(context.incident_id)


def create_fallback_remediation_plan(
    incident_id: int,
    *,
    investigation_session_id: str | None = None,
    generated_by: str = "system",
) -> RemediationPlan:
    fallback_context = RemediationPlanningContext(
        incident_id=incident_id,
        investigation_session_id=investigation_session_id,
        generated_by=generated_by,
    )
    actions = _default_actions(fallback_context)
    return RemediationPlan(
        plan_id=_new_plan_id(incident_id),
        incident_id=incident_id,
        investigation_session_id=investigation_session_id,
        generated_by=generated_by,
        status=RemediationPlanStatus.PROPOSED,
        summary="Fallback remediation plan requires human review.",
        rationale="Fallback planning is available for workflow continuity only.",
        actions=actions,
        overall_risk=_overall_risk(actions),
        expected_benefit="Provides a governed review path when structured remediation context is incomplete.",
        business_impact="Business impact cannot be assessed from fallback context alone.",
        technical_impact="No technical impact occurs because execution is not supported.",
        prerequisites=["Human analyst review", "Additional evidence collection"],
        pre_checks=[
            RemediationPreCheck(
                check_id="fallback-precheck-evidence",
                title="Collect supporting evidence",
                description="Collect supporting evidence before selecting any operational remediation.",
            )
        ],
        post_checks=[],
        rollback_plan=_plan_rollback(actions),
        limitations=[
            "Fallback plan has limited context.",
            "No remediation execution exists in Step 8.",
        ],
        execution_supported=False,
        simulation_supported=False,
    )
