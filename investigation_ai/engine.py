from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from uuid import uuid4

from llm_output import is_invalid_llm_output, sanitize_llm_output

from .adapters import (
    InvestigationContext,
    evidence_references_from_context,
    mitre_techniques_from_context,
    normalize_investigation_context,
    safe_text,
)
from .factory import create_fallback_investigation_brief
from .models import (
    ConfidenceAssessment,
    InvestigationBrief,
    InvestigationClaimClassification,
    InvestigationConfidenceLevel,
    InvestigationFinding,
    InvestigationFindingType,
    InvestigationHypothesis,
    InvestigationHypothesisStatus,
    InvestigationLimitation,
    InvestigationSessionStatus,
    RecommendedAction,
    RecommendedActionApprovalRequirement,
    RecommendedActionCategory,
    RecommendedCheck,
    RecommendedCheckPriority,
)
from .prompts import INVESTIGATION_SYSTEM_PROMPT, build_investigation_prompt
from .validators import (
    action_implies_operational_change,
    assert_valid_investigation_brief,
    contains_unqualified_certainty,
    validate_investigation_brief,
)


logger = logging.getLogger(__name__)

InvestigationLlmClient = Callable[[list[dict[str, str]]], str]


def _new_session_id() -> str:
    return f"investigation-{uuid4().hex}"


def _brief_incident_id(context: InvestigationContext, incident_id: int | None) -> int:
    if incident_id is not None:
        return incident_id
    if context.incident_id is not None:
        return context.incident_id
    return 0


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = sanitize_llm_output(text)
    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start < 0 or end < start:
        raise ValueError("LLM output did not contain a JSON object.")

    payload = json.loads(cleaned[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("LLM output JSON root must be an object.")
    return payload


def _limited_list(values: Sequence[Any], limit: int = 4) -> list[Any]:
    return list(values[:limit])


def _correlation_value(context: InvestigationContext, key: str) -> Any:
    summary = context.correlation_summary
    if isinstance(summary, Mapping):
        return summary.get(key)
    return None


def _correlation_score(context: InvestigationContext) -> int:
    incident_score = context.incident.get("correlation_score")
    summary_score = _correlation_value(context, "final_correlation_score")
    for value in (summary_score, incident_score):
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return 0


def _risk_score(context: InvestigationContext) -> int:
    for value in (context.incident.get("risk_score"), context.incident.get("level")):
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return 0


def _rule_label(context: InvestigationContext) -> str:
    return (
        safe_text(context.incident.get("rule"))
        or safe_text(context.incident.get("rule_description"))
        or safe_text(context.incident.get("rule_id"))
        or "source alert"
    )


def _host_label(context: InvestigationContext) -> str:
    return (
        safe_text(context.incident.get("agent"))
        or safe_text(context.incident.get("host"))
        or "affected host"
    )


def _confidence_from_context(context: InvestigationContext) -> ConfidenceAssessment:
    score = 15
    positive_signals: list[str] = []
    missing_evidence: list[str] = []

    if context.incident:
        score += 15
        positive_signals.append("Primary incident record is available.")
    else:
        missing_evidence.append("Primary incident record")

    if context.raw_events:
        score += min(15, len(context.raw_events) * 5)
        positive_signals.append("Raw event context is available.")
    else:
        missing_evidence.append("Raw event context")

    if context.security_alerts:
        score += min(15, len(context.security_alerts) * 5)
        positive_signals.append("Normalized security alert context is available.")
    else:
        missing_evidence.append("Normalized security alert context")

    correlation_score = _correlation_score(context)
    if context.correlation_summary or correlation_score:
        score += 20 if correlation_score >= 60 else 10
        positive_signals.append("Correlation context is available.")
    else:
        missing_evidence.append("Correlation context")

    mitre_techniques = mitre_techniques_from_context(context)
    if mitre_techniques:
        score += 10
        positive_signals.append("MITRE mapping is available.")
    else:
        missing_evidence.append("MITRE mapping")

    if context.timeline:
        score += 10
        positive_signals.append("Timeline context is available.")
    else:
        missing_evidence.append("Timeline context")

    return ConfidenceAssessment(
        score=min(85, score),
        level=InvestigationConfidenceLevel.UNKNOWN,
        rationale="Confidence is based on available incident, evidence, correlation and timeline context.",
        positive_signals=positive_signals,
        missing_evidence=missing_evidence,
    )


def _risk_assessment(context: InvestigationContext) -> str:
    risk = _risk_score(context)
    correlation = _correlation_score(context)
    priority = safe_text(context.incident.get("recommended_priority"))
    escalation_reason = safe_text(context.incident.get("escalation_reason"))

    parts = [
        f"Risk score: {risk or 'not available'}.",
        f"Correlation score: {correlation or 'not available'}.",
    ]
    if priority:
        parts.append(f"Recommended priority: {priority}.")
    if escalation_reason:
        parts.append(f"Escalation rationale: {escalation_reason}.")
    parts.append("Analyst validation is required before operational response decisions.")
    return " ".join(parts)


def _summary_from_context(context: InvestigationContext) -> str:
    status = safe_text(context.incident.get("status")) or "UNKNOWN"
    rule = _rule_label(context)
    host = _host_label(context)
    correlation_type = safe_text(context.incident.get("correlation_type"))

    summary = f"Incident {context.incident_id or 'unknown'} is in {status} status for {rule} on {host}."
    if correlation_type:
        summary = f"{summary} Correlation type: {correlation_type}."
    return f"{summary} The brief is structured for analyst review and does not execute remediation."


def _build_limitations(context: InvestigationContext, fallback_reason: str | None = None) -> list[InvestigationLimitation]:
    limitations: list[InvestigationLimitation] = []

    if fallback_reason:
        limitations.append(
            InvestigationLimitation(
                limitation_id="investigation-engine-fallback",
                description=fallback_reason,
                impact="The brief was generated from deterministic evidence-aware logic.",
                missing_data=["validated LLM structured output"],
                suggested_resolution="Review the structured brief and rerun generation when the AI runtime is available.",
            )
        )

    missing: list[str] = []
    if not context.raw_events:
        missing.append("raw events")
    if not context.security_alerts:
        missing.append("normalized security alerts")
    if not context.correlation_summary:
        missing.append("correlation summary")
    if not context.timeline:
        missing.append("event timeline")

    if missing:
        limitations.append(
            InvestigationLimitation(
                limitation_id="investigation-context-gaps",
                description="Some investigation context is not available to the engine.",
                impact="Confidence is limited and hypotheses require analyst validation.",
                missing_data=missing,
                suggested_resolution="Attach additional evidence before making final investigation or response decisions.",
            )
        )

    return limitations


def _build_deterministic_brief(
    context: InvestigationContext,
    *,
    incident_id: int,
    session_id: str,
    fallback_reason: str | None = None,
) -> InvestigationBrief:
    evidence = evidence_references_from_context(context)
    confidence = _confidence_from_context(context)
    mitre_techniques = mitre_techniques_from_context(context)
    primary_evidence = _limited_list(evidence, 5)
    missing_evidence = [
        item
        for item in (
            "raw event payload" if not context.raw_events else None,
            "security alert normalization" if not context.security_alerts else None,
            "correlation timeline" if not context.timeline else None,
        )
        if item
    ]

    hypotheses = [
        InvestigationHypothesis(
            hypothesis_id="hypothesis-primary-alert",
            title="Source alert requires validation",
            statement=(
                "The source alert and incident metadata indicate security-relevant activity "
                "that should be validated against available telemetry."
            ),
            status=InvestigationHypothesisStatus.ACTIVE,
            confidence=confidence,
            supporting_evidence=primary_evidence,
            missing_evidence=missing_evidence,
            rationale="This hypothesis is based on the primary incident record and any attached normalized evidence.",
            related_mitre_techniques=mitre_techniques,
        )
    ]

    if context.correlation_summary or _correlation_score(context):
        correlation_evidence = [
            item
            for item in evidence
            if item.evidence_type.value == "CORRELATION_SUMMARY"
        ]
        correlation_missing_evidence = []
        if not correlation_evidence:
            correlation_missing_evidence.append("structured correlation summary")
        if not context.timeline:
            correlation_missing_evidence.append("full related event timeline")

        hypotheses.append(
            InvestigationHypothesis(
                hypothesis_id="hypothesis-correlation-context",
                title="Correlation context may increase investigation priority",
                statement=(
                    "Correlation metadata indicates this incident should be reviewed together "
                    "with related signals before prioritization is finalized."
                ),
                status=InvestigationHypothesisStatus.ACTIVE,
                confidence=confidence,
                supporting_evidence=correlation_evidence,
                missing_evidence=correlation_missing_evidence,
                rationale="Correlation context is decision support and requires analyst validation.",
                related_mitre_techniques=mitre_techniques,
            )
        )

    findings = [
        InvestigationFinding(
            finding_id="finding-primary-incident",
            finding_type=InvestigationFindingType.INDICATOR,
            title="Primary incident record is available",
            description=f"The incident record references {_rule_label(context)} on {_host_label(context)}.",
            claim_classification=InvestigationClaimClassification.EVIDENCE_BACKED if evidence else InvestigationClaimClassification.INFERRED,
            confidence=confidence,
            evidence=primary_evidence,
            technical_impact="The source signal should be validated against host, alert and timeline context.",
        )
    ]

    if mitre_techniques:
        findings.append(
            InvestigationFinding(
                finding_id="finding-mitre-context",
                finding_type=InvestigationFindingType.BEHAVIOR,
                title="MITRE mapping is available",
                description="The incident includes MITRE ATT&CK context for analyst-oriented behavior review.",
                claim_classification=InvestigationClaimClassification.INFERRED,
                confidence=ConfidenceAssessment(
                    score=min(confidence.score, 65),
                    level=InvestigationConfidenceLevel.UNKNOWN,
                    rationale="MITRE mapping provides behavioral context but does not prove intent by itself.",
                    positive_signals=mitre_techniques,
                ),
                evidence=[
                    item
                    for item in evidence
                    if item.evidence_type.value == "MITRE_METADATA"
                ],
                technical_impact="MITRE context can guide evidence review and recommended checks.",
            )
        )

    recommended_checks = [
        RecommendedCheck(
            check_id="check-source-alert",
            title="Validate source alert details",
            description="Review the source alert, affected host, rule metadata, severity and timestamp.",
            priority=RecommendedCheckPriority.HIGH,
            reason="Primary evidence must be validated before response decisions.",
            expected_evidence=["raw alert", "security alert", "host timeline"],
            related_hypothesis_ids=["hypothesis-primary-alert"],
            source_system="ai-soc",
            requires_human_input=True,
        ),
        RecommendedCheck(
            check_id="check-correlation-context",
            title="Review correlation and timeline context",
            description="Review related events, matched patterns, attack-chain context and any contradictory telemetry.",
            priority=RecommendedCheckPriority.MEDIUM,
            reason="Correlation context can affect priority but should remain explainable.",
            expected_evidence=["correlation summary", "related events", "attack-chain mapping"],
            related_hypothesis_ids=["hypothesis-correlation-context"],
            source_system="ai-soc",
            requires_human_input=True,
        ),
    ]

    recommended_actions = [
        RecommendedAction(
            action_id="action-document-investigation",
            title="Document investigation assessment",
            description="Record validated evidence, open gaps and analyst decision points in the incident workflow.",
            category=RecommendedActionCategory.DOCUMENTATION,
            approval_requirement=RecommendedActionApprovalRequirement.ANALYST_APPROVAL,
            reason="Structured investigation output is decision support and should be reviewed by an analyst.",
            expected_impact="Improves auditability and handoff quality.",
            risk="Low. No operational remediation is executed by this action.",
            related_hypothesis_ids=[hypothesis.hypothesis_id for hypothesis in hypotheses],
            related_evidence_ids=[item.evidence_id for item in primary_evidence],
            execution_supported=False,
        )
    ]

    brief = InvestigationBrief(
        incident_id=incident_id,
        session_id=session_id,
        status=InvestigationSessionStatus.NEEDS_HUMAN_INPUT if fallback_reason else InvestigationSessionStatus.READY_FOR_ANALYST,
        summary=_summary_from_context(context),
        risk_assessment=_risk_assessment(context),
        hypotheses=hypotheses,
        findings=findings,
        recommended_checks=recommended_checks,
        recommended_actions=recommended_actions,
        evidence_used=evidence,
        confidence=confidence,
        limitations=_build_limitations(context, fallback_reason=fallback_reason),
        next_investigation_steps=[
            "Validate source alert details and affected entity context.",
            "Review supporting and contradictory evidence before selecting response actions.",
            "Keep remediation decisions human-approved and auditable.",
        ],
    )
    assert_valid_investigation_brief(brief)
    return brief


def _soften_certainty_language(value: str | None) -> str | None:
    if not value or not contains_unqualified_certainty(value):
        return value

    replacements = {
        "definitely": "may",
        "certainly": "may",
        "without doubt": "with available evidence suggesting",
        "proves": "may support",
        "proven": "supported",
        "root cause is": "possible root cause is",
        "confirmed compromise": "possible compromise",
        "confirmed malicious": "potentially malicious",
    }
    updated = value
    for source, replacement in replacements.items():
        updated = updated.replace(source, replacement)
        updated = updated.replace(source.title(), replacement)
        updated = updated.replace(source.upper(), replacement.upper())
    return updated


def _add_limitation(
    brief: InvestigationBrief,
    *,
    limitation_id: str,
    description: str,
    impact: str,
    missing_data: list[str] | None = None,
    suggested_resolution: str | None = None,
) -> None:
    if any(item.limitation_id == limitation_id for item in brief.limitations):
        return

    brief.limitations.append(
        InvestigationLimitation(
            limitation_id=limitation_id,
            description=description,
            impact=impact,
            missing_data=missing_data or [],
            suggested_resolution=suggested_resolution,
        )
    )


def _enforce_claim_governance(brief: InvestigationBrief) -> InvestigationBrief:
    brief.summary = _soften_certainty_language(brief.summary) or brief.summary
    brief.risk_assessment = _soften_certainty_language(brief.risk_assessment)

    unsupported_count = 0

    for hypothesis in brief.hypotheses:
        hypothesis.statement = _soften_certainty_language(hypothesis.statement) or hypothesis.statement
        for evidence in hypothesis.supporting_evidence:
            if evidence.claim_classification == InvestigationClaimClassification.UNSUPPORTED:
                evidence.claim_classification = InvestigationClaimClassification.SPECULATIVE
                unsupported_count += 1

        if not hypothesis.supporting_evidence and not hypothesis.missing_evidence:
            hypothesis.missing_evidence.append(
                "Additional supporting evidence is required before this hypothesis can be treated as evidence-backed."
            )

    for finding in brief.findings:
        finding.description = _soften_certainty_language(finding.description) or finding.description
        if finding.claim_classification == InvestigationClaimClassification.UNSUPPORTED:
            finding.claim_classification = InvestigationClaimClassification.SPECULATIVE
            unsupported_count += 1

        if (
            finding.claim_classification == InvestigationClaimClassification.EVIDENCE_BACKED
            and not finding.evidence
        ):
            finding.claim_classification = InvestigationClaimClassification.INFERRED
            unsupported_count += 1

    for evidence in brief.evidence_used:
        if evidence.claim_classification == InvestigationClaimClassification.UNSUPPORTED:
            evidence.claim_classification = InvestigationClaimClassification.SPECULATIVE
            unsupported_count += 1

    for action in brief.recommended_actions:
        if action.execution_supported:
            action.execution_supported = False
            _add_limitation(
                brief,
                limitation_id="action-execution-disabled",
                description="A recommended action requested execution support, but execution is disabled in this investigation step.",
                impact="The action remains decision support only.",
                suggested_resolution="Use future human-approved remediation workflow before any operational execution.",
            )

        if (
            action_implies_operational_change(action)
            and action.approval_requirement == RecommendedActionApprovalRequirement.NONE
        ):
            action.approval_requirement = RecommendedActionApprovalRequirement.ANALYST_APPROVAL
            _add_limitation(
                brief,
                limitation_id="operational-action-approval-added",
                description="Operational action guidance was normalized to require analyst approval.",
                impact="No operational change can be treated as automatically approved.",
                suggested_resolution="Review operational actions through the governed approval workflow.",
            )

    if unsupported_count:
        logger.warning(
            "investigation_unsupported_claims_detected",
            extra={"unsupported_claim_count": unsupported_count},
        )
        _add_limitation(
            brief,
            limitation_id="unsupported-claims-normalized",
            description="Unsupported claims were downgraded to speculative or inferred decision-support language.",
            impact="Analyst validation is required before those statements can be used as findings.",
            missing_data=["direct supporting evidence"],
            suggested_resolution="Attach direct evidence or mark the claims as not supported.",
        )

    return brief


def _brief_from_llm_payload(
    payload: dict[str, Any],
    *,
    context: InvestigationContext,
    incident_id: int,
    session_id: str,
) -> InvestigationBrief:
    allowed_fields = set(InvestigationBrief.model_fields)
    filtered = {key: value for key, value in payload.items() if key in allowed_fields}
    filtered["incident_id"] = incident_id
    filtered["session_id"] = session_id
    filtered.setdefault("status", InvestigationSessionStatus.READY_FOR_ANALYST)
    filtered.setdefault(
        "evidence_used",
        [
            item.model_dump(mode="json", exclude_none=True)
            for item in evidence_references_from_context(context)
        ],
    )
    filtered.setdefault("confidence", _confidence_from_context(context).model_dump(mode="json"))
    filtered.setdefault("next_investigation_steps", ["Review the structured brief with an analyst before response decisions."])

    brief = InvestigationBrief(**filtered)
    return _enforce_claim_governance(brief)


def _validate_generated_brief(brief: InvestigationBrief) -> None:
    issues = validate_investigation_brief(brief)
    if issues:
        logger.warning(
            "investigation_validation_failed",
            extra={"issue_count": len(issues), "issue_codes": [issue.code for issue in issues]},
        )
    assert_valid_investigation_brief(brief)


def generate_investigation_brief(
    *,
    context: InvestigationContext | None = None,
    incident_id: int | None = None,
    incident: Any = None,
    raw_events: Sequence[Any] | None = None,
    security_alerts: Sequence[Any] | None = None,
    correlation_summary: Any = None,
    mitre_mapping: Any = None,
    related_entities: Mapping[str, Sequence[str]] | None = None,
    timeline: Sequence[Any] | None = None,
    existing_ai_analysis: str | None = None,
    llm_client: InvestigationLlmClient | None = None,
    model_name: str | None = None,
    session_id: str | None = None,
) -> InvestigationBrief:
    if context is None:
        context = normalize_investigation_context(
            incident_id=incident_id,
            incident=incident,
            raw_events=raw_events,
            security_alerts=security_alerts,
            correlation_summary=correlation_summary,
            mitre_mapping=mitre_mapping,
            related_entities=related_entities,
            timeline=timeline,
            existing_ai_analysis=existing_ai_analysis,
        )
    elif incident_id is not None and context.incident_id is None:
        context = context.model_copy(update={"incident_id": incident_id})
    resolved_incident_id = _brief_incident_id(context, incident_id)
    resolved_session_id = session_id or _new_session_id()

    logger.info(
        "investigation_generation_started",
        extra={
            "incident_id": resolved_incident_id,
            "has_llm_client": bool(llm_client),
            "model_name": model_name,
        },
    )

    if llm_client is None:
        brief = _build_deterministic_brief(
            context,
            incident_id=resolved_incident_id,
            session_id=resolved_session_id,
        )
        logger.info(
            "investigation_generation_completed",
            extra={"incident_id": resolved_incident_id, "mode": "deterministic"},
        )
        return brief

    try:
        messages = [
            {"role": "system", "content": INVESTIGATION_SYSTEM_PROMPT},
            {"role": "user", "content": build_investigation_prompt(context)},
        ]
        raw_output = llm_client(messages)
        if is_invalid_llm_output(raw_output):
            raise ValueError("LLM output was empty, unsafe or not usable.")

        payload = _extract_json_object(raw_output)
        brief = _brief_from_llm_payload(
            payload,
            context=context,
            incident_id=resolved_incident_id,
            session_id=resolved_session_id,
        )
        _validate_generated_brief(brief)
        logger.info(
            "investigation_generation_completed",
            extra={"incident_id": resolved_incident_id, "mode": "llm"},
        )
        return brief

    except Exception as exc:
        reason = f"Structured investigation AI output unavailable: {exc.__class__.__name__}."
        logger.warning(
            "investigation_generation_fallback",
            extra={"incident_id": resolved_incident_id, "reason": reason},
        )
        try:
            brief = _build_deterministic_brief(
                context,
                incident_id=resolved_incident_id,
                session_id=resolved_session_id,
                fallback_reason=reason,
            )
            logger.info(
                "investigation_generation_completed",
                extra={"incident_id": resolved_incident_id, "mode": "fallback"},
            )
            return brief
        except Exception:
            logger.warning(
                "investigation_generation_fallback_minimal",
                extra={"incident_id": resolved_incident_id},
            )
            return create_fallback_investigation_brief(
                incident_id=resolved_incident_id,
                session_id=resolved_session_id,
                reason=reason,
            )
