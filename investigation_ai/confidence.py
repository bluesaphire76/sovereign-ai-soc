from __future__ import annotations

import logging
from typing import Iterable

from .adapters import InvestigationContext, safe_text
from .evidence import has_ioc_evidence
from .models import (
    ConfidenceAssessment,
    EvidenceReference,
    InvestigationConfidenceLevel,
    InvestigationEvidenceStrength,
)


logger = logging.getLogger(__name__)


def _normalize_score(value: int) -> int:
    return min(100, max(0, int(round(value))))


def confidence_level_for_score(score: int) -> InvestigationConfidenceLevel:
    if score >= 75:
        return InvestigationConfidenceLevel.HIGH
    if score >= 40:
        return InvestigationConfidenceLevel.MEDIUM
    if score > 0:
        return InvestigationConfidenceLevel.LOW
    return InvestigationConfidenceLevel.UNKNOWN


def _related_event_count(context: InvestigationContext | None) -> int:
    if context is None:
        return 0

    summary = context.correlation_summary
    if isinstance(summary, dict):
        for key in ("related_events", "related_event_count", "count"):
            value = summary.get(key)
            try:
                return int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue

    return 0


def _has_repeated_pattern(context: InvestigationContext | None) -> bool:
    if context is None:
        return False

    summary = context.correlation_summary
    if isinstance(summary, dict):
        patterns = summary.get("matched_patterns")
        if isinstance(patterns, list) and patterns:
            return True

    corpus = " ".join(
        safe_text(value)
        for value in (
            context.incident.get("rule"),
            context.incident.get("rule_description"),
            context.incident.get("correlation_type"),
            context.correlation_summary,
        )
    ).lower()
    return "pattern" in corpus or "repeated" in corpus


def _has_mitre_mapping(context: InvestigationContext | None, evidence: list[EvidenceReference]) -> bool:
    if context is not None and context.mitre_mapping:
        return True
    return any(item.mitre_technique for item in evidence)


def _evidence_points(evidence: list[EvidenceReference]) -> tuple[int, list[str]]:
    points = 0
    factors: list[str] = []
    strength_points = {
        InvestigationEvidenceStrength.STRONG: 12,
        InvestigationEvidenceStrength.MODERATE: 8,
        InvestigationEvidenceStrength.CONTEXTUAL: 3,
        InvestigationEvidenceStrength.WEAK: 2,
        InvestigationEvidenceStrength.UNKNOWN: 1,
    }

    for item in evidence[:8]:
        item_points = strength_points.get(item.strength, 1)
        points += item_points
        factors.append(f"{item.evidence_id}: +{item_points} evidence strength {item.strength.value}")

    return min(points, 32), factors


def calculate_confidence(
    *,
    context: InvestigationContext | None = None,
    supporting_evidence: Iterable[EvidenceReference] | None = None,
    missing_evidence: Iterable[str] | None = None,
    contradictory_evidence: Iterable[EvidenceReference] | None = None,
    negative_signals: Iterable[str] | None = None,
    unsupported_claim_count: int = 0,
    noisy_operational_pattern: bool = False,
) -> ConfidenceAssessment:
    evidence = list(supporting_evidence or [])
    missing = sorted({item for item in (missing_evidence or []) if item})
    contradictions = list(contradictory_evidence or [])
    explicit_negative_signals = sorted({item for item in (negative_signals or []) if item})

    score = 20
    positive: list[str] = []
    negative: list[str] = []
    factors: list[str] = ["base: +20 structured investigation baseline"]

    evidence_score, evidence_factors = _evidence_points(evidence)
    score += evidence_score
    factors.extend(evidence_factors)
    if evidence:
        positive.append(f"{len(evidence)} supporting evidence reference(s).")

    related_events = _related_event_count(context)
    if related_events >= 2:
        score += 12
        positive.append("Multiple correlated events are present.")
        factors.append("multiple correlated events: +12")

    if _has_repeated_pattern(context):
        score += 8
        positive.append("Repeated or matched pattern context is present.")
        factors.append("repeated pattern context: +8")

    if _has_mitre_mapping(context, evidence):
        score += 6
        positive.append("MITRE mapping is available.")
        factors.append("MITRE mapping present: +6")

    if has_ioc_evidence(evidence):
        score += 6
        positive.append("IOC-like evidence is present.")
        factors.append("IOC evidence present: +6")

    if context is not None and len(context.timeline) >= 2:
        score += 6
        positive.append("Timeline context is available.")
        factors.append("timeline context: +6")

    if missing:
        penalty = min(24, len(missing) * 4)
        score -= penalty
        negative.append("Missing evidence limits confidence.")
        factors.append(f"missing evidence ({len(missing)}): -{penalty}")

    if contradictions:
        penalty = min(30, len(contradictions) * 12)
        score -= penalty
        negative.append("Contradictory evidence reduces confidence.")
        factors.append(f"contradictory evidence ({len(contradictions)}): -{penalty}")

    if noisy_operational_pattern:
        score -= 10
        negative.append("Noisy operational pattern reduces confidence.")
        factors.append("noisy operational pattern: -10")

    if unsupported_claim_count:
        penalty = min(45, unsupported_claim_count * 20)
        score -= penalty
        negative.append("Unsupported claims were downgraded.")
        factors.append(f"unsupported claims ({unsupported_claim_count}): -{penalty}")
        logger.warning(
            "confidence_downgraded_for_unsupported_claims",
            extra={"unsupported_claim_count": unsupported_claim_count, "penalty": penalty},
        )

    if explicit_negative_signals:
        penalty = min(12, len(explicit_negative_signals) * 3)
        score -= penalty
        negative.extend(explicit_negative_signals)
        factors.append(f"negative reasoning signals ({len(explicit_negative_signals)}): -{penalty}")

    normalized_score = _normalize_score(score)
    level = confidence_level_for_score(normalized_score)
    rationale = (
        "Deterministic confidence is calculated from evidence strength, correlation, MITRE context, "
        "timeline availability, missing evidence, contradictory evidence and unsupported-claim penalties."
    )

    logger.debug(
        "confidence_calculated",
        extra={"score": normalized_score, "level": level.value, "factor_count": len(factors)},
    )

    return ConfidenceAssessment(
        score=normalized_score,
        level=level,
        rationale=rationale,
        positive_signals=sorted(set(positive)),
        negative_signals=sorted(set(negative)),
        missing_evidence=missing,
        contradictory_evidence=[item.evidence_id for item in contradictions],
        scoring_factors=factors,
    )


def calculate_hypothesis_confidence(
    *,
    context: InvestigationContext | None = None,
    supporting_evidence: Iterable[EvidenceReference] | None = None,
    missing_evidence: Iterable[str] | None = None,
    contradictory_evidence: Iterable[EvidenceReference] | None = None,
    unsupported_claim_count: int = 0,
) -> ConfidenceAssessment:
    return calculate_confidence(
        context=context,
        supporting_evidence=supporting_evidence,
        missing_evidence=missing_evidence,
        contradictory_evidence=contradictory_evidence,
        unsupported_claim_count=unsupported_claim_count,
    )
