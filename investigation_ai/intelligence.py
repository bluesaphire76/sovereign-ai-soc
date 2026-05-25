from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Sequence
from enum import Enum
from typing import Any

from pydantic import Field, field_validator

from .adapters import InvestigationContext
from .models import (
    ConfidenceAssessment,
    InvestigationBaseModel,
    InvestigationBrief,
    InvestigationClaimClassification,
    InvestigationConfidenceLevel,
    InvestigationFinding,
    InvestigationFindingType,
    InvestigationLimitation,
    RecommendedCheck,
    RecommendedCheckPriority,
)
from .similarity import (
    IncidentSimilarityMatch,
    IncidentSimilarityProfile,
    SimilaritySignalType,
    SimilarityStrength,
    build_similarity_match,
    build_similarity_profile,
)


logger = logging.getLogger(__name__)


class RecurringEntityType(str, Enum):
    HOST = "HOST"
    USER = "USER"
    SOURCE_IP = "SOURCE_IP"
    DESTINATION_IP = "DESTINATION_IP"
    RULE_ID = "RULE_ID"
    MITRE_TECHNIQUE = "MITRE_TECHNIQUE"
    EVIDENCE_KEYWORD = "EVIDENCE_KEYWORD"


class RecurringPatternType(str, Enum):
    MITRE_OVERLAP = "MITRE_OVERLAP"
    RULE_OVERLAP = "RULE_OVERLAP"
    ENTITY_OVERLAP = "ENTITY_OVERLAP"
    INVESTIGATION_PATTERN = "INVESTIGATION_PATTERN"
    TIMELINE_PROXIMITY = "TIMELINE_PROXIMITY"


class SimilarityAnalysisLimits(InvestigationBaseModel):
    max_related_incidents: int = 8
    max_time_window_days: int = 30
    max_entity_expansion: int = 20
    max_similarity_depth: int = 1
    timeout_seconds: float = 2.0
    min_score: int = 35

    @field_validator("max_related_incidents", mode="before")
    @classmethod
    def normalize_related_incidents(cls, value: object) -> int:
        return max(1, min(50, int(value or 1)))

    @field_validator("max_time_window_days", mode="before")
    @classmethod
    def normalize_window(cls, value: object) -> int:
        return max(1, min(365, int(value or 1)))

    @field_validator("max_entity_expansion", mode="before")
    @classmethod
    def normalize_entity_limit(cls, value: object) -> int:
        return max(1, min(100, int(value or 1)))

    @field_validator("max_similarity_depth", mode="before")
    @classmethod
    def normalize_depth(cls, value: object) -> int:
        return max(0, min(3, int(value or 0)))

    @field_validator("timeout_seconds", mode="before")
    @classmethod
    def normalize_timeout(cls, value: object) -> float:
        return max(0.1, min(30.0, float(value or 0.1)))

    @field_validator("min_score", mode="before")
    @classmethod
    def normalize_min_score(cls, value: object) -> int:
        return max(0, min(100, int(value or 0)))


class RecurringEntity(InvestigationBaseModel):
    entity_type: RecurringEntityType
    value: str
    occurrence_count: int
    related_incident_ids: list[int] = Field(default_factory=list)


class RecurringPattern(InvestigationBaseModel):
    pattern_type: RecurringPatternType
    name: str
    occurrence_count: int
    related_incident_ids: list[int] = Field(default_factory=list)
    rationale: str


class HistoricalInvestigationContext(InvestigationBaseModel):
    incident_id: int
    generated_at: str
    total_candidates: int = 0
    matches: list[IncidentSimilarityMatch] = Field(default_factory=list)
    recurring_entities: list[RecurringEntity] = Field(default_factory=list)
    recurring_patterns: list[RecurringPattern] = Field(default_factory=list)
    boundaries_applied: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)
    rationale: str = "No historical similarity context was available."


def _now_text() -> str:
    from .models import utc_now

    return utc_now().isoformat()


def _context_incident_id(context: InvestigationContext) -> int:
    if context.incident_id is not None:
        return context.incident_id

    for value in (context.incident.get("id"), context.incident.get("incident_id")):
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return 0


def _counter_from_matches(
    matches: Sequence[IncidentSimilarityMatch],
    *,
    key: str,
) -> Counter[str]:
    counter: Counter[str] = Counter()
    for match in matches:
        values = match.matched_entities.get(key, [])
        counter.update(values)
    return counter


def _recurring_entities(
    matches: Sequence[IncidentSimilarityMatch],
    limits: SimilarityAnalysisLimits,
) -> list[RecurringEntity]:
    entities: list[RecurringEntity] = []

    entity_specs = (
        (RecurringEntityType.HOST, "hosts"),
        (RecurringEntityType.USER, "users"),
        (RecurringEntityType.SOURCE_IP, "source_ips"),
        (RecurringEntityType.DESTINATION_IP, "destination_ips"),
    )
    for entity_type, key in entity_specs:
        counter = _counter_from_matches(matches, key=key)
        for value, count in counter.most_common(limits.max_entity_expansion):
            incident_ids = [
                match.incident_id
                for match in matches
                if value in match.matched_entities.get(key, [])
            ]
            entities.append(
                RecurringEntity(
                    entity_type=entity_type,
                    value=value,
                    occurrence_count=count,
                    related_incident_ids=incident_ids[: limits.max_related_incidents],
                )
            )

    mitre_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()
    for match in matches:
        mitre_counter.update(match.matched_mitre)
        rule_counter.update(match.matched_rule_ids)

    for value, count in mitre_counter.most_common(limits.max_entity_expansion):
        entities.append(
            RecurringEntity(
                entity_type=RecurringEntityType.MITRE_TECHNIQUE,
                value=value,
                occurrence_count=count,
                related_incident_ids=[
                    match.incident_id for match in matches if value in match.matched_mitre
                ][: limits.max_related_incidents],
            )
        )
    for value, count in rule_counter.most_common(limits.max_entity_expansion):
        entities.append(
            RecurringEntity(
                entity_type=RecurringEntityType.RULE_ID,
                value=value,
                occurrence_count=count,
                related_incident_ids=[
                    match.incident_id for match in matches if value in match.matched_rule_ids
                ][: limits.max_related_incidents],
            )
        )

    return sorted(
        entities,
        key=lambda item: (-item.occurrence_count, item.entity_type.value, item.value),
    )[: limits.max_entity_expansion]


def _recurring_patterns(matches: Sequence[IncidentSimilarityMatch]) -> list[RecurringPattern]:
    patterns: list[RecurringPattern] = []

    mitre_matches = [match for match in matches if match.matched_mitre]
    if mitre_matches:
        patterns.append(
            RecurringPattern(
                pattern_type=RecurringPatternType.MITRE_OVERLAP,
                name="Recurring MITRE technique overlap",
                occurrence_count=len(mitre_matches),
                related_incident_ids=[match.incident_id for match in mitre_matches],
                rationale="Historical incidents share MITRE technique mappings with the current incident.",
            )
        )

    rule_matches = [match for match in matches if match.matched_rule_ids]
    if rule_matches:
        patterns.append(
            RecurringPattern(
                pattern_type=RecurringPatternType.RULE_OVERLAP,
                name="Recurring detector or rule overlap",
                occurrence_count=len(rule_matches),
                related_incident_ids=[match.incident_id for match in rule_matches],
                rationale="Historical incidents share detector or rule identifiers with the current incident.",
            )
        )

    entity_matches = [match for match in matches if match.matched_entities]
    if entity_matches:
        patterns.append(
            RecurringPattern(
                pattern_type=RecurringPatternType.ENTITY_OVERLAP,
                name="Recurring entity overlap",
                occurrence_count=len(entity_matches),
                related_incident_ids=[match.incident_id for match in entity_matches],
                rationale="Historical incidents share hosts, users or network entities with the current incident.",
            )
        )

    timeline_matches = [
        match
        for match in matches
        if any(
            signal.signal_type == SimilaritySignalType.TIMELINE_PROXIMITY
            for signal in match.score.signals
        )
    ]
    if timeline_matches:
        patterns.append(
            RecurringPattern(
                pattern_type=RecurringPatternType.TIMELINE_PROXIMITY,
                name="Timeline proximity",
                occurrence_count=len(timeline_matches),
                related_incident_ids=[match.incident_id for match in timeline_matches],
                rationale="Historical incidents occurred within the configured similarity window.",
            )
        )

    return patterns


def build_historical_investigation_context(
    *,
    current_context: InvestigationContext,
    historical_contexts: Sequence[InvestigationContext] | None = None,
    current_brief: InvestigationBrief | None = None,
    historical_briefs: Sequence[InvestigationBrief] | None = None,
    limits: SimilarityAnalysisLimits | None = None,
) -> HistoricalInvestigationContext:
    resolved_limits = limits or SimilarityAnalysisLimits()
    started = time.monotonic()
    boundaries: list[str] = []
    failures: list[str] = []
    candidate_contexts = list(historical_contexts or [])
    candidate_briefs = {
        brief.incident_id: brief
        for brief in (historical_briefs or [])
    }
    current_profile = build_similarity_profile(current_context, brief=current_brief)
    matches: list[IncidentSimilarityMatch] = []

    logger.info(
        "cross_incident_similarity_started",
        extra={
            "incident_id": current_profile.incident_id,
            "candidate_count": len(candidate_contexts),
        },
    )

    if resolved_limits.max_similarity_depth <= 0:
        boundaries.append("max_similarity_depth")
        return HistoricalInvestigationContext(
            incident_id=current_profile.incident_id,
            generated_at=_now_text(),
            total_candidates=len(candidate_contexts),
            boundaries_applied=boundaries,
            rationale="Similarity analysis skipped because max similarity depth is zero.",
        )

    for candidate_context in candidate_contexts:
        if time.monotonic() - started > resolved_limits.timeout_seconds:
            boundaries.append("timeout_seconds")
            break

        candidate_id = _context_incident_id(candidate_context)
        candidate_profile = build_similarity_profile(
            candidate_context,
            brief=candidate_briefs.get(candidate_id),
        )
        if candidate_profile.incident_id == current_profile.incident_id:
            continue

        try:
            match = build_similarity_match(
                current_profile,
                candidate_profile,
                max_time_window_days=resolved_limits.max_time_window_days,
            )
        except Exception as exc:
            logger.warning(
                "cross_incident_similarity_failure",
                extra={"reason": exc.__class__.__name__},
            )
            failures.append(exc.__class__.__name__)
            continue

        if match.score.score >= resolved_limits.min_score:
            matches.append(match)

    matches = sorted(
        matches,
        key=lambda match: (-match.score.score, match.incident_id),
    )
    if len(matches) > resolved_limits.max_related_incidents:
        boundaries.append("max_related_incidents")
        matches = matches[: resolved_limits.max_related_incidents]

    recurring_entities = _recurring_entities(matches, resolved_limits)
    recurring_patterns = _recurring_patterns(matches)
    if recurring_entities and len(recurring_entities) >= resolved_limits.max_entity_expansion:
        boundaries.append("max_entity_expansion")

    rationale = (
        f"{len(matches)} related incident(s) met the deterministic similarity threshold."
        if matches
        else "No historical incidents met the deterministic similarity threshold."
    )

    logger.info(
        "cross_incident_similarity_completed",
        extra={
            "incident_id": current_profile.incident_id,
            "match_count": len(matches),
            "recurring_entity_count": len(recurring_entities),
            "boundary_count": len(boundaries),
        },
    )

    return HistoricalInvestigationContext(
        incident_id=current_profile.incident_id,
        generated_at=_now_text(),
        total_candidates=len(candidate_contexts),
        matches=matches,
        recurring_entities=recurring_entities,
        recurring_patterns=recurring_patterns,
        boundaries_applied=sorted(set(boundaries)),
        failures=failures,
        rationale=rationale,
    )


def confidence_with_historical_context(
    confidence: ConfidenceAssessment,
    historical_context: HistoricalInvestigationContext,
) -> ConfidenceAssessment:
    if not historical_context.matches:
        return confidence

    strongest = historical_context.matches[0].score
    bonus = 0
    if strongest.strength == SimilarityStrength.STRONG:
        bonus = 8
    elif strongest.strength == SimilarityStrength.MODERATE:
        bonus = 5
    elif strongest.strength == SimilarityStrength.WEAK:
        bonus = 2

    score = min(100, confidence.score + bonus)
    level = InvestigationConfidenceLevel.UNKNOWN
    if score >= 75:
        level = InvestigationConfidenceLevel.HIGH
    elif score >= 40:
        level = InvestigationConfidenceLevel.MEDIUM
    elif score > 0:
        level = InvestigationConfidenceLevel.LOW

    return ConfidenceAssessment(
        score=score,
        level=level,
        rationale=confidence.rationale,
        positive_signals=sorted(
            {
                *confidence.positive_signals,
                f"{len(historical_context.matches)} historical similarity match(es) met threshold.",
            }
        ),
        negative_signals=confidence.negative_signals,
        missing_evidence=confidence.missing_evidence,
        contradictory_evidence=confidence.contradictory_evidence,
        scoring_factors=[
            *confidence.scoring_factors,
            f"historical similarity context: +{bonus}",
        ],
    )


def enrich_brief_with_historical_context(
    brief: InvestigationBrief,
    historical_context: HistoricalInvestigationContext,
) -> InvestigationBrief:
    if not historical_context.matches:
        return brief

    top_matches = historical_context.matches[:3]
    related_ids = [str(match.incident_id) for match in top_matches]
    finding = InvestigationFinding(
        finding_id="finding-cross-incident-context",
        finding_type=InvestigationFindingType.TIMELINE_OBSERVATION,
        title="Historical similarity context is available",
        description=(
            "Deterministic similarity scoring found related historical incidents for analyst context. "
            f"Top related incident IDs: {', '.join(related_ids)}."
        ),
        claim_classification=InvestigationClaimClassification.INFERRED,
        confidence=confidence_with_historical_context(brief.confidence, historical_context),
        evidence=[],
        technical_impact="Historical context can guide review of recurring entities, MITRE mappings and detector patterns.",
    )
    check = RecommendedCheck(
        check_id="check-historical-similarity-context",
        title="Review similar historical incidents",
        description="Review related incidents, recurring entities and repeated MITRE/rule overlaps before finalizing conclusions.",
        priority=RecommendedCheckPriority.MEDIUM,
        reason="Historical similarity is contextual intelligence and should be validated by an analyst.",
        expected_evidence=["similar incident list", "similarity rationale", "recurring entity summary"],
        requires_human_input=True,
    )
    limitation = InvestigationLimitation(
        limitation_id="cross-incident-context-is-contextual",
        description="Cross-incident similarity is contextual intelligence, not proof of common cause.",
        impact="Related historical incidents should guide investigation, not automatically change response decisions.",
        missing_data=[],
        suggested_resolution="Review similarity signals and supporting evidence before treating incidents as related.",
    )

    findings = [*brief.findings]
    if not any(item.finding_id == finding.finding_id for item in findings):
        findings.append(finding)

    checks = [*brief.recommended_checks]
    if not any(item.check_id == check.check_id for item in checks):
        checks.append(check)

    limitations = [*brief.limitations]
    if not any(item.limitation_id == limitation.limitation_id for item in limitations):
        limitations.append(limitation)

    next_steps = [*brief.next_investigation_steps]
    next_step = "Review similar historical incidents and recurring entities as contextual decision support."
    if next_step not in next_steps:
        next_steps.append(next_step)

    return brief.model_copy(
        update={
            "findings": findings,
            "recommended_checks": checks,
            "limitations": limitations,
            "confidence": confidence_with_historical_context(brief.confidence, historical_context),
            "next_investigation_steps": next_steps,
        }
    )
