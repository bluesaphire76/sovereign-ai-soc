from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field, field_validator

from .adapters import InvestigationContext, mitre_techniques_from_context, safe_text
from .evidence import evidence_text, normalize_evidence_references
from .models import InvestigationBaseModel, InvestigationBrief


logger = logging.getLogger(__name__)


class SimilarityStrength(str, Enum):
    NONE = "NONE"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"


class SimilaritySignalType(str, Enum):
    MITRE_OVERLAP = "MITRE_OVERLAP"
    SAME_SOURCE_IP = "SAME_SOURCE_IP"
    SAME_DESTINATION_IP = "SAME_DESTINATION_IP"
    SAME_USER = "SAME_USER"
    SAME_HOST = "SAME_HOST"
    SAME_RULE_ID = "SAME_RULE_ID"
    TIMELINE_PROXIMITY = "TIMELINE_PROXIMITY"
    EVIDENCE_TEXT_SIMILARITY = "EVIDENCE_TEXT_SIMILARITY"
    HYPOTHESIS_SIMILARITY = "HYPOTHESIS_SIMILARITY"


class SimilaritySignal(InvestigationBaseModel):
    signal_type: SimilaritySignalType
    description: str
    weight: int
    overlap_values: list[str] = Field(default_factory=list)


class IncidentSimilarityScore(InvestigationBaseModel):
    score: int = 0
    strength: SimilarityStrength = SimilarityStrength.NONE
    signals: list[SimilaritySignal] = Field(default_factory=list)
    rationale: str = "No meaningful similarity signals were detected."

    @field_validator("score", mode="before")
    @classmethod
    def normalize_score(cls, value: object) -> int:
        try:
            numeric = int(round(float(value)))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return 0
        return min(100, max(0, numeric))


class IncidentSimilarityMatch(InvestigationBaseModel):
    incident_id: int
    score: IncidentSimilarityScore
    matched_entities: dict[str, list[str]] = Field(default_factory=dict)
    matched_mitre: list[str] = Field(default_factory=list)
    matched_rule_ids: list[str] = Field(default_factory=list)
    matched_evidence_ids: list[str] = Field(default_factory=list)
    rationale: str


class IncidentSimilarityProfile(InvestigationBaseModel):
    incident_id: int
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence_keywords: list[str] = Field(default_factory=list)
    hypothesis_keywords: list[str] = Field(default_factory=list)
    timestamp: datetime | None = None
    evidence_ids: list[str] = Field(default_factory=list)


TOKEN_RE = re.compile(r"[a-zA-Z0-9_.:-]{3,}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


STOP_WORDS = {
    "this",
    "that",
    "with",
    "from",
    "into",
    "over",
    "under",
    "alert",
    "event",
    "events",
    "incident",
    "source",
    "security",
    "available",
    "review",
    "validate",
    "requires",
    "required",
}


def _normalize_values(values: Sequence[Any]) -> list[str]:
    normalized = {
        safe_text(value).lower()
        for value in values
        if safe_text(value)
    }
    return sorted(normalized)


def _get_first(data: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None

    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = f"{candidate[:-1]}+00:00"

    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _incident_id(context: InvestigationContext) -> int:
    for value in (context.incident_id, context.incident.get("id"), context.incident.get("incident_id")):
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
    return 0


def _keywords_from_text(value: str, *, limit: int = 24) -> list[str]:
    tokens = {
        token.lower()
        for token in TOKEN_RE.findall(value)
        if token.lower() not in STOP_WORDS and not token.isdigit()
    }
    return sorted(tokens)[:limit]


def _context_timestamp(context: InvestigationContext) -> datetime | None:
    incident = context.incident
    timestamp = _parse_timestamp(
        _get_first(incident, "timestamp", "event_timestamp", "created_at", "updated_at")
    )
    if timestamp:
        return timestamp

    for row in [*context.raw_events, *context.security_alerts, *context.timeline]:
        timestamp = _parse_timestamp(
            _get_first(row, "timestamp", "event_timestamp", "created_at", "updated_at")
        )
        if timestamp:
            return timestamp
    return None


def build_similarity_profile(
    context: InvestigationContext,
    *,
    brief: InvestigationBrief | None = None,
) -> IncidentSimilarityProfile:
    evidence = normalize_evidence_references(context)
    incident = context.incident
    text_parts: list[str] = [
        safe_text(incident.get("rule")),
        safe_text(incident.get("rule_description")),
        safe_text(incident.get("correlation_type")),
        safe_text(incident.get("attack_chain")),
        safe_text(context.correlation_summary),
        safe_text(context.existing_ai_analysis),
    ]
    text_parts.extend(evidence_text(item) for item in evidence)

    for entity_values in context.related_entities.values():
        text_parts.extend(safe_text(value) for value in entity_values)

    ips = set(IP_RE.findall(" ".join(text_parts)))

    hosts = [
        incident.get("agent"),
        incident.get("host"),
        *[item.host for item in evidence],
        *context.related_entities.get("host", []),
        *context.related_entities.get("agent", []),
    ]
    users = [
        incident.get("user"),
        *[item.user for item in evidence],
        *context.related_entities.get("user", []),
        *context.related_entities.get("account", []),
    ]
    source_ips = [
        incident.get("source_ip"),
        incident.get("src_ip"),
        *[item.source_ip for item in evidence],
        *context.related_entities.get("source_ip", []),
        *context.related_entities.get("ip", []),
    ]
    destination_ips = [
        incident.get("destination_ip"),
        incident.get("dest_ip"),
        *[item.destination_ip for item in evidence],
        *context.related_entities.get("destination_ip", []),
    ]
    rule_ids = [
        incident.get("rule_id"),
        incident.get("rule"),
        *[item.rule_id for item in evidence],
    ]
    mitre = [
        *mitre_techniques_from_context(context),
        *[item.mitre_technique for item in evidence],
    ]
    hypothesis_keywords: list[str] = []
    if brief:
        for hypothesis in brief.hypotheses:
            hypothesis_keywords.extend(
                _keywords_from_text(f"{hypothesis.title} {hypothesis.statement}", limit=16)
            )

    return IncidentSimilarityProfile(
        incident_id=_incident_id(context),
        hosts=_normalize_values(hosts),
        users=_normalize_values(users),
        source_ips=_normalize_values([*source_ips, *ips]),
        destination_ips=_normalize_values(destination_ips),
        rule_ids=_normalize_values(rule_ids),
        mitre_techniques=_normalize_values(mitre),
        evidence_keywords=_keywords_from_text(" ".join(text_parts)),
        hypothesis_keywords=_normalize_values(hypothesis_keywords),
        timestamp=_context_timestamp(context),
        evidence_ids=[item.evidence_id for item in evidence],
    )


def _overlap(left: Sequence[str], right: Sequence[str], *, limit: int = 12) -> list[str]:
    return sorted(set(left).intersection(set(right)))[:limit]


def _strength_for_score(score: int) -> SimilarityStrength:
    if score >= 70:
        return SimilarityStrength.STRONG
    if score >= 45:
        return SimilarityStrength.MODERATE
    if score > 0:
        return SimilarityStrength.WEAK
    return SimilarityStrength.NONE


def _timeline_signal(
    current: IncidentSimilarityProfile,
    candidate: IncidentSimilarityProfile,
    *,
    max_time_window_days: int,
) -> SimilaritySignal | None:
    if current.timestamp is None or candidate.timestamp is None:
        return None

    delta_seconds = abs((current.timestamp - candidate.timestamp).total_seconds())
    days = delta_seconds / 86400
    if days > max_time_window_days:
        return None

    if days <= 1:
        weight = 8
    elif days <= 7:
        weight = 5
    else:
        weight = 3

    return SimilaritySignal(
        signal_type=SimilaritySignalType.TIMELINE_PROXIMITY,
        description="Incidents occurred within the configured historical similarity window.",
        weight=weight,
        overlap_values=[f"{days:.1f} day(s) apart"],
    )


def explain_similarity(
    current: IncidentSimilarityProfile,
    candidate: IncidentSimilarityProfile,
    *,
    max_time_window_days: int = 30,
) -> IncidentSimilarityScore:
    signals: list[SimilaritySignal] = []

    signal_specs = (
        (
            SimilaritySignalType.MITRE_OVERLAP,
            current.mitre_techniques,
            candidate.mitre_techniques,
            24,
            "MITRE ATT&CK technique overlap was observed.",
        ),
        (
            SimilaritySignalType.SAME_SOURCE_IP,
            current.source_ips,
            candidate.source_ips,
            22,
            "Source IP overlap was observed.",
        ),
        (
            SimilaritySignalType.SAME_DESTINATION_IP,
            current.destination_ips,
            candidate.destination_ips,
            14,
            "Destination IP overlap was observed.",
        ),
        (
            SimilaritySignalType.SAME_USER,
            current.users,
            candidate.users,
            16,
            "User or account overlap was observed.",
        ),
        (
            SimilaritySignalType.SAME_HOST,
            current.hosts,
            candidate.hosts,
            18,
            "Host or agent overlap was observed.",
        ),
        (
            SimilaritySignalType.SAME_RULE_ID,
            current.rule_ids,
            candidate.rule_ids,
            14,
            "Rule or detector overlap was observed.",
        ),
    )

    for signal_type, left, right, weight, description in signal_specs:
        values = _overlap(left, right)
        if values:
            signals.append(
                SimilaritySignal(
                    signal_type=signal_type,
                    description=description,
                    weight=weight,
                    overlap_values=values,
                )
            )

    keyword_overlap = _overlap(current.evidence_keywords, candidate.evidence_keywords, limit=16)
    if len(keyword_overlap) >= 3:
        signals.append(
            SimilaritySignal(
                signal_type=SimilaritySignalType.EVIDENCE_TEXT_SIMILARITY,
                description="Evidence summaries share investigation-relevant terms.",
                weight=min(10, len(keyword_overlap) * 2),
                overlap_values=keyword_overlap,
            )
        )

    hypothesis_overlap = _overlap(current.hypothesis_keywords, candidate.hypothesis_keywords, limit=16)
    if len(hypothesis_overlap) >= 2:
        signals.append(
            SimilaritySignal(
                signal_type=SimilaritySignalType.HYPOTHESIS_SIMILARITY,
                description="Investigation hypotheses share recurring terms.",
                weight=min(8, len(hypothesis_overlap) * 2),
                overlap_values=hypothesis_overlap,
            )
        )

    timeline = _timeline_signal(
        current,
        candidate,
        max_time_window_days=max_time_window_days,
    )
    if timeline:
        signals.append(timeline)

    score = min(100, sum(signal.weight for signal in signals))
    strength = _strength_for_score(score)
    if signals:
        rationale = " ".join(
            f"{signal.signal_type.value}: {', '.join(signal.overlap_values[:4])}."
            for signal in signals[:5]
        )
    else:
        rationale = "No configured similarity signals overlapped."

    logger.debug(
        "incident_similarity_score_calculated",
        extra={
            "incident_id": current.incident_id,
            "candidate_incident_id": candidate.incident_id,
            "score": score,
            "strength": strength.value,
            "signal_count": len(signals),
        },
    )

    return IncidentSimilarityScore(
        score=score,
        strength=strength,
        signals=signals,
        rationale=rationale,
    )


def build_similarity_match(
    current: IncidentSimilarityProfile,
    candidate: IncidentSimilarityProfile,
    *,
    max_time_window_days: int = 30,
) -> IncidentSimilarityMatch:
    score = explain_similarity(
        current,
        candidate,
        max_time_window_days=max_time_window_days,
    )
    matched_entities = {
        "hosts": _overlap(current.hosts, candidate.hosts),
        "users": _overlap(current.users, candidate.users),
        "source_ips": _overlap(current.source_ips, candidate.source_ips),
        "destination_ips": _overlap(current.destination_ips, candidate.destination_ips),
    }
    matched_entities = {key: values for key, values in matched_entities.items() if values}
    matched_mitre = _overlap(current.mitre_techniques, candidate.mitre_techniques)
    matched_rule_ids = _overlap(current.rule_ids, candidate.rule_ids)

    return IncidentSimilarityMatch(
        incident_id=candidate.incident_id,
        score=score,
        matched_entities=matched_entities,
        matched_mitre=matched_mitre,
        matched_rule_ids=matched_rule_ids,
        matched_evidence_ids=candidate.evidence_ids[:8],
        rationale=score.rationale,
    )
