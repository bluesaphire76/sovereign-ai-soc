from __future__ import annotations

import logging
import re
from collections import Counter

from pydantic import Field

from .adapters import InvestigationContext, evidence_references_from_context, safe_text
from .models import (
    EvidenceReference,
    InvestigationBaseModel,
    InvestigationClaimClassification,
    InvestigationEvidenceStrength,
    InvestigationEvidenceType,
)


logger = logging.getLogger(__name__)

IOC_PATTERN = re.compile(
    r"("
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|[a-fA-F0-9]{32,64}"
    r"|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    r")"
)


class EvidenceNormalizationResult(InvestigationBaseModel):
    evidence: list[EvidenceReference] = Field(default_factory=list)
    source_counts: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


def evidence_text(evidence: EvidenceReference) -> str:
    return " ".join(
        safe_text(value)
        for value in (
            evidence.summary,
            evidence.source_system,
            evidence.source_table,
            evidence.source_reference,
            evidence.rule_id,
            evidence.mitre_technique,
            evidence.host,
            evidence.user,
            evidence.source_ip,
            evidence.destination_ip,
            evidence.raw_reference,
        )
        if safe_text(value)
    )


def _dedupe_evidence(items: list[EvidenceReference]) -> list[EvidenceReference]:
    seen: set[str] = set()
    normalized: list[EvidenceReference] = []

    for item in items:
        if item.evidence_id in seen:
            logger.debug(
                "evidence_normalization_duplicate_skipped",
                extra={"evidence_id": item.evidence_id},
            )
            continue
        seen.add(item.evidence_id)
        normalized.append(item)

    return normalized


def _existing_ai_analysis_evidence(context: InvestigationContext) -> EvidenceReference | None:
    if not context.existing_ai_analysis:
        return None

    incident_id = context.incident_id or 0
    return EvidenceReference(
        evidence_id=f"existing-ai-analysis-{incident_id}",
        evidence_type=InvestigationEvidenceType.OTHER,
        source_system="ai-soc-ai",
        source_reference=f"incident:{incident_id}:ai_analysis",
        summary=(
            "Existing AI analysis is available as contextual decision support. "
            "It is not treated as evidence-backed fact by itself."
        ),
        raw_reference=f"incident:{incident_id}:ai_analysis",
        strength=InvestigationEvidenceStrength.CONTEXTUAL,
        claim_classification=InvestigationClaimClassification.INFERRED,
    )


def normalize_evidence(context: InvestigationContext) -> EvidenceNormalizationResult:
    warnings: list[str] = []

    try:
        evidence = evidence_references_from_context(context)
    except Exception as exc:
        logger.warning(
            "evidence_normalization_failed",
            extra={"reason": exc.__class__.__name__},
        )
        evidence = []
        warnings.append("evidence_normalization_failed")

    ai_evidence = _existing_ai_analysis_evidence(context)
    if ai_evidence:
        evidence.append(ai_evidence)

    evidence = _dedupe_evidence(evidence)
    source_counts = Counter(item.evidence_type.value for item in evidence)

    return EvidenceNormalizationResult(
        evidence=evidence,
        source_counts=dict(sorted(source_counts.items())),
        warnings=warnings,
    )


def normalize_evidence_references(context: InvestigationContext) -> list[EvidenceReference]:
    return normalize_evidence(context).evidence


def evidence_by_type(
    evidence: list[EvidenceReference],
) -> dict[InvestigationEvidenceType, list[EvidenceReference]]:
    grouped: dict[InvestigationEvidenceType, list[EvidenceReference]] = {}
    for item in evidence:
        grouped.setdefault(item.evidence_type, []).append(item)
    return grouped


def evidence_ids(evidence: list[EvidenceReference]) -> list[str]:
    return [item.evidence_id for item in evidence]


def has_ioc_evidence(evidence: list[EvidenceReference]) -> bool:
    return any(IOC_PATTERN.search(evidence_text(item)) for item in evidence)


def select_evidence_for_keywords(
    evidence: list[EvidenceReference],
    keywords: list[str],
    *,
    limit: int = 5,
) -> list[EvidenceReference]:
    lowered_keywords = [keyword.lower() for keyword in keywords if keyword]
    selected: list[EvidenceReference] = []

    for item in evidence:
        text = evidence_text(item).lower()
        if any(keyword in text for keyword in lowered_keywords):
            selected.append(item)
        if len(selected) >= limit:
            break

    return selected


def strongest_evidence(
    evidence: list[EvidenceReference],
    *,
    limit: int = 5,
) -> list[EvidenceReference]:
    ranking = {
        InvestigationEvidenceStrength.STRONG: 0,
        InvestigationEvidenceStrength.MODERATE: 1,
        InvestigationEvidenceStrength.CONTEXTUAL: 2,
        InvestigationEvidenceStrength.WEAK: 3,
        InvestigationEvidenceStrength.UNKNOWN: 4,
    }
    return sorted(evidence, key=lambda item: ranking.get(item.strength, 5))[:limit]
