from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from pydantic import Field

from .adapters import InvestigationContext, safe_text
from .evidence import evidence_text, has_ioc_evidence
from .models import (
    EvidenceReference,
    InvestigationBaseModel,
    InvestigationClaimClassification,
    InvestigationEvidenceStrength,
    InvestigationEvidenceType,
)


logger = logging.getLogger(__name__)


class ReasoningAssessment(InvestigationBaseModel):
    positive_signals: list[str] = Field(default_factory=list)
    negative_signals: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    contradictory_evidence: list[EvidenceReference] = Field(default_factory=list)
    consistency_notes: list[str] = Field(default_factory=list)


def _text_corpus(context: InvestigationContext, evidence: list[EvidenceReference]) -> str:
    parts: list[str] = []
    parts.extend(safe_text(value) for value in context.incident.values())
    parts.extend(evidence_text(item) for item in evidence)
    parts.append(safe_text(context.correlation_summary))
    parts.append(safe_text(context.mitre_mapping))
    parts.append(safe_text(context.existing_ai_analysis))
    for row in context.timeline:
        parts.append(safe_text(row))
    return " ".join(part for part in parts if part).lower()


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


def _timeline_timestamps(context: InvestigationContext) -> list[datetime]:
    timestamps: list[datetime] = []
    for row in context.timeline:
        timestamp = _parse_timestamp(
            row.get("timestamp")
            or row.get("event_timestamp")
            or row.get("created_at")
        )
        if timestamp:
            timestamps.append(timestamp)
    return timestamps


def timeline_is_coherent(context: InvestigationContext) -> bool:
    timestamps = _timeline_timestamps(context)
    if len(timestamps) < 2:
        return False

    ascending = all(left <= right for left, right in zip(timestamps, timestamps[1:]))
    descending = all(left >= right for left, right in zip(timestamps, timestamps[1:]))
    return ascending or descending


def _contradiction_evidence(
    evidence_id: str,
    summary: str,
) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=evidence_id,
        evidence_type=InvestigationEvidenceType.OTHER,
        source_system="ai-soc-reasoning",
        summary=summary,
        strength=InvestigationEvidenceStrength.CONTEXTUAL,
        claim_classification=InvestigationClaimClassification.INFERRED,
    )


def detect_contradictions(
    context: InvestigationContext,
    evidence: list[EvidenceReference],
) -> list[EvidenceReference]:
    contradictions: list[EvidenceReference] = []
    corpus = _text_corpus(context, evidence)

    if any(term in corpus for term in ("false positive", "false_positive", "benign", "suppressed", "noise")):
        contradictions.append(
            _contradiction_evidence(
                "contradiction-noisy-or-benign-context",
                "Evidence contains false-positive, suppressed, benign or noisy operational context.",
            )
        )

    if any(term in corpus for term in ("brute force", "authentication", "login", "ssh")) and any(
        term in corpus
        for term in ("no successful login", "no accepted password", "no session opened")
    ):
        contradictions.append(
            _contradiction_evidence(
                "contradiction-no-successful-login-after-authentication-failure",
                "Authentication context indicates failures without evidence of a successful login.",
            )
        )

    timestamps = _timeline_timestamps(context)
    if len(timestamps) >= 2 and not timeline_is_coherent(context):
        contradictions.append(
            _contradiction_evidence(
                "contradiction-inconsistent-timeline-order",
                "Timeline ordering is inconsistent and should be reviewed before drawing sequence-based conclusions.",
            )
        )

    if contradictions:
        logger.info(
            "investigation_contradictions_detected",
            extra={"contradiction_count": len(contradictions)},
        )

    return contradictions


def identify_missing_evidence(
    context: InvestigationContext,
    evidence: list[EvidenceReference],
) -> list[str]:
    missing: list[str] = []
    corpus = _text_corpus(context, evidence)

    if not context.raw_events:
        missing.append("raw event payload")
    if not context.security_alerts:
        missing.append("normalized security alert record")
    if not context.correlation_summary:
        missing.append("structured correlation summary")
    if not context.timeline:
        missing.append("event timeline")

    if any(term in corpus for term in ("brute force", "authentication", "login", "ssh")):
        if not any(term in corpus for term in ("successful login", "accepted password", "session opened")):
            missing.append("successful login verification")

    if any(term in corpus for term in ("sudo", "privilege", "escalation")):
        if "sudo" not in corpus and "session opened" not in corpus:
            missing.append("sudo or privilege escalation logs")

    if any(term in corpus for term in ("malware", "trojan", "ransomware", "process", "persistence")):
        if not any(term in corpus for term in ("process tree", "file hash", "sha256", "pid", "command line")):
            missing.append("process tree and file hash evidence")

    if any(term in corpus for term in ("exfil", "beacon", "c2", "dns", "outbound")):
        if not any(term in corpus for term in ("dns", "network", "suricata", "destination_ip", "dest_ip")):
            missing.append("DNS and outbound network activity")

    return sorted(set(missing))


def analyze_reasoning_context(
    context: InvestigationContext,
    evidence: list[EvidenceReference],
) -> ReasoningAssessment:
    positive_signals: list[str] = []
    negative_signals: list[str] = []
    consistency_notes: list[str] = []

    if evidence:
        positive_signals.append(f"{len(evidence)} evidence reference(s) normalized.")
    else:
        negative_signals.append("No evidence references were normalized.")

    if len(evidence) >= 3:
        positive_signals.append("Multiple evidence sources are available.")

    if context.correlation_summary or context.incident.get("correlation_score"):
        positive_signals.append("Correlation context is available.")

    if has_ioc_evidence(evidence):
        positive_signals.append("IOC-like evidence is present.")

    if timeline_is_coherent(context):
        positive_signals.append("Timeline ordering is coherent.")
        consistency_notes.append("Timeline can support sequence-based reasoning.")
    elif context.timeline:
        negative_signals.append("Timeline ordering needs analyst review.")

    missing_evidence = identify_missing_evidence(context, evidence)
    contradictory_evidence = detect_contradictions(context, evidence)

    if contradictory_evidence:
        negative_signals.append("Contradictory or dampening evidence is present.")

    if missing_evidence:
        negative_signals.append("Required evidence is missing for stronger conclusions.")

    return ReasoningAssessment(
        positive_signals=sorted(set(positive_signals)),
        negative_signals=sorted(set(negative_signals)),
        missing_evidence=missing_evidence,
        contradictory_evidence=contradictory_evidence,
        consistency_notes=consistency_notes,
    )


def classify_hypothesis_claim(
    supporting_evidence: list[EvidenceReference],
    missing_evidence: list[str],
    contradictory_evidence: list[EvidenceReference],
) -> InvestigationClaimClassification:
    if contradictory_evidence and not supporting_evidence:
        return InvestigationClaimClassification.SPECULATIVE
    if supporting_evidence and not contradictory_evidence:
        return InvestigationClaimClassification.EVIDENCE_BACKED
    if supporting_evidence:
        return InvestigationClaimClassification.INFERRED
    if missing_evidence:
        return InvestigationClaimClassification.SPECULATIVE
    return InvestigationClaimClassification.UNSUPPORTED


def build_hypothesis_rationale(
    *,
    supporting_evidence: list[EvidenceReference],
    missing_evidence: list[str],
    contradictory_evidence: list[EvidenceReference],
) -> str:
    parts: list[str] = []

    if supporting_evidence:
        parts.append(f"Supported by {len(supporting_evidence)} evidence reference(s).")
    if missing_evidence:
        parts.append("Additional evidence required: " + ", ".join(missing_evidence[:5]) + ".")
    if contradictory_evidence:
        parts.append(f"{len(contradictory_evidence)} contradictory or dampening signal(s) require analyst review.")

    if not parts:
        return "This hypothesis has insufficient evidence and must be treated as unsupported."

    return " ".join(parts)
