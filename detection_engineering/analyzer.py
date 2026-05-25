from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from pydantic import Field

from .models import (
    CorrelationOpportunity,
    DetectionEngineeringBaseModel,
    DetectionEngineeringCategory,
    DetectionEngineeringConfidence,
    DetectionEngineeringFinding,
    DetectionEngineeringReport,
    DetectionEngineeringSeverity,
    DetectionEngineeringSignal,
    DetectionGap,
    DetectionRuleAssessment,
    SuppressionCandidate,
    ThresholdTuningRecommendation,
)
from .recommendations import generate_recommendations
from .scoring import (
    calculate_confidence,
    calculate_detection_quality_score,
    calculate_noise_score,
    calculate_recurrence_score,
    severity_from_scores,
)


logger = logging.getLogger(__name__)


class DetectionEngineeringContext(DetectionEngineeringBaseModel):
    raw_events: list[dict[str, Any]] = Field(default_factory=list)
    security_alerts: list[dict[str, Any]] = Field(default_factory=list)
    incidents: list[dict[str, Any]] = Field(default_factory=list)
    event_aggregates: list[dict[str, Any]] = Field(default_factory=list)
    suppression_outcomes: list[dict[str, Any]] = Field(default_factory=list)
    historical_contexts: list[Any] = Field(default_factory=list)
    generated_by: str = "system"


def safe_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            return str(value)
    return str(value).strip()


def _safe_json(value: object) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _record_to_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        data = dict(value)
    elif hasattr(value, "model_dump"):
        candidate = value.model_dump()
        data = dict(candidate) if isinstance(candidate, Mapping) else {}
    else:
        fields = (
            "id",
            "source",
            "source_event_id",
            "raw_event_id",
            "security_alert_id",
            "incident_id",
            "status",
            "event_timestamp",
            "timestamp",
            "created_at",
            "agent",
            "host",
            "location",
            "decoder",
            "rule_id",
            "rule_description",
            "rule",
            "level",
            "severity",
            "severity_bucket",
            "mitre",
            "count",
            "sample_event_json",
            "last_event_json",
            "raw_alert",
            "correlation_type",
            "correlation_score",
            "policy_id",
            "decision",
            "should_suppress",
            "reasons",
        )
        data = {field: getattr(value, field) for field in fields if hasattr(value, field)}

    normalized: dict[str, Any] = {}
    for key, item in data.items():
        if isinstance(item, datetime):
            normalized[key] = item.isoformat()
        else:
            normalized[key] = item

    for key in ("payload_json", "sample_event_json", "last_event_json", "raw_alert"):
        parsed = _safe_json(normalized.get(key))
        if parsed is not None:
            normalized[key] = parsed

    return normalized


def normalize_detection_engineering_context(
    *,
    raw_events: Sequence[Any] | None = None,
    security_alerts: Sequence[Any] | None = None,
    incidents: Sequence[Any] | None = None,
    event_aggregates: Sequence[Any] | None = None,
    suppression_outcomes: Sequence[Any] | None = None,
    historical_contexts: Sequence[Any] | None = None,
    generated_by: str = "system",
) -> DetectionEngineeringContext:
    return DetectionEngineeringContext(
        raw_events=[_record_to_dict(item) for item in (raw_events or [])],
        security_alerts=[_record_to_dict(item) for item in (security_alerts or [])],
        incidents=[_record_to_dict(item) for item in (incidents or [])],
        event_aggregates=[_record_to_dict(item) for item in (event_aggregates or [])],
        suppression_outcomes=[_record_to_dict(item) for item in (suppression_outcomes or [])],
        historical_contexts=list(historical_contexts or []),
        generated_by=generated_by,
    )


def _nested(data: Mapping[str, Any], *path: str) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _first(data: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


def _rule_id(record: Mapping[str, Any]) -> str:
    raw_alert = record.get("raw_alert") if isinstance(record.get("raw_alert"), Mapping) else {}
    payload = record.get("payload_json") if isinstance(record.get("payload_json"), Mapping) else {}
    value = (
        _first(record, "rule_id", "rule.id")
        or _nested(record, "rule", "id")
        or _nested(raw_alert, "rule", "id")
        or _nested(payload, "rule", "id")
        or "unknown"
    )
    return safe_text(value) or "unknown"


def _rule_description(record: Mapping[str, Any]) -> str | None:
    raw_alert = record.get("raw_alert") if isinstance(record.get("raw_alert"), Mapping) else {}
    payload = record.get("payload_json") if isinstance(record.get("payload_json"), Mapping) else {}
    value = (
        _first(record, "rule_description", "rule")
        or _nested(record, "rule", "description")
        or _nested(raw_alert, "rule", "description")
        or _nested(payload, "rule", "description")
    )
    return safe_text(value) or None


def _mitre_values(record: Mapping[str, Any]) -> list[str]:
    raw_alert = record.get("raw_alert") if isinstance(record.get("raw_alert"), Mapping) else {}
    payload = record.get("payload_json") if isinstance(record.get("payload_json"), Mapping) else {}
    candidates = [
        record.get("mitre"),
        _nested(record, "rule", "mitre"),
        _nested(raw_alert, "rule", "mitre"),
        _nested(payload, "rule", "mitre"),
    ]
    values: set[str] = set()

    def add_value(item: Any) -> None:
        if not item:
            return
        if isinstance(item, str):
            stripped = item.strip()
            if stripped and stripped not in {"{}", "[]", "None", "null"}:
                values.add(stripped)
            return
        if isinstance(item, Mapping):
            for value in item.values():
                add_value(value)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes)):
            for value in item:
                add_value(value)
            return
        values.add(str(item).strip())

    for candidate in candidates:
        add_value(candidate)
    return sorted(value for value in values if value)


def _level(record: Mapping[str, Any]) -> int:
    raw_alert = record.get("raw_alert") if isinstance(record.get("raw_alert"), Mapping) else {}
    payload = record.get("payload_json") if isinstance(record.get("payload_json"), Mapping) else {}
    value = (
        _first(record, "level")
        or _nested(record, "rule", "level")
        or _nested(raw_alert, "rule", "level")
        or _nested(payload, "rule", "level")
    )
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _signal(source_type: str, record: Mapping[str, Any], index: int) -> DetectionEngineeringSignal:
    rule_id = _rule_id(record)
    count = record.get("count") if source_type in {"event_aggregate", "suppression_outcome"} else 1
    source_reference = safe_text(
        _first(record, "id", "source_event_id", "incident_id", "raw_event_id")
    ) or f"{source_type}:{index}"
    return DetectionEngineeringSignal(
        signal_id=f"{source_type}-{source_reference}",
        source_type=source_type,
        source_system=safe_text(record.get("source")) or "unknown",
        source_reference=source_reference,
        rule_id=rule_id,
        rule_description=_rule_description(record),
        timestamp=safe_text(_first(record, "event_timestamp", "timestamp", "created_at")) or None,
        host=safe_text(_first(record, "agent", "host")) or None,
        severity=safe_text(_first(record, "severity_bucket", "severity", "level")) or None,
        count=count,
        details={
            "level": _level(record),
            "mitre": _mitre_values(record),
            "status": safe_text(record.get("status")),
            "decision": safe_text(record.get("decision")),
            "policy_id": safe_text(record.get("policy_id")),
        },
    )


def _is_low_severity(signal: DetectionEngineeringSignal) -> bool:
    severity = safe_text(signal.severity).lower()
    if severity in {"low", "info", "informational"}:
        return True
    try:
        return int(severity) <= 3
    except (TypeError, ValueError):
        return signal.details.get("level", 0) <= 3


def _is_false_positive(record: Mapping[str, Any]) -> bool:
    text = " ".join(
        safe_text(value).lower()
        for value in (
            record.get("status"),
            record.get("status_reason"),
            record.get("comment"),
            record.get("closure_reason"),
        )
    )
    return "false" in text and "positive" in text


def _build_rule_assessments(context: DetectionEngineeringContext) -> list[DetectionRuleAssessment]:
    grouped: dict[str, list[DetectionEngineeringSignal]] = defaultdict(list)
    source_records = {
        "raw_event": context.raw_events,
        "security_alert": context.security_alerts,
        "incident": context.incidents,
        "event_aggregate": context.event_aggregates,
        "suppression_outcome": context.suppression_outcomes,
    }
    false_positive_counts: Counter[str] = Counter()

    for source_type, records in source_records.items():
        for index, record in enumerate(records):
            signal = _signal(source_type, record, index)
            grouped[signal.rule_id or "unknown"].append(signal)
            if source_type == "incident" and _is_false_positive(record):
                false_positive_counts[signal.rule_id or "unknown"] += 1

    assessments: list[DetectionRuleAssessment] = []
    for rule_id, evidence in grouped.items():
        alert_count = sum(
            signal.count
            for signal in evidence
            if signal.source_type in {"raw_event", "security_alert", "event_aggregate"}
        )
        incident_count = sum(1 for signal in evidence if signal.source_type == "incident")
        suppressed_count = sum(
            signal.count
            for signal in evidence
            if signal.source_type == "suppression_outcome"
            and (
                signal.details.get("decision", "").upper().startswith("SUPPRESS")
                or signal.details.get("policy_id")
            )
        )
        low_severity_count = sum(signal.count for signal in evidence if _is_low_severity(signal))
        mitre = sorted(
            {
                value
                for signal in evidence
                for value in signal.details.get("mitre", [])
                if safe_text(value)
            }
        )
        noise_score = calculate_noise_score(
            alert_count=alert_count,
            incident_count=incident_count,
            suppressed_count=suppressed_count,
            false_positive_count=false_positive_counts[rule_id],
            low_severity_count=low_severity_count,
        )
        recurrence_score = calculate_recurrence_score(
            alert_count=alert_count,
            incident_count=incident_count,
        )
        quality_score = calculate_detection_quality_score(
            noise_score=noise_score,
            recurrence_score=recurrence_score,
            mitre_present=bool(mitre),
            evidence_count=len(evidence),
        )
        descriptions = [signal.rule_description for signal in evidence if signal.rule_description]
        source_systems = [signal.source_system for signal in evidence if signal.source_system]
        assessments.append(
            DetectionRuleAssessment(
                rule_id=rule_id,
                source_system=Counter(source_systems).most_common(1)[0][0] if source_systems else "unknown",
                rule_description=Counter(descriptions).most_common(1)[0][0] if descriptions else None,
                alert_count=alert_count,
                incident_count=incident_count,
                suppressed_count=suppressed_count,
                false_positive_count=false_positive_counts[rule_id],
                low_severity_count=low_severity_count,
                mitre_techniques=mitre,
                noise_score=noise_score,
                recurrence_score=recurrence_score,
                quality_score=quality_score,
                evidence=evidence[:12],
                rationale=(
                    f"Rule {rule_id} has {alert_count} alert observations, "
                    f"{incident_count} incidents and {suppressed_count} suppression outcomes."
                ),
            )
        )

    return sorted(
        assessments,
        key=lambda item: (-item.noise_score, -item.recurrence_score, item.rule_id),
    )


def _finding(
    *,
    suffix: str,
    assessment: DetectionRuleAssessment,
    category: DetectionEngineeringCategory,
    title: str,
    description: str,
    rationale: str,
    unsupported: bool = False,
) -> DetectionEngineeringFinding:
    evidence = assessment.evidence[:8]
    return DetectionEngineeringFinding(
        finding_id=f"{suffix}-{assessment.rule_id}",
        title=title,
        description=description,
        category=category,
        severity=severity_from_scores(
            noise_score=assessment.noise_score,
            recurrence_score=assessment.recurrence_score,
            quality_score=assessment.quality_score,
        ),
        confidence=calculate_confidence(
            evidence_count=len(evidence),
            recurrence_score=assessment.recurrence_score,
            unsupported=unsupported,
        ),
        evidence=evidence,
        rationale=rationale,
        rule_id=assessment.rule_id,
        source_system=assessment.source_system,
        unsupported=unsupported,
    )


def _derive_findings(
    assessments: Sequence[DetectionRuleAssessment],
    context: DetectionEngineeringContext,
) -> tuple[
    list[DetectionEngineeringFinding],
    list[DetectionGap],
    list[SuppressionCandidate],
    list[ThresholdTuningRecommendation],
    list[CorrelationOpportunity],
]:
    findings: list[DetectionEngineeringFinding] = []
    gaps: list[DetectionGap] = []
    suppression_candidates: list[SuppressionCandidate] = []
    threshold_tuning: list[ThresholdTuningRecommendation] = []
    correlation_opportunities: list[CorrelationOpportunity] = []

    for assessment in assessments:
        if assessment.noise_score >= 55:
            reason = (
                "Repeated low-value or suppressed observations indicate a candidate for governed "
                "noise-reduction review."
            )
            findings.append(
                _finding(
                    suffix="finding-noise",
                    assessment=assessment,
                    category=DetectionEngineeringCategory.SUPPRESSION_CANDIDATE,
                    title=f"Governed suppression review for rule {assessment.rule_id}",
                    description=(
                        "The rule shows recurring noise indicators. Review whether suppression, "
                        "deduplication or routing policy should be adjusted after analyst validation."
                    ),
                    rationale=reason,
                )
            )
            suppression_candidates.append(
                SuppressionCandidate(
                    candidate_id=f"suppression-{assessment.rule_id}",
                    rule_id=assessment.rule_id,
                    source_system=assessment.source_system,
                    reason=reason,
                    evidence=assessment.evidence[:8],
                    risk="Suppression can hide relevant signals if applied too broadly.",
                )
            )

        if assessment.alert_count >= 20 and assessment.incident_count <= max(1, assessment.alert_count // 10):
            reason = (
                "High alert volume with limited incident conversion suggests threshold or routing "
                "review may reduce analyst load."
            )
            findings.append(
                _finding(
                    suffix="finding-threshold",
                    assessment=assessment,
                    category=DetectionEngineeringCategory.THRESHOLD_TUNING,
                    title=f"Threshold review for high-volume rule {assessment.rule_id}",
                    description=(
                        "The rule produces recurring alert volume with limited incident conversion. "
                        "Review thresholds, aggregation windows and severity routing."
                    ),
                    rationale=reason,
                )
            )
            threshold_tuning.append(
                ThresholdTuningRecommendation(
                    tuning_id=f"threshold-{assessment.rule_id}",
                    rule_id=assessment.rule_id,
                    source_system=assessment.source_system,
                    current_behavior=(
                        f"{assessment.alert_count} alert observations and "
                        f"{assessment.incident_count} incident conversions were observed."
                    ),
                    suggested_review="Review threshold, aggregation and severity routing against historical data.",
                    evidence=assessment.evidence[:8],
                    expected_benefit="Reduced alert fatigue while retaining visibility for meaningful signals.",
                    operational_risk="Incorrect thresholds can suppress early-stage attacker behavior.",
                )
            )

        if assessment.recurrence_score >= 25 and not assessment.mitre_techniques:
            reason = "Recurring detection behavior lacks MITRE technique context in the available metadata."
            findings.append(
                _finding(
                    suffix="finding-mitre-gap",
                    assessment=assessment,
                    category=DetectionEngineeringCategory.MITRE_ENRICHMENT,
                    title=f"MITRE enrichment gap for rule {assessment.rule_id}",
                    description=(
                        "The rule recurs in available telemetry but does not expose MITRE mapping. "
                        "Review whether ATT&CK metadata can improve investigation and reporting context."
                    ),
                    rationale=reason,
                )
            )
            gaps.append(
                DetectionGap(
                    gap_id=f"gap-mitre-{assessment.rule_id}",
                    title=f"Missing MITRE context for rule {assessment.rule_id}",
                    description=reason,
                    affected_rule_ids=[assessment.rule_id],
                    missing_context=["MITRE technique mapping"],
                    evidence=assessment.evidence[:8],
                    severity=DetectionEngineeringSeverity.LOW,
                    confidence=calculate_confidence(
                        evidence_count=len(assessment.evidence),
                        recurrence_score=assessment.recurrence_score,
                    ),
                )
            )

        if assessment.incident_count >= 2 and assessment.recurrence_score >= 30:
            reason = "The same rule appears across multiple incidents and may benefit from correlation review."
            findings.append(
                _finding(
                    suffix="finding-correlation",
                    assessment=assessment,
                    category=DetectionEngineeringCategory.CORRELATION_IMPROVEMENT,
                    title=f"Correlation review for recurring rule {assessment.rule_id}",
                    description=(
                        "Review whether repeated incidents for this rule should be correlated with host, "
                        "user, MITRE or timeline context."
                    ),
                    rationale=reason,
                )
            )
            correlation_opportunities.append(
                CorrelationOpportunity(
                    opportunity_id=f"correlation-{assessment.rule_id}",
                    title=f"Correlation opportunity for rule {assessment.rule_id}",
                    description=reason,
                    related_rule_ids=[assessment.rule_id],
                    recurring_entities=sorted(
                        {
                            signal.host
                            for signal in assessment.evidence
                            if signal.host
                        }
                    ),
                    evidence=assessment.evidence[:8],
                    expected_benefit="Improved incident grouping and clearer correlation-first decisions.",
                )
            )

    description_to_rules: dict[str, list[str]] = defaultdict(list)
    for assessment in assessments:
        if assessment.rule_description:
            description_to_rules[assessment.rule_description.lower()].append(assessment.rule_id)

    for description, rule_ids in sorted(description_to_rules.items()):
        unique_ids = sorted(set(rule_ids))
        if len(unique_ids) < 2:
            continue
        matching = [item for item in assessments if item.rule_id in unique_ids]
        evidence = [signal for item in matching for signal in item.evidence[:3]]
        findings.append(
            DetectionEngineeringFinding(
                finding_id=f"finding-duplicate-rules-{'-'.join(unique_ids[:3])}",
                title="Potential duplicate detection rules",
                description=(
                    "Multiple rule identifiers share the same description. Review whether this is expected "
                    "source behavior or duplicate detection logic."
                ),
                category=DetectionEngineeringCategory.RULE_DEDUPLICATION,
                severity=DetectionEngineeringSeverity.LOW,
                confidence=calculate_confidence(
                    evidence_count=len(evidence),
                    recurrence_score=sum(item.recurrence_score for item in matching) // max(1, len(matching)),
                ),
                evidence=evidence[:8],
                rationale=f"Rule IDs {', '.join(unique_ids)} share description: {description}.",
                rule_id=",".join(unique_ids),
                source_system="mixed",
            )
        )

    for historical in context.historical_contexts:
        recurring_patterns = getattr(historical, "recurring_patterns", None) or []
        if not recurring_patterns:
            continue
        findings.append(
            DetectionEngineeringFinding(
                finding_id="finding-cross-incident-pattern-context",
                title="Cross-incident recurring pattern available for detection review",
                description=(
                    "Historical investigation context contains recurring patterns that may inform "
                    "detection tuning or correlation review."
                ),
                category=DetectionEngineeringCategory.CORRELATION_IMPROVEMENT,
                severity=DetectionEngineeringSeverity.LOW,
                confidence=DetectionEngineeringConfidence.MEDIUM,
                evidence=[],
                rationale=(
                    "Cross-incident context is available but should be reviewed alongside concrete "
                    "alert and incident evidence before implementation."
                ),
                unsupported=True,
            )
        )
        break

    return findings, gaps, suppression_candidates, threshold_tuning, correlation_opportunities


def analyze_detection_engineering(
    context: DetectionEngineeringContext,
) -> DetectionEngineeringReport:
    logger.info(
        "detection_engineering_analysis_started",
        extra={
            "raw_events": len(context.raw_events),
            "security_alerts": len(context.security_alerts),
            "incidents": len(context.incidents),
            "event_aggregates": len(context.event_aggregates),
        },
    )

    try:
        assessments = _build_rule_assessments(context)
        findings, gaps, suppression_candidates, threshold_tuning, correlation_opportunities = (
            _derive_findings(assessments, context)
        )
        recommendations = generate_recommendations(findings)
        source_counts = {
            "raw_events": len(context.raw_events),
            "security_alerts": len(context.security_alerts),
            "incidents": len(context.incidents),
            "event_aggregates": len(context.event_aggregates),
            "suppression_outcomes": len(context.suppression_outcomes),
            "historical_contexts": len(context.historical_contexts),
        }
        report = DetectionEngineeringReport(
            report_id="detection-engineering-report",
            summary=(
                f"Detection engineering analysis reviewed {len(assessments)} rule assessments "
                f"and produced {len(recommendations)} analyst-reviewable recommendations."
            ),
            rule_assessments=assessments,
            findings=findings,
            gaps=gaps,
            suppression_candidates=suppression_candidates,
            threshold_tuning=threshold_tuning,
            correlation_opportunities=correlation_opportunities,
            recommendations=recommendations,
            limitations=[
                "Recommendations are proposals for analyst review and do not modify production detection rules.",
                "Available findings are limited to the supplied alert, incident, aggregate and historical context.",
            ],
            source_counts=source_counts,
            no_production_rule_changes=True,
        )
        logger.info(
            "detection_engineering_recommendations_generated",
            extra={
                "rule_assessments": len(assessments),
                "findings": len(findings),
                "recommendations": len(recommendations),
            },
        )
        return report
    except Exception as exc:
        logger.warning(
            "detection_engineering_analysis_fallback",
            extra={"reason": exc.__class__.__name__},
        )
        return DetectionEngineeringReport(
            report_id="detection-engineering-report",
            summary="Detection engineering analysis could not complete. No production rule changes were made.",
            limitations=[
                "Detection engineering fallback was used because analysis failed.",
                "No production rules, thresholds or suppression policies were modified.",
            ],
            source_counts={
                "raw_events": len(context.raw_events),
                "security_alerts": len(context.security_alerts),
                "incidents": len(context.incidents),
                "event_aggregates": len(context.event_aggregates),
                "suppression_outcomes": len(context.suppression_outcomes),
                "historical_contexts": len(context.historical_contexts),
            },
            no_production_rule_changes=True,
        )
