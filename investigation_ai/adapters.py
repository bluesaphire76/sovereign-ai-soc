from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from pydantic import Field

from .models import (
    EvidenceReference,
    InvestigationBaseModel,
    InvestigationClaimClassification,
    InvestigationEvidenceStrength,
    InvestigationEvidenceType,
)


class InvestigationContext(InvestigationBaseModel):
    incident_id: int | None = None
    incident: dict[str, Any] = Field(default_factory=dict)
    raw_events: list[dict[str, Any]] = Field(default_factory=list)
    security_alerts: list[dict[str, Any]] = Field(default_factory=list)
    correlation_summary: dict[str, Any] | list[Any] | str | None = None
    mitre_mapping: dict[str, Any] | list[Any] | str | None = None
    related_entities: dict[str, list[str]] = Field(default_factory=dict)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    existing_ai_analysis: str | None = None


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


def safe_json_loads(value: object) -> Any:
    if isinstance(value, (dict, list)):
        return value

    if not isinstance(value, str) or not value.strip():
        return None

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}

    if isinstance(value, Mapping):
        return dict(value)

    if hasattr(value, "model_dump"):
        data = value.model_dump()
        return dict(data) if isinstance(data, Mapping) else {}

    fields = (
        "id",
        "incident_id",
        "status",
        "timestamp",
        "event_timestamp",
        "created_at",
        "agent",
        "host",
        "user",
        "source",
        "source_event_id",
        "source_index",
        "source_table",
        "source_reference",
        "raw_event_id",
        "security_alert_id",
        "rule",
        "rule_id",
        "rule_description",
        "level",
        "severity",
        "severity_bucket",
        "mitre",
        "risk_score",
        "ai_analysis",
        "raw_alert",
        "correlated",
        "correlation_summary",
        "correlation_score",
        "attack_chain",
        "correlation_type",
        "escalation_reason",
        "recommended_priority",
        "payload_json",
    )
    data: dict[str, Any] = {}
    for field in fields:
        if hasattr(value, field):
            data[field] = getattr(value, field)
    return data


def _normalize_record(value: Any) -> dict[str, Any]:
    data = _as_dict(value)
    normalized: dict[str, Any] = {}

    for key, item in data.items():
        if isinstance(item, datetime):
            normalized[key] = item.isoformat()
        else:
            normalized[key] = item

    payload = safe_json_loads(normalized.get("payload_json"))
    if payload is not None:
        normalized["payload_json"] = payload

    raw_alert = safe_json_loads(normalized.get("raw_alert"))
    if raw_alert is not None:
        normalized["raw_alert"] = raw_alert

    return normalized


def _as_record_list(values: Mapping[str, Any] | Sequence[Any] | None) -> list[dict[str, Any]]:
    if not values:
        return []

    if isinstance(values, Mapping):
        return [_normalize_record(values)]

    return [_normalize_record(value) for value in values]


def _get_first(data: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return value
    return None


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _coerce_timestamp(value: object) -> datetime | None:
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


def _normalize_entities(values: Mapping[str, Sequence[str]] | None) -> dict[str, list[str]]:
    if not values:
        return {}

    normalized: dict[str, list[str]] = {}
    for key, items in values.items():
        normalized[key] = sorted(
            {
                safe_text(item)
                for item in items
                if safe_text(item)
            }
        )
    return normalized


def normalize_investigation_context(
    *,
    incident_id: int | None = None,
    incident: Any = None,
    raw_events: Mapping[str, Any] | Sequence[Any] | None = None,
    security_alerts: Mapping[str, Any] | Sequence[Any] | None = None,
    correlation_summary: Any = None,
    mitre_mapping: Any = None,
    related_entities: Mapping[str, Sequence[str]] | None = None,
    timeline: Sequence[Any] | None = None,
    existing_ai_analysis: str | None = None,
) -> InvestigationContext:
    incident_record = _normalize_record(incident)
    resolved_incident_id = incident_id or _coerce_int(
        _get_first(incident_record, "incident_id", "id")
    )

    resolved_correlation_summary = correlation_summary
    if resolved_correlation_summary is None:
        resolved_correlation_summary = safe_json_loads(
            incident_record.get("correlation_summary")
        ) or incident_record.get("correlation_summary")

    resolved_mitre_mapping = mitre_mapping
    if resolved_mitre_mapping is None:
        resolved_mitre_mapping = safe_json_loads(incident_record.get("mitre")) or incident_record.get("mitre")

    resolved_ai_analysis = existing_ai_analysis
    if resolved_ai_analysis is None:
        resolved_ai_analysis = safe_text(incident_record.get("ai_analysis")) or None

    return InvestigationContext(
        incident_id=resolved_incident_id,
        incident=incident_record,
        raw_events=_as_record_list(raw_events),
        security_alerts=_as_record_list(security_alerts),
        correlation_summary=resolved_correlation_summary,
        mitre_mapping=resolved_mitre_mapping,
        related_entities=_normalize_entities(related_entities),
        timeline=_as_record_list(timeline),
        existing_ai_analysis=resolved_ai_analysis,
    )


def normalize_existing_ai_analysis(value: Any) -> str | None:
    text = safe_text(value)
    return text or None


def context_from_command_room_payload(payload: Mapping[str, Any]) -> InvestigationContext:
    """Normalize existing command-room style payloads without coupling to frontend shape."""
    incident = payload.get("incident") or payload.get("incident_payload") or payload
    return normalize_investigation_context(
        incident=incident,
        raw_events=payload.get("raw_events") or payload.get("raw_event_context"),
        security_alerts=payload.get("security_alerts") or payload.get("alerts"),
        correlation_summary=payload.get("correlation_summary"),
        mitre_mapping=payload.get("mitre_mapping") or payload.get("mitre"),
        related_entities=payload.get("related_entities") or payload.get("entities"),
        timeline=payload.get("timeline") or payload.get("events"),
        existing_ai_analysis=normalize_existing_ai_analysis(
            payload.get("ai_analysis")
            or payload.get("command_brief")
            or payload.get("incident_ai_brief")
        ),
    )


def context_from_incident_ai_payload(
    incident_payload: Mapping[str, Any],
    *,
    ai_brief: Any = None,
) -> InvestigationContext:
    """Adapter for existing Incident AI Brief payloads used by current workflows."""
    return normalize_investigation_context(
        incident=incident_payload,
        correlation_summary=incident_payload.get("correlation_summary"),
        mitre_mapping=incident_payload.get("mitre"),
        related_entities=incident_payload.get("extracted_entities"),
        existing_ai_analysis=normalize_existing_ai_analysis(
            ai_brief or incident_payload.get("ai_analysis")
        ),
    )


def _extract_mitre_label(value: object) -> str | None:
    if isinstance(value, str):
        return value.strip() or None

    if isinstance(value, Mapping):
        for key in ("technique", "technique_id", "id", "name"):
            text = safe_text(value.get(key))
            if text:
                return text

    return None


def mitre_techniques_from_context(context: InvestigationContext) -> list[str]:
    value = context.mitre_mapping

    if isinstance(value, str):
        loaded = safe_json_loads(value)
        if loaded is None:
            return [item.strip() for item in value.split(",") if item.strip()]
        value = loaded

    if isinstance(value, Mapping):
        candidates: list[object] = []
        for key in ("techniques", "mitre", "attack", "ids", "tactics"):
            item = value.get(key)
            if isinstance(item, list):
                candidates.extend(item)
            elif item:
                candidates.append(item)
        label = _extract_mitre_label(value)
        if label:
            candidates.append(label)
        return sorted({label for item in candidates if (label := _extract_mitre_label(item))})

    if isinstance(value, list):
        return sorted({label for item in value if (label := _extract_mitre_label(item))})

    return []


def evidence_references_from_context(context: InvestigationContext) -> list[EvidenceReference]:
    evidence: list[EvidenceReference] = []
    incident = context.incident
    incident_id = context.incident_id or _coerce_int(_get_first(incident, "id")) or 0

    if incident:
        evidence.append(
            EvidenceReference(
                evidence_id=f"incident-{incident_id}",
                evidence_type=InvestigationEvidenceType.INCIDENT,
                source_system="ai-soc",
                source_table="incidents",
                source_reference=str(incident_id),
                timestamp=_coerce_timestamp(_get_first(incident, "timestamp", "created_at")),
                host=safe_text(_get_first(incident, "agent", "host")) or None,
                rule_id=safe_text(_get_first(incident, "rule_id", "rule")) or None,
                mitre_technique=safe_text(incident.get("mitre")) or None,
                summary=safe_text(_get_first(incident, "rule", "rule_description", "escalation_reason"))
                or "Primary incident record.",
                raw_reference=f"incident:{incident_id}",
                strength=InvestigationEvidenceStrength.MODERATE,
                claim_classification=InvestigationClaimClassification.EVIDENCE_BACKED,
            )
        )

    for index, row in enumerate(context.raw_events):
        row_id = _coerce_int(row.get("id")) or index + 1
        evidence.append(
            EvidenceReference(
                evidence_id=f"raw-event-{row_id}",
                evidence_type=InvestigationEvidenceType.RAW_EVENT,
                source_system=safe_text(row.get("source")) or "wazuh",
                source_table="raw_events",
                source_reference=safe_text(_get_first(row, "source_event_id", "id")),
                timestamp=_coerce_timestamp(_get_first(row, "event_timestamp", "created_at")),
                host=safe_text(row.get("agent")) or None,
                rule_id=safe_text(row.get("rule_id")) or None,
                summary=safe_text(row.get("rule_description")) or "Raw event associated with the incident.",
                raw_reference=f"raw_events:{row_id}",
                strength=InvestigationEvidenceStrength.MODERATE,
                claim_classification=InvestigationClaimClassification.EVIDENCE_BACKED,
            )
        )

    for index, row in enumerate(context.security_alerts):
        row_id = _coerce_int(row.get("id")) or index + 1
        evidence.append(
            EvidenceReference(
                evidence_id=f"security-alert-{row_id}",
                evidence_type=InvestigationEvidenceType.SECURITY_ALERT,
                source_system=safe_text(row.get("source")) or "wazuh",
                source_table="security_alerts",
                source_reference=safe_text(_get_first(row, "source_event_id", "id")),
                timestamp=_coerce_timestamp(_get_first(row, "event_timestamp", "created_at")),
                host=safe_text(row.get("agent")) or None,
                rule_id=safe_text(row.get("rule_id")) or None,
                summary=safe_text(row.get("rule_description")) or "Security alert associated with the incident.",
                raw_reference=f"security_alerts:{row_id}",
                strength=InvestigationEvidenceStrength.STRONG,
                claim_classification=InvestigationClaimClassification.EVIDENCE_BACKED,
            )
        )

    if context.correlation_summary:
        evidence.append(
            EvidenceReference(
                evidence_id=f"correlation-summary-{incident_id}",
                evidence_type=InvestigationEvidenceType.CORRELATION_SUMMARY,
                source_system="ai-soc",
                source_table="incidents",
                source_reference=f"incident:{incident_id}:correlation_summary",
                summary="Correlation summary associated with the incident.",
                raw_reference=f"incident:{incident_id}:correlation_summary",
                strength=InvestigationEvidenceStrength.CONTEXTUAL,
                claim_classification=InvestigationClaimClassification.INFERRED,
            )
        )

    for technique in mitre_techniques_from_context(context):
        evidence.append(
            EvidenceReference(
                evidence_id=f"mitre-{technique.lower().replace(' ', '-')}",
                evidence_type=InvestigationEvidenceType.MITRE_METADATA,
                source_system="mitre-attack",
                mitre_technique=technique,
                summary=f"MITRE ATT&CK mapping referenced by the incident: {technique}.",
                strength=InvestigationEvidenceStrength.CONTEXTUAL,
                claim_classification=InvestigationClaimClassification.INFERRED,
            )
        )

    return evidence
