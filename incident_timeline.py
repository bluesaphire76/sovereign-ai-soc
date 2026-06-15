from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException, Request
from sqlalchemy import or_

from models import (
    CaseAIAnalysis,
    CaseAction,
    CaseAudit,
    CaseIncident,
    EventAggregate,
    Incident,
    IncidentAudit,
    IncidentCase,
    IncidentNote,
    RawEvent,
    SecurityAlert,
    SecurityAuditEvent,
)


TIMELINE_CATEGORIES = (
    "RAW_EVENT",
    "SECURITY_ALERT",
    "AGGREGATED_DUPLICATE",
    "CORRELATION_DECISION",
    "INCIDENT_CREATED",
    "INCIDENT_STATUS_CHANGE",
    "INCIDENT_SEVERITY_CHANGE",
    "AI_ANALYSIS",
    "AI_COMMAND_BRIEF",
    "ANALYST_NOTE",
    "CASE_CREATED",
    "CASE_STATUS_CHANGE",
    "CASE_ACTION_CREATED",
    "CASE_ACTION_COMPLETED",
    "DETECTION_RULE_MATCH",
    "NOISE_SUPPRESSION_MATCH",
    "EXCEPTION_MATCH",
    "SERVICE_OPERATION",
    "REPORT_EXPORTED",
    "UNKNOWN",
)

RAW_PAYLOAD_ROLES = {"ADMIN", "ANALYST"}
DEFAULT_LIMIT = 200
MAX_LIMIT = 500
INTERNAL_ROW_LIMIT = 500
KEY_STATUSES = {"CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"}
SUPPRESSED_STATUSES = {"SUPPRESSED_NOISE"}
AGGREGATED_STATUSES = {"AGGREGATED_DUPLICATE", "DUPLICATE_DOC_ID"}


@dataclass(frozen=True)
class TimelineQuery:
    categories: set[str] | None = None
    source: str | None = None
    severity: str | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    include_raw_payload: bool = False
    limit: int = DEFAULT_LIMIT
    cursor: int = 0
    sort: str = "asc"
    key_only: bool = False
    entity: str | None = None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def current_user_role(current_user: Mapping[str, Any] | None) -> str:
    return str((current_user or {}).get("role") or "").upper().strip()


def _current_user_id(current_user: Mapping[str, Any] | None) -> int | None:
    value = (current_user or {}).get("id")

    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _request_client_ip(request: Request | None) -> str | None:
    if request is None:
        return None

    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    return request.client.host if request.client else None


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str, sort_keys=True)


def _json_loads(value: Any, fallback: Any = None) -> Any:
    if value is None:
        return fallback

    if isinstance(value, (dict, list)):
        return value

    if not isinstance(value, str):
        return value

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None

    if isinstance(value, datetime):
        parsed = value
    else:
        normalized = str(value).strip().replace("Z", "+00:00")
        if re.search(r"[+-]\d{4}$", normalized):
            normalized = f"{normalized[:-2]}:{normalized[-2:]}"

        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    return parsed.astimezone(timezone.utc)


def _iso(value: Any) -> str | None:
    if not value:
        return None

    parsed = _parse_datetime(value)
    if parsed:
        return parsed.isoformat()

    return str(value)


def _sort_key(item: Mapping[str, Any]) -> tuple[datetime, str]:
    parsed = _parse_datetime(item.get("timestamp"))
    timestamp = parsed or datetime.min.replace(tzinfo=timezone.utc)
    return timestamp, str(item.get("id") or "")


def _shorten(value: Any, limit: int = 320) -> str | None:
    if value is None:
        return None

    if isinstance(value, (dict, list)):
        text = _json_dumps(value)
    else:
        text = str(value)

    text = text.replace("\x00", "").strip()
    text = re.sub(r"\s+", " ", text)

    if len(text) <= limit:
        return text

    return f"{text[: limit - 1].rstrip()}..."


def _sanitize_detail(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return _shorten(value, 180)

    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for index, (key, child) in enumerate(value.items()):
            if index >= 30:
                sanitized["_truncated"] = True
                break
            sanitized[str(key)] = _sanitize_detail(child, depth=depth + 1)
        return sanitized

    if isinstance(value, list):
        return [_sanitize_detail(child, depth=depth + 1) for child in value[:30]]

    if isinstance(value, datetime):
        return _iso(value)

    if isinstance(value, (str, bytes)):
        text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
        return _shorten(text, 700)

    return value


def _add_entity(refs: list[dict[str, str]], entity_type: str, value: Any) -> None:
    if value is None:
        return

    if isinstance(value, (list, tuple, set)):
        for item in value:
            _add_entity(refs, entity_type, item)
        return

    text = str(value).strip()
    if not text or text in {"-", "None", "null", "[]", "{}"}:
        return

    refs.append({"type": entity_type, "value": text[:160]})


def _dedupe_entities(refs: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, str]] = []

    for ref in refs:
        key = (ref["type"], ref["value"].lower())
        if key in seen:
            continue
        seen.add(key)
        result.append(ref)

    return result[:30]


def _payload_entities(value: Any, stack: tuple[str, ...] = ()) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []

    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            path = stack + (key_text.lower(),)

            if len(path) >= 2 and path[-2:] == ("agent", "name"):
                _add_entity(refs, "host", child)
            elif len(path) >= 2 and path[-2:] == ("rule", "id"):
                _add_entity(refs, "rule_id", child)
            elif len(path) >= 2 and path[-2:] == ("rule", "groups"):
                _add_entity(refs, "rule_group", child)
            elif path[-1] in {"srcip", "src_ip", "source_ip", "client_ip"}:
                _add_entity(refs, "source_ip", child)
            elif path[-1] in {"dstip", "dst_ip", "destination_ip", "resolver_ip"}:
                _add_entity(refs, "destination_ip", child)
            elif path[-1] in {"srcuser", "dstuser", "user", "username", "targetusername"}:
                _add_entity(refs, "user", child)
            elif path[-1] in {"process", "process_name", "program_name", "exe", "command"}:
                _add_entity(refs, "process", child)
            elif path[-1] in {"path", "file", "filename"}:
                _add_entity(refs, "file", child)
            elif path[-1] in {"package", "package_name"}:
                _add_entity(refs, "package", child)
            elif "mitre" in path and path[-1] in {"id", "technique", "techniques"}:
                _add_entity(refs, "mitre_technique", child)

            refs.extend(_payload_entities(child, path))

    elif isinstance(value, list):
        for child in value:
            refs.extend(_payload_entities(child, stack))

    return refs


def _mitre_tags(*values: Any) -> list[str]:
    tags: set[str] = set()

    def collect(value: Any) -> None:
        parsed = _json_loads(value, value)
        if isinstance(parsed, Mapping):
            for child in parsed.values():
                collect(child)
            return
        if isinstance(parsed, list):
            for child in parsed:
                collect(child)
            return

        for match in re.findall(r"T\d{4}(?:\.\d{3})?", str(parsed or "").upper()):
            tags.add(match)

    for value in values:
        collect(value)

    return sorted(tags)


def _severity_from_level(level: int | None) -> str | None:
    try:
        value = int(level or 0)
    except (TypeError, ValueError):
        return None

    if value >= 15:
        return "CRITICAL"
    if value >= 12:
        return "HIGH"
    if value >= 7:
        return "MEDIUM"
    return "LOW"


def _incident_severity(incident: Incident) -> str | None:
    priority = str(incident.recommended_priority or "").upper().strip()
    if priority:
        return priority

    risk_score = incident.risk_score or 0
    if risk_score >= 80:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH"
    if risk_score >= 40:
        return "MEDIUM"

    return _severity_from_level(incident.level)


def _security_alert_category(alert: SecurityAlert) -> str:
    status = str(alert.status or "").upper()

    if status in SUPPRESSED_STATUSES or "SUPPRESS" in status or "NOISE" in status:
        return "NOISE_SUPPRESSION_MATCH"
    if status in AGGREGATED_STATUSES or "DUPLICATE" in status or "AGGREGATED" in status:
        return "AGGREGATED_DUPLICATE"
    if "EXCEPTION" in status:
        return "EXCEPTION_MATCH"

    return "SECURITY_ALERT"


def _source_matches(item_source: str | None, wanted: str | None) -> bool:
    if not wanted:
        return True

    return str(item_source or "").lower() == wanted.lower()


def _severity_matches(item_severity: str | None, wanted: str | None) -> bool:
    if not wanted:
        return True

    return str(item_severity or "").upper() == wanted.upper()


def _entity_matches(item: Mapping[str, Any], wanted: str | None) -> bool:
    if not wanted:
        return True

    needle = wanted.lower().strip()
    if not needle:
        return True

    haystacks = [
        item.get("title"),
        item.get("summary"),
        item.get("status"),
        item.get("severity"),
        item.get("source_system"),
        item.get("category"),
    ]
    for ref in item.get("entity_refs") or []:
        if isinstance(ref, Mapping):
            haystacks.extend([ref.get("type"), ref.get("value")])

    return any(needle in str(value or "").lower() for value in haystacks)


def _normalize_limit(value: int | None) -> int:
    try:
        limit = int(value or DEFAULT_LIMIT)
    except (TypeError, ValueError):
        limit = DEFAULT_LIMIT

    return max(1, min(limit, MAX_LIMIT))


def _normalize_cursor(value: int | str | None) -> int:
    try:
        cursor = int(value or 0)
    except (TypeError, ValueError):
        cursor = 0

    return max(0, cursor)


def _timeline_item(
    *,
    item_id: str,
    incident_id: int,
    category: str,
    source_system: str,
    timestamp: Any,
    title: str,
    summary: str | None = None,
    case_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    entity_refs: list[dict[str, str]] | None = None,
    evidence_refs: list[dict[str, Any]] | None = None,
    mitre: list[str] | None = None,
    confidence: int | None = None,
    actor: str | None = None,
    is_key_event: bool = False,
    is_suppressed: bool = False,
    is_correlated: bool = False,
    details: dict[str, Any] | None = None,
    raw_payload_available: bool = False,
    raw_payload: Any | None = None,
) -> dict[str, Any]:
    item = {
        "id": item_id,
        "incident_id": incident_id,
        "case_id": case_id,
        "category": category if category in TIMELINE_CATEGORIES else "UNKNOWN",
        "source_system": source_system,
        "timestamp": _iso(timestamp),
        "title": _shorten(title, 180) or "Timeline event",
        "summary": _shorten(summary, 500),
        "severity": str(severity).upper() if severity else None,
        "status": status,
        "entity_refs": _dedupe_entities(entity_refs or []),
        "evidence_refs": evidence_refs or [],
        "mitre": mitre or [],
        "confidence": confidence,
        "actor": actor,
        "is_key_event": bool(is_key_event),
        "is_suppressed": bool(is_suppressed),
        "is_correlated": bool(is_correlated),
        "details": _sanitize_detail(details or {}),
        "raw_payload_available": bool(raw_payload_available),
    }

    if raw_payload is not None:
        item["raw_payload"] = _sanitize_detail(raw_payload)

    return item


def _record_raw_payload_audit(
    db,
    *,
    outcome: str,
    current_user: Mapping[str, Any] | None,
    incident_id: int,
    request: Request | None,
    details: dict[str, Any] | None = None,
) -> None:
    row = SecurityAuditEvent(
        event_type="INCIDENT_TIMELINE_RAW_PAYLOAD_ACCESS",
        outcome=outcome,
        actor_user_id=_current_user_id(current_user),
        actor_username=(current_user or {}).get("username"),
        actor_role=(current_user or {}).get("role"),
        target_type="INCIDENT",
        target_id=str(incident_id),
        method=request.method if request else None,
        path=request.url.path if request else None,
        client_ip=_request_client_ip(request),
        user_agent=request.headers.get("user-agent") if request else None,
        details_json=_json_dumps(_sanitize_detail(details or {})),
    )
    db.add(row)
    db.commit()


def _base_incident_entities(incident: Incident) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    _add_entity(refs, "incident_id", incident.id)
    _add_entity(refs, "host", incident.agent)
    _add_entity(refs, "mitre_technique", _mitre_tags(incident.mitre))
    return refs


def _raw_event_entities(raw_event: RawEvent) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    _add_entity(refs, "host", raw_event.agent)
    _add_entity(refs, "rule_id", raw_event.rule_id)
    refs.extend(_payload_entities(_json_loads(raw_event.payload_json, {})))
    return refs


def _security_alert_entities(alert: SecurityAlert) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    _add_entity(refs, "host", alert.agent)
    _add_entity(refs, "rule_id", alert.rule_id)
    return refs


def _case_entities(case: IncidentCase | None = None, action: CaseAction | None = None) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []

    if case:
        _add_entity(refs, "case_id", case.id)
        _add_entity(refs, "host", case.agent)

    if action:
        _add_entity(refs, "case_id", action.case_id)

    return refs


def _incident_created_item(incident: Incident) -> dict[str, Any]:
    severity = _incident_severity(incident)

    return _timeline_item(
        item_id=f"incident:{incident.id}:created",
        incident_id=incident.id,
        category="INCIDENT_CREATED",
        source_system="incident",
        timestamp=incident.timestamp,
        title=f"Incident #{incident.id} created",
        summary=incident.rule or "Incident record created from linked security telemetry.",
        severity=severity,
        status=incident.status,
        entity_refs=_base_incident_entities(incident),
        evidence_refs=[{"type": "incident", "id": incident.id}],
        mitre=_mitre_tags(incident.mitre),
        confidence=incident.risk_score,
        is_key_event=True,
        is_correlated=bool(incident.correlated),
        details={
            "wazuh_doc_id": incident.wazuh_doc_id,
            "level": incident.level,
            "risk_score": incident.risk_score,
            "recommended_priority": incident.recommended_priority,
            "raw_event_id": incident.raw_event_id,
            "security_alert_id": incident.security_alert_id,
        },
        raw_payload_available=bool(incident.raw_alert),
    )


def _correlation_item(incident: Incident) -> dict[str, Any] | None:
    if not (
        incident.correlated
        or incident.correlation_summary
        or incident.correlation_score
        or incident.attack_chain
        or incident.correlation_type
        or incident.escalation_reason
    ):
        return None

    return _timeline_item(
        item_id=f"incident:{incident.id}:correlation",
        incident_id=incident.id,
        category="CORRELATION_DECISION",
        source_system="correlation_engine",
        timestamp=incident.timestamp,
        title="Correlation decision recorded",
        summary=incident.escalation_reason or incident.correlation_type or "Incident correlation metadata is available.",
        severity=_incident_severity(incident),
        status=incident.status,
        entity_refs=_base_incident_entities(incident),
        evidence_refs=[{"type": "incident", "id": incident.id}],
        mitre=_mitre_tags(incident.mitre, incident.attack_chain, incident.correlation_summary),
        confidence=incident.correlation_score,
        is_key_event=True,
        is_correlated=True,
        details={
            "correlated": incident.correlated,
            "correlation_score": incident.correlation_score,
            "correlation_type": incident.correlation_type,
            "attack_chain": incident.attack_chain,
            "correlation_summary": _json_loads(incident.correlation_summary, incident.correlation_summary),
        },
    )


def _ai_analysis_item(incident: Incident) -> dict[str, Any] | None:
    if not incident.ai_analysis:
        return None

    return _timeline_item(
        item_id=f"incident:{incident.id}:ai-analysis",
        incident_id=incident.id,
        category="AI_ANALYSIS",
        source_system="ai_triage",
        timestamp=incident.timestamp,
        title="AI analysis attached",
        summary=incident.ai_analysis,
        severity=_incident_severity(incident),
        status=incident.status,
        entity_refs=_base_incident_entities(incident),
        evidence_refs=[{"type": "incident", "id": incident.id}],
        mitre=_mitre_tags(incident.mitre, incident.ai_analysis),
        confidence=incident.risk_score,
        actor="local_ai",
        is_key_event=True,
        details={"analysis_length": len(incident.ai_analysis or "")},
    )


def _raw_event_item(
    incident: Incident,
    raw_event: RawEvent,
    *,
    include_raw_payload: bool,
    first_raw_event_id: int | None,
) -> dict[str, Any]:
    payload = _json_loads(raw_event.payload_json, raw_event.payload_json)
    entities = _raw_event_entities(raw_event) + _base_incident_entities(incident)

    return _timeline_item(
        item_id=f"raw-event:{raw_event.id}",
        incident_id=incident.id,
        category="RAW_EVENT",
        source_system=raw_event.source or "raw_event",
        timestamp=raw_event.event_timestamp or raw_event.ingested_at,
        title=f"Raw event {raw_event.source_event_id}",
        summary=raw_event.rule_description or "Raw telemetry event linked to incident.",
        severity=_severity_from_level(raw_event.level),
        entity_refs=entities,
        evidence_refs=[{"type": "raw_event", "id": raw_event.id}],
        mitre=_mitre_tags(payload),
        is_key_event=raw_event.id == first_raw_event_id,
        details={
            "source_event_id": raw_event.source_event_id,
            "source_index": raw_event.source_index,
            "rule_id": raw_event.rule_id,
            "level": raw_event.level,
            "payload_hash": raw_event.payload_hash,
            "ingested_at": _iso(raw_event.ingested_at),
        },
        raw_payload_available=bool(raw_event.payload_json),
        raw_payload=payload if include_raw_payload else None,
    )


def _security_alert_item(
    incident: Incident,
    alert: SecurityAlert,
    *,
    first_alert_id: int | None,
) -> dict[str, Any]:
    category = _security_alert_category(alert)

    return _timeline_item(
        item_id=f"security-alert:{alert.id}",
        incident_id=incident.id,
        category=category,
        source_system=alert.source or "security_alert",
        timestamp=alert.event_timestamp or alert.created_at,
        title=f"Security alert {alert.source_event_id}",
        summary=alert.rule_description or f"Security alert status {alert.status or 'OBSERVED'}.",
        severity=alert.severity_bucket or _severity_from_level(alert.level),
        status=alert.status,
        entity_refs=_security_alert_entities(alert) + _base_incident_entities(incident),
        evidence_refs=[
            {"type": "security_alert", "id": alert.id},
            {"type": "raw_event", "id": alert.raw_event_id},
        ],
        is_key_event=alert.id == first_alert_id and category == "SECURITY_ALERT",
        is_suppressed=category in {"NOISE_SUPPRESSION_MATCH", "EXCEPTION_MATCH"},
        details={
            "raw_event_id": alert.raw_event_id,
            "fingerprint": alert.fingerprint,
            "rule_id": alert.rule_id,
            "level": alert.level,
            "updated_at": _iso(alert.updated_at),
        },
    )


def _aggregate_item(incident: Incident, aggregate: EventAggregate) -> dict[str, Any]:
    return _timeline_item(
        item_id=f"event-aggregate:{aggregate.id}",
        incident_id=incident.id,
        category="AGGREGATED_DUPLICATE",
        source_system=aggregate.source or "event_aggregation",
        timestamp=aggregate.last_seen or aggregate.updated_at,
        title="Duplicate event aggregate updated",
        summary=(
            f"{aggregate.count or 0} similar event(s) grouped for rule "
            f"{aggregate.rule_id or 'unknown'}."
        ),
        severity=aggregate.severity_bucket or _severity_from_level(aggregate.level),
        status="AGGREGATED",
        entity_refs=_dedupe_entities(
            _base_incident_entities(incident)
            + [
                {"type": "host", "value": str(aggregate.agent)}
                if aggregate.agent
                else {"type": "incident_id", "value": str(incident.id)}
            ]
        ),
        evidence_refs=[{"type": "event_aggregate", "id": aggregate.id}],
        is_suppressed=True,
        details={
            "fingerprint": aggregate.fingerprint,
            "rule_id": aggregate.rule_id,
            "location": aggregate.location,
            "decoder": aggregate.decoder,
            "first_seen": aggregate.first_seen,
            "last_seen": aggregate.last_seen,
            "count": aggregate.count,
            "first_wazuh_doc_id": aggregate.first_wazuh_doc_id,
            "last_wazuh_doc_id": aggregate.last_wazuh_doc_id,
        },
        raw_payload_available=bool(aggregate.sample_event_json or aggregate.last_event_json),
    )


def _audit_category(row: IncidentAudit) -> str:
    event_type = str(row.event_type or "").upper()

    if "STATUS" in event_type:
        return "INCIDENT_STATUS_CHANGE"
    if "SEVERITY" in event_type:
        return "INCIDENT_SEVERITY_CHANGE"
    if event_type == "INCIDENT_AI_BRIEF_GENERATED":
        return "AI_COMMAND_BRIEF"
    if "AI" in event_type or "REMEDIATION_PLAN" in event_type:
        return "AI_ANALYSIS"
    if event_type == "NOTE_ADDED":
        return "ANALYST_NOTE"

    return "UNKNOWN"


def _audit_item(incident: Incident, row: IncidentAudit) -> dict[str, Any]:
    category = _audit_category(row)
    new_value = str(row.new_value or "").upper()

    return _timeline_item(
        item_id=f"incident-audit:{row.id}",
        incident_id=incident.id,
        category=category,
        source_system="incident_audit",
        timestamp=row.created_at,
        title=(row.event_type or "Incident audit event").replace("_", " ").title(),
        summary=row.comment or row.new_value or row.old_value,
        severity=_incident_severity(incident),
        status=row.new_value,
        actor=row.created_by,
        entity_refs=_base_incident_entities(incident),
        evidence_refs=[{"type": "incident_audit", "id": row.id}],
        is_key_event=(
            category in {"AI_COMMAND_BRIEF", "AI_ANALYSIS"}
            or (category == "INCIDENT_STATUS_CHANGE" and new_value in KEY_STATUSES)
        ),
        details={
            "event_type": row.event_type,
            "old_value": row.old_value,
            "new_value": row.new_value,
        },
    )


def _note_item(incident: Incident, row: IncidentNote) -> dict[str, Any]:
    return _timeline_item(
        item_id=f"incident-note:{row.id}",
        incident_id=incident.id,
        category="ANALYST_NOTE",
        source_system="incident_notes",
        timestamp=row.created_at,
        title="Analyst note added",
        summary=row.note,
        status=incident.status,
        actor=row.created_by,
        entity_refs=_base_incident_entities(incident),
        evidence_refs=[{"type": "incident_note", "id": row.id}],
        details={"note_length": len(row.note or "")},
    )


def _case_created_item(incident: Incident, case: IncidentCase) -> dict[str, Any]:
    return _timeline_item(
        item_id=f"case:{case.id}:created",
        incident_id=incident.id,
        case_id=case.id,
        category="CASE_CREATED",
        source_system="case_management",
        timestamp=case.created_at,
        title=f"Case #{case.id} created",
        summary=case.title or case.summary,
        severity=case.severity,
        status=case.status,
        actor=case.created_by,
        entity_refs=_case_entities(case) + _base_incident_entities(incident),
        evidence_refs=[{"type": "case", "id": case.id}],
        is_key_event=True,
        is_correlated=bool(case.correlation_type),
        details={
            "group_key": case.group_key,
            "correlation_type": case.correlation_type,
            "risk_score": case.risk_score,
            "owner": case.owner,
            "assignee": case.assignee,
        },
    )


def _case_audit_item(incident: Incident, case: IncidentCase, row: CaseAudit) -> dict[str, Any]:
    event_type = str(row.event_type or "").upper()
    category = "CASE_STATUS_CHANGE" if "WORKFLOW" in event_type or "STATUS" in event_type or "CLOSURE" in event_type else "UNKNOWN"
    new_value = _json_loads(row.new_value, row.new_value)
    status_value = None

    if isinstance(new_value, Mapping):
        status_value = new_value.get("status") or new_value.get("workflow_status")
    elif isinstance(new_value, str):
        status_value = new_value

    return _timeline_item(
        item_id=f"case-audit:{row.id}",
        incident_id=incident.id,
        case_id=case.id,
        category=category,
        source_system="case_audit",
        timestamp=row.created_at,
        title=(row.event_type or "Case audit event").replace("_", " ").title(),
        summary=row.comment,
        severity=case.severity,
        status=str(status_value) if status_value else case.status,
        actor=row.created_by,
        entity_refs=_case_entities(case) + _base_incident_entities(incident),
        evidence_refs=[{"type": "case_audit", "id": row.id}, {"type": "case", "id": case.id}],
        is_key_event=str(status_value or "").upper() in KEY_STATUSES,
        details={
            "event_type": row.event_type,
            "old_value": _json_loads(row.old_value, row.old_value),
            "new_value": new_value,
        },
    )


def _case_action_created_item(incident: Incident, case: IncidentCase, action: CaseAction) -> dict[str, Any]:
    return _timeline_item(
        item_id=f"case-action:{action.id}:created",
        incident_id=incident.id,
        case_id=case.id,
        category="CASE_ACTION_CREATED",
        source_system="case_actions",
        timestamp=action.created_at,
        title=f"Case action #{action.id} created",
        summary=action.title,
        severity=action.priority,
        status=action.status,
        actor=action.created_by,
        entity_refs=_case_entities(case, action) + _base_incident_entities(incident),
        evidence_refs=[{"type": "case_action", "id": action.id}, {"type": "case", "id": case.id}],
        details={
            "category": action.category,
            "description": action.description,
            "due_at": _iso(action.due_at),
        },
    )


def _case_action_completed_item(incident: Incident, case: IncidentCase, action: CaseAction) -> dict[str, Any] | None:
    if not action.completed_at:
        return None

    return _timeline_item(
        item_id=f"case-action:{action.id}:completed",
        incident_id=incident.id,
        case_id=case.id,
        category="CASE_ACTION_COMPLETED",
        source_system="case_actions",
        timestamp=action.completed_at,
        title=f"Case action #{action.id} completed",
        summary=action.title,
        severity=action.priority,
        status=action.status,
        actor=action.created_by,
        entity_refs=_case_entities(case, action) + _base_incident_entities(incident),
        evidence_refs=[{"type": "case_action", "id": action.id}, {"type": "case", "id": case.id}],
        is_key_event=True,
        details={"category": action.category},
    )


def _case_ai_item(incident: Incident, case: IncidentCase, analysis: CaseAIAnalysis) -> dict[str, Any]:
    return _timeline_item(
        item_id=f"case-ai-analysis:{analysis.id}",
        incident_id=incident.id,
        case_id=case.id,
        category="AI_ANALYSIS",
        source_system="case_ai_analysis",
        timestamp=analysis.created_at,
        title="AI case analysis generated",
        summary=analysis.analysis,
        severity=analysis.recommended_severity,
        status=analysis.recommended_status,
        actor=analysis.created_by,
        entity_refs=_case_entities(case) + _base_incident_entities(incident),
        evidence_refs=[{"type": "case_ai_analysis", "id": analysis.id}, {"type": "case", "id": case.id}],
        is_key_event=True,
        details={"model": analysis.model},
    )


def _load_incident(db, incident_id: int) -> Incident:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise ValueError(f"Incident {incident_id} not found")

    return incident


def _collect_security_alerts(db, incident: Incident) -> list[SecurityAlert]:
    filters = [SecurityAlert.incident_id == incident.id]
    if incident.security_alert_id:
        filters.append(SecurityAlert.id == incident.security_alert_id)

    rows = (
        db.query(SecurityAlert)
        .filter(or_(*filters))
        .order_by(SecurityAlert.event_timestamp.asc(), SecurityAlert.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )

    seen: set[int] = set()
    result: list[SecurityAlert] = []
    for row in rows:
        if row.id in seen:
            continue
        seen.add(row.id)
        result.append(row)

    return result


def _collect_raw_events(db, incident: Incident, security_alerts: list[SecurityAlert]) -> list[RawEvent]:
    raw_event_ids = {alert.raw_event_id for alert in security_alerts if alert.raw_event_id}
    if incident.raw_event_id:
        raw_event_ids.add(incident.raw_event_id)

    if not raw_event_ids:
        return []

    return (
        db.query(RawEvent)
        .filter(RawEvent.id.in_(sorted(raw_event_ids)))
        .order_by(RawEvent.event_timestamp.asc(), RawEvent.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )


def _collect_cases(db, incident_id: int) -> list[IncidentCase]:
    case_ids = [
        row.case_id
        for row in db.query(CaseIncident)
        .filter(CaseIncident.incident_id == incident_id)
        .order_by(CaseIncident.created_at.asc(), CaseIncident.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    ]

    if not case_ids:
        return []

    return (
        db.query(IncidentCase)
        .filter(IncidentCase.id.in_(case_ids))
        .order_by(IncidentCase.created_at.asc(), IncidentCase.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )


def _collect_items(
    db,
    incident: Incident,
    *,
    include_raw_payload: bool,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    security_alerts = _collect_security_alerts(db, incident)
    raw_events = _collect_raw_events(db, incident, security_alerts)

    items.append(_incident_created_item(incident))

    correlation = _correlation_item(incident)
    if correlation:
        items.append(correlation)

    ai_analysis = _ai_analysis_item(incident)
    if ai_analysis:
        items.append(ai_analysis)

    first_raw_event_id = raw_events[0].id if raw_events else None
    for raw_event in raw_events:
        items.append(
            _raw_event_item(
                incident,
                raw_event,
                include_raw_payload=include_raw_payload,
                first_raw_event_id=first_raw_event_id,
            )
        )

    first_alert_id = security_alerts[0].id if security_alerts else None
    for alert in security_alerts:
        items.append(_security_alert_item(incident, alert, first_alert_id=first_alert_id))

    aggregates = (
        db.query(EventAggregate)
        .filter(EventAggregate.last_incident_id == incident.id)
        .order_by(EventAggregate.last_seen.asc(), EventAggregate.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )
    for aggregate in aggregates:
        items.append(_aggregate_item(incident, aggregate))

    audit_events = (
        db.query(IncidentAudit)
        .filter(IncidentAudit.incident_id == incident.id)
        .order_by(IncidentAudit.created_at.asc(), IncidentAudit.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )
    for row in audit_events:
        items.append(_audit_item(incident, row))

    notes = (
        db.query(IncidentNote)
        .filter(IncidentNote.incident_id == incident.id)
        .order_by(IncidentNote.created_at.asc(), IncidentNote.id.asc())
        .limit(INTERNAL_ROW_LIMIT)
        .all()
    )
    for row in notes:
        items.append(_note_item(incident, row))

    for case in _collect_cases(db, incident.id):
        items.append(_case_created_item(incident, case))

        case_audit = (
            db.query(CaseAudit)
            .filter(CaseAudit.case_id == case.id)
            .order_by(CaseAudit.created_at.asc(), CaseAudit.id.asc())
            .limit(INTERNAL_ROW_LIMIT)
            .all()
        )
        for row in case_audit:
            items.append(_case_audit_item(incident, case, row))

        actions = (
            db.query(CaseAction)
            .filter(CaseAction.case_id == case.id)
            .order_by(CaseAction.created_at.asc(), CaseAction.id.asc())
            .limit(INTERNAL_ROW_LIMIT)
            .all()
        )
        for action in actions:
            items.append(_case_action_created_item(incident, case, action))
            completed = _case_action_completed_item(incident, case, action)
            if completed:
                items.append(completed)

        analyses = (
            db.query(CaseAIAnalysis)
            .filter(CaseAIAnalysis.case_id == case.id)
            .order_by(CaseAIAnalysis.created_at.asc(), CaseAIAnalysis.id.asc())
            .limit(INTERNAL_ROW_LIMIT)
            .all()
        )
        for analysis in analyses:
            items.append(_case_ai_item(incident, case, analysis))

    return sorted(items, key=_sort_key)


def _filter_items(items: list[dict[str, Any]], query: TimelineQuery) -> list[dict[str, Any]]:
    categories = {category.upper() for category in query.categories or set() if category}
    sort_desc = str(query.sort or "asc").lower() == "desc"

    filtered = []
    for item in items:
        category = str(item.get("category") or "").upper()
        timestamp = _parse_datetime(item.get("timestamp"))

        if categories and category not in categories:
            continue
        if query.key_only and not item.get("is_key_event"):
            continue
        if not _source_matches(item.get("source_system"), query.source):
            continue
        if not _severity_matches(item.get("severity"), query.severity):
            continue
        if query.time_from and timestamp and timestamp < query.time_from:
            continue
        if query.time_to and timestamp and timestamp > query.time_to:
            continue
        if not _entity_matches(item, query.entity):
            continue

        filtered.append(item)

    return sorted(filtered, key=_sort_key, reverse=sort_desc)


def _summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    counts_by_category = Counter(str(item.get("category") or "UNKNOWN") for item in items)
    counts_by_source = Counter(str(item.get("source_system") or "unknown") for item in items)
    timestamps = [_parse_datetime(item.get("timestamp")) for item in items]
    timestamps = [value for value in timestamps if value]

    entity_counter: Counter[str] = Counter()
    for item in items:
        for ref in item.get("entity_refs") or []:
            if isinstance(ref, Mapping):
                label = f"{ref.get('type')}:{ref.get('value')}"
                entity_counter[label] += 1

    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None

    return {
        "total": len(items),
        "key_events": sum(1 for item in items if item.get("is_key_event")),
        "raw_events": counts_by_category.get("RAW_EVENT", 0),
        "alerts": counts_by_category.get("SECURITY_ALERT", 0),
        "ai_events": counts_by_category.get("AI_ANALYSIS", 0)
        + counts_by_category.get("AI_COMMAND_BRIEF", 0),
        "lifecycle_events": counts_by_category.get("INCIDENT_CREATED", 0)
        + counts_by_category.get("INCIDENT_STATUS_CHANGE", 0)
        + counts_by_category.get("INCIDENT_SEVERITY_CHANGE", 0),
        "case_events": counts_by_category.get("CASE_CREATED", 0)
        + counts_by_category.get("CASE_STATUS_CHANGE", 0)
        + counts_by_category.get("CASE_ACTION_CREATED", 0)
        + counts_by_category.get("CASE_ACTION_COMPLETED", 0),
        "notes": counts_by_category.get("ANALYST_NOTE", 0),
        "detection_noise_events": counts_by_category.get("NOISE_SUPPRESSION_MATCH", 0)
        + counts_by_category.get("EXCEPTION_MATCH", 0)
        + counts_by_category.get("AGGREGATED_DUPLICATE", 0),
        "counts_by_category": dict(sorted(counts_by_category.items())),
        "counts_by_source": dict(sorted(counts_by_source.items())),
        "first_seen": _iso(first_seen),
        "last_seen": _iso(last_seen),
        "duration_seconds": int((last_seen - first_seen).total_seconds())
        if first_seen and last_seen
        else None,
        "top_entities": [
            {"entity": entity, "count": count}
            for entity, count in entity_counter.most_common(10)
        ],
    }


def _capability_reason(category: str) -> str:
    reasons = {
        "DETECTION_RULE_MATCH": "No incident-linked detection lifecycle hit table is available yet.",
        "SERVICE_OPERATION": "Service operations are config/service scoped and are not linked to incidents.",
        "REPORT_EXPORTED": "Report export events are not stored with an incident foreign key.",
        "UNKNOWN": "No unclassified source rows were found for this incident.",
    }

    return reasons.get(category, "No linked rows for this incident.")


def _capabilities(incident_id: int, items: list[dict[str, Any]]) -> dict[str, Any]:
    categories = sorted({str(item.get("category") or "UNKNOWN") for item in items})
    sources = sorted({str(item.get("source_system") or "unknown") for item in items})
    unavailable = [
        {"category": category, "reason": _capability_reason(category)}
        for category in TIMELINE_CATEGORIES
        if category not in categories
    ]

    return {
        "incident_id": incident_id,
        "generated_at": _iso(utc_now()),
        "available_categories": categories,
        "unavailable_categories": unavailable,
        "sources": sources,
        "raw_payload_default": "redacted",
        "raw_payload_roles": sorted(RAW_PAYLOAD_ROLES),
    }


def build_incident_timeline_payload(
    db,
    incident_id: int,
    query: TimelineQuery | None = None,
    *,
    current_user: Mapping[str, Any] | None = None,
    request: Request | None = None,
) -> dict[str, Any]:
    query = query or TimelineQuery()
    query = TimelineQuery(
        categories=query.categories,
        source=query.source,
        severity=query.severity,
        time_from=query.time_from,
        time_to=query.time_to,
        include_raw_payload=bool(query.include_raw_payload),
        limit=_normalize_limit(query.limit),
        cursor=_normalize_cursor(query.cursor),
        sort="desc" if str(query.sort or "").lower() == "desc" else "asc",
        key_only=query.key_only,
        entity=query.entity,
    )
    incident = _load_incident(db, incident_id)

    if query.include_raw_payload and current_user_role(current_user) not in RAW_PAYLOAD_ROLES:
        _record_raw_payload_audit(
            db,
            outcome="DENIED",
            current_user=current_user,
            incident_id=incident.id,
            request=request,
            details={"reason": "role_not_authorized"},
        )
        raise HTTPException(status_code=403, detail="Raw payload access requires ADMIN or ANALYST role.")

    items = _collect_items(db, incident, include_raw_payload=query.include_raw_payload)
    filtered = _filter_items(items, query)
    start = query.cursor
    end = start + query.limit
    page_items = filtered[start:end]
    next_cursor = str(end) if end < len(filtered) else None

    if query.include_raw_payload:
        included_count = sum(1 for item in page_items if "raw_payload" in item)
        _record_raw_payload_audit(
            db,
            outcome="SUCCESS",
            current_user=current_user,
            incident_id=incident.id,
            request=request,
            details={"raw_payload_items_returned": included_count},
        )

    return {
        "incident_id": incident.id,
        "generated_at": _iso(utc_now()),
        "sort": query.sort,
        "limit": query.limit,
        "cursor": str(query.cursor),
        "next_cursor": next_cursor,
        "total_items": len(items),
        "filtered_count": len(filtered),
        "returned_count": len(page_items),
        "summary": _summary(filtered),
        "capabilities": _capabilities(incident.id, items),
        "items": page_items,
    }


def build_incident_timeline_summary(
    db,
    incident_id: int,
    query: TimelineQuery | None = None,
) -> dict[str, Any]:
    effective_query = query or TimelineQuery()
    safe_query = TimelineQuery(
        categories=effective_query.categories,
        source=effective_query.source,
        severity=effective_query.severity,
        time_from=effective_query.time_from,
        time_to=effective_query.time_to,
        include_raw_payload=False,
        limit=MAX_LIMIT,
        cursor=0,
        sort=effective_query.sort,
        key_only=effective_query.key_only,
        entity=effective_query.entity,
    )
    payload = build_incident_timeline_payload(db, incident_id, safe_query)
    return {
        "incident_id": payload["incident_id"],
        "generated_at": payload["generated_at"],
        "summary": payload["summary"],
        "filtered_count": payload["filtered_count"],
        "total_items": payload["total_items"],
    }


def build_incident_timeline_capabilities(db, incident_id: int) -> dict[str, Any]:
    incident = _load_incident(db, incident_id)
    items = _collect_items(db, incident, include_raw_payload=False)
    return _capabilities(incident.id, items)
