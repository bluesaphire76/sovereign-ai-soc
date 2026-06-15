from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException, Request

from detection_config_versioning import affected_services_for_domain, domain_for_rule_type
from detection_control_plane import (
    _request_client_ip,
    _sanitize_audit_details,
    current_user_role,
)
from models import (
    DetectionControlRule,
    DetectionRuleLifecycleEvent,
    DetectionRuleLifecycleItem,
    EventAggregate,
    Incident,
    RawEvent,
    SecurityAlert,
    SecurityAuditEvent,
)


OPERATOR_ROLES = {"ADMIN", "ANALYST"}
VISIBLE_ITEM_TYPES = {"DETECTION_RULE", "NOISE_SUPPRESSION", "EXCEPTION"}
WILDCARD_VALUES = {"", "*", ".*", "^.*$", "all", "any"}
BROAD_SCOPE_VALUES = {"global", "all", "any", "*", "tenant", "environment"}
REVIEW_DUE_DAYS = 14


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, default=str, sort_keys=True, separators=(",", ":"))


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return fallback

    return parsed


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None

    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _aware_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None

    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _metadata(value: str | None) -> dict[str, Any]:
    parsed = _json_loads(value, {})
    return parsed if isinstance(parsed, dict) else {}


def _content(row: DetectionRuleLifecycleItem) -> dict[str, Any]:
    parsed = _json_loads(row.content_json, {})
    return parsed if isinstance(parsed, dict) else {}


def _current_user_id(current_user: Mapping[str, Any] | None) -> int | None:
    value = (current_user or {}).get("id")

    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _require_operator(current_user: Mapping[str, Any] | None) -> None:
    if current_user_role(current_user) not in OPERATOR_ROLES:
        raise HTTPException(status_code=403, detail="ADMIN or ANALYST role required.")


def _matcher_hash(value: str | None) -> str | None:
    if not value:
        return None

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _record_audit(
    db,
    *,
    event_type: str,
    outcome: str,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    row = SecurityAuditEvent(
        event_type=event_type,
        outcome=outcome,
        actor_user_id=_current_user_id(current_user),
        actor_username=(current_user or {}).get("username"),
        actor_role=(current_user or {}).get("role"),
        target_type="DETECTION_OPERATIONS_ITEM",
        target_id=target_id,
        method=request.method if request else None,
        path=request.url.path if request else None,
        client_ip=_request_client_ip(request),
        user_agent=request.headers.get("user-agent") if request else None,
        details_json=_json_dumps(_sanitize_audit_details(details or {})),
    )
    db.add(row)
    db.flush()


def _record_lifecycle_history(
    db,
    *,
    row: DetectionRuleLifecycleItem,
    action: str,
    current_user: Mapping[str, Any] | None,
    comment: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    event = DetectionRuleLifecycleEvent(
        item_id=row.id,
        action=action,
        from_state=row.state,
        to_state=row.state,
        actor_user_id=_current_user_id(current_user),
        actor_username=(current_user or {}).get("username"),
        actor_role=(current_user or {}).get("role"),
        comment=comment,
        details_json=_json_dumps(_sanitize_audit_details(details or {})),
        created_at=utc_now(),
    )
    db.add(event)
    db.flush()


def _scalar_values(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        values: list[str] = []
        for item in value.values():
            values.extend(_scalar_values(item))
        return values

    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_scalar_values(item))
        return values

    return [str(value or "").strip().lower()]


def _match_criteria_from_content(content: Mapping[str, Any]) -> Any:
    if "match" in content:
        return content.get("match")
    if "criteria" in content:
        return content.get("criteria")
    if "matcher_value" in content:
        return content.get("matcher_value")
    return content.get("expression")


def _matcher_value_from_content(content: Mapping[str, Any]) -> str:
    explicit = str(content.get("matcher_value") or content.get("pattern") or "").strip()

    if explicit:
        return explicit

    criteria = _match_criteria_from_content(content)

    if isinstance(criteria, str):
        return criteria

    return _json_dumps(criteria)


def _matcher_kind_from_content(content: Mapping[str, Any]) -> str:
    explicit = str(content.get("matcher_kind") or "").strip().upper()

    if explicit:
        return explicit

    return "JSON" if not isinstance(_match_criteria_from_content(content), str) else "CONTAINS"


def _scope_from_content(content: Mapping[str, Any], source_system: str | None) -> str:
    return str(
        content.get("scope")
        or content.get("host")
        or content.get("agent")
        or (source_system or "unknown").lower()
    ).strip()


def classify_detection_scope(
    *,
    scope: str | None,
    matcher_kind: str | None,
    matcher_value: str | None,
    content: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_scope = str(scope or "").strip().lower()
    normalized_matcher = str(matcher_value or "").strip().lower()
    criteria = _match_criteria_from_content(content or {})
    scalar_values = {item for item in _scalar_values(criteria) if item}
    reasons: list[str] = []

    scope_is_broad = normalized_scope in BROAD_SCOPE_VALUES
    matcher_is_wildcard = normalized_matcher in WILDCARD_VALUES or normalized_matcher in {"(?s).*", "(.*)"}
    criteria_is_wildcard = bool(scalar_values) and scalar_values.issubset(WILDCARD_VALUES)

    if matcher_kind and str(matcher_kind).upper() == "REGEX":
        try:
            if re.fullmatch(r"\^?\.?\*\.?\$?", normalized_matcher):
                matcher_is_wildcard = True
        except re.error:
            pass

    if scope_is_broad:
        reasons.append("scope covers a global or environment-wide target")
    if matcher_is_wildcard:
        reasons.append("matcher can match nearly any event")
    if criteria_is_wildcard:
        reasons.append("match criteria are wildcard-only")

    if scope_is_broad and (matcher_is_wildcard or criteria_is_wildcard):
        return {"classification": "dangerously_broad", "reasons": reasons}

    if scope_is_broad or matcher_is_wildcard or criteria_is_wildcard:
        return {"classification": "broad", "reasons": reasons}

    moderate_markers = ("group", "subnet", "network", "domain", "cidr", "/", ",")
    if any(marker in normalized_scope for marker in moderate_markers):
        return {
            "classification": "moderate",
            "reasons": ["scope covers a grouped or network-level target"],
        }

    narrow_keys = {"host", "agent", "agent_name", "rule_id", "user", "username", "source_event_id"}
    content_keys = set()
    if isinstance(criteria, Mapping):
        content_keys = {str(key).lower() for key in criteria.keys()}

    if normalized_scope or content_keys.intersection(narrow_keys):
        return {
            "classification": "narrow",
            "reasons": ["scope or matcher targets a specific host, rule, user or event field"],
        }

    return {"classification": "unknown", "reasons": ["scope could not be classified from available fields"]}


def _review_metadata(container: Mapping[str, Any]) -> dict[str, Any]:
    value = container.get("operations_review")
    return dict(value) if isinstance(value, Mapping) else {}


def _review_status(
    *,
    item_type: str,
    expires_at: datetime | None,
    scope_classification: str,
    validation_status: str | None,
    review_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    now = utc_now()
    expires_at = _aware_datetime(expires_at)
    expired = bool(expires_at and expires_at < now)
    seconds_until_expiry = (expires_at - now).total_seconds() if expires_at else None
    due_reasons: list[str] = []

    if expired:
        due_reasons.append("expired")
    elif seconds_until_expiry is not None and seconds_until_expiry <= REVIEW_DUE_DAYS * 86400:
        due_reasons.append("expires_soon")
    if item_type in {"NOISE_SUPPRESSION", "EXCEPTION"} and not expires_at:
        due_reasons.append("missing_expiration")

    if scope_classification in {"broad", "dangerously_broad", "unknown"}:
        due_reasons.append(f"{scope_classification}_scope")

    if str(validation_status or "").lower() in {"failed", "error", "failed_validation"}:
        due_reasons.append("validation_failed")

    stored_status = str(review_metadata.get("review_status") or "").strip().lower()
    risk_reviewed = stored_status in {"reviewed", "risk_accepted"} and bool(review_metadata.get("reviewed_at"))

    if risk_reviewed:
        due_reasons = [
            reason
            for reason in due_reasons
            if reason not in {"broad_scope", "unknown_scope"}
        ]

    review_due = bool(due_reasons)

    if expired:
        status = "expired"
    elif review_due:
        status = "review_due"
    elif stored_status:
        status = stored_status
    else:
        status = "not_reviewed"

    return {
        "review_status": status,
        "review_due": review_due,
        "expired": expired,
        "reviewed_at": review_metadata.get("reviewed_at"),
        "reviewed_by": review_metadata.get("reviewed_by"),
        "review_notes": review_metadata.get("review_notes"),
        "review_due_reasons": due_reasons,
    }


def _operation_item_from_lifecycle(row: DetectionRuleLifecycleItem) -> dict[str, Any]:
    content = _content(row)
    matcher_kind = _matcher_kind_from_content(content)
    matcher_value = _matcher_value_from_content(content)
    scope = _scope_from_content(content, row.source_system)
    domain = domain_for_rule_type(row.policy_type)
    scope_risk = classify_detection_scope(
        scope=scope,
        matcher_kind=matcher_kind,
        matcher_value=matcher_value,
        content=content,
    )
    review = _review_status(
        item_type=row.policy_type,
        expires_at=row.expires_at,
        scope_classification=scope_risk["classification"],
        validation_status=row.validation_status,
        review_metadata=_review_metadata(content),
    )

    return {
        "id": f"lifecycle:{row.id}",
        "source": "lifecycle",
        "native_id": row.id,
        "type": row.policy_type,
        "name": row.title,
        "description": row.description,
        "rule_key": row.rule_key,
        "version_number": row.version_number,
        "state": row.state,
        "status": row.state,
        "enabled": row.state not in {"DISABLED", "REJECTED", "ROLLED_BACK"},
        "active": row.state == "ACTIVE",
        "scope": scope,
        "scope_classification": scope_risk["classification"],
        "scope_reasons": scope_risk["reasons"],
        "matcher_kind": matcher_kind,
        "matcher_value": matcher_value,
        "matcher_sha256": _matcher_hash(matcher_value),
        "matcher_length": len(matcher_value or ""),
        "owner": row.owner,
        "source_system": row.source_system,
        "business_reason": row.business_reason,
        "risk_note": row.risk_note,
        "expires_at": _iso(row.expires_at),
        "validation_status": row.validation_status,
        "validation_errors": _json_loads(row.validation_errors_json, []),
        "validation_warnings": _json_loads(row.validation_warnings_json, []),
        "hit_count": int(row.hit_count or 0),
        "hit_count_source": "lifecycle_counter",
        "last_match_at": _iso(row.last_hit_at),
        "config_domain": domain,
        "affected_services": affected_services_for_domain(domain),
        "restart_recommended": bool(affected_services_for_domain(domain)),
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "metadata": {"content_json": content},
        **review,
    }


def _operation_item_from_rule(row: DetectionControlRule) -> dict[str, Any]:
    metadata = _metadata(row.metadata_json)
    domain = domain_for_rule_type(row.rule_type)
    scope_risk = classify_detection_scope(
        scope=row.scope,
        matcher_kind=row.matcher_kind,
        matcher_value=row.matcher_value,
        content=metadata,
    )
    expires_at = _parse_datetime(metadata.get("expires_at"))
    review = _review_status(
        item_type=row.rule_type,
        expires_at=expires_at,
        scope_classification=scope_risk["classification"],
        validation_status=row.last_validation_status,
        review_metadata=_review_metadata(metadata),
    )

    return {
        "id": f"managed:{row.id}",
        "source": "managed",
        "native_id": row.id,
        "type": row.rule_type,
        "name": row.name,
        "description": row.description,
        "rule_key": row.id,
        "version_number": None,
        "state": row.status,
        "status": row.status,
        "enabled": bool(row.enabled),
        "active": bool(row.enabled) and row.status == "ACTIVE",
        "scope": row.scope,
        "scope_classification": scope_risk["classification"],
        "scope_reasons": scope_risk["reasons"],
        "matcher_kind": row.matcher_kind,
        "matcher_value": row.matcher_value,
        "matcher_sha256": _matcher_hash(row.matcher_value),
        "matcher_length": len(row.matcher_value or ""),
        "owner": row.owner,
        "source_system": metadata.get("source_system") or metadata.get("inventory_source"),
        "business_reason": row.reason,
        "risk_note": metadata.get("risk_note"),
        "expires_at": _iso(expires_at),
        "validation_status": row.last_validation_status,
        "validation_errors": [],
        "validation_warnings": [row.last_validation_message] if row.last_validation_message else [],
        "hit_count": None,
        "hit_count_source": "unavailable_for_managed_rules",
        "last_match_at": None,
        "config_domain": domain,
        "affected_services": affected_services_for_domain(domain),
        "restart_recommended": bool(affected_services_for_domain(domain)),
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "metadata": metadata,
        **review,
    }


def _all_operation_items(db) -> list[dict[str, Any]]:
    lifecycle_rows = (
        db.query(DetectionRuleLifecycleItem)
        .filter(DetectionRuleLifecycleItem.policy_type.in_(VISIBLE_ITEM_TYPES))
        .order_by(DetectionRuleLifecycleItem.updated_at.desc(), DetectionRuleLifecycleItem.id.desc())
        .all()
    )
    items = [_operation_item_from_lifecycle(row) for row in lifecycle_rows]

    managed_rows = (
        db.query(DetectionControlRule)
        .filter(DetectionControlRule.deleted_at.is_(None))
        .filter(DetectionControlRule.rule_type.in_(VISIBLE_ITEM_TYPES))
        .order_by(DetectionControlRule.updated_at.desc(), DetectionControlRule.name.asc())
        .all()
    )

    for row in managed_rows:
        metadata = _metadata(row.metadata_json)
        if metadata.get("lifecycle_item_id"):
            continue
        items.append(_operation_item_from_rule(row))

    return items


def _matches_term(item: Mapping[str, Any], search: str | None) -> bool:
    term = str(search or "").strip().lower()

    if not term:
        return True

    haystack = " ".join(
        str(item.get(field) or "")
        for field in (
            "name",
            "description",
            "rule_key",
            "owner",
            "source_system",
            "business_reason",
            "scope",
            "matcher_value",
        )
    ).lower()

    return term in haystack


def _matches_status(item: Mapping[str, Any], status: str | None) -> bool:
    normalized = str(status or "all").strip().lower()

    if normalized in {"", "all"}:
        return True
    if normalized == "active":
        return bool(item.get("active"))
    if normalized in {"inactive", "disabled"}:
        return not bool(item.get("active"))
    if normalized == "failed_validation":
        return str(item.get("validation_status") or "").lower() in {
            "failed",
            "error",
            "failed_validation",
        }
    if normalized == "review_due":
        return bool(item.get("review_due"))
    if normalized == "expired":
        return bool(item.get("expired"))

    return str(item.get("status") or "").lower() == normalized or str(item.get("state") or "").lower() == normalized


def _filter_items(
    items: list[dict[str, Any]],
    *,
    item_type: str | None = None,
    status: str | None = None,
    scope_classification: str | None = None,
    review_status: str | None = None,
    search: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    normalized_type = str(item_type or "").strip().upper()
    normalized_scope = str(scope_classification or "all").strip().lower()
    normalized_review = str(review_status or "all").strip().lower()

    filtered = []

    for item in items:
        if normalized_type and item["type"] != normalized_type:
            continue
        if normalized_scope not in {"", "all"} and item["scope_classification"] != normalized_scope:
            continue
        if normalized_review not in {"", "all"} and item["review_status"] != normalized_review:
            continue
        if not _matches_status(item, status):
            continue
        if not _matches_term(item, search):
            continue
        filtered.append(item)

    filtered.sort(
        key=lambda item: (
            not bool(item.get("review_due")),
            not bool(item.get("active")),
            str(item.get("updated_at") or ""),
        ),
        reverse=False,
    )

    return filtered[: max(1, min(limit, 500))]


def _summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    scope_counts = {key: 0 for key in ("narrow", "moderate", "broad", "dangerously_broad", "unknown")}
    type_counts = {key: 0 for key in sorted(VISIBLE_ITEM_TYPES)}
    status_counts: dict[str, int] = {}
    total_hits = 0
    latest_match: datetime | None = None
    affected_services: set[str] = set()

    for item in items:
        scope_counts[item["scope_classification"]] = scope_counts.get(item["scope_classification"], 0) + 1
        type_counts[item["type"]] = type_counts.get(item["type"], 0) + 1
        status = str(item.get("status") or "UNKNOWN")
        status_counts[status] = status_counts.get(status, 0) + 1

        if isinstance(item.get("hit_count"), int):
            total_hits += int(item["hit_count"])

        parsed_match = _parse_datetime(item.get("last_match_at"))
        if parsed_match and (latest_match is None or parsed_match > latest_match):
            latest_match = parsed_match

        affected_services.update(item.get("affected_services") or [])

    return {
        "total": len(items),
        "active": sum(1 for item in items if item["active"]),
        "inactive": sum(1 for item in items if not item["active"]),
        "review_due": sum(1 for item in items if item["review_due"]),
        "expired": sum(1 for item in items if item["expired"]),
        "validation_failed": sum(1 for item in items if str(item.get("validation_status") or "").lower() in {"failed", "error", "failed_validation"}),
        "scope": scope_counts,
        "types": type_counts,
        "statuses": status_counts,
        "stored_hit_count": total_hits,
        "last_match_at": _iso(latest_match),
        "affected_services": sorted(affected_services),
    }


def operations_overview(db, *, current_user: Mapping[str, Any] | None) -> dict[str, Any]:
    items = _all_operation_items(db)
    active_items = [item for item in items if item["active"]]

    return {
        "summary": _summary(items),
        "active_summary": _summary(active_items),
        "top_review_items": [item for item in items if item["review_due"]][:8],
        "rbac": {
            "role": (current_user or {}).get("role"),
            "can_preview": current_user_role(current_user) in OPERATOR_ROLES,
            "can_review": current_user_role(current_user) in OPERATOR_ROLES,
            "can_admin": current_user_role(current_user) == "ADMIN",
        },
        "generated_at": utc_now().isoformat(),
    }


def list_operation_items(
    db,
    *,
    item_type: str | None = None,
    status: str | None = None,
    scope_classification: str | None = None,
    review_status: str | None = None,
    search: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    all_items = _all_operation_items(db)
    items = _filter_items(
        all_items,
        item_type=item_type,
        status=status,
        scope_classification=scope_classification,
        review_status=review_status,
        search=search,
        limit=limit,
    )

    return {
        "items": items,
        "summary": _summary(items),
        "available_filters": {
            "status": ["all", "active", "inactive", "failed_validation", "review_due", "expired"],
            "scope_classification": ["all", "narrow", "moderate", "broad", "dangerously_broad", "unknown"],
            "review_status": ["all", "not_reviewed", "review_due", "reviewed", "needs_follow_up", "expired"],
        },
        "generated_at": utc_now().isoformat(),
    }


def _get_lifecycle_row(db, item_id: str) -> DetectionRuleLifecycleItem:
    try:
        native_id = int(item_id.split(":", 1)[1] if item_id.startswith("lifecycle:") else item_id)
    except (IndexError, TypeError, ValueError):
        raise HTTPException(status_code=404, detail="Detection operations item not found.")

    row = db.query(DetectionRuleLifecycleItem).filter(DetectionRuleLifecycleItem.id == native_id).first()

    if not row:
        raise HTTPException(status_code=404, detail="Detection operations item not found.")

    return row


def _get_managed_row(db, item_id: str) -> DetectionControlRule:
    native_id = item_id.split(":", 1)[1] if item_id.startswith("managed:") else item_id
    row = (
        db.query(DetectionControlRule)
        .filter(DetectionControlRule.id == native_id)
        .filter(DetectionControlRule.deleted_at.is_(None))
        .first()
    )

    if not row:
        raise HTTPException(status_code=404, detail="Detection operations item not found.")

    return row


def get_operation_item_summary(db, *, item_id: str) -> dict[str, Any]:
    if item_id.startswith("lifecycle:"):
        item = _operation_item_from_lifecycle(_get_lifecycle_row(db, item_id))
    elif item_id.startswith("managed:"):
        item = _operation_item_from_rule(_get_managed_row(db, item_id))
    else:
        try:
            item = _operation_item_from_lifecycle(_get_lifecycle_row(db, item_id))
        except HTTPException:
            item = _operation_item_from_rule(_get_managed_row(db, item_id))

    return {"item": item, "generated_at": utc_now().isoformat()}


def _flatten_json(value: Any) -> str:
    if isinstance(value, Mapping):
        return " ".join(f"{key} {_flatten_json(item)}" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(_flatten_json(item) for item in value)
    return str(value or "")


def _json_payload(value: str | None) -> dict[str, Any]:
    parsed = _json_loads(value, {})
    return parsed if isinstance(parsed, dict) else {}


def _event_records(db, *, scan_limit: int) -> list[dict[str, Any]]:
    per_table = max(1, min(scan_limit, 2000) // 4)
    records: list[dict[str, Any]] = []

    for row in db.query(RawEvent).order_by(RawEvent.id.desc()).limit(per_table).all():
        records.append(
            {
                "source_table": "raw_events",
                "id": row.id,
                "source": row.source,
                "timestamp": row.event_timestamp,
                "agent": row.agent,
                "rule_id": row.rule_id,
                "rule_description": row.rule_description,
                "level": row.level,
                "event_count": 1,
                "payload": _json_payload(row.payload_json),
            }
        )

    for row in db.query(SecurityAlert).order_by(SecurityAlert.id.desc()).limit(per_table).all():
        records.append(
            {
                "source_table": "security_alerts",
                "id": row.id,
                "source": row.source,
                "timestamp": row.event_timestamp,
                "agent": row.agent,
                "rule_id": row.rule_id,
                "rule_description": row.rule_description,
                "level": row.level,
                "severity_bucket": row.severity_bucket,
                "event_count": 1,
                "payload": {},
            }
        )

    for row in db.query(Incident).order_by(Incident.id.desc()).limit(per_table).all():
        records.append(
            {
                "source_table": "incidents",
                "id": row.id,
                "source": "incident",
                "timestamp": row.timestamp,
                "agent": row.agent,
                "rule_id": row.rule,
                "rule_description": row.rule,
                "level": row.level,
                "risk_score": row.risk_score,
                "event_count": 1,
                "payload": _json_payload(row.raw_alert),
            }
        )

    for row in db.query(EventAggregate).order_by(EventAggregate.id.desc()).limit(per_table).all():
        payload = _json_payload(row.last_event_json) or _json_payload(row.sample_event_json)
        records.append(
            {
                "source_table": "event_aggregates",
                "id": row.id,
                "source": row.source,
                "timestamp": row.last_seen,
                "agent": row.agent,
                "rule_id": row.rule_id,
                "rule_description": row.rule_description,
                "level": row.level,
                "severity_bucket": row.severity_bucket,
                "event_count": row.count or 1,
                "payload": payload,
            }
        )

    return records


def _record_haystack(record: Mapping[str, Any]) -> str:
    values = [
        record.get("source"),
        record.get("agent"),
        record.get("rule_id"),
        record.get("rule_description"),
        record.get("level"),
        record.get("severity_bucket"),
        record.get("risk_score"),
        _flatten_json(record.get("payload") or {}),
    ]
    return " ".join(str(value or "") for value in values).lower()


def _scope_tokens(scope: str | None) -> list[str]:
    normalized = str(scope or "").strip().lower()

    if not normalized or normalized in BROAD_SCOPE_VALUES or normalized in {"specific_host", "specific-user"}:
        return []

    tokens = re.split(r"[\s,;/]+", normalized)
    cleaned = []

    for token in tokens:
        if ":" in token:
            token = token.split(":", 1)[1]
        token = token.strip()
        if len(token) >= 3 and token not in BROAD_SCOPE_VALUES:
            cleaned.append(token)

    return cleaned[:5]


def _criteria_match(criteria: Any, haystack: str) -> bool:
    values = [value for value in _scalar_values(criteria) if value and value not in WILDCARD_VALUES]

    if not values:
        return True

    return all(value in haystack for value in values)


def _matcher_matches(*, matcher_kind: str, matcher_value: str, content: Mapping[str, Any], haystack: str) -> bool:
    kind = str(matcher_kind or "CONTAINS").upper()
    matcher = str(matcher_value or "").strip()

    if kind == "REGEX":
        try:
            return bool(re.search(matcher, haystack, flags=re.IGNORECASE))
        except re.error:
            return False

    if kind == "EXACT":
        return matcher.lower() == haystack or matcher.lower() in haystack.split()

    if kind in {"JSON", "YAML"}:
        criteria = _json_loads(matcher, None)

        if criteria is None:
            criteria = _match_criteria_from_content(content)

        return _criteria_match(criteria, haystack)

    if not matcher:
        return False

    return matcher.lower() in haystack


def _record_matches_item(record: Mapping[str, Any], item: Mapping[str, Any]) -> bool:
    haystack = _record_haystack(record)
    tokens = _scope_tokens(str(item.get("scope") or ""))

    if tokens and not any(token in haystack for token in tokens):
        return False

    content = item.get("metadata", {}).get("content_json") if isinstance(item.get("metadata"), Mapping) else None
    if not isinstance(content, Mapping):
        content = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}

    return _matcher_matches(
        matcher_kind=str(item.get("matcher_kind") or "CONTAINS"),
        matcher_value=str(item.get("matcher_value") or ""),
        content=content,
        haystack=haystack,
    )


def _event_preview(record: Mapping[str, Any]) -> dict[str, Any]:
    payload = record.get("payload") if isinstance(record.get("payload"), Mapping) else {}
    payload_preview = _flatten_json(payload)[:320]

    return {
        "source_table": record.get("source_table"),
        "id": record.get("id"),
        "source": record.get("source"),
        "timestamp": record.get("timestamp"),
        "agent": record.get("agent"),
        "rule_id": record.get("rule_id"),
        "rule_description": record.get("rule_description"),
        "level": record.get("level"),
        "severity_bucket": record.get("severity_bucket"),
        "risk_score": record.get("risk_score"),
        "event_count": record.get("event_count"),
        "payload_preview": payload_preview,
    }


def matched_events_for_item(
    db,
    *,
    item_id: str,
    limit: int = 25,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    item = get_operation_item_summary(db, item_id=item_id)["item"]
    matches = []
    observed_count = 0

    for record in _event_records(db, scan_limit=scan_limit):
        if not _record_matches_item(record, item):
            continue

        observed_count += 1
        if len(matches) < max(1, min(limit, 100)):
            matches.append(_event_preview(record))

    return {
        "item": item,
        "matches": matches,
        "observed_count": observed_count,
        "scan_limit": max(1, min(scan_limit, 2000)),
        "count_source": "recent_event_scan",
        "generated_at": utc_now().isoformat(),
    }


def match_preview(
    db,
    *,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    _require_operator(current_user)

    scan_limit = int(payload.get("scan_limit") or 500)
    limit = int(payload.get("limit") or 25)
    content = payload.get("content_json")

    if not isinstance(content, Mapping):
        content = payload.get("metadata") if isinstance(payload.get("metadata"), Mapping) else {}

    item = {
        "id": "preview",
        "source": "preview",
        "type": str(payload.get("type") or "NOISE_SUPPRESSION").upper(),
        "name": str(payload.get("name") or "Match preview"),
        "scope": str(payload.get("scope") or _scope_from_content(content, None)),
        "matcher_kind": str(payload.get("matcher_kind") or _matcher_kind_from_content(content)).upper(),
        "matcher_value": str(payload.get("matcher_value") or _matcher_value_from_content(content)),
        "metadata": {"content_json": dict(content)},
    }
    matches = []
    observed_count = 0

    for record in _event_records(db, scan_limit=scan_limit):
        if not _record_matches_item(record, item):
            continue

        observed_count += 1
        if len(matches) < max(1, min(limit, 100)):
            matches.append(_event_preview(record))

    _record_audit(
        db,
        event_type="DETECTION_OPERATIONS_MATCH_PREVIEW_RUN",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        target_id="preview",
        details={
            "type": item["type"],
            "scope": item["scope"],
            "matcher_kind": item["matcher_kind"],
            "matcher_sha256": _matcher_hash(item["matcher_value"]),
            "matcher_length": len(item["matcher_value"]),
            "observed_count": observed_count,
            "scan_limit": max(1, min(scan_limit, 2000)),
        },
    )
    db.commit()

    return {
        "preview": {
            "scope_classification": classify_detection_scope(
                scope=item["scope"],
                matcher_kind=item["matcher_kind"],
                matcher_value=item["matcher_value"],
                content=content,
            ),
            "observed_count": observed_count,
            "scan_limit": max(1, min(scan_limit, 2000)),
            "count_source": "recent_event_scan",
        },
        "matches": matches,
        "generated_at": utc_now().isoformat(),
    }


def _update_review_metadata(
    container: dict[str, Any],
    *,
    current_user: Mapping[str, Any] | None,
    review_status: str,
    review_notes: str | None,
    expires_at: datetime | None = None,
    extension_reason: str | None = None,
) -> None:
    now = utc_now().isoformat()
    review = _review_metadata(container)
    review["review_status"] = review_status
    review["reviewed_at"] = now
    review["reviewed_by"] = (current_user or {}).get("username")

    if review_notes is not None:
        review["review_notes"] = review_notes

    if expires_at is not None:
        review["extended_at"] = now
        review["extended_by"] = (current_user or {}).get("username")
        review["extension_reason"] = extension_reason
        container["expires_at"] = expires_at.isoformat()

    container["operations_review"] = review


def extend_review(
    db,
    *,
    item_id: str,
    expires_at: Any,
    reason: str | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    _require_operator(current_user)
    parsed_expires_at = _parse_datetime(expires_at)

    if not parsed_expires_at:
        raise HTTPException(status_code=400, detail="expires_at must be a valid ISO datetime or date.")

    if parsed_expires_at < utc_now():
        raise HTTPException(status_code=400, detail="expires_at must be in the future.")

    if item_id.startswith("lifecycle:"):
        row = _get_lifecycle_row(db, item_id)
        content = _content(row)
        row.expires_at = parsed_expires_at
        row.updated_by_user_id = _current_user_id(current_user)
        row.updated_by_username = (current_user or {}).get("username")
        row.updated_at = utc_now()
        _update_review_metadata(
            content,
            current_user=current_user,
            review_status="reviewed",
            review_notes=reason,
            expires_at=parsed_expires_at,
            extension_reason=reason,
        )
        row.content_json = _json_dumps(content)
        _record_lifecycle_history(
            db,
            row=row,
            action="review_extended",
            current_user=current_user,
            comment=reason,
            details={"expires_at": parsed_expires_at.isoformat()},
        )
        target_id = f"lifecycle:{row.id}"
    else:
        row = _get_managed_row(db, item_id)
        metadata = _metadata(row.metadata_json)
        _update_review_metadata(
            metadata,
            current_user=current_user,
            review_status="reviewed",
            review_notes=reason,
            expires_at=parsed_expires_at,
            extension_reason=reason,
        )
        row.metadata_json = _json_dumps(metadata)
        row.updated_by = (current_user or {}).get("username")
        row.updated_at = utc_now()
        target_id = f"managed:{row.id}"

    _record_audit(
        db,
        event_type="DETECTION_OPERATIONS_REVIEW_EXTENDED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        target_id=target_id,
        details={"expires_at": parsed_expires_at.isoformat(), "reason": reason},
    )
    db.commit()

    return get_operation_item_summary(db, item_id=target_id)


def mark_reviewed(
    db,
    *,
    item_id: str,
    review_status: str | None,
    review_notes: str | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    _require_operator(current_user)
    normalized_status = str(review_status or "reviewed").strip().lower()

    if normalized_status not in {"reviewed", "needs_follow_up", "risk_accepted"}:
        raise HTTPException(
            status_code=400,
            detail="review_status must be reviewed, needs_follow_up or risk_accepted.",
        )

    if item_id.startswith("lifecycle:"):
        row = _get_lifecycle_row(db, item_id)
        content = _content(row)
        _update_review_metadata(
            content,
            current_user=current_user,
            review_status=normalized_status,
            review_notes=review_notes,
        )
        row.content_json = _json_dumps(content)
        row.updated_by_user_id = _current_user_id(current_user)
        row.updated_by_username = (current_user or {}).get("username")
        row.updated_at = utc_now()
        _record_lifecycle_history(
            db,
            row=row,
            action="marked_reviewed",
            current_user=current_user,
            comment=review_notes,
            details={"review_status": normalized_status},
        )
        target_id = f"lifecycle:{row.id}"
    else:
        row = _get_managed_row(db, item_id)
        metadata = _metadata(row.metadata_json)
        _update_review_metadata(
            metadata,
            current_user=current_user,
            review_status=normalized_status,
            review_notes=review_notes,
        )
        row.metadata_json = _json_dumps(metadata)
        row.updated_by = (current_user or {}).get("username")
        row.updated_at = utc_now()
        target_id = f"managed:{row.id}"

    _record_audit(
        db,
        event_type="DETECTION_OPERATIONS_REVIEW_MARKED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        target_id=target_id,
        details={"review_status": normalized_status},
    )
    db.commit()

    return get_operation_item_summary(db, item_id=target_id)
