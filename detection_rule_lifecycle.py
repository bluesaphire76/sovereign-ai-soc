from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException, Request
from sqlalchemy import func, or_

from detection_config_versioning import (
    affected_services_for_domain,
    apply_config_payload,
    current_config_payload,
    diff_config_payload,
    domain_for_rule_type,
)
from detection_control_plane import (
    _request_client_ip,
    _sanitize_audit_details,
    current_user_role,
)
from detection_control_validation import validate_detection_control_payload
from models import (
    DetectionRuleLifecycleEvent,
    DetectionRuleLifecycleItem,
    SecurityAuditEvent,
)


POLICY_TYPES = {"DETECTION_RULE", "NOISE_SUPPRESSION", "EXCEPTION"}
SOURCE_SYSTEMS = {"WAZUH", "SURICATA", "AI_SOC", "DNS", "OTHER"}

STATE_DRAFT = "DRAFT"
STATE_PROPOSED = "PROPOSED"
STATE_APPROVED = "APPROVED"
STATE_ACTIVE = "ACTIVE"
STATE_DISABLED = "DISABLED"
STATE_SUPERSEDED = "SUPERSEDED"
STATE_FAILED_VALIDATION = "FAILED_VALIDATION"
STATE_ROLLED_BACK = "ROLLED_BACK"
STATE_REJECTED = "REJECTED"

LIFECYCLE_STATES = {
    STATE_DRAFT,
    STATE_PROPOSED,
    STATE_APPROVED,
    STATE_ACTIVE,
    STATE_DISABLED,
    STATE_SUPERSEDED,
    STATE_FAILED_VALIDATION,
    STATE_ROLLED_BACK,
    STATE_REJECTED,
}

VALIDATION_NOT_RUN = "not_validated"
VALIDATION_PASSED = "passed"
VALIDATION_FAILED = "failed"

ALLOWED_TRANSITIONS = {
    STATE_DRAFT: {STATE_PROPOSED, STATE_FAILED_VALIDATION},
    STATE_PROPOSED: {STATE_APPROVED, STATE_REJECTED, STATE_DRAFT, STATE_FAILED_VALIDATION},
    STATE_APPROVED: {STATE_ACTIVE, STATE_REJECTED},
    STATE_ACTIVE: {STATE_DISABLED, STATE_SUPERSEDED},
    STATE_DISABLED: {STATE_DRAFT, STATE_PROPOSED},
    STATE_SUPERSEDED: {STATE_ROLLED_BACK},
    STATE_FAILED_VALIDATION: {STATE_DRAFT, STATE_PROPOSED},
    STATE_REJECTED: {STATE_DRAFT},
}

WILDCARD_VALUES = {"", "*", ".*", "^.*$", "all", "any"}


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


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _upper(value: Any) -> str:
    return _clean_text(value).upper()


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return normalized or "lifecycle-item"


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


def _current_user_id(current_user: Mapping[str, Any] | None) -> int | None:
    value = (current_user or {}).get("id")

    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _role_allowed(current_user: Mapping[str, Any] | None, allowed: set[str]) -> bool:
    return current_user_role(current_user) in allowed


def _content(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="content_json must be valid JSON.")

        if isinstance(parsed, dict):
            return parsed

    raise HTTPException(status_code=400, detail="content_json must be an object.")


def _content_for_row(row: DetectionRuleLifecycleItem) -> dict[str, Any]:
    parsed = _json_loads(row.content_json, {})
    return parsed if isinstance(parsed, dict) else {}


def _validation_lists(row: DetectionRuleLifecycleItem) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    errors = _json_loads(row.validation_errors_json, [])
    warnings = _json_loads(row.validation_warnings_json, [])

    return (
        errors if isinstance(errors, list) else [],
        warnings if isinstance(warnings, list) else [],
    )


def _source_system(payload: Mapping[str, Any], content: Mapping[str, Any]) -> str:
    return _upper(payload.get("source_system") or content.get("source_system") or content.get("source") or "OTHER")


def _expires_at(payload: Mapping[str, Any], content: Mapping[str, Any]) -> datetime | None:
    return _parse_datetime(payload.get("expires_at") or content.get("expires_at"))


def _rule_key(payload: Mapping[str, Any], policy_type: str, title: str) -> str:
    value = _clean_text(payload.get("rule_key"))
    return value or f"{policy_type.lower()}:{_slug(title)}"


def _next_version_number(db, *, policy_type: str, rule_key: str) -> int:
    latest = (
        db.query(func.max(DetectionRuleLifecycleItem.version_number))
        .filter(DetectionRuleLifecycleItem.policy_type == policy_type)
        .filter(DetectionRuleLifecycleItem.rule_key == rule_key)
        .scalar()
    )
    return int(latest or 0) + 1


def _match_criteria(content: Mapping[str, Any]) -> Any:
    return (
        content.get("match")
        if "match" in content
        else content.get("criteria")
        if "criteria" in content
        else content.get("matcher_value")
        if "matcher_value" in content
        else content.get("expression")
    )


def _match_is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str):
        return not value.strip()
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    return False


def _scalar_values(value: Any) -> list[str]:
    if isinstance(value, dict):
        values: list[str] = []
        for item in value.values():
            values.extend(_scalar_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(_scalar_values(item))
        return values
    return [_clean_text(value).lower()]


def _is_wildcard_only(value: Any) -> bool:
    values = [item for item in _scalar_values(value) if item]
    return bool(values) and all(item in WILDCARD_VALUES for item in values)


def _field(field: str, message: str) -> dict[str, str]:
    return {"field": field, "message": message}


def _config_item_id(row: DetectionRuleLifecycleItem) -> str:
    return f"lifecycle:{row.policy_type.lower()}:{row.rule_key}"


def _matcher_value(content: Mapping[str, Any]) -> str:
    explicit = _clean_text(content.get("matcher_value") or content.get("pattern"))
    if explicit:
        return explicit

    match = _match_criteria(content)
    if isinstance(match, str):
        return match

    return _json_dumps(match)


def _matcher_kind(content: Mapping[str, Any]) -> str:
    kind = _upper(content.get("matcher_kind"))
    return kind or ("JSON" if not isinstance(_match_criteria(content), str) else "CONTAINS")


def _scope(content: Mapping[str, Any], source_system: str) -> str:
    return _clean_text(content.get("scope") or content.get("host") or source_system.lower())


def _config_item_for_row(
    row: DetectionRuleLifecycleItem,
    *,
    enabled: bool = True,
    status: str = "ACTIVE",
) -> dict[str, Any]:
    content = _content_for_row(row)
    source_system = row.source_system or _source_system({}, content)

    return {
        "id": _config_item_id(row),
        "name": row.title,
        "type": row.policy_type,
        "status": status,
        "scope": _scope(content, source_system),
        "matcher_kind": _matcher_kind(content),
        "matcher_value": _matcher_value(content),
        "reason": row.business_reason or row.description or "Detection lifecycle managed change.",
        "owner": row.owner or row.created_by_username or "SOC",
        "enabled": enabled,
        "description": row.description,
        "metadata": {
            "lifecycle_item_id": row.id,
            "lifecycle_rule_key": row.rule_key,
            "lifecycle_version_number": row.version_number,
            "policy_type": row.policy_type,
            "source_system": source_system,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "risk_note": row.risk_note,
            "business_reason": row.business_reason,
            "content_json": content,
        },
    }


def _domain_for_item(row: DetectionRuleLifecycleItem) -> str:
    return domain_for_rule_type(row.policy_type)


def _payload_with_lifecycle_item(
    db,
    row: DetectionRuleLifecycleItem,
    *,
    enabled: bool,
    status: str,
) -> dict[str, Any]:
    domain = _domain_for_item(row)
    active_payload = current_config_payload(db, domain)
    lifecycle_id = _config_item_id(row)
    items = [
        item
        for item in active_payload.get("items", [])
        if item.get("id") != lifecycle_id
    ]
    items.append(_config_item_for_row(row, enabled=enabled, status=status))
    items.sort(key=lambda item: str(item.get("id") or ""))

    return {"items": items}


def _transition_error(row: DetectionRuleLifecycleItem, to_state: str) -> HTTPException:
    allowed = sorted(ALLOWED_TRANSITIONS.get(row.state, set()))
    return HTTPException(
        status_code=400,
        detail={
            "error": "Invalid lifecycle transition",
            "from_state": row.state,
            "to_state": to_state,
            "allowed_transitions": allowed,
        },
    )


def _assert_transition(row: DetectionRuleLifecycleItem, to_state: str) -> None:
    if to_state not in ALLOWED_TRANSITIONS.get(row.state, set()):
        raise _transition_error(row, to_state)


def _record_history(
    db,
    *,
    row: DetectionRuleLifecycleItem,
    action: str,
    current_user: Mapping[str, Any] | None,
    from_state: str | None,
    to_state: str | None,
    comment: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    event = DetectionRuleLifecycleEvent(
        item_id=row.id,
        action=action,
        from_state=from_state,
        to_state=to_state,
        actor_user_id=_current_user_id(current_user),
        actor_username=(current_user or {}).get("username"),
        actor_role=(current_user or {}).get("role"),
        comment=comment,
        details_json=_json_dumps(_sanitize_audit_details(details or {})),
        created_at=utc_now(),
    )
    db.add(event)
    db.flush()


def _record_audit(
    db,
    *,
    event_type: str,
    outcome: str,
    current_user: Mapping[str, Any] | None,
    row: DetectionRuleLifecycleItem | None = None,
    request: Request | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    audit = SecurityAuditEvent(
        event_type=event_type,
        outcome=outcome,
        actor_user_id=_current_user_id(current_user),
        actor_username=(current_user or {}).get("username"),
        actor_role=(current_user or {}).get("role"),
        target_type="DETECTION_RULE_LIFECYCLE_ITEM",
        target_id=str(row.id) if row else None,
        method=request.method if request else None,
        path=request.url.path if request else None,
        client_ip=_request_client_ip(request),
        user_agent=request.headers.get("user-agent") if request else None,
        details_json=_json_dumps(
            _sanitize_audit_details(
                {
                    "item_id": row.id if row else None,
                    "policy_type": row.policy_type if row else None,
                    "rule_key": row.rule_key if row else None,
                    "state": row.state if row else None,
                    "actor": (current_user or {}).get("username"),
                    "role": current_user_role(current_user),
                    **(details or {}),
                }
            )
        ),
    )
    db.add(audit)
    db.flush()


def _deny(
    db,
    *,
    row: DetectionRuleLifecycleItem | None,
    action: str,
    current_user: Mapping[str, Any] | None,
    request: Request | None,
    reason: str,
    status_code: int = 403,
) -> None:
    _record_audit(
        db,
        event_type="DETECTION_RULE_TRANSITION_DENIED",
        outcome="DENIED",
        current_user=current_user,
        row=row,
        request=request,
        details={"action": action, "reason": reason},
    )
    db.commit()
    raise HTTPException(status_code=status_code, detail=reason)


def _require_operator(
    db,
    *,
    row: DetectionRuleLifecycleItem | None,
    action: str,
    current_user: Mapping[str, Any] | None,
    request: Request | None,
) -> None:
    if not _role_allowed(current_user, {"ADMIN", "ANALYST"}):
        _deny(
            db,
            row=row,
            action=action,
            current_user=current_user,
            request=request,
            reason="ADMIN or ANALYST role required.",
        )


def _require_admin(
    db,
    *,
    row: DetectionRuleLifecycleItem | None,
    action: str,
    current_user: Mapping[str, Any] | None,
    request: Request | None,
) -> None:
    if not _role_allowed(current_user, {"ADMIN"}):
        _deny(
            db,
            row=row,
            action=action,
            current_user=current_user,
            request=request,
            reason="ADMIN role required.",
        )


def _can_edit_draft(row: DetectionRuleLifecycleItem, current_user: Mapping[str, Any] | None) -> bool:
    if current_user_role(current_user) == "ADMIN":
        return True

    return (
        current_user_role(current_user) == "ANALYST"
        and row.state in {STATE_DRAFT, STATE_FAILED_VALIDATION}
        and row.created_by_user_id == _current_user_id(current_user)
    )


def validate_lifecycle_payload(
    *,
    policy_type: str,
    title: str,
    owner: str | None,
    business_reason: str | None,
    source_system: str,
    content: Mapping[str, Any],
    expires_at: datetime | None,
) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    match = _match_criteria(content)

    if policy_type not in POLICY_TYPES:
        errors.append(_field("policy_type", "Policy type must be DETECTION_RULE, NOISE_SUPPRESSION or EXCEPTION."))
    if not title:
        errors.append(_field("title", "Title is required."))
    if not owner:
        errors.append(_field("owner", "Owner is required."))
    if not business_reason:
        errors.append(_field("business_reason", "Business reason is required."))
    if source_system not in SOURCE_SYSTEMS:
        errors.append(_field("source_system", f"Source system must be one of: {', '.join(sorted(SOURCE_SYSTEMS))}."))
    if _match_is_empty(match):
        errors.append(_field("content_json.match", "Match criteria cannot be empty."))
    if _is_wildcard_only(match):
        errors.append(_field("content_json.match", "Wildcard-only match criteria are not allowed."))

    if policy_type == "NOISE_SUPPRESSION":
        if _clean_text(content.get("action")).lower() != "suppress":
            errors.append(_field("content_json.action", "Noise suppression action must be suppress."))
        if not _scope(content, source_system):
            errors.append(_field("content_json.scope", "Noise suppression scope is required."))
        if _clean_text(content.get("host")).lower() in WILDCARD_VALUES:
            warnings.append(_field("content_json.host", "Host wildcard should be narrowed before approval."))
        if not expires_at:
            warnings.append(_field("expires_at", "Noise suppression has no review or expiration date."))

    if policy_type == "EXCEPTION":
        no_expiration_reason = _clean_text(content.get("no_expiration_justification"))
        if not expires_at and not no_expiration_reason:
            errors.append(
                _field(
                    "expires_at",
                    "Exception requires an expiration date or explicit no-expiration justification.",
                )
            )
        elif not expires_at:
            warnings.append(_field("expires_at", "Exception has no expiration date."))
        if _clean_text(content.get("severity")).lower() in {"critical", "high"}:
            warnings.append(_field("content_json.severity", "High or critical severity exception requires careful review."))

    if policy_type == "DETECTION_RULE":
        if not _clean_text(content.get("severity") or content.get("risk_score")):
            warnings.append(_field("content_json.severity", "Detection rule has no severity or risk mapping."))
        if not content.get("mitre"):
            warnings.append(_field("content_json.mitre", "Detection rule has no MITRE mapping."))
        if not content.get("test_scenario"):
            warnings.append(_field("content_json.test_scenario", "Detection rule has no validation test scenario."))

    control_validation = validate_detection_control_payload(
        {
            "name": title,
            "type": policy_type,
            "status": "ACTIVE",
            "scope": _scope(content, source_system),
            "matcher_kind": _matcher_kind(content),
            "matcher_value": _matcher_value(content),
            "reason": business_reason,
            "owner": owner,
            "enabled": True,
            "description": content.get("description"),
            "metadata": content,
        }
    )

    errors.extend(_field("config_payload", message) for message in control_validation.messages)
    warnings.extend(_field("config_payload", message) for message in control_validation.warnings)

    return {
        "valid": not errors,
        "validation_status": VALIDATION_FAILED if errors else VALIDATION_PASSED,
        "errors": errors,
        "warnings": warnings,
    }


def _validate_row(row: DetectionRuleLifecycleItem) -> dict[str, Any]:
    return validate_lifecycle_payload(
        policy_type=row.policy_type,
        title=row.title,
        owner=row.owner,
        business_reason=row.business_reason,
        source_system=row.source_system or "OTHER",
        content=_content_for_row(row),
        expires_at=row.expires_at,
    )


def _store_validation(row: DetectionRuleLifecycleItem, validation: Mapping[str, Any]) -> None:
    row.validation_status = str(validation["validation_status"])
    row.validation_errors_json = _json_dumps(validation.get("errors") or [])
    row.validation_warnings_json = _json_dumps(validation.get("warnings") or [])
    row.updated_at = utc_now()


def serialize_lifecycle_item(row: DetectionRuleLifecycleItem) -> dict[str, Any]:
    errors, warnings = _validation_lists(row)
    domain = _domain_for_item(row)
    affected_services = affected_services_for_domain(domain)

    return {
        "id": row.id,
        "policy_type": row.policy_type,
        "rule_key": row.rule_key,
        "version_number": row.version_number,
        "title": row.title,
        "description": row.description,
        "content_json": _content_for_row(row),
        "state": row.state,
        "created_by_user_id": row.created_by_user_id,
        "created_by_username": row.created_by_username,
        "updated_by_user_id": row.updated_by_user_id,
        "updated_by_username": row.updated_by_username,
        "submitted_by_user_id": row.submitted_by_user_id,
        "submitted_at": row.submitted_at.isoformat() if row.submitted_at else None,
        "approved_by_user_id": row.approved_by_user_id,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "rejected_by_user_id": row.rejected_by_user_id,
        "rejected_at": row.rejected_at.isoformat() if row.rejected_at else None,
        "rejection_reason": row.rejection_reason,
        "applied_by_user_id": row.applied_by_user_id,
        "applied_at": row.applied_at.isoformat() if row.applied_at else None,
        "disabled_by_user_id": row.disabled_by_user_id,
        "disabled_at": row.disabled_at.isoformat() if row.disabled_at else None,
        "disable_reason": row.disable_reason,
        "superseded_by_item_id": row.superseded_by_item_id,
        "cloned_from_item_id": row.cloned_from_item_id,
        "related_config_version_id": row.related_config_version_id,
        "validation_status": row.validation_status,
        "validation_errors": errors,
        "validation_warnings": warnings,
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "owner": row.owner,
        "business_reason": row.business_reason,
        "risk_note": row.risk_note,
        "last_hit_at": row.last_hit_at.isoformat() if row.last_hit_at else None,
        "hit_count": row.hit_count,
        "source_system": row.source_system,
        "config_domain": domain,
        "restart_recommended": bool(affected_services),
        "affected_services": affected_services,
        "allowed_transitions": sorted(ALLOWED_TRANSITIONS.get(row.state, set())),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def get_lifecycle_item(db, item_id: int) -> DetectionRuleLifecycleItem:
    row = (
        db.query(DetectionRuleLifecycleItem)
        .filter(DetectionRuleLifecycleItem.id == item_id)
        .first()
    )

    if not row:
        raise HTTPException(status_code=404, detail="Detection lifecycle item not found.")

    return row


def list_lifecycle_items(
    db,
    *,
    policy_type: str | None = None,
    state: str | None = None,
    source_system: str | None = None,
    validation_status: str | None = None,
    owner: str | None = None,
    search: str | None = None,
    limit: int = 200,
) -> dict[str, Any]:
    query = db.query(DetectionRuleLifecycleItem)

    if policy_type:
        query = query.filter(DetectionRuleLifecycleItem.policy_type == _upper(policy_type))
    if state:
        query = query.filter(DetectionRuleLifecycleItem.state == _upper(state))
    if source_system:
        query = query.filter(DetectionRuleLifecycleItem.source_system == _upper(source_system))
    if validation_status:
        query = query.filter(DetectionRuleLifecycleItem.validation_status == _clean_text(validation_status).lower())
    if owner:
        query = query.filter(DetectionRuleLifecycleItem.owner.ilike(f"%{owner.strip()}%"))

    term = _clean_text(search)
    if term:
        like_term = f"%{term}%"
        query = query.filter(
            or_(
                DetectionRuleLifecycleItem.title.ilike(like_term),
                DetectionRuleLifecycleItem.description.ilike(like_term),
                DetectionRuleLifecycleItem.rule_key.ilike(like_term),
                DetectionRuleLifecycleItem.owner.ilike(like_term),
                DetectionRuleLifecycleItem.business_reason.ilike(like_term),
                DetectionRuleLifecycleItem.content_json.ilike(like_term),
            )
        )

    rows = (
        query.order_by(DetectionRuleLifecycleItem.updated_at.desc(), DetectionRuleLifecycleItem.id.desc())
        .limit(max(1, min(limit, 500)))
        .all()
    )
    items = [serialize_lifecycle_item(row) for row in rows]
    states = {state: 0 for state in sorted(LIFECYCLE_STATES)}

    for item in items:
        states[item["state"]] = states.get(item["state"], 0) + 1

    return {
        "items": items,
        "summary": {
            "total": len(items),
            "states": states,
            "validation_failed": sum(1 for item in items if item["validation_status"] == VALIDATION_FAILED),
            "restart_recommended": sum(1 for item in items if item["restart_recommended"]),
        },
        "states": sorted(LIFECYCLE_STATES),
        "policy_types": sorted(POLICY_TYPES),
        "source_systems": sorted(SOURCE_SYSTEMS),
    }


def create_lifecycle_item(
    db,
    *,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    _require_operator(db, row=None, action="create_draft", current_user=current_user, request=request)

    content = _content(payload.get("content_json") or payload.get("content") or {})
    policy_type = _upper(payload.get("policy_type"))
    title = _clean_text(payload.get("title"))
    source_system = _source_system(payload, content)
    expires_at = _expires_at(payload, content)
    owner = _clean_text(payload.get("owner") or content.get("owner") or (current_user or {}).get("username"))
    business_reason = _clean_text(payload.get("business_reason") or content.get("business_reason") or payload.get("reason"))
    rule_key = _rule_key(payload, policy_type, title)
    now = utc_now()

    if policy_type not in POLICY_TYPES:
        raise HTTPException(status_code=400, detail="Policy type must be DETECTION_RULE, NOISE_SUPPRESSION or EXCEPTION.")

    if not title:
        raise HTTPException(status_code=400, detail="Title is required.")

    row = DetectionRuleLifecycleItem(
        policy_type=policy_type,
        rule_key=rule_key,
        version_number=_next_version_number(db, policy_type=policy_type, rule_key=rule_key),
        title=title,
        description=_clean_text(payload.get("description") or content.get("description")) or None,
        content_json=_json_dumps(content),
        state=STATE_DRAFT,
        created_by_user_id=_current_user_id(current_user),
        created_by_username=current_user.get("username"),
        updated_by_user_id=_current_user_id(current_user),
        updated_by_username=current_user.get("username"),
        validation_status=VALIDATION_NOT_RUN,
        validation_errors_json="[]",
        validation_warnings_json="[]",
        expires_at=expires_at,
        owner=owner,
        business_reason=business_reason,
        risk_note=_clean_text(payload.get("risk_note") or content.get("risk_note")) or None,
        hit_count=0,
        source_system=source_system,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()

    _record_history(
        db,
        row=row,
        action="created",
        current_user=current_user,
        from_state=None,
        to_state=STATE_DRAFT,
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_DRAFT_CREATED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={"to_state": STATE_DRAFT},
    )
    db.commit()
    db.refresh(row)

    return {"item": serialize_lifecycle_item(row)}


def update_lifecycle_item(
    db,
    *,
    item_id: int,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)

    if not _can_edit_draft(row, current_user):
        _deny(
            db,
            row=row,
            action="edit",
            current_user=current_user,
            request=request,
            reason="Only ADMIN or the owning ANALYST can edit draft lifecycle items.",
        )

    if row.state not in {STATE_DRAFT, STATE_FAILED_VALIDATION}:
        raise _transition_error(row, STATE_DRAFT)

    from_state = row.state
    content = _content(payload.get("content_json", _content_for_row(row)))
    policy_type = _upper(payload.get("policy_type") or row.policy_type)
    title = _clean_text(payload.get("title") or row.title)
    source_system = _source_system(payload, content)
    expires_at = _expires_at(payload, content) if ("expires_at" in payload or "expires_at" in content) else row.expires_at

    if policy_type not in POLICY_TYPES:
        raise HTTPException(status_code=400, detail="Policy type must be DETECTION_RULE, NOISE_SUPPRESSION or EXCEPTION.")

    if not title:
        raise HTTPException(status_code=400, detail="Title is required.")

    row.policy_type = policy_type
    row.title = title
    row.description = _clean_text(payload.get("description", row.description)) or None
    row.content_json = _json_dumps(content)
    row.owner = _clean_text(payload.get("owner") or row.owner)
    row.business_reason = _clean_text(payload.get("business_reason") or row.business_reason)
    row.risk_note = _clean_text(payload.get("risk_note") or row.risk_note) or None
    row.source_system = source_system
    row.expires_at = expires_at
    row.updated_by_user_id = _current_user_id(current_user)
    row.updated_by_username = current_user.get("username")
    row.updated_at = utc_now()

    if row.state == STATE_FAILED_VALIDATION:
        row.state = STATE_DRAFT
    row.validation_status = VALIDATION_NOT_RUN
    row.validation_errors_json = "[]"
    row.validation_warnings_json = "[]"
    db.flush()

    _record_history(
        db,
        row=row,
        action="updated",
        current_user=current_user,
        from_state=from_state,
        to_state=row.state,
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_UPDATED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={"state": row.state},
    )
    db.commit()
    db.refresh(row)

    return {"item": serialize_lifecycle_item(row)}


def validate_lifecycle_item(
    db,
    *,
    item_id: int,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)
    _require_operator(db, row=row, action="validate", current_user=current_user, request=request)

    if row.state not in {STATE_DRAFT, STATE_PROPOSED, STATE_FAILED_VALIDATION}:
        raise _transition_error(row, STATE_FAILED_VALIDATION)

    from_state = row.state
    validation = _validate_row(row)
    _store_validation(row, validation)

    if not validation["valid"]:
        if row.state != STATE_FAILED_VALIDATION:
            _assert_transition(row, STATE_FAILED_VALIDATION)
            row.state = STATE_FAILED_VALIDATION

    row.updated_by_user_id = _current_user_id(current_user)
    row.updated_by_username = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    _record_history(
        db,
        row=row,
        action="validated",
        current_user=current_user,
        from_state=from_state,
        to_state=row.state,
        details={"validation": validation},
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_VALIDATED",
        outcome="SUCCESS" if validation["valid"] else "FAILURE",
        current_user=current_user,
        row=row,
        request=request,
        details={
            "from_state": from_state,
            "to_state": row.state,
            "validation_status": validation["validation_status"],
        },
    )
    db.commit()
    db.refresh(row)

    return {"item": serialize_lifecycle_item(row), "validation": validation}


def submit_lifecycle_item(
    db,
    *,
    item_id: int,
    comment: str | None,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)
    _require_operator(db, row=row, action="submit", current_user=current_user, request=request)

    if row.state not in {STATE_DRAFT, STATE_FAILED_VALIDATION}:
        raise _transition_error(row, STATE_PROPOSED)

    from_state = row.state
    validation = _validate_row(row)
    _store_validation(row, validation)

    if not validation["valid"]:
        if row.state != STATE_FAILED_VALIDATION:
            _assert_transition(row, STATE_FAILED_VALIDATION)
            row.state = STATE_FAILED_VALIDATION
        db.flush()
        _record_history(
            db,
            row=row,
            action="submit_failed_validation",
            current_user=current_user,
            from_state=from_state,
            to_state=row.state,
            comment=comment,
            details={"validation": validation},
        )
        _record_audit(
            db,
            event_type="DETECTION_RULE_SUBMITTED",
            outcome="FAILURE",
            current_user=current_user,
            row=row,
            request=request,
            details={"from_state": from_state, "to_state": row.state, "validation_status": VALIDATION_FAILED},
        )
        db.commit()
        raise HTTPException(
            status_code=400,
            detail={"message": "Validation failed.", "validation": validation},
        )

    _assert_transition(row, STATE_PROPOSED)
    row.state = STATE_PROPOSED
    row.submitted_by_user_id = _current_user_id(current_user)
    row.submitted_at = utc_now()
    row.updated_by_user_id = _current_user_id(current_user)
    row.updated_by_username = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    _record_history(
        db,
        row=row,
        action="submitted",
        current_user=current_user,
        from_state=from_state,
        to_state=STATE_PROPOSED,
        comment=comment,
        details={"validation": validation},
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_SUBMITTED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={"from_state": from_state, "to_state": STATE_PROPOSED, "comment": comment},
    )
    db.commit()
    db.refresh(row)

    return {"item": serialize_lifecycle_item(row), "validation": validation}


def approve_lifecycle_item(
    db,
    *,
    item_id: int,
    approval_comment: str | None,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)
    _require_admin(db, row=row, action="approve", current_user=current_user, request=request)
    _assert_transition(row, STATE_APPROVED)

    from_state = row.state
    row.state = STATE_APPROVED
    row.approved_by_user_id = _current_user_id(current_user)
    row.approved_at = utc_now()
    row.updated_by_user_id = _current_user_id(current_user)
    row.updated_by_username = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    _record_history(
        db,
        row=row,
        action="approved",
        current_user=current_user,
        from_state=from_state,
        to_state=STATE_APPROVED,
        comment=approval_comment,
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_APPROVED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={"from_state": from_state, "to_state": STATE_APPROVED, "comment": approval_comment},
    )
    db.commit()
    db.refresh(row)

    return {"item": serialize_lifecycle_item(row)}


def reject_lifecycle_item(
    db,
    *,
    item_id: int,
    rejection_reason: str | None,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    reason = _clean_text(rejection_reason)

    if not reason:
        raise HTTPException(status_code=400, detail="Rejection reason is required.")

    row = get_lifecycle_item(db, item_id)
    _require_admin(db, row=row, action="reject", current_user=current_user, request=request)
    _assert_transition(row, STATE_REJECTED)

    from_state = row.state
    row.state = STATE_REJECTED
    row.rejected_by_user_id = _current_user_id(current_user)
    row.rejected_at = utc_now()
    row.rejection_reason = reason
    row.updated_by_user_id = _current_user_id(current_user)
    row.updated_by_username = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    _record_history(
        db,
        row=row,
        action="rejected",
        current_user=current_user,
        from_state=from_state,
        to_state=STATE_REJECTED,
        comment=reason,
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_REJECTED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={"from_state": from_state, "to_state": STATE_REJECTED, "reason": reason},
    )
    db.commit()
    db.refresh(row)

    return {"item": serialize_lifecycle_item(row)}


def return_lifecycle_item_to_draft(
    db,
    *,
    item_id: int,
    comment: str | None,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)
    _require_operator(db, row=row, action="return_to_draft", current_user=current_user, request=request)
    _assert_transition(row, STATE_DRAFT)

    from_state = row.state
    row.state = STATE_DRAFT
    row.updated_by_user_id = _current_user_id(current_user)
    row.updated_by_username = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    _record_history(
        db,
        row=row,
        action="returned_to_draft",
        current_user=current_user,
        from_state=from_state,
        to_state=STATE_DRAFT,
        comment=comment,
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_UPDATED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={"action": "return_to_draft", "from_state": from_state, "to_state": STATE_DRAFT},
    )
    db.commit()
    db.refresh(row)

    return {"item": serialize_lifecycle_item(row)}


def apply_lifecycle_item(
    db,
    *,
    item_id: int,
    comment: str | None,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)
    _require_admin(db, row=row, action="apply", current_user=current_user, request=request)
    _assert_transition(row, STATE_ACTIVE)

    validation = _validate_row(row)
    _store_validation(row, validation)

    if not validation["valid"]:
        _record_audit(
            db,
            event_type="DETECTION_RULE_APPLIED",
            outcome="FAILURE",
            current_user=current_user,
            row=row,
            request=request,
            details={"validation_status": VALIDATION_FAILED},
        )
        db.commit()
        raise HTTPException(
            status_code=400,
            detail={"message": "Validation failed.", "validation": validation},
        )

    from_state = row.state
    domain = _domain_for_item(row)
    payload = _payload_with_lifecycle_item(db, row, enabled=True, status=STATE_ACTIVE)
    applied = apply_config_payload(
        db,
        config_domain=domain,
        payload=payload,
        reason=comment or f"Apply lifecycle item #{row.id}.",
        current_user=current_user,
        request=request,
    )
    version = applied["version"]
    now = utc_now()

    active_rows = (
        db.query(DetectionRuleLifecycleItem)
        .filter(DetectionRuleLifecycleItem.id != row.id)
        .filter(DetectionRuleLifecycleItem.policy_type == row.policy_type)
        .filter(DetectionRuleLifecycleItem.rule_key == row.rule_key)
        .filter(DetectionRuleLifecycleItem.state == STATE_ACTIVE)
        .all()
    )

    for active_row in active_rows:
        active_from_state = active_row.state
        _assert_transition(active_row, STATE_SUPERSEDED)
        active_row.state = STATE_SUPERSEDED
        active_row.superseded_by_item_id = row.id
        active_row.updated_by_user_id = _current_user_id(current_user)
        active_row.updated_by_username = current_user.get("username")
        active_row.updated_at = now
        _record_history(
            db,
            row=active_row,
            action="superseded",
            current_user=current_user,
            from_state=active_from_state,
            to_state=STATE_SUPERSEDED,
            details={"superseded_by_item_id": row.id},
        )
        _record_audit(
            db,
            event_type="DETECTION_RULE_SUPERSEDED",
            outcome="SUCCESS",
            current_user=current_user,
            row=active_row,
            request=request,
            details={"superseded_by_item_id": row.id},
        )

    row.state = STATE_ACTIVE
    row.applied_by_user_id = _current_user_id(current_user)
    row.applied_at = now
    row.related_config_version_id = version["id"]
    row.updated_by_user_id = _current_user_id(current_user)
    row.updated_by_username = current_user.get("username")
    row.updated_at = now
    db.flush()

    _record_history(
        db,
        row=row,
        action="applied",
        current_user=current_user,
        from_state=from_state,
        to_state=STATE_ACTIVE,
        comment=comment,
        details={
            "related_config_version_id": version["id"],
            "affected_services": applied["affected_services"],
            "restart_recommended": applied["requires_restart"],
        },
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_APPLIED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={
            "from_state": from_state,
            "to_state": STATE_ACTIVE,
            "related_config_version_id": version["id"],
            "affected_services": applied["affected_services"],
            "restart_recommended": applied["requires_restart"],
        },
    )
    db.commit()
    db.refresh(row)

    return {
        "item": serialize_lifecycle_item(row),
        "item_id": row.id,
        "state": row.state,
        "related_config_version_id": version["id"],
        "related_config_version_number": version["version_number"],
        "restart_recommended": applied["requires_restart"],
        "affected_services": applied["affected_services"],
        "message": (
            "Rule activated. Restart of affected services is recommended to load the updated configuration."
            if applied["requires_restart"]
            else "Rule activated."
        ),
    }


def disable_lifecycle_item(
    db,
    *,
    item_id: int,
    disable_reason: str | None,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    reason = _clean_text(disable_reason)

    if not reason:
        raise HTTPException(status_code=400, detail="Disable reason is required.")

    row = get_lifecycle_item(db, item_id)
    _require_admin(db, row=row, action="disable", current_user=current_user, request=request)
    _assert_transition(row, STATE_DISABLED)

    from_state = row.state
    domain = _domain_for_item(row)
    payload = _payload_with_lifecycle_item(db, row, enabled=False, status=STATE_DISABLED)
    applied = apply_config_payload(
        db,
        config_domain=domain,
        payload=payload,
        reason=reason,
        current_user=current_user,
        request=request,
    )
    version = applied["version"]

    row.state = STATE_DISABLED
    row.disabled_by_user_id = _current_user_id(current_user)
    row.disabled_at = utc_now()
    row.disable_reason = reason
    row.related_config_version_id = version["id"]
    row.updated_by_user_id = _current_user_id(current_user)
    row.updated_by_username = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    _record_history(
        db,
        row=row,
        action="disabled",
        current_user=current_user,
        from_state=from_state,
        to_state=STATE_DISABLED,
        comment=reason,
        details={
            "related_config_version_id": version["id"],
            "affected_services": applied["affected_services"],
            "restart_recommended": applied["requires_restart"],
        },
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_DISABLED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={
            "from_state": from_state,
            "to_state": STATE_DISABLED,
            "reason": reason,
            "related_config_version_id": version["id"],
            "affected_services": applied["affected_services"],
            "restart_recommended": applied["requires_restart"],
        },
    )
    db.commit()
    db.refresh(row)

    return {
        "item": serialize_lifecycle_item(row),
        "item_id": row.id,
        "state": row.state,
        "related_config_version_id": version["id"],
        "related_config_version_number": version["version_number"],
        "restart_recommended": applied["requires_restart"],
        "affected_services": applied["affected_services"],
        "message": (
            "Rule disabled. Restart of affected services is recommended to load the updated configuration."
            if applied["requires_restart"]
            else "Rule disabled."
        ),
    }


def clone_lifecycle_item(
    db,
    *,
    item_id: int,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    source = get_lifecycle_item(db, item_id)
    _require_operator(db, row=source, action="clone", current_user=current_user, request=request)

    now = utc_now()
    clone = DetectionRuleLifecycleItem(
        policy_type=source.policy_type,
        rule_key=source.rule_key,
        version_number=_next_version_number(db, policy_type=source.policy_type, rule_key=source.rule_key),
        title=f"{source.title} draft",
        description=source.description,
        content_json=source.content_json,
        state=STATE_DRAFT,
        created_by_user_id=_current_user_id(current_user),
        created_by_username=current_user.get("username"),
        updated_by_user_id=_current_user_id(current_user),
        updated_by_username=current_user.get("username"),
        cloned_from_item_id=source.id,
        validation_status=VALIDATION_NOT_RUN,
        validation_errors_json="[]",
        validation_warnings_json="[]",
        expires_at=source.expires_at,
        owner=source.owner,
        business_reason=source.business_reason,
        risk_note=source.risk_note,
        hit_count=0,
        source_system=source.source_system,
        created_at=now,
        updated_at=now,
    )
    db.add(clone)
    db.flush()

    _record_history(
        db,
        row=clone,
        action="cloned",
        current_user=current_user,
        from_state=None,
        to_state=STATE_DRAFT,
        details={"cloned_from_item_id": source.id},
    )
    _record_audit(
        db,
        event_type="DETECTION_RULE_CLONED",
        outcome="SUCCESS",
        current_user=current_user,
        row=clone,
        request=request,
        details={"cloned_from_item_id": source.id},
    )
    db.commit()
    db.refresh(clone)

    return {"item": serialize_lifecycle_item(clone)}


def delete_lifecycle_draft(
    db,
    *,
    item_id: int,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)

    if not _can_edit_draft(row, current_user):
        _deny(
            db,
            row=row,
            action="delete_draft",
            current_user=current_user,
            request=request,
            reason="Only ADMIN or the owning ANALYST can delete draft lifecycle items.",
        )

    if row.state != STATE_DRAFT:
        raise _transition_error(row, "deleted")

    item_id_value = row.id
    _record_audit(
        db,
        event_type="DETECTION_RULE_UPDATED",
        outcome="SUCCESS",
        current_user=current_user,
        row=row,
        request=request,
        details={"action": "delete_draft"},
    )
    db.query(DetectionRuleLifecycleEvent).filter(DetectionRuleLifecycleEvent.item_id == row.id).delete()
    db.delete(row)
    db.commit()

    return {"status": "deleted", "item_id": item_id_value}


def lifecycle_item_history(db, *, item_id: int) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)
    events = (
        db.query(DetectionRuleLifecycleEvent)
        .filter(DetectionRuleLifecycleEvent.item_id == item_id)
        .order_by(DetectionRuleLifecycleEvent.created_at.asc(), DetectionRuleLifecycleEvent.id.asc())
        .all()
    )

    return {
        "item_id": row.id,
        "events": [
            {
                "id": event.id,
                "timestamp": event.created_at.isoformat() if event.created_at else None,
                "actor": event.actor_username,
                "actor_role": event.actor_role,
                "action": event.action,
                "from_state": event.from_state,
                "to_state": event.to_state,
                "comment": event.comment,
                "details": _json_loads(event.details_json, {}),
            }
            for event in events
        ],
    }


def lifecycle_item_diff(db, *, item_id: int) -> dict[str, Any]:
    row = get_lifecycle_item(db, item_id)
    domain = _domain_for_item(row)
    payload = _payload_with_lifecycle_item(
        db,
        row,
        enabled=row.state != STATE_DISABLED,
        status=STATE_DISABLED if row.state == STATE_DISABLED else STATE_ACTIVE,
    )

    return diff_config_payload(db, domain, payload)
