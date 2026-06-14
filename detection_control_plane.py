from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException, Request
from sqlalchemy import func

from detection_control_validation import (
    DetectionControlValidationResult,
    normalize_detection_control_payload,
    validate_detection_control_payload,
)
from models import DetectionControlRule, SecurityAuditEvent


SENSITIVE_AUDIT_KEYS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "authorization",
    "secret",
    "api_key",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def current_user_role(current_user: Mapping[str, Any] | None) -> str:
    return str((current_user or {}).get("role") or "").upper().strip()


def ensure_admin(current_user: Mapping[str, Any] | None) -> None:
    if current_user_role(current_user) != "ADMIN":
        raise HTTPException(status_code=403, detail="ADMIN role required.")


def _request_client_ip(request: Request | None) -> str | None:
    if request is None:
        return None

    forwarded_for = request.headers.get("x-forwarded-for")

    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    if request.client:
        return request.client.host

    return None


def _sanitize_audit_details(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized = {}

        for key, item in value.items():
            if str(key).lower() in SENSITIVE_AUDIT_KEYS:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = _sanitize_audit_details(item)

        return sanitized

    if isinstance(value, list):
        return [_sanitize_audit_details(item) for item in value]

    return value


def _metadata(value: str | None) -> dict[str, Any]:
    if not value:
        return {}

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}

    return parsed if isinstance(parsed, dict) else {}


def _validation_message(result: DetectionControlValidationResult) -> str:
    details = result.messages + result.warnings
    return "; ".join(details) if details else "Validation passed."


def _service_for_rule_type(rule_type: str) -> tuple[bool, str | None]:
    if rule_type in {"NOISE_SUPPRESSION", "SOURCE_POLICY"}:
        return True, "ai-soc-worker"

    if rule_type == "DETECTION_RULE":
        return True, "detection-source"

    if rule_type == "EXCEPTION":
        return True, "ai-soc-worker"

    if rule_type == "TELEMETRY_SOURCE":
        return False, None

    if rule_type == "SERVICE_CONTROL":
        return True, "service-control"

    return False, None


def serialize_detection_control_rule(row: DetectionControlRule) -> dict[str, Any]:
    requires_apply, affected_service = _service_for_rule_type(row.rule_type)

    return {
        "id": row.id,
        "name": row.name,
        "type": row.rule_type,
        "status": row.status,
        "scope": row.scope,
        "matcher_kind": row.matcher_kind,
        "matcher_value": row.matcher_value,
        "reason": row.reason,
        "owner": row.owner,
        "enabled": bool(row.enabled),
        "description": row.description,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "created_by": row.created_by,
        "updated_by": row.updated_by,
        "last_validation_status": row.last_validation_status,
        "last_validation_message": row.last_validation_message,
        "metadata": _metadata(row.metadata_json),
        "requires_apply": requires_apply,
        "affected_service": affected_service,
        "restart_note": "Restart orchestration will be enabled in Step 3.",
    }


def _rule_audit_summary(row: DetectionControlRule | None) -> dict[str, Any] | None:
    if row is None:
        return None

    matcher = row.matcher_value or ""

    return {
        "id": row.id,
        "type": row.rule_type,
        "name": row.name,
        "status": row.status,
        "enabled": bool(row.enabled),
        "scope": row.scope,
        "matcher_kind": row.matcher_kind,
        "matcher_sha256": hashlib.sha256(matcher.encode("utf-8")).hexdigest()
        if matcher
        else None,
        "matcher_length": len(matcher),
        "owner": row.owner,
        "last_validation_status": row.last_validation_status,
    }


def _payload_audit_summary(payload: Mapping[str, Any]) -> dict[str, Any]:
    normalized = normalize_detection_control_payload(payload)
    matcher = normalized["matcher_value"] or ""

    return {
        "type": normalized["type"],
        "name": normalized["name"],
        "status": normalized["status"],
        "enabled": normalized["enabled"],
        "scope": normalized["scope"],
        "matcher_kind": normalized["matcher_kind"],
        "matcher_sha256": hashlib.sha256(matcher.encode("utf-8")).hexdigest()
        if matcher
        else None,
        "matcher_length": len(matcher),
        "owner": normalized["owner"],
    }


def record_detection_control_audit(
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
        actor_user_id=(current_user or {}).get("id"),
        actor_username=(current_user or {}).get("username"),
        actor_role=(current_user or {}).get("role"),
        target_type="DETECTION_CONTROL_RULE",
        target_id=target_id,
        method=request.method if request else None,
        path=request.url.path if request else None,
        client_ip=_request_client_ip(request),
        user_agent=request.headers.get("user-agent") if request else None,
        details_json=json.dumps(
            _sanitize_audit_details(details or {}),
            default=str,
            sort_keys=True,
        ),
    )
    db.add(row)
    db.flush()


def list_detection_control_rules(db) -> list[dict[str, Any]]:
    rows = (
        db.query(DetectionControlRule)
        .filter(DetectionControlRule.deleted_at.is_(None))
        .order_by(DetectionControlRule.updated_at.desc(), DetectionControlRule.name.asc())
        .all()
    )

    return [serialize_detection_control_rule(row) for row in rows]


def get_detection_control_rule(db, rule_id: str) -> DetectionControlRule:
    row = (
        db.query(DetectionControlRule)
        .filter(DetectionControlRule.id == rule_id)
        .filter(DetectionControlRule.deleted_at.is_(None))
        .first()
    )

    if not row:
        raise HTTPException(status_code=404, detail="Detection control rule not found.")

    return row


def detection_control_summary(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(items),
        "active": sum(1 for item in items if item["status"] == "ACTIVE"),
        "disabled": sum(1 for item in items if not item["enabled"] or item["status"] == "DISABLED"),
        "failed_validation": sum(
            1
            for item in items
            if item["status"] == "FAILED_VALIDATION"
            or item["last_validation_status"] == "ERROR"
        ),
        "generated_at": utc_now().isoformat(),
        "restart_orchestration": "planned_step_3",
    }


def _ensure_unique_name(db, *, name: str, rule_type: str, exclude_id: str | None = None) -> None:
    query = (
        db.query(DetectionControlRule)
        .filter(DetectionControlRule.deleted_at.is_(None))
        .filter(func.lower(DetectionControlRule.name) == name.lower())
        .filter(DetectionControlRule.rule_type == rule_type)
    )

    if exclude_id:
        query = query.filter(DetectionControlRule.id != exclude_id)

    if query.first():
        raise HTTPException(
            status_code=409,
            detail="A detection control rule with this type and name already exists.",
        )


def _validation_failure(
    db,
    *,
    payload: Mapping[str, Any],
    validation: DetectionControlValidationResult,
    current_user: Mapping[str, Any] | None,
    request: Request | None,
    action: str,
    target_id: str | None = None,
) -> None:
    record_detection_control_audit(
        db,
        event_type="DETECTION_CONTROL_RULE_VALIDATION_FAILED",
        outcome="FAILURE",
        current_user=current_user,
        request=request,
        target_id=target_id,
        details={
            "action": action,
            "payload": _payload_audit_summary(payload),
            "validation": validation.model_dump(mode="json"),
        },
    )
    db.commit()


def _conflict_failure(
    db,
    *,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any] | None,
    request: Request | None,
    action: str,
    target_id: str | None = None,
) -> None:
    record_detection_control_audit(
        db,
        event_type="DETECTION_CONTROL_RULE_CONFLICT",
        outcome="FAILURE",
        current_user=current_user,
        request=request,
        target_id=target_id,
        details={
            "action": action,
            "payload": _payload_audit_summary(payload),
            "reason": "duplicate_type_name",
        },
    )
    db.commit()


def create_detection_control_rule(
    db,
    *,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    validation = validate_detection_control_payload(payload)

    if not validation.valid:
        _validation_failure(
            db,
            payload=payload,
            validation=validation,
            current_user=current_user,
            request=request,
            action="create",
        )
        raise HTTPException(
            status_code=400,
            detail={"message": "Validation failed.", "validation": validation.model_dump(mode="json")},
        )

    normalized = normalize_detection_control_payload(payload)

    try:
        _ensure_unique_name(db, name=normalized["name"], rule_type=normalized["type"])
    except HTTPException:
        _conflict_failure(
            db,
            payload=payload,
            current_user=current_user,
            request=request,
            action="create",
        )
        raise

    now = utc_now()
    row = DetectionControlRule(
        id=f"dcr_{uuid.uuid4().hex}",
        rule_type=normalized["type"],
        name=normalized["name"],
        description=normalized["description"],
        scope=normalized["scope"],
        matcher_kind=normalized["matcher_kind"],
        matcher_value=normalized["matcher_value"],
        reason=normalized["reason"],
        owner=normalized["owner"],
        enabled=normalized["enabled"],
        status=normalized["status"],
        created_by=current_user.get("username"),
        updated_by=current_user.get("username"),
        created_at=now,
        updated_at=now,
        last_validation_status=validation.severity,
        last_validation_message=_validation_message(validation),
        metadata_json=json.dumps(normalized["metadata"], sort_keys=True),
    )

    db.add(row)
    db.flush()

    record_detection_control_audit(
        db,
        event_type="DETECTION_CONTROL_RULE_CREATED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        target_id=row.id,
        details={
            "action": "create",
            "after": _rule_audit_summary(row),
            "validation": validation.model_dump(mode="json"),
        },
    )
    db.commit()
    db.refresh(row)

    return {
        "rule": serialize_detection_control_rule(row),
        "validation": validation.model_dump(mode="json"),
    }


def update_detection_control_rule(
    db,
    *,
    rule_id: str,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_detection_control_rule(db, rule_id)
    before = _rule_audit_summary(row)

    current_payload = {
        "name": row.name,
        "type": row.rule_type,
        "status": row.status,
        "scope": row.scope,
        "matcher_kind": row.matcher_kind,
        "matcher_value": row.matcher_value,
        "reason": row.reason,
        "owner": row.owner,
        "enabled": row.enabled,
        "description": row.description,
        "metadata": _metadata(row.metadata_json),
    }
    current_payload.update(payload)

    validation = validate_detection_control_payload(current_payload)

    if not validation.valid:
        _validation_failure(
            db,
            payload=current_payload,
            validation=validation,
            current_user=current_user,
            request=request,
            action="update",
            target_id=row.id,
        )
        raise HTTPException(
            status_code=400,
            detail={"message": "Validation failed.", "validation": validation.model_dump(mode="json")},
        )

    normalized = normalize_detection_control_payload(current_payload)
    try:
        _ensure_unique_name(
            db,
            name=normalized["name"],
            rule_type=normalized["type"],
            exclude_id=row.id,
        )
    except HTTPException:
        _conflict_failure(
            db,
            payload=current_payload,
            current_user=current_user,
            request=request,
            action="update",
            target_id=row.id,
        )
        raise

    row.rule_type = normalized["type"]
    row.name = normalized["name"]
    row.description = normalized["description"]
    row.scope = normalized["scope"]
    row.matcher_kind = normalized["matcher_kind"]
    row.matcher_value = normalized["matcher_value"]
    row.reason = normalized["reason"]
    row.owner = normalized["owner"]
    row.enabled = normalized["enabled"]
    row.status = normalized["status"]
    row.updated_by = current_user.get("username")
    row.updated_at = utc_now()
    row.last_validation_status = validation.severity
    row.last_validation_message = _validation_message(validation)
    row.metadata_json = json.dumps(normalized["metadata"], sort_keys=True)

    db.flush()

    record_detection_control_audit(
        db,
        event_type="DETECTION_CONTROL_RULE_UPDATED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        target_id=row.id,
        details={
            "action": "update",
            "before": before,
            "after": _rule_audit_summary(row),
            "validation": validation.model_dump(mode="json"),
        },
    )
    db.commit()
    db.refresh(row)

    return {
        "rule": serialize_detection_control_rule(row),
        "validation": validation.model_dump(mode="json"),
    }


def set_detection_control_rule_enabled(
    db,
    *,
    rule_id: str,
    enabled: bool,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_detection_control_rule(db, rule_id)
    before = _rule_audit_summary(row)

    row.enabled = enabled
    row.status = "ACTIVE" if enabled else "DISABLED"
    row.updated_by = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    record_detection_control_audit(
        db,
        event_type=(
            "DETECTION_CONTROL_RULE_ENABLED"
            if enabled
            else "DETECTION_CONTROL_RULE_DISABLED"
        ),
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        target_id=row.id,
        details={
            "action": "enable" if enabled else "disable",
            "before": before,
            "after": _rule_audit_summary(row),
        },
    )
    db.commit()
    db.refresh(row)

    return {"rule": serialize_detection_control_rule(row)}


def validate_existing_detection_control_rule(
    db,
    *,
    rule_id: str,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_detection_control_rule(db, rule_id)
    before = _rule_audit_summary(row)
    payload = serialize_detection_control_rule(row)
    validation = validate_detection_control_payload(payload)

    row.last_validation_status = validation.severity
    row.last_validation_message = _validation_message(validation)

    if validation.valid:
        if row.enabled and row.status in {"FAILED_VALIDATION", "DISABLED"}:
            row.status = "ACTIVE"
    else:
        row.status = "FAILED_VALIDATION"

    row.updated_by = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    record_detection_control_audit(
        db,
        event_type="DETECTION_CONTROL_RULE_VALIDATED",
        outcome="SUCCESS" if validation.valid else "FAILURE",
        current_user=current_user,
        request=request,
        target_id=row.id,
        details={
            "action": "validate",
            "before": before,
            "after": _rule_audit_summary(row),
            "validation": validation.model_dump(mode="json"),
        },
    )
    db.commit()
    db.refresh(row)

    return {
        "rule": serialize_detection_control_rule(row),
        "validation": validation.model_dump(mode="json"),
    }


def archive_detection_control_rule(
    db,
    *,
    rule_id: str,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_detection_control_rule(db, rule_id)
    before = _rule_audit_summary(row)

    row.deleted_at = utc_now()
    row.enabled = False
    row.status = "DISABLED"
    row.updated_by = current_user.get("username")
    row.updated_at = utc_now()
    db.flush()

    record_detection_control_audit(
        db,
        event_type="DETECTION_CONTROL_RULE_ARCHIVED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        target_id=row.id,
        details={
            "action": "archive",
            "before": before,
            "after": _rule_audit_summary(row),
        },
    )
    db.commit()

    return {"status": "archived", "rule_id": rule_id}
