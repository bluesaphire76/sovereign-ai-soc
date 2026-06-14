from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException, Request
from sqlalchemy import func

from detection_control_plane import (
    _request_client_ip,
    _sanitize_audit_details,
    serialize_detection_control_rule,
)
from detection_control_validation import (
    ALLOWED_STATUSES,
    normalize_detection_control_payload,
    validate_detection_control_payload,
)
from models import DetectionConfigVersion, DetectionControlRule, SecurityAuditEvent


SUPPORTED_CONFIG_DOMAINS = {
    "noise_suppression",
    "exceptions",
    "detection_rules",
    "source_controls",
}

DOMAIN_RULE_TYPES = {
    "noise_suppression": {"NOISE_SUPPRESSION"},
    "exceptions": {"EXCEPTION"},
    "detection_rules": {"DETECTION_RULE"},
    "source_controls": {"SOURCE_POLICY", "TELEMETRY_SOURCE", "SERVICE_CONTROL"},
}

VERSION_STATUS_ACTIVE = "ACTIVE"
VERSION_STATUS_SUPERSEDED = "SUPERSEDED"
VERSION_STATUS_FAILED_VALIDATION = "FAILED_VALIDATION"

VERSION_FIELDS = [
    "id",
    "name",
    "type",
    "status",
    "scope",
    "matcher_kind",
    "matcher_value",
    "reason",
    "owner",
    "enabled",
    "description",
    "metadata",
]

ALLOWED_CONFIG_ITEM_FIELDS = set(VERSION_FIELDS) | {
    "rule_type",
    "pattern",
    "created_at",
    "updated_at",
    "created_by",
    "updated_by",
    "last_validation_status",
    "last_validation_message",
    "requires_apply",
    "affected_service",
    "restart_note",
}

SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "authorization",
    "secret",
    "api_key",
}

SENSITIVE_KEY_MARKERS = (
    "password",
    "token",
    "authorization",
    "secret",
    "api_key",
    "apikey",
    "private_key",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_config_domain(config_domain: str) -> str:
    normalized = str(config_domain or "").strip().lower()

    if normalized not in SUPPORTED_CONFIG_DOMAINS:
        raise HTTPException(
            status_code=404,
            detail=f"Unsupported config domain. Allowed: {sorted(SUPPORTED_CONFIG_DOMAINS)}",
        )

    return normalized


def domain_for_rule_type(rule_type: str) -> str:
    normalized = str(rule_type or "").strip().upper()

    for domain, rule_types in DOMAIN_RULE_TYPES.items():
        if normalized in rule_types:
            return domain

    return "source_controls"


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _json_dumps(value: Any) -> str:
    return json.dumps(value, default=str, sort_keys=True, separators=(",", ":"))


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _is_sensitive_key(key) else _redact(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_redact(item) for item in value]

    return value


def _is_sensitive_key(key: Any) -> bool:
    normalized = str(key).lower()

    return normalized in SENSITIVE_KEYS or any(marker in normalized for marker in SENSITIVE_KEY_MARKERS)


def _checksum(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_json_dumps(_redact(payload)).encode("utf-8")).hexdigest()


def _config_item_key(item: Mapping[str, Any]) -> str:
    item_id = str(item.get("id") or "").strip()

    if item_id:
        return item_id

    return f"{item.get('type')}:{item.get('name')}"


def _canonical_item(item: Mapping[str, Any], *, config_domain: str) -> dict[str, Any]:
    normalized = normalize_detection_control_payload(item)
    metadata = normalized["metadata"] if isinstance(normalized["metadata"], dict) else {}
    item_id = str(item.get("id") or "").strip()

    if not item_id:
        item_id = f"versioned:{config_domain}:{normalized['type']}:{normalized['name']}"

    return {
        "id": item_id,
        "name": normalized["name"],
        "type": normalized["type"],
        "status": normalized["status"],
        "scope": normalized["scope"],
        "matcher_kind": normalized["matcher_kind"],
        "matcher_value": normalized["matcher_value"],
        "reason": normalized["reason"],
        "owner": normalized["owner"],
        "enabled": bool(normalized["enabled"]),
        "description": normalized["description"],
        "metadata": _redact(metadata),
    }


def normalize_config_payload(config_domain: str, payload: Mapping[str, Any] | list[Any]) -> dict[str, Any]:
    domain = normalize_config_domain(config_domain)

    if isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, dict):
        raw_items = payload.get("items", [])
    else:
        raise HTTPException(status_code=400, detail="Config payload must be an object or list.")

    if not isinstance(raw_items, list):
        raise HTTPException(status_code=400, detail="Config payload items must be a list.")

    items = [
        _canonical_item(item, config_domain=domain)
        for item in raw_items
        if isinstance(item, dict)
    ]
    items.sort(key=lambda item: _config_item_key(item))

    return {
        "config_domain": domain,
        "items": items,
    }


def version_to_dict(row: DetectionConfigVersion, *, include_payload: bool = True) -> dict[str, Any]:
    payload = _json_loads(row.config_payload, {"items": []}) if include_payload else None
    diff_summary = _json_loads(row.diff_summary, None)

    result = {
        "id": row.id,
        "config_domain": row.config_domain,
        "version_number": row.version_number,
        "status": row.status,
        "config_checksum": row.config_checksum,
        "checksum_short": row.config_checksum[:12] if row.config_checksum else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "created_by": row.created_by,
        "created_reason": row.created_reason,
        "activated_at": row.activated_at.isoformat() if row.activated_at else None,
        "activated_by": row.activated_by,
        "validation_status": row.validation_status,
        "validation_errors": _json_loads(row.validation_errors, []),
        "validation_warnings": _json_loads(row.validation_warnings, []),
        "diff_summary": diff_summary,
        "rollback_of_version_id": row.rollback_of_version_id,
        "source_identifier": row.source_identifier,
        "requires_restart": row.config_domain in {"noise_suppression", "exceptions", "detection_rules"},
        "affected_services": affected_services_for_domain(row.config_domain),
    }

    if include_payload:
        result["config_payload"] = _redact(payload)

    return result


def affected_services_for_domain(config_domain: str) -> list[str]:
    domain = normalize_config_domain(config_domain)

    if domain in {"noise_suppression", "exceptions"}:
        return ["ai-soc-worker"]

    if domain == "detection_rules":
        return ["detection-source"]

    return []


def record_detection_config_audit(
    db,
    *,
    event_type: str,
    outcome: str,
    current_user: Mapping[str, Any] | None,
    config_domain: str,
    request: Request | None = None,
    target_id: str | int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    row = SecurityAuditEvent(
        event_type=event_type,
        outcome=outcome,
        actor_user_id=(current_user or {}).get("id"),
        actor_username=(current_user or {}).get("username"),
        actor_role=(current_user or {}).get("role"),
        target_type="DETECTION_CONFIG_VERSION",
        target_id=str(target_id) if target_id is not None else config_domain,
        method=request.method if request else None,
        path=request.url.path if request else None,
        client_ip=_request_client_ip(request),
        user_agent=request.headers.get("user-agent") if request else None,
        details_json=_json_dumps(_sanitize_audit_details(details or {})),
    )
    db.add(row)
    db.flush()


def _domain_rule_rows(db, config_domain: str) -> list[DetectionControlRule]:
    domain = normalize_config_domain(config_domain)

    return (
        db.query(DetectionControlRule)
        .filter(DetectionControlRule.deleted_at.is_(None))
        .filter(DetectionControlRule.rule_type.in_(DOMAIN_RULE_TYPES[domain]))
        .order_by(DetectionControlRule.name.asc(), DetectionControlRule.id.asc())
        .all()
    )


def current_config_payload(db, config_domain: str) -> dict[str, Any]:
    domain = normalize_config_domain(config_domain)

    return normalize_config_payload(
        domain,
        {"items": [serialize_detection_control_rule(row) for row in _domain_rule_rows(db, domain)]},
    )


def get_active_version(db, config_domain: str) -> DetectionConfigVersion | None:
    domain = normalize_config_domain(config_domain)

    return (
        db.query(DetectionConfigVersion)
        .filter(DetectionConfigVersion.config_domain == domain)
        .filter(DetectionConfigVersion.status == VERSION_STATUS_ACTIVE)
        .order_by(DetectionConfigVersion.version_number.desc())
        .first()
    )


def _next_version_number(db, config_domain: str) -> int:
    latest = (
        db.query(func.max(DetectionConfigVersion.version_number))
        .filter(DetectionConfigVersion.config_domain == config_domain)
        .scalar()
    )

    return int(latest or 0) + 1


def _create_version_row(
    db,
    *,
    config_domain: str,
    payload: Mapping[str, Any],
    status: str,
    current_user: Mapping[str, Any] | None,
    reason: str | None,
    validation: Mapping[str, Any],
    diff: Mapping[str, Any] | None = None,
    rollback_of_version_id: int | None = None,
) -> DetectionConfigVersion:
    now = utc_now()
    row = DetectionConfigVersion(
        config_domain=config_domain,
        version_number=_next_version_number(db, config_domain),
        status=status,
        config_payload=_json_dumps(payload),
        config_checksum=_checksum(payload),
        created_at=now,
        created_by=(current_user or {}).get("username") or "system",
        created_reason=reason,
        activated_at=now if status == VERSION_STATUS_ACTIVE else None,
        activated_by=(current_user or {}).get("username") if status == VERSION_STATUS_ACTIVE else None,
        validation_status=str(validation.get("severity") or "OK"),
        validation_errors=_json_dumps(validation.get("messages") or []),
        validation_warnings=_json_dumps(validation.get("warnings") or []),
        diff_summary=_json_dumps(diff) if diff is not None else None,
        rollback_of_version_id=rollback_of_version_id,
        source_identifier="detection_control_rules",
    )
    db.add(row)
    db.flush()
    return row


def ensure_baseline_versions(db, *, current_user: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
    created: list[dict[str, Any]] = []

    for config_domain in sorted(SUPPORTED_CONFIG_DOMAINS):
        active = get_active_version(db, config_domain)
        payload = current_config_payload(db, config_domain)
        checksum = _checksum(payload)

        if active and active.config_checksum == checksum:
            continue

        if active:
            continue

        validation = validate_config_payload(config_domain, payload)
        row = _create_version_row(
            db,
            config_domain=config_domain,
            payload=payload,
            status=VERSION_STATUS_ACTIVE,
            current_user=current_user,
            reason="Baseline import from current Detection Control Plane configuration.",
            validation=validation,
            diff=None,
        )
        record_detection_config_audit(
            db,
            event_type="CONFIG_VERSION_BASELINE_CREATED",
            outcome="SUCCESS",
            current_user=current_user,
            config_domain=config_domain,
            target_id=row.id,
            details={
                "version_number": row.version_number,
                "checksum": row.config_checksum,
            },
        )
        created.append(version_to_dict(row, include_payload=False))

    if created:
        db.commit()

    return created


def list_versions(db, *, config_domain: str | None = None) -> list[dict[str, Any]]:
    query = db.query(DetectionConfigVersion)

    if config_domain:
        query = query.filter(DetectionConfigVersion.config_domain == normalize_config_domain(config_domain))

    rows = (
        query.order_by(
            DetectionConfigVersion.config_domain.asc(),
            DetectionConfigVersion.version_number.desc(),
        )
        .all()
    )

    return [version_to_dict(row, include_payload=False) for row in rows]


def get_version(db, config_domain: str, version_number: int) -> DetectionConfigVersion:
    domain = normalize_config_domain(config_domain)
    row = (
        db.query(DetectionConfigVersion)
        .filter(DetectionConfigVersion.config_domain == domain)
        .filter(DetectionConfigVersion.version_number == version_number)
        .first()
    )

    if not row:
        raise HTTPException(status_code=404, detail="Detection config version not found.")

    return row


def validate_config_payload(config_domain: str, payload: Mapping[str, Any] | list[Any]) -> dict[str, Any]:
    domain = normalize_config_domain(config_domain)
    normalized_payload = normalize_config_payload(domain, payload)
    messages: list[str] = []
    warnings: list[str] = []
    seen_ids: set[str] = set()
    seen_names: set[str] = set()

    for raw_item in (payload if isinstance(payload, list) else payload.get("items", [])):
        if not isinstance(raw_item, dict):
            messages.append("Every config item must be an object.")
            continue

        unknown_fields = sorted(set(raw_item) - ALLOWED_CONFIG_ITEM_FIELDS)

        if unknown_fields:
            warnings.append(
                f"Item {raw_item.get('name') or raw_item.get('id') or 'unknown'} has unknown fields: {', '.join(unknown_fields)}."
            )

    for item in normalized_payload["items"]:
        item_id = str(item.get("id") or "").strip()
        name_key = f"{item.get('type')}:{str(item.get('name') or '').strip().lower()}"

        if item_id in seen_ids:
            messages.append(f"Duplicate rule identifier: {item_id}.")
        seen_ids.add(item_id)

        if name_key in seen_names:
            messages.append(f"Duplicate active rule name/type: {item.get('type')} / {item.get('name')}.")
        seen_names.add(name_key)

        if item.get("type") not in DOMAIN_RULE_TYPES[domain]:
            messages.append(
                f"Item {item.get('name') or item_id} type {item.get('type')} is not valid for {domain}."
            )

        if item.get("status") not in ALLOWED_STATUSES:
            messages.append(f"Item {item.get('name') or item_id} has invalid status.")

        item_validation = validate_detection_control_payload(item)
        messages.extend(item_validation.messages)
        warnings.extend(item_validation.warnings)

        expiry = item.get("metadata", {}).get("expires_at") if isinstance(item.get("metadata"), dict) else None

        if expiry:
            try:
                expires_at = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
                if expires_at < utc_now():
                    messages.append(f"Item {item.get('name') or item_id} expiry is in the past.")
            except ValueError:
                messages.append(f"Item {item.get('name') or item_id} has malformed expiry.")

    valid = len(messages) == 0

    return {
        "valid": valid,
        "severity": "ERROR" if messages else ("WARNING" if warnings else "OK"),
        "messages": messages,
        "warnings": warnings,
        "affected_services": affected_services_for_domain(domain),
        "requires_restart": bool(affected_services_for_domain(domain)),
    }


def diff_config_payload(db, config_domain: str, payload: Mapping[str, Any] | list[Any]) -> dict[str, Any]:
    domain = normalize_config_domain(config_domain)
    active = get_active_version(db, domain)
    before_payload = (
        _json_loads(active.config_payload, {"items": []})
        if active
        else {"config_domain": domain, "items": []}
    )
    after_payload = normalize_config_payload(domain, payload)
    before = {_config_item_key(item): item for item in before_payload.get("items", [])}
    after = {_config_item_key(item): item for item in after_payload.get("items", [])}
    added = []
    removed = []
    modified = []
    unchanged_count = 0

    for key, item in sorted(after.items()):
        if key not in before:
            added.append(_redact(item))
            continue

        changes = {}

        for field in VERSION_FIELDS:
            before_value = before[key].get(field)
            after_value = item.get(field)

            if before_value != after_value:
                changes[field] = {
                    "from": _redact(before_value),
                    "to": _redact(after_value),
                }

        if changes:
            modified.append(
                {
                    "rule_id": key,
                    "name": item.get("name"),
                    "type": item.get("type"),
                    "changes": changes,
                }
            )
        else:
            unchanged_count += 1

    for key, item in sorted(before.items()):
        if key not in after:
            removed.append(_redact(item))

    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "unchanged_count": unchanged_count,
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
        },
    }


def _sync_domain_rules(
    db,
    *,
    config_domain: str,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any] | None,
) -> None:
    domain = normalize_config_domain(config_domain)
    now = utc_now()
    payload_by_id = {item["id"]: item for item in payload.get("items", [])}
    rows = _domain_rule_rows(db, domain)
    rows_by_id = {row.id: row for row in rows}

    for row in rows:
        if row.id not in payload_by_id:
            row.deleted_at = now
            row.status = "DISABLED"
            row.enabled = False
            row.updated_at = now
            row.updated_by = (current_user or {}).get("username")

    for item_id, item in payload_by_id.items():
        row = rows_by_id.get(item_id)

        if not row:
            row = DetectionControlRule(
                id=item_id,
                created_at=now,
                created_by=(current_user or {}).get("username"),
            )
            db.add(row)

        row.rule_type = item["type"]
        row.name = item["name"]
        row.description = item.get("description")
        row.scope = item["scope"]
        row.matcher_kind = item["matcher_kind"]
        row.matcher_value = item["matcher_value"]
        row.reason = item["reason"]
        row.owner = item["owner"]
        row.enabled = bool(item["enabled"])
        row.status = item["status"]
        row.updated_by = (current_user or {}).get("username")
        row.updated_at = now
        row.deleted_at = None
        row.last_validation_status = "OK"
        row.last_validation_message = "Validation passed."
        row.metadata_json = _json_dumps(item.get("metadata") or {})

    db.flush()


def apply_config_payload(
    db,
    *,
    config_domain: str,
    payload: Mapping[str, Any] | list[Any],
    reason: str | None,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    domain = normalize_config_domain(config_domain)
    normalized_payload = normalize_config_payload(domain, payload)
    validation = validate_config_payload(domain, normalized_payload)

    record_detection_config_audit(
        db,
        event_type="CONFIG_VALIDATION_RUN",
        outcome="SUCCESS" if validation["valid"] else "FAILURE",
        current_user=current_user,
        config_domain=domain,
        request=request,
        details={"validation": validation, "action": "apply"},
    )

    if not validation["valid"]:
        record_detection_config_audit(
            db,
            event_type="CONFIG_VALIDATION_FAILED",
            outcome="FAILURE",
            current_user=current_user,
            config_domain=domain,
            request=request,
            details={"validation": validation, "action": "apply"},
        )
        db.commit()
        raise HTTPException(
            status_code=400,
            detail={"message": "Validation failed.", "validation": validation},
        )

    diff = diff_config_payload(db, domain, normalized_payload)

    record_detection_config_audit(
        db,
        event_type="CONFIG_DIFF_GENERATED",
        outcome="SUCCESS",
        current_user=current_user,
        config_domain=domain,
        request=request,
        details={"diff_summary": diff["summary"], "action": "apply"},
    )

    previous_active = get_active_version(db, domain)

    if previous_active:
        previous_active.status = VERSION_STATUS_SUPERSEDED

    _sync_domain_rules(
        db,
        config_domain=domain,
        payload=normalized_payload,
        current_user=current_user,
    )
    row = _create_version_row(
        db,
        config_domain=domain,
        payload=normalized_payload,
        status=VERSION_STATUS_ACTIVE,
        current_user=current_user,
        reason=reason,
        validation=validation,
        diff=diff,
    )

    record_detection_config_audit(
        db,
        event_type="CONFIG_VERSION_APPLIED",
        outcome="SUCCESS",
        current_user=current_user,
        config_domain=domain,
        request=request,
        target_id=row.id,
        details={
            "version_number": row.version_number,
            "previous_active_version": previous_active.version_number if previous_active else None,
            "diff_summary": diff["summary"],
            "requires_restart": validation["requires_restart"],
            "affected_services": validation["affected_services"],
        },
    )
    db.commit()
    db.refresh(row)

    return {
        "version": version_to_dict(row),
        "validation": validation,
        "diff": diff,
        "requires_restart": validation["requires_restart"],
        "affected_services": validation["affected_services"],
        "message": "Configuration applied. Restart may be required for changes to take effect."
        if validation["requires_restart"]
        else "Configuration applied.",
    }


def rollback_config_version(
    db,
    *,
    config_domain: str,
    version_number: int,
    reason: str | None,
    current_user: Mapping[str, Any],
    request: Request | None = None,
) -> dict[str, Any]:
    domain = normalize_config_domain(config_domain)
    target = get_version(db, domain, version_number)

    record_detection_config_audit(
        db,
        event_type="CONFIG_ROLLBACK_REQUESTED",
        outcome="REQUESTED",
        current_user=current_user,
        config_domain=domain,
        request=request,
        target_id=target.id,
        details={"target_version_number": target.version_number},
    )

    payload = _json_loads(target.config_payload, {"items": []})
    validation = validate_config_payload(domain, payload)

    if not validation["valid"]:
        record_detection_config_audit(
            db,
            event_type="CONFIG_ROLLBACK_FAILED",
            outcome="FAILURE",
            current_user=current_user,
            config_domain=domain,
            request=request,
            target_id=target.id,
            details={"validation": validation, "target_version_number": target.version_number},
        )
        db.commit()
        raise HTTPException(
            status_code=400,
            detail={"message": "Rollback target failed validation.", "validation": validation},
        )

    diff = diff_config_payload(db, domain, payload)
    previous_active = get_active_version(db, domain)

    if previous_active:
        previous_active.status = VERSION_STATUS_SUPERSEDED

    normalized_payload = normalize_config_payload(domain, payload)
    _sync_domain_rules(
        db,
        config_domain=domain,
        payload=normalized_payload,
        current_user=current_user,
    )
    row = _create_version_row(
        db,
        config_domain=domain,
        payload=normalized_payload,
        status=VERSION_STATUS_ACTIVE,
        current_user=current_user,
        reason=reason or f"Rollback to version {version_number}.",
        validation=validation,
        diff=diff,
        rollback_of_version_id=target.id,
    )

    record_detection_config_audit(
        db,
        event_type="CONFIG_ROLLBACK_COMPLETED",
        outcome="SUCCESS",
        current_user=current_user,
        config_domain=domain,
        request=request,
        target_id=row.id,
        details={
            "new_version_number": row.version_number,
            "rollback_of_version_id": target.id,
            "rollback_of_version_number": target.version_number,
            "previous_active_version": previous_active.version_number if previous_active else None,
            "diff_summary": diff["summary"],
            "requires_restart": validation["requires_restart"],
            "affected_services": validation["affected_services"],
        },
    )
    db.commit()
    db.refresh(row)

    return {
        "version": version_to_dict(row),
        "validation": validation,
        "diff": diff,
        "requires_restart": validation["requires_restart"],
        "affected_services": validation["affected_services"],
        "message": "Rollback applied. Restart may be required for changes to take effect."
        if validation["requires_restart"]
        else "Rollback applied.",
    }
