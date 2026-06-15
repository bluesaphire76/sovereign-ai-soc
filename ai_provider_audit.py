from __future__ import annotations

import json
from typing import Any

from database import SessionLocal
from models import SecurityAuditEvent


SENSITIVE_DETAIL_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "password",
    "prompt",
    "raw_prompt",
    "raw_response",
    "response",
    "secret",
    "token",
}


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SENSITIVE_DETAIL_KEYS:
                sanitized[str(key)] = "[REDACTED]"
            else:
                sanitized[str(key)] = _sanitize(item)
        return sanitized

    if isinstance(value, list):
        return [_sanitize(item) for item in value]

    return value


def record_ai_provider_audit(
    *,
    event_type: str,
    outcome: str,
    provider_key: str,
    provider_type: str,
    feature: str,
    model: str | None,
    external: bool,
    redaction_mode: str,
    redaction_applied: bool,
    input_character_count_after_redaction: int | None,
    output_character_count: int | None,
    latency_ms: int | None,
    fallback_used: bool,
    safe_error: str | None,
    current_user: dict[str, Any] | None = None,
    incident_id: int | str | None = None,
    case_id: int | str | None = None,
    request_metadata: dict[str, Any] | None = None,
) -> None:
    db = SessionLocal()
    details = {
        "provider_key": provider_key,
        "provider_type": provider_type,
        "feature": feature,
        "model": model,
        "external": external,
        "redaction_mode": redaction_mode,
        "redaction_applied": redaction_applied,
        "input_character_count_after_redaction": input_character_count_after_redaction,
        "output_character_count": output_character_count,
        "latency_ms": latency_ms,
        "fallback_used": fallback_used,
        "safe_error": safe_error,
        "incident_id": incident_id,
        "case_id": case_id,
        "request_metadata": request_metadata or {},
    }

    try:
        db.add(
            SecurityAuditEvent(
                event_type=event_type,
                outcome=outcome,
                actor_user_id=(current_user or {}).get("id"),
                actor_username=(current_user or {}).get("username"),
                actor_role=(current_user or {}).get("role"),
                target_type="AI_PROVIDER",
                target_id=provider_key,
                details_json=json.dumps(_sanitize(details), default=str, sort_keys=True),
            )
        )
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()
