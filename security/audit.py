from __future__ import annotations

import json

from fastapi import Request

from database import SessionLocal
from models import SecurityAuditEvent


SENSITIVE_AUDIT_KEYS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "authorization",
}


def sanitize_audit_details(value):
    if isinstance(value, dict):
        sanitized = {}

        for key, item in value.items():
            if str(key).lower() in SENSITIVE_AUDIT_KEYS:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_audit_details(item)

        return sanitized

    if isinstance(value, list):
        return [sanitize_audit_details(item) for item in value]

    return value


def request_client_ip(request: Request | None) -> str | None:
    if request is None:
        return None

    forwarded_for = request.headers.get("x-forwarded-for")

    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    if request.client:
        return request.client.host

    return None


def write_security_audit(
    *,
    event_type: str,
    outcome: str,
    current_user: dict | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    target_username: str | None = None,
    request: Request | None = None,
    details: dict | None = None,
):
    audit_db = SessionLocal()

    try:
        audit_db.add(
            SecurityAuditEvent(
                event_type=event_type,
                outcome=outcome,
                actor_user_id=current_user.get("id") if current_user else None,
                actor_username=current_user.get("username") if current_user else None,
                actor_role=current_user.get("role") if current_user else None,
                target_type=target_type,
                target_id=str(target_id) if target_id is not None else None,
                target_username=target_username,
                method=request.method if request else None,
                path=request.url.path if request else None,
                client_ip=request_client_ip(request),
                user_agent=request.headers.get("user-agent") if request else None,
                details_json=json.dumps(
                    sanitize_audit_details(details or {}),
                    default=str,
                    sort_keys=True,
                ),
            )
        )
        audit_db.commit()
    except Exception:
        audit_db.rollback()
    finally:
        audit_db.close()


def security_audit_actor(request: Request) -> dict | None:
    return getattr(request.state, "current_user", None)
