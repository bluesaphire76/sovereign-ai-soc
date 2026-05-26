from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any


ACTIVE_USER_WINDOW_SECONDS = int(os.getenv("ACTIVE_USER_WINDOW_SECONDS", "300"))
ACTIVE_USER_RETENTION_SECONDS = int(os.getenv("ACTIVE_USER_RETENTION_SECONDS", "3600"))

_LOCK = threading.Lock()
_ACTIVE_USERS: dict[str, dict[str, Any]] = {}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_role(value: Any) -> str:
    role = str(value or "UNKNOWN").upper().strip()
    if role in {"ADMIN", "ANALYST", "VIEWER"}:
        return role
    return "UNKNOWN"


def _user_key(current_user: dict[str, Any]) -> str:
    value = current_user.get("id") or current_user.get("username") or current_user.get("sub")
    return str(value or "unknown")


def mark_active_user(current_user: dict[str, Any]) -> None:
    if not current_user:
        return

    now = _now_utc()
    key = _user_key(current_user)

    with _LOCK:
        _ACTIVE_USERS[key] = {
            "last_seen_at": now,
            "role": _normalize_role(current_user.get("role")),
        }

        retention_cutoff = now - timedelta(seconds=ACTIVE_USER_RETENTION_SECONDS)
        stale_keys = [
            item_key
            for item_key, item in _ACTIVE_USERS.items()
            if item.get("last_seen_at", retention_cutoff) < retention_cutoff
        ]

        for item_key in stale_keys:
            _ACTIVE_USERS.pop(item_key, None)


def get_active_users_snapshot(window_seconds: int | None = None) -> dict[str, Any]:
    window = int(window_seconds or ACTIVE_USER_WINDOW_SECONDS)
    now = _now_utc()
    cutoff = now - timedelta(seconds=window)

    roles = {
        "ADMIN": 0,
        "ANALYST": 0,
        "VIEWER": 0,
        "UNKNOWN": 0,
    }

    with _LOCK:
        active_items = [
            item
            for item in _ACTIVE_USERS.values()
            if item.get("last_seen_at", cutoff) >= cutoff
        ]

    for item in active_items:
        role = _normalize_role(item.get("role"))
        roles[role] = roles.get(role, 0) + 1

    return {
        "count": len(active_items),
        "window_seconds": window,
        "roles": roles,
        "checked_at": now.isoformat(),
    }
