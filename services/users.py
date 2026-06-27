from __future__ import annotations

from fastapi import HTTPException

from auth_utils import hash_password
from models import AppUser


VALID_USER_ROLES = {
    "ADMIN",
    "ANALYST",
    "VIEWER",
}


def normalize_username(username: str) -> str:
    return username.strip().lower()


def hash_password_or_400(password: str) -> str:
    try:
        return hash_password(password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid request.")


def serialize_user(user: AppUser) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }
