from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from auth_utils import hash_password
from models import AppUser


VALID_USER_ROLES = {
    "ADMIN",
    "ANALYST",
    "VIEWER",
}

LAST_ADMIN_MESSAGE = "At least one enabled administrator must remain."


def lock_user_management(db: Session) -> None:
    """Serialize account writes before reading users; release at commit/rollback."""
    dialect = db.get_bind().dialect.name
    try:
        if dialect == "postgresql":
            # A fresh snapshot after waiting is essential for the count below.
            db.connection(execution_options={"isolation_level": "READ COMMITTED"})
            db.execute(text("SET LOCAL lock_timeout = '5s'"))
            db.execute(text("LOCK TABLE app_users IN SHARE ROW EXCLUSIVE MODE"))
        elif dialect == "sqlite":
            db.execute(text("BEGIN IMMEDIATE"))
        else:
            raise HTTPException(status_code=503, detail="User management unavailable.")
    except OperationalError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail="User management is busy. Please retry.") from exc


def ensure_enabled_administrator(db: Session) -> None:
    # SessionLocal disables autoflush: inspect the proposed persisted state.
    db.flush()
    if not db.query(AppUser.id).filter(
        AppUser.role == "ADMIN", AppUser.is_active.is_(True)
    ).first():
        raise HTTPException(status_code=409, detail=LAST_ADMIN_MESSAGE)


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
