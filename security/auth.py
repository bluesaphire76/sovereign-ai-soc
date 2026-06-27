from __future__ import annotations

from fastapi import Depends, Header, HTTPException

from auth_utils import decode_access_token
from database import SessionLocal
from models import AppUser


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


def get_current_user(authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.id == user_id).first()

        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User is inactive or no longer exists.")

        return serialize_user(user)
    finally:
        db.close()


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="ADMIN role required.")

    return current_user
