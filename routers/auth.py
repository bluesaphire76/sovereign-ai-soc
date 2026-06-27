from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from auth_utils import create_access_token, verify_password
from database import SessionLocal
from models import AppUser
from schemas.auth import LoginRequest
from security.audit import write_security_audit
from security.auth import get_current_user
from services.users import normalize_username, serialize_user


router = APIRouter()


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request):
    username = normalize_username(payload.username)

    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.username == username).first()

        if not user or not verify_password(payload.password, user.password_hash):
            write_security_audit(
                event_type="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                target_type="USER",
                target_username=username,
                request=request,
                details={"reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        if not user.is_active:
            write_security_audit(
                event_type="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                target_type="USER",
                target_id=user.id,
                target_username=user.username,
                request=request,
                details={"reason": "disabled_account"},
            )
            raise HTTPException(status_code=403, detail="User account is disabled.")

        user.last_login_at = datetime.now(timezone.utc)
        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)

        token = create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role,
        )

        write_security_audit(
            event_type="AUTH_LOGIN_SUCCESS",
            outcome="SUCCESS",
            current_user=serialize_user(user),
            target_type="USER",
            target_id=user.id,
            target_username=user.username,
            request=request,
        )

        return {
            **token,
            "user": serialize_user(user),
        }
    finally:
        db.close()


@router.get("/auth/me")
def auth_me(current_user: dict = Depends(get_current_user)):
    return current_user
