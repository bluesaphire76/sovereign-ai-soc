from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from database import SessionLocal
from models import AppUser
from schemas.users import UserCreate, UserPasswordUpdate, UserUpdate
from security.audit import write_security_audit
from security.auth import get_current_user, require_admin
from security.rbac import ROLE_ADMIN, current_user_role
from services.users import (
    VALID_USER_ROLES,
    hash_password_or_400,
    normalize_username,
    serialize_user,
)


router = APIRouter()


@router.get("/users")
def list_users(current_user: dict = Depends(get_current_user)):
    db = SessionLocal()

    try:
        if current_user_role(current_user) == ROLE_ADMIN:
            users = db.query(AppUser).order_by(AppUser.username.asc()).all()
        else:
            users = (
                db.query(AppUser)
                .filter(AppUser.id == current_user["id"])
                .order_by(AppUser.username.asc())
                .all()
            )

        return {
            "items": [serialize_user(user) for user in users],
        }
    finally:
        db.close()


@router.post("/users")
def create_user(payload: UserCreate, request: Request, current_user: dict = Depends(require_admin)):
    username = normalize_username(payload.username)

    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    role = payload.role.upper().strip()

    if role not in VALID_USER_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Allowed: {sorted(VALID_USER_ROLES)}")

    db = SessionLocal()

    try:
        existing = db.query(AppUser).filter(AppUser.username == username).first()

        if existing:
            raise HTTPException(status_code=409, detail="Username already exists.")

        user = AppUser(
            username=username,
            display_name=payload.display_name,
            role=role,
            password_hash=hash_password_or_400(payload.password),
            is_active=payload.is_active,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        write_security_audit(
            event_type="USER_CREATED",
            outcome="SUCCESS",
            current_user=current_user,
            target_type="USER",
            target_id=user.id,
            target_username=user.username,
            request=request,
            details={
                "role": user.role,
                "is_active": user.is_active,
            },
        )

        return serialize_user(user)
    finally:
        db.close()


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    current_user: dict = Depends(require_admin),
):
    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.id == user_id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        changes = {}

        if payload.display_name is not None and user.display_name != payload.display_name:
            changes["display_name"] = [user.display_name, payload.display_name]
            user.display_name = payload.display_name

        if payload.role is not None:
            role = payload.role.upper().strip()

            if role not in VALID_USER_ROLES:
                raise HTTPException(status_code=400, detail=f"Invalid role. Allowed: {sorted(VALID_USER_ROLES)}")

            if user.role != role:
                changes["role"] = [user.role, role]
                user.role = role

        if payload.is_active is not None:
            if user.id == current_user["id"] and payload.is_active is False:
                raise HTTPException(status_code=400, detail="You cannot disable your own account.")

            if user.is_active != payload.is_active:
                changes["is_active"] = [user.is_active, payload.is_active]
                user.is_active = payload.is_active

        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)

        if changes:
            write_security_audit(
                event_type="USER_UPDATED",
                outcome="SUCCESS",
                current_user=current_user,
                target_type="USER",
                target_id=user.id,
                target_username=user.username,
                request=request,
                details={"changes": changes},
            )

        return serialize_user(user)
    finally:
        db.close()


@router.post("/users/{user_id}/password")
def update_user_password(
    user_id: int,
    payload: UserPasswordUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.id == user_id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        if current_user_role(current_user) != ROLE_ADMIN and user.id != current_user["id"]:
            raise HTTPException(status_code=403, detail="You can reset only your own password.")

        user.password_hash = hash_password_or_400(payload.password)
        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)

        write_security_audit(
            event_type="USER_PASSWORD_RESET",
            outcome="SUCCESS",
            current_user=current_user,
            target_type="USER",
            target_id=user.id,
            target_username=user.username,
            request=request,
            details={
                "self_service": user.id == current_user["id"],
                "performed_by_role": current_user_role(current_user),
            },
        )

        return {
            "status": "password_updated",
            "user": serialize_user(user),
        }
    finally:
        db.close()


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, current_user: dict = Depends(require_admin)):
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.id == user_id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        deleted_username = user.username
        deleted_role = user.role
        deleted_is_active = user.is_active

        db.delete(user)
        db.commit()

        write_security_audit(
            event_type="USER_DELETED",
            outcome="SUCCESS",
            current_user=current_user,
            target_type="USER",
            target_id=user_id,
            target_username=deleted_username,
            request=request,
            details={
                "role": deleted_role,
                "is_active": deleted_is_active,
            },
        )

        return {
            "status": "deleted",
            "user_id": user_id,
        }
    finally:
        db.close()
