from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from database import SessionLocal
from detection_control_plane import (
    archive_detection_control_rule,
    create_detection_control_rule,
    detection_control_summary,
    ensure_admin,
    get_detection_control_rule,
    list_detection_control_rules,
    serialize_detection_control_rule,
    set_detection_control_rule_enabled,
    update_detection_control_rule,
    validate_existing_detection_control_rule,
)
from detection_control_inventory import get_detection_control_inventory


router = APIRouter(tags=["Detection Control"])


class DetectionControlRulePayload(BaseModel):
    name: str | None = None
    type: str | None = None
    status: str | None = None
    scope: str | None = None
    matcher_kind: str | None = None
    matcher_value: str | None = None
    pattern: str | None = None
    reason: str | None = None
    owner: str | None = None
    enabled: bool | None = None
    description: str | None = None
    metadata: Any = Field(default_factory=dict)


def _current_user(request: Request) -> dict:
    return getattr(request.state, "current_user", None) or {}


@router.get("/settings/detection-control")
def detection_control_inventory():
    return get_detection_control_inventory()


@router.get("/detection-control/rules")
def detection_control_rules(request: Request):
    db = SessionLocal()

    try:
        items = list_detection_control_rules(db)

        return {
            "items": items,
            "summary": detection_control_summary(items),
            "rbac": {
                "role": _current_user(request).get("role"),
                "can_write": _current_user(request).get("role") == "ADMIN",
            },
        }
    finally:
        db.close()


@router.get("/detection-control/rules/{rule_id}")
def detection_control_rule(rule_id: str):
    db = SessionLocal()

    try:
        return serialize_detection_control_rule(get_detection_control_rule(db, rule_id))
    finally:
        db.close()


@router.post("/detection-control/rules")
def create_managed_detection_control_rule(
    payload: DetectionControlRulePayload,
    request: Request,
):
    current_user = _current_user(request)
    ensure_admin(current_user)

    db = SessionLocal()

    try:
        return create_detection_control_rule(
            db,
            payload=payload.model_dump(exclude_unset=True),
            current_user=current_user,
            request=request,
        )
    finally:
        db.close()


@router.patch("/detection-control/rules/{rule_id}")
def update_managed_detection_control_rule(
    rule_id: str,
    payload: DetectionControlRulePayload,
    request: Request,
):
    current_user = _current_user(request)
    ensure_admin(current_user)

    db = SessionLocal()

    try:
        return update_detection_control_rule(
            db,
            rule_id=rule_id,
            payload=payload.model_dump(exclude_unset=True),
            current_user=current_user,
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/rules/{rule_id}/enable")
def enable_managed_detection_control_rule(rule_id: str, request: Request):
    current_user = _current_user(request)
    ensure_admin(current_user)

    db = SessionLocal()

    try:
        return set_detection_control_rule_enabled(
            db,
            rule_id=rule_id,
            enabled=True,
            current_user=current_user,
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/rules/{rule_id}/disable")
def disable_managed_detection_control_rule(rule_id: str, request: Request):
    current_user = _current_user(request)
    ensure_admin(current_user)

    db = SessionLocal()

    try:
        return set_detection_control_rule_enabled(
            db,
            rule_id=rule_id,
            enabled=False,
            current_user=current_user,
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/rules/{rule_id}/validate")
def validate_managed_detection_control_rule(rule_id: str, request: Request):
    current_user = _current_user(request)
    ensure_admin(current_user)

    db = SessionLocal()

    try:
        return validate_existing_detection_control_rule(
            db,
            rule_id=rule_id,
            current_user=current_user,
            request=request,
        )
    finally:
        db.close()


@router.delete("/detection-control/rules/{rule_id}")
def archive_managed_detection_control_rule(rule_id: str, request: Request):
    current_user = _current_user(request)
    ensure_admin(current_user)

    db = SessionLocal()

    try:
        return archive_detection_control_rule(
            db,
            rule_id=rule_id,
            current_user=current_user,
            request=request,
        )
    finally:
        db.close()
