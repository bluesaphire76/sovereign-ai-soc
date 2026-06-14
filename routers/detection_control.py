from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from database import SessionLocal
from detection_config_versioning import (
    SUPPORTED_CONFIG_DOMAINS,
    apply_config_payload,
    diff_config_payload,
    ensure_baseline_versions,
    get_active_version,
    get_version,
    list_versions,
    record_detection_config_audit,
    rollback_config_version,
    validate_config_payload,
    version_to_dict,
)
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


class DetectionConfigPayload(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)


class DetectionConfigApplyRequest(BaseModel):
    items: list[dict[str, Any]] = Field(default_factory=list)
    reason: str | None = None


class DetectionConfigRollbackRequest(BaseModel):
    version_number: int
    reason: str | None = None


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


@router.get("/detection-control/config-versions")
def detection_config_versions(request: Request):
    db = SessionLocal()

    try:
        ensure_baseline_versions(db, current_user=_current_user(request))

        return {
            "items": list_versions(db),
            "domains": sorted(SUPPORTED_CONFIG_DOMAINS),
        }
    finally:
        db.close()


@router.get("/detection-control/config-versions/{config_domain}")
def detection_config_domain_versions(config_domain: str, request: Request):
    db = SessionLocal()

    try:
        ensure_baseline_versions(db, current_user=_current_user(request))

        return {
            "items": list_versions(db, config_domain=config_domain),
            "domains": sorted(SUPPORTED_CONFIG_DOMAINS),
        }
    finally:
        db.close()


@router.get("/detection-control/config-versions/{config_domain}/active")
def active_detection_config_version(config_domain: str, request: Request):
    db = SessionLocal()

    try:
        ensure_baseline_versions(db, current_user=_current_user(request))
        active = get_active_version(db, config_domain)

        if not active:
            return None

        return version_to_dict(active)
    finally:
        db.close()


@router.get("/detection-control/config-versions/{config_domain}/{version_number}")
def detection_config_version(config_domain: str, version_number: int, request: Request):
    db = SessionLocal()

    try:
        ensure_baseline_versions(db, current_user=_current_user(request))

        return version_to_dict(get_version(db, config_domain, version_number))
    finally:
        db.close()


@router.post("/detection-control/config-versions/{config_domain}/validate")
def validate_detection_config(
    config_domain: str,
    payload: DetectionConfigPayload,
    request: Request,
):
    current_user = _current_user(request)
    db = SessionLocal()

    try:
        validation = validate_config_payload(config_domain, payload.model_dump())
        record_detection_config_audit(
            db,
            event_type="CONFIG_VALIDATION_RUN",
            outcome="SUCCESS" if validation["valid"] else "FAILURE",
            current_user=current_user,
            config_domain=config_domain,
            request=request,
            details={"validation": validation, "action": "validate"},
        )

        if not validation["valid"]:
            record_detection_config_audit(
                db,
                event_type="CONFIG_VALIDATION_FAILED",
                outcome="FAILURE",
                current_user=current_user,
                config_domain=config_domain,
                request=request,
                details={"validation": validation, "action": "validate"},
            )

        db.commit()

        return validation
    finally:
        db.close()


@router.post("/detection-control/config-versions/{config_domain}/diff")
def diff_detection_config(config_domain: str, payload: DetectionConfigPayload, request: Request):
    db = SessionLocal()

    try:
        ensure_baseline_versions(db, current_user=_current_user(request))
        diff = diff_config_payload(db, config_domain, payload.model_dump())
        record_detection_config_audit(
            db,
            event_type="CONFIG_DIFF_GENERATED",
            outcome="SUCCESS",
            current_user=_current_user(request),
            config_domain=config_domain,
            request=request,
            details={"diff_summary": diff["summary"], "action": "diff"},
        )
        db.commit()

        return diff
    finally:
        db.close()


@router.post("/detection-control/config-versions/{config_domain}/apply")
def apply_detection_config(
    config_domain: str,
    payload: DetectionConfigApplyRequest,
    request: Request,
):
    current_user = _current_user(request)
    ensure_admin(current_user)
    db = SessionLocal()

    try:
        ensure_baseline_versions(db, current_user=current_user)

        return apply_config_payload(
            db,
            config_domain=config_domain,
            payload={"items": payload.items},
            reason=payload.reason,
            current_user=current_user,
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/config-versions/{config_domain}/rollback")
def rollback_detection_config(
    config_domain: str,
    payload: DetectionConfigRollbackRequest,
    request: Request,
):
    current_user = _current_user(request)
    ensure_admin(current_user)
    db = SessionLocal()

    try:
        ensure_baseline_versions(db, current_user=current_user)

        return rollback_config_version(
            db,
            config_domain=config_domain,
            version_number=payload.version_number,
            reason=payload.reason,
            current_user=current_user,
            request=request,
        )
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
