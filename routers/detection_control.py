from typing import Any

from fastapi import APIRouter, Query, Request
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
from detection_control_semantic_context import (
    DetectionControlSemanticContextRequest,
    build_detection_control_semantic_context,
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
from detection_operations import (
    extend_review,
    list_operation_items,
    mark_reviewed,
    match_preview,
    matched_events_for_item,
    operations_overview,
    get_operation_item_summary,
)
from detection_control_inventory import get_detection_control_inventory
from detection_rule_lifecycle import (
    apply_lifecycle_item,
    approve_lifecycle_item,
    clone_lifecycle_item,
    create_lifecycle_item,
    delete_lifecycle_draft,
    disable_lifecycle_item,
    get_lifecycle_item,
    lifecycle_item_diff,
    lifecycle_item_history,
    list_lifecycle_items,
    reject_lifecycle_item,
    return_lifecycle_item_to_draft,
    serialize_lifecycle_item,
    submit_lifecycle_item,
    update_lifecycle_item,
    validate_lifecycle_item,
)


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


class LifecycleItemPayload(BaseModel):
    policy_type: str | None = None
    rule_key: str | None = None
    title: str | None = None
    description: str | None = None
    business_reason: str | None = None
    owner: str | None = None
    source_system: str | None = None
    content_json: Any = Field(default_factory=dict)
    expires_at: str | None = None
    risk_note: str | None = None


class LifecycleCommentRequest(BaseModel):
    comment: str | None = None


class LifecycleApprovalRequest(BaseModel):
    approval_comment: str | None = None


class LifecycleRejectRequest(BaseModel):
    rejection_reason: str | None = None


class LifecycleDisableRequest(BaseModel):
    disable_reason: str | None = None


class DetectionOperationMatchPreviewRequest(BaseModel):
    name: str | None = None
    type: str | None = None
    scope: str | None = None
    matcher_kind: str | None = None
    matcher_value: str | None = None
    content_json: Any = Field(default_factory=dict)
    metadata: Any = Field(default_factory=dict)
    limit: int | None = Field(default=25, ge=1, le=100)
    scan_limit: int | None = Field(default=500, ge=1, le=2000)


class DetectionOperationExtendReviewRequest(BaseModel):
    expires_at: str
    reason: str | None = None


class DetectionOperationMarkReviewedRequest(BaseModel):
    review_status: str | None = None
    review_notes: str | None = None


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


@router.get("/detection-control/lifecycle/items")
def detection_lifecycle_items(
    policy_type: str | None = Query(default=None),
    state: str | None = Query(default=None),
    source_system: str | None = Query(default=None),
    validation_status: str | None = Query(default=None),
    owner: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
):
    db = SessionLocal()

    try:
        return list_lifecycle_items(
            db,
            policy_type=policy_type,
            state=state,
            source_system=source_system,
            validation_status=validation_status,
            owner=owner,
            search=search,
            limit=limit,
        )
    finally:
        db.close()


@router.get("/detection-control/operations/overview")
def detection_operations_summary(request: Request):
    db = SessionLocal()

    try:
        return operations_overview(db, current_user=_current_user(request))
    finally:
        db.close()


@router.get("/detection-control/operations/noise-suppression")
def detection_operations_noise_suppression(
    status: str | None = Query(default=None),
    scope_classification: str | None = Query(default=None),
    review_status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
):
    db = SessionLocal()

    try:
        return list_operation_items(
            db,
            item_type="NOISE_SUPPRESSION",
            status=status,
            scope_classification=scope_classification,
            review_status=review_status,
            search=search,
            limit=limit,
        )
    finally:
        db.close()


@router.get("/detection-control/operations/exceptions")
def detection_operations_exceptions(
    status: str | None = Query(default=None),
    scope_classification: str | None = Query(default=None),
    review_status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
):
    db = SessionLocal()

    try:
        return list_operation_items(
            db,
            item_type="EXCEPTION",
            status=status,
            scope_classification=scope_classification,
            review_status=review_status,
            search=search,
            limit=limit,
        )
    finally:
        db.close()


@router.get("/detection-control/operations/rules")
def detection_operations_rules(
    status: str | None = Query(default=None),
    scope_classification: str | None = Query(default=None),
    review_status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=500),
):
    db = SessionLocal()

    try:
        return list_operation_items(
            db,
            item_type="DETECTION_RULE",
            status=status,
            scope_classification=scope_classification,
            review_status=review_status,
            search=search,
            limit=limit,
        )
    finally:
        db.close()


@router.get("/detection-control/operations/items/{item_id}/summary")
def detection_operations_item_summary(item_id: str):
    db = SessionLocal()

    try:
        return get_operation_item_summary(db, item_id=item_id)
    finally:
        db.close()


@router.get("/detection-control/operations/items/{item_id}/matched-events")
def detection_operations_item_matches(
    item_id: str,
    limit: int = Query(default=25, ge=1, le=100),
    scan_limit: int = Query(default=1000, ge=1, le=2000),
):
    db = SessionLocal()

    try:
        return matched_events_for_item(
            db,
            item_id=item_id,
            limit=limit,
            scan_limit=scan_limit,
        )
    finally:
        db.close()


@router.post("/detection-control/operations/match-preview")
def detection_operations_match_preview(
    payload: DetectionOperationMatchPreviewRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return match_preview(
            db,
            payload=payload.model_dump(exclude_unset=True),
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/operations/items/{item_id}/extend-review")
def detection_operations_extend_review(
    item_id: str,
    payload: DetectionOperationExtendReviewRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return extend_review(
            db,
            item_id=item_id,
            expires_at=payload.expires_at,
            reason=payload.reason,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/operations/items/{item_id}/mark-reviewed")
def detection_operations_mark_reviewed(
    item_id: str,
    payload: DetectionOperationMarkReviewedRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return mark_reviewed(
            db,
            item_id=item_id,
            review_status=payload.review_status,
            review_notes=payload.review_notes,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/semantic-context")
def detection_control_semantic_context(
    payload: DetectionControlSemanticContextRequest,
    limit: int = Query(default=4, ge=1, le=8),
):
    return build_detection_control_semantic_context(payload, limit=limit)


@router.post("/detection-control/lifecycle/items")
def create_detection_lifecycle_item(payload: LifecycleItemPayload, request: Request):
    db = SessionLocal()

    try:
        return create_lifecycle_item(
            db,
            payload=payload.model_dump(exclude_unset=True),
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.get("/detection-control/lifecycle/items/{item_id}")
def detection_lifecycle_item(item_id: int):
    db = SessionLocal()

    try:
        return serialize_lifecycle_item(get_lifecycle_item(db, item_id))
    finally:
        db.close()


@router.patch("/detection-control/lifecycle/items/{item_id}")
def update_detection_lifecycle_item(item_id: int, payload: LifecycleItemPayload, request: Request):
    db = SessionLocal()

    try:
        return update_lifecycle_item(
            db,
            item_id=item_id,
            payload=payload.model_dump(exclude_unset=True),
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.delete("/detection-control/lifecycle/items/{item_id}")
def delete_detection_lifecycle_item(item_id: int, request: Request):
    db = SessionLocal()

    try:
        return delete_lifecycle_draft(
            db,
            item_id=item_id,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/lifecycle/items/{item_id}/validate")
def validate_detection_lifecycle_item(item_id: int, request: Request):
    db = SessionLocal()

    try:
        return validate_lifecycle_item(
            db,
            item_id=item_id,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/lifecycle/items/{item_id}/submit")
def submit_detection_lifecycle_item(
    item_id: int,
    payload: LifecycleCommentRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return submit_lifecycle_item(
            db,
            item_id=item_id,
            comment=payload.comment,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/lifecycle/items/{item_id}/approve")
def approve_detection_lifecycle_item(
    item_id: int,
    payload: LifecycleApprovalRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return approve_lifecycle_item(
            db,
            item_id=item_id,
            approval_comment=payload.approval_comment,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/lifecycle/items/{item_id}/reject")
def reject_detection_lifecycle_item(
    item_id: int,
    payload: LifecycleRejectRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return reject_lifecycle_item(
            db,
            item_id=item_id,
            rejection_reason=payload.rejection_reason,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/lifecycle/items/{item_id}/return-to-draft")
def return_detection_lifecycle_item_to_draft(
    item_id: int,
    payload: LifecycleCommentRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return return_lifecycle_item_to_draft(
            db,
            item_id=item_id,
            comment=payload.comment,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/lifecycle/items/{item_id}/apply")
def apply_detection_lifecycle_item(
    item_id: int,
    payload: LifecycleCommentRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return apply_lifecycle_item(
            db,
            item_id=item_id,
            comment=payload.comment,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/lifecycle/items/{item_id}/disable")
def disable_detection_lifecycle_item(
    item_id: int,
    payload: LifecycleDisableRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return disable_lifecycle_item(
            db,
            item_id=item_id,
            disable_reason=payload.disable_reason,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/detection-control/lifecycle/items/{item_id}/clone")
def clone_detection_lifecycle_item(item_id: int, request: Request):
    db = SessionLocal()

    try:
        return clone_lifecycle_item(
            db,
            item_id=item_id,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.get("/detection-control/lifecycle/items/{item_id}/history")
def detection_lifecycle_item_history(item_id: int):
    db = SessionLocal()

    try:
        return lifecycle_item_history(db, item_id=item_id)
    finally:
        db.close()


@router.get("/detection-control/lifecycle/items/{item_id}/diff")
def detection_lifecycle_item_diff(item_id: int):
    db = SessionLocal()

    try:
        return lifecycle_item_diff(db, item_id=item_id)
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
