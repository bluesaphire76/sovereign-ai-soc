import json

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from detection_rule_lifecycle import (
    STATE_ACTIVE,
    STATE_APPROVED,
    STATE_DISABLED,
    STATE_DRAFT,
    STATE_FAILED_VALIDATION,
    STATE_PROPOSED,
    approve_lifecycle_item,
    apply_lifecycle_item,
    clone_lifecycle_item,
    create_lifecycle_item,
    disable_lifecycle_item,
    lifecycle_item_history,
    reject_lifecycle_item,
    submit_lifecycle_item,
    validate_lifecycle_item,
)
from models import Base, DetectionControlRule, DetectionRuleLifecycleItem, SecurityAuditEvent


def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def admin():
    return {
        "id": 1,
        "username": "admin",
        "role": "ADMIN",
    }


def analyst():
    return {
        "id": 2,
        "username": "analyst",
        "role": "ANALYST",
    }


def viewer():
    return {
        "id": 3,
        "username": "viewer",
        "role": "VIEWER",
    }


def lifecycle_payload(**overrides):
    value = {
        "policy_type": "NOISE_SUPPRESSION",
        "title": "Suppress known operational sudo session noise",
        "description": "Suppress low-value PAM sudo session events for a known admin host.",
        "business_reason": "Known operational activity repeatedly creates low-severity noise.",
        "owner": "SOC",
        "source_system": "WAZUH",
        "content_json": {
            "source": "wazuh",
            "match": {
                "rule_group": "pam,sudo",
                "level_max": 3,
                "host": "atomicstar",
            },
            "action": "suppress",
            "scope": "specific_host",
        },
    }
    value.update(overrides)
    return value


def create_valid_draft(db, user=None):
    result = create_lifecycle_item(
        db,
        payload=lifecycle_payload(),
        current_user=user or admin(),
    )
    return result["item"]


def test_admin_and_analyst_can_create_drafts_but_viewer_cannot():
    db = db_session()

    try:
        admin_item = create_lifecycle_item(
            db,
            payload=lifecycle_payload(title="Admin draft"),
            current_user=admin(),
        )["item"]
        analyst_item = create_lifecycle_item(
            db,
            payload=lifecycle_payload(title="Analyst draft"),
            current_user=analyst(),
        )["item"]

        assert admin_item["state"] == STATE_DRAFT
        assert analyst_item["state"] == STATE_DRAFT

        with pytest.raises(HTTPException) as exc:
            create_lifecycle_item(
                db,
                payload=lifecycle_payload(title="Viewer draft"),
                current_user=viewer(),
            )

        assert exc.value.status_code == 403
        assert db.query(DetectionRuleLifecycleItem).count() == 2
        assert db.query(SecurityAuditEvent).filter(SecurityAuditEvent.event_type == "DETECTION_RULE_TRANSITION_DENIED").count() == 1
    finally:
        db.close()


def test_submit_runs_validation_and_invalid_item_becomes_failed_validation():
    db = db_session()

    try:
        item = create_lifecycle_item(
            db,
            payload=lifecycle_payload(
                title="Invalid broad suppression",
                content_json={
                    "source": "wazuh",
                    "match": {"host": "*"},
                    "action": "suppress",
                    "scope": "specific_host",
                },
            ),
            current_user=admin(),
        )["item"]

        with pytest.raises(HTTPException) as exc:
            submit_lifecycle_item(
                db,
                item_id=item["id"],
                comment="Ready for approval.",
                current_user=admin(),
            )

        assert exc.value.status_code == 400
        row = db.query(DetectionRuleLifecycleItem).filter(DetectionRuleLifecycleItem.id == item["id"]).one()
        assert row.state == STATE_FAILED_VALIDATION
        assert row.validation_status == "failed"
    finally:
        db.close()


def test_draft_can_validate_submit_and_admin_approve():
    db = db_session()

    try:
        item = create_valid_draft(db)
        validation = validate_lifecycle_item(db, item_id=item["id"], current_user=admin())

        assert validation["validation"]["valid"] is True
        assert validation["item"]["validation_status"] == "passed"

        submitted = submit_lifecycle_item(
            db,
            item_id=item["id"],
            comment="Ready for admin approval.",
            current_user=admin(),
        )["item"]

        assert submitted["state"] == STATE_PROPOSED

        approved = approve_lifecycle_item(
            db,
            item_id=item["id"],
            approval_comment="Reviewed and approved.",
            current_user=admin(),
        )["item"]

        assert approved["state"] == STATE_APPROVED

        events = [event.event_type for event in db.query(SecurityAuditEvent).all()]
        assert "DETECTION_RULE_VALIDATED" in events
        assert "DETECTION_RULE_SUBMITTED" in events
        assert "DETECTION_RULE_APPROVED" in events
    finally:
        db.close()


def test_analyst_cannot_approve_and_denial_is_audited():
    db = db_session()

    try:
        item = create_valid_draft(db)
        submit_lifecycle_item(
            db,
            item_id=item["id"],
            comment="Ready for admin approval.",
            current_user=admin(),
        )

        with pytest.raises(HTTPException) as exc:
            approve_lifecycle_item(
                db,
                item_id=item["id"],
                approval_comment="I approve.",
                current_user=analyst(),
            )

        assert exc.value.status_code == 403
        events = [event.event_type for event in db.query(SecurityAuditEvent).all()]
        assert "DETECTION_RULE_TRANSITION_DENIED" in events
    finally:
        db.close()


def test_approved_item_can_apply_and_disable_through_config_versioning():
    db = db_session()

    try:
        item = create_valid_draft(db)
        submit_lifecycle_item(db, item_id=item["id"], comment="Ready.", current_user=admin())
        approve_lifecycle_item(db, item_id=item["id"], approval_comment="Approved.", current_user=admin())

        applied = apply_lifecycle_item(
            db,
            item_id=item["id"],
            comment="Apply controlled lifecycle item.",
            current_user=admin(),
        )

        assert applied["state"] == STATE_ACTIVE
        assert applied["related_config_version_id"] == 1
        assert applied["restart_recommended"] is True
        assert applied["affected_services"] == ["ai-soc-worker"]

        rule = db.query(DetectionControlRule).one()
        assert rule.status == "ACTIVE"
        assert rule.rule_type == "NOISE_SUPPRESSION"

        disabled = disable_lifecycle_item(
            db,
            item_id=item["id"],
            disable_reason="Source tuning removed the need.",
            current_user=admin(),
        )

        assert disabled["state"] == STATE_DISABLED
        assert disabled["related_config_version_id"] == 2
        assert db.query(DetectionControlRule).one().status == "DISABLED"

        history = lifecycle_item_history(db, item_id=item["id"])
        assert [event["action"] for event in history["events"]] == [
            "created",
            "submitted",
            "approved",
            "applied",
            "disabled",
        ]
    finally:
        db.close()


def test_rejection_requires_reason_and_clone_creates_new_draft_version():
    db = db_session()

    try:
        item = create_valid_draft(db)
        submit_lifecycle_item(db, item_id=item["id"], comment="Ready.", current_user=admin())

        with pytest.raises(HTTPException) as exc:
            reject_lifecycle_item(
                db,
                item_id=item["id"],
                rejection_reason="",
                current_user=admin(),
            )

        assert exc.value.status_code == 400

        rejected = reject_lifecycle_item(
            db,
            item_id=item["id"],
            rejection_reason="Scope too broad.",
            current_user=admin(),
        )["item"]

        assert rejected["state"] == "REJECTED"

        cloned = clone_lifecycle_item(
            db,
            item_id=item["id"],
            current_user=analyst(),
        )["item"]

        assert cloned["state"] == STATE_DRAFT
        assert cloned["version_number"] == 2
        assert cloned["cloned_from_item_id"] == item["id"]
    finally:
        db.close()


def test_invalid_transition_is_rejected_with_allowed_transitions():
    db = db_session()

    try:
        item = create_valid_draft(db)
        submit_lifecycle_item(db, item_id=item["id"], comment="Ready.", current_user=admin())
        approve_lifecycle_item(db, item_id=item["id"], approval_comment="Approved.", current_user=admin())
        apply_lifecycle_item(db, item_id=item["id"], comment="Apply.", current_user=admin())

        with pytest.raises(HTTPException) as exc:
            approve_lifecycle_item(
                db,
                item_id=item["id"],
                approval_comment="Approve again.",
                current_user=admin(),
            )

        assert exc.value.status_code == 400
        assert exc.value.detail["error"] == "Invalid lifecycle transition"
        assert exc.value.detail["from_state"] == STATE_ACTIVE
        assert exc.value.detail["allowed_transitions"] == [STATE_DISABLED, "SUPERSEDED"]

        audit_details = [
            json.loads(event.details_json or "{}")
            for event in db.query(SecurityAuditEvent).all()
            if event.event_type == "DETECTION_RULE_APPLIED"
        ]
        assert audit_details[0]["related_config_version_id"] == 1
    finally:
        db.close()
