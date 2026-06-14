import json

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from detection_control_plane import (
    archive_detection_control_rule,
    create_detection_control_rule,
    list_detection_control_rules,
    set_detection_control_rule_enabled,
    update_detection_control_rule,
    validate_existing_detection_control_rule,
)
from models import Base, SecurityAuditEvent


def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def actor():
    return {
        "id": 1,
        "username": "admin",
        "role": "ADMIN",
    }


def payload(**overrides):
    value = {
        "name": "Known safe sudo checks",
        "type": "NOISE_SUPPRESSION",
        "scope": "host:darkstar",
        "matcher_kind": "CONTAINS",
        "matcher_value": "systemctl status ai-soc-api",
        "reason": "Approved operational checks.",
        "owner": "admin",
        "enabled": True,
    }
    value.update(overrides)
    return value


def test_detection_control_rule_lifecycle_writes_audit_events():
    db = db_session()

    try:
        created = create_detection_control_rule(
            db,
            payload=payload(),
            current_user=actor(),
        )
        rule_id = created["rule"]["id"]

        updated = update_detection_control_rule(
            db,
            rule_id=rule_id,
            payload={"reason": "Approved operational checks during maintenance."},
            current_user=actor(),
        )
        disabled = set_detection_control_rule_enabled(
            db,
            rule_id=rule_id,
            enabled=False,
            current_user=actor(),
        )
        enabled = set_detection_control_rule_enabled(
            db,
            rule_id=rule_id,
            enabled=True,
            current_user=actor(),
        )
        validation = validate_existing_detection_control_rule(
            db,
            rule_id=rule_id,
            current_user=actor(),
        )
        archived = archive_detection_control_rule(
            db,
            rule_id=rule_id,
            current_user=actor(),
        )

        assert updated["rule"]["reason"] == "Approved operational checks during maintenance."
        assert disabled["rule"]["enabled"] is False
        assert enabled["rule"]["enabled"] is True
        assert validation["validation"]["valid"] is True
        assert archived["status"] == "archived"
        assert list_detection_control_rules(db) == []

        events = db.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc()).all()
        event_types = [event.event_type for event in events]

        assert event_types == [
            "DETECTION_CONTROL_RULE_CREATED",
            "DETECTION_CONTROL_RULE_UPDATED",
            "DETECTION_CONTROL_RULE_DISABLED",
            "DETECTION_CONTROL_RULE_ENABLED",
            "DETECTION_CONTROL_RULE_VALIDATED",
            "DETECTION_CONTROL_RULE_ARCHIVED",
        ]

        details = json.loads(events[0].details_json)
        assert "matcher_value" not in json.dumps(details)
        assert details["after"]["matcher_length"] > 0
    finally:
        db.close()


def test_detection_control_invalid_payload_writes_validation_audit():
    db = db_session()

    try:
        with pytest.raises(HTTPException) as exc:
            create_detection_control_rule(
                db,
                payload=payload(matcher_value=".*"),
                current_user=actor(),
            )

        assert exc.value.status_code == 400

        events = db.query(SecurityAuditEvent).all()
        assert len(events) == 1
        assert events[0].event_type == "DETECTION_CONTROL_RULE_VALIDATION_FAILED"
        assert events[0].outcome == "FAILURE"
    finally:
        db.close()


def test_detection_control_duplicate_name_writes_conflict_audit():
    db = db_session()

    try:
        create_detection_control_rule(
            db,
            payload=payload(),
            current_user=actor(),
        )

        with pytest.raises(HTTPException) as exc:
            create_detection_control_rule(
                db,
                payload=payload(),
                current_user=actor(),
            )

        assert exc.value.status_code == 409

        events = db.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc()).all()
        assert events[-1].event_type == "DETECTION_CONTROL_RULE_CONFLICT"
        assert events[-1].outcome == "FAILURE"
    finally:
        db.close()
