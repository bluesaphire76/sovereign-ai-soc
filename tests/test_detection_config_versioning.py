import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from detection_config_versioning import (
    apply_config_payload,
    diff_config_payload,
    ensure_baseline_versions,
    get_active_version,
    list_versions,
    rollback_config_version,
    validate_config_payload,
    version_to_dict,
)
from detection_control_plane import create_detection_control_rule, list_detection_control_rules
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


def noise_payload(**overrides):
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


def test_baseline_apply_and_rollback_version_detection_config():
    db = db_session()

    try:
        created = create_detection_control_rule(
            db,
            payload=noise_payload(),
            current_user=actor(),
        )
        rule = created["rule"]
        baseline = ensure_baseline_versions(db, current_user=actor())

        active_v1 = get_active_version(db, "noise_suppression")

        assert baseline
        assert active_v1 is not None
        assert active_v1.version_number == 1

        proposed = {
            "items": [
                {
                    **rule,
                    "reason": "Approved operational checks during maintenance.",
                }
            ]
        }
        validation = validate_config_payload("noise_suppression", proposed)
        diff = diff_config_payload(db, "noise_suppression", proposed)

        assert validation["valid"] is True
        assert diff["summary"]["modified_count"] == 1

        applied = apply_config_payload(
            db,
            config_domain="noise_suppression",
            payload=proposed,
            reason="Apply safe sudo tuning.",
            current_user=actor(),
        )

        assert applied["version"]["version_number"] == 2
        assert get_active_version(db, "noise_suppression").version_number == 2

        rows = list_detection_control_rules(db)
        assert rows[0]["reason"] == "Approved operational checks during maintenance."

        rollback = rollback_config_version(
            db,
            config_domain="noise_suppression",
            version_number=1,
            reason="Rollback test.",
            current_user=actor(),
        )

        assert rollback["version"]["version_number"] == 3
        assert rollback["version"]["rollback_of_version_id"] == active_v1.id
        assert get_active_version(db, "noise_suppression").version_number == 3
        assert list_detection_control_rules(db)[0]["reason"] == "Approved operational checks."

        versions = list_versions(db, config_domain="noise_suppression")
        assert [version["version_number"] for version in versions] == [3, 2, 1]

        events = [event.event_type for event in db.query(SecurityAuditEvent).all()]
        assert "CONFIG_VERSION_BASELINE_CREATED" in events
        assert "CONFIG_VERSION_APPLIED" in events
        assert "CONFIG_ROLLBACK_COMPLETED" in events

        active_payload = version_to_dict(get_active_version(db, "noise_suppression"))
        assert active_payload["config_payload"]["items"]
    finally:
        db.close()


def test_invalid_config_apply_is_blocked_and_audited():
    db = db_session()

    try:
        ensure_baseline_versions(db, current_user=actor())

        with pytest.raises(HTTPException) as exc:
            apply_config_payload(
                db,
                config_domain="noise_suppression",
                payload={"items": [noise_payload(matcher_value=".*")]},
                reason="Invalid apply.",
                current_user=actor(),
            )

        assert exc.value.status_code == 400

        events = [event.event_type for event in db.query(SecurityAuditEvent).all()]
        assert "CONFIG_VALIDATION_FAILED" in events
        assert get_active_version(db, "noise_suppression").version_number == 1
    finally:
        db.close()


def test_version_payload_redacts_sensitive_metadata_keys():
    db = db_session()

    try:
        create_detection_control_rule(
            db,
            payload=noise_payload(
                metadata={
                    "api_token": "secret-token",
                    "nested": {
                        "client_secret": "secret-value",
                        "owner_note": "visible",
                    },
                }
            ),
            current_user=actor(),
        )
        ensure_baseline_versions(db, current_user=actor())

        payload = version_to_dict(get_active_version(db, "noise_suppression"))
        metadata = payload["config_payload"]["items"][0]["metadata"]

        assert metadata["api_token"] == "[REDACTED]"
        assert metadata["nested"]["client_secret"] == "[REDACTED]"
        assert metadata["nested"]["owner_note"] == "visible"
    finally:
        db.close()
