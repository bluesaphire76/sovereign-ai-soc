import json
from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from detection_control_plane import create_detection_control_rule
from detection_operations import (
    classify_detection_scope,
    extend_review,
    list_operation_items,
    mark_reviewed,
    matched_events_for_item,
    operations_overview,
    utc_now,
)
from detection_rule_lifecycle import create_lifecycle_item
from models import (
    Base,
    DetectionControlRule,
    DetectionRuleLifecycleEvent,
    DetectionRuleLifecycleItem,
    RawEvent,
    SecurityAuditEvent,
)


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


def future_iso(days=60):
    return (utc_now() + timedelta(days=days)).isoformat()


def lifecycle_payload(**overrides):
    value = {
        "policy_type": "NOISE_SUPPRESSION",
        "title": "Suppress known service status noise",
        "description": "Suppress service status checks from a managed host.",
        "business_reason": "Approved operational checks create low-value noise.",
        "owner": "SOC",
        "source_system": "WAZUH",
        "expires_at": future_iso(),
        "content_json": {
            "source": "wazuh",
            "match": {
                "host": "darkstar",
                "command": "systemctl status ai-soc-api",
            },
            "action": "suppress",
            "scope": "host:darkstar",
        },
    }
    value.update(overrides)
    return value


def managed_rule_payload(**overrides):
    value = {
        "name": "Darkstar service status detection",
        "type": "DETECTION_RULE",
        "scope": "host:darkstar",
        "matcher_kind": "CONTAINS",
        "matcher_value": "systemctl status ai-soc-api",
        "reason": "Track recurring service status checks.",
        "owner": "SOC",
        "enabled": True,
    }
    value.update(overrides)
    return value


def test_scope_classification_identifies_dangerously_broad_matchers():
    result = classify_detection_scope(
        scope="global",
        matcher_kind="REGEX",
        matcher_value=".*",
        content={"match": {"host": "*"}},
    )

    assert result["classification"] == "dangerously_broad"
    assert result["reasons"]


def test_operations_overview_lists_lifecycle_and_managed_controls_without_duplicate_lifecycle_rules():
    db = db_session()

    try:
        lifecycle = create_lifecycle_item(
            db,
            payload=lifecycle_payload(),
            current_user=admin(),
        )["item"]
        lifecycle_row = db.query(DetectionRuleLifecycleItem).filter_by(id=lifecycle["id"]).one()
        lifecycle_row.state = "ACTIVE"
        lifecycle_row.hit_count = 7
        lifecycle_row.last_hit_at = utc_now()

        create_detection_control_rule(
            db,
            payload=managed_rule_payload(),
            current_user=admin(),
        )
        lifecycle_managed = DetectionControlRule(
            id="lifecycle:noise_suppression:suppress-known-service-status-noise",
            rule_type="NOISE_SUPPRESSION",
            name="Lifecycle projection",
            scope="host:darkstar",
            matcher_kind="CONTAINS",
            matcher_value="systemctl status ai-soc-api",
            reason="Projected from lifecycle.",
            owner="SOC",
            enabled=True,
            status="ACTIVE",
            metadata_json=json.dumps({"lifecycle_item_id": lifecycle["id"]}),
        )
        db.add(lifecycle_managed)
        db.commit()

        overview = operations_overview(db, current_user=admin())
        rules = list_operation_items(db, item_type="DETECTION_RULE")
        noise = list_operation_items(db, item_type="NOISE_SUPPRESSION")

        assert overview["summary"]["total"] == 2
        assert overview["summary"]["stored_hit_count"] == 7
        assert rules["summary"]["total"] == 1
        assert noise["summary"]["total"] == 1
        assert noise["items"][0]["hit_count_source"] == "lifecycle_counter"
    finally:
        db.close()


def test_matched_events_preview_uses_real_recent_event_records():
    db = db_session()

    try:
        created = create_detection_control_rule(
            db,
            payload=managed_rule_payload(),
            current_user=admin(),
        )["rule"]
        db.add(
            RawEvent(
                source="wazuh",
                source_event_id="evt-1",
                event_timestamp="2026-06-15T08:00:00+00:00",
                agent="darkstar",
                rule_id="100100",
                rule_description="Service status command observed",
                level=3,
                payload_hash="hash-evt-1",
                payload_json=json.dumps(
                    {
                        "agent": {"name": "darkstar"},
                        "full_log": "systemctl status ai-soc-api returned active",
                        "rule": {"id": "100100"},
                    }
                ),
            )
        )
        db.commit()

        result = matched_events_for_item(db, item_id=f"managed:{created['id']}", limit=10, scan_limit=100)

        assert result["observed_count"] == 1
        assert result["matches"][0]["source_table"] == "raw_events"
        assert "systemctl status ai-soc-api" in result["matches"][0]["payload_preview"]
    finally:
        db.close()


def test_review_workflow_updates_lifecycle_and_managed_metadata_with_audit():
    db = db_session()

    try:
        lifecycle = create_lifecycle_item(
            db,
            payload=lifecycle_payload(),
            current_user=admin(),
        )["item"]
        marked = mark_reviewed(
            db,
            item_id=f"lifecycle:{lifecycle['id']}",
            review_status="reviewed",
            review_notes="Reviewed during Step 5 test.",
            current_user=analyst(),
        )

        assert marked["item"]["reviewed_by"] == "analyst"

        created = create_detection_control_rule(
            db,
            payload=managed_rule_payload(),
            current_user=admin(),
        )["rule"]
        extended = extend_review(
            db,
            item_id=f"managed:{created['id']}",
            expires_at=future_iso(days=90),
            reason="Quarterly review complete.",
            current_user=analyst(),
        )

        assert extended["item"]["expires_at"]
        assert extended["item"]["review_status"] == "reviewed"

        event_types = [event.event_type for event in db.query(SecurityAuditEvent).all()]
        history_actions = [event.action for event in db.query(DetectionRuleLifecycleEvent).all()]

        assert "DETECTION_OPERATIONS_REVIEW_MARKED" in event_types
        assert "DETECTION_OPERATIONS_REVIEW_EXTENDED" in event_types
        assert "marked_reviewed" in history_actions
    finally:
        db.close()
