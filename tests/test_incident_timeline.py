import json
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from incident_timeline import (
    TimelineQuery,
    build_incident_timeline_capabilities,
    build_incident_timeline_payload,
    build_incident_timeline_summary,
)
from models import (
    Base,
    CaseAction,
    CaseIncident,
    EventAggregate,
    Incident,
    IncidentAudit,
    IncidentCase,
    IncidentNote,
    RawEvent,
    SecurityAlert,
    SecurityAuditEvent,
)


def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def admin():
    return {"id": 1, "username": "admin", "role": "ADMIN"}


def viewer():
    return {"id": 2, "username": "viewer", "role": "VIEWER"}


def add_incident_fixture(db) -> int:
    raw_payload = {
        "@timestamp": "2026-01-01T10:00:00Z",
        "agent": {"name": "darkstar"},
        "rule": {
            "id": "550",
            "description": "Integrity checksum changed",
            "mitre": {"id": ["T1499"]},
        },
        "data": {
            "srcip": "10.0.0.5",
            "dstip": "10.0.0.10",
            "user": "root",
        },
        "syscheck": {"path": "/etc/passwd"},
    }
    raw_event = RawEvent(
        source="wazuh",
        source_event_id="wazuh-1",
        source_index="alerts-2026",
        event_timestamp="2026-01-01T10:00:00Z",
        agent="darkstar",
        rule_id="550",
        rule_description="Integrity checksum changed",
        level=12,
        payload_hash="abc123",
        payload_json=json.dumps(raw_payload),
    )
    db.add(raw_event)
    db.flush()

    alert = SecurityAlert(
        raw_event_id=raw_event.id,
        source="wazuh",
        source_event_id="wazuh-1",
        fingerprint="fp-1",
        status="INCIDENT_CREATED",
        agent="darkstar",
        rule_id="550",
        rule_description="Integrity checksum changed",
        level=12,
        severity_bucket="HIGH",
        event_timestamp="2026-01-01T10:00:01Z",
    )
    db.add(alert)
    db.flush()

    incident = Incident(
        wazuh_doc_id="wazuh-1",
        raw_event_id=raw_event.id,
        security_alert_id=alert.id,
        status="INVESTIGATING",
        timestamp="2026-01-01T10:00:02Z",
        agent="darkstar",
        rule="Integrity checksum changed",
        level=12,
        mitre=json.dumps(["T1499"]),
        risk_score=75,
        ai_analysis="AI assessment: likely sensitive file integrity alert.",
        raw_alert=json.dumps(raw_payload),
        correlated=True,
        correlation_summary=json.dumps({"related_events": 2}),
        correlation_score=82,
        attack_chain="T1499",
        correlation_type="fim_integrity_chain",
        escalation_reason="Sensitive integrity path changed.",
        recommended_priority="HIGH",
    )
    db.add(incident)
    db.flush()

    alert.incident_id = incident.id

    db.add(
        EventAggregate(
            fingerprint="fp-1",
            source="wazuh",
            rule_id="550",
            rule_description="Integrity checksum changed",
            agent="darkstar",
            level=12,
            severity_bucket="HIGH",
            first_seen="2026-01-01T09:58:00Z",
            last_seen="2026-01-01T10:01:00Z",
            count=4,
            first_wazuh_doc_id="wazuh-0",
            last_wazuh_doc_id="wazuh-3",
            last_incident_id=incident.id,
            sample_event_json=json.dumps(raw_payload),
        )
    )
    db.add(
        IncidentAudit(
            incident_id=incident.id,
            event_type="STATUS_CHANGE",
            old_value="NEW",
            new_value="CONTAINED",
            comment="Contained after validation.",
            created_by="analyst",
            created_at=datetime(2026, 1, 1, 10, 5, tzinfo=timezone.utc),
        )
    )
    db.add(
        IncidentNote(
            incident_id=incident.id,
            note="Checked the host and opened a case.",
            created_by="analyst",
            created_at=datetime(2026, 1, 1, 10, 6, tzinfo=timezone.utc),
        )
    )
    case = IncidentCase(
        group_key=f"incident:{incident.id}",
        title="Incident investigation",
        status="OPEN",
        severity="HIGH",
        agent="darkstar",
        correlation_type="manual_incident_escalation",
        risk_score=75,
        created_by="analyst",
        created_at=datetime(2026, 1, 1, 10, 7, tzinfo=timezone.utc),
    )
    db.add(case)
    db.flush()

    db.add(CaseIncident(case_id=case.id, incident_id=incident.id))
    db.add(
        CaseAction(
            case_id=case.id,
            title="Validate file integrity baseline",
            description="Compare the changed file with the approved baseline.",
            category="INVESTIGATION",
            priority="HIGH",
            status="DONE",
            created_by="analyst",
            created_at=datetime(2026, 1, 1, 10, 8, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, 10, 9, tzinfo=timezone.utc),
        )
    )

    db.commit()
    return incident.id


def test_incident_timeline_builds_unified_real_event_categories():
    db = db_session()

    try:
        incident_id = add_incident_fixture(db)
        payload = build_incident_timeline_payload(db, incident_id, TimelineQuery())
        categories = {item["category"] for item in payload["items"]}

        assert {
            "INCIDENT_CREATED",
            "RAW_EVENT",
            "SECURITY_ALERT",
            "AGGREGATED_DUPLICATE",
            "CORRELATION_DECISION",
            "AI_ANALYSIS",
            "INCIDENT_STATUS_CHANGE",
            "ANALYST_NOTE",
            "CASE_CREATED",
            "CASE_ACTION_CREATED",
            "CASE_ACTION_COMPLETED",
        }.issubset(categories)

        raw_item = next(item for item in payload["items"] if item["category"] == "RAW_EVENT")
        assert raw_item["raw_payload_available"] is True
        assert "raw_payload" not in raw_item
        assert {"type": "source_ip", "value": "10.0.0.5"} in raw_item["entity_refs"]
        assert payload["summary"]["key_events"] >= 4
    finally:
        db.close()


def test_incident_timeline_filters_and_summarizes():
    db = db_session()

    try:
        incident_id = add_incident_fixture(db)
        payload = build_incident_timeline_payload(
            db,
            incident_id,
            TimelineQuery(categories={"RAW_EVENT"}, limit=1, sort="desc"),
        )

        assert payload["returned_count"] == 1
        assert payload["filtered_count"] == 1
        assert payload["items"][0]["category"] == "RAW_EVENT"

        summary = build_incident_timeline_summary(db, incident_id)
        assert summary["summary"]["raw_events"] == 1
        assert summary["summary"]["case_events"] >= 2

        capabilities = build_incident_timeline_capabilities(db, incident_id)
        assert "RAW_EVENT" in capabilities["available_categories"]
        assert any(
            item["category"] == "SERVICE_OPERATION"
            for item in capabilities["unavailable_categories"]
        )
    finally:
        db.close()


def test_raw_payload_requires_operator_role_and_is_audited():
    db = db_session()

    try:
        incident_id = add_incident_fixture(db)

        with pytest.raises(HTTPException) as denied:
            build_incident_timeline_payload(
                db,
                incident_id,
                TimelineQuery(include_raw_payload=True),
                current_user=viewer(),
            )

        assert denied.value.status_code == 403
        denied_event = db.query(SecurityAuditEvent).one()
        assert denied_event.event_type == "INCIDENT_TIMELINE_RAW_PAYLOAD_ACCESS"
        assert denied_event.outcome == "DENIED"

        payload = build_incident_timeline_payload(
            db,
            incident_id,
            TimelineQuery(include_raw_payload=True),
            current_user=admin(),
        )
        raw_item = next(item for item in payload["items"] if item["category"] == "RAW_EVENT")

        assert raw_item["raw_payload"]["agent"]["name"] == "darkstar"
        outcomes = [row.outcome for row in db.query(SecurityAuditEvent).order_by(SecurityAuditEvent.id.asc())]
        assert outcomes == ["DENIED", "SUCCESS"]
    finally:
        db.close()
