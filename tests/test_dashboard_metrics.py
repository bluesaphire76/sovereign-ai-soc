from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from dashboard_metrics import (
    build_detection_funnel,
    build_incident_trend,
    build_queue_aging,
)
from models import Base, Incident, IncidentCase, RawEvent, SecurityAlert


def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def test_incident_trend_groups_recent_incidents_by_day_and_risk():
    db = db_session()
    now = datetime(2026, 1, 8, 12, 0, tzinfo=timezone.utc)

    try:
        db.add_all(
            [
                Incident(
                    wazuh_doc_id="trend-1",
                    status="NEW",
                    timestamp="2026-01-08T10:00:00Z",
                    risk_score=85,
                ),
                Incident(
                    wazuh_doc_id="trend-2",
                    status="TRIAGED",
                    timestamp="2026-01-08T11:00:00Z",
                    risk_score=65,
                ),
                Incident(
                    wazuh_doc_id="trend-3",
                    status="CLOSED",
                    timestamp="2026-01-06T09:00:00Z",
                    risk_score=20,
                ),
                Incident(
                    wazuh_doc_id="trend-old",
                    status="NEW",
                    timestamp="2025-12-01T00:00:00Z",
                    risk_score=100,
                ),
            ]
        )
        db.commit()

        payload = build_incident_trend(db, days=7, now=now)

        assert payload["start_date"] == "2026-01-02"
        assert payload["end_date"] == "2026-01-08"
        assert len(payload["items"]) == 7

        today = payload["items"][-1]
        assert today["date"] == "2026-01-08"
        assert today["total"] == 2
        assert today["high_or_critical"] == 2
        assert today["critical"] == 1
        assert today["average_risk"] == 75
    finally:
        db.close()


def test_queue_aging_counts_open_incidents_cases_and_sla_breaches():
    db = db_session()
    now = datetime(2026, 1, 8, 12, 0, tzinfo=timezone.utc)

    try:
        db.add_all(
            [
                Incident(
                    wazuh_doc_id="queue-1",
                    status="NEW",
                    timestamp="2026-01-08T06:00:00Z",
                    risk_score=40,
                ),
                Incident(
                    wazuh_doc_id="queue-2",
                    status="INVESTIGATING",
                    timestamp="2026-01-05T12:00:00Z",
                    risk_score=70,
                ),
                Incident(
                    wazuh_doc_id="queue-closed",
                    status="CLOSED",
                    timestamp="2026-01-02T12:00:00Z",
                    risk_score=90,
                ),
                IncidentCase(
                    group_key="case-1",
                    title="Open case",
                    status="OPEN",
                    created_at=now - timedelta(hours=6),
                    sla_due_at=now - timedelta(hours=1),
                ),
                IncidentCase(
                    group_key="case-2",
                    title="Escalated case",
                    status="ESCALATED",
                    created_at=now - timedelta(days=5),
                    sla_due_at=now + timedelta(days=1),
                ),
                IncidentCase(
                    group_key="case-closed",
                    title="Closed case",
                    status="FALSE_POSITIVE",
                    created_at=now - timedelta(days=10),
                ),
            ]
        )
        db.commit()

        payload = build_queue_aging(db, now=now)
        buckets = {item["name"]: item for item in payload["items"]}

        assert buckets["0-24h"]["incidents"] == 1
        assert buckets["0-24h"]["cases"] == 1
        assert buckets["0-24h"]["sla_breached"] == 1
        assert buckets["1-3d"]["incidents"] == 1
        assert buckets["3-7d"]["cases"] == 1
        assert buckets[">7d"]["total"] == 0
    finally:
        db.close()


def test_detection_funnel_counts_pipeline_and_noise_statuses():
    db = db_session()

    try:
        raw_events = [
            RawEvent(
                source_event_id="raw-1",
                payload_hash="raw-hash-1",
                payload_json="{}",
            ),
            RawEvent(
                source_event_id="raw-2",
                payload_hash="raw-hash-2",
                payload_json="{}",
            ),
            RawEvent(
                source_event_id="raw-3",
                payload_hash="raw-hash-3",
                payload_json="{}",
            ),
        ]
        db.add_all(raw_events)
        db.flush()

        db.add_all(
            [
                SecurityAlert(
                    raw_event_id=raw_events[0].id,
                    source_event_id="alert-1",
                    status="INCIDENT_CREATED",
                ),
                SecurityAlert(
                    raw_event_id=raw_events[1].id,
                    source_event_id="alert-2",
                    status="NOISE_SUPPRESSED",
                ),
                SecurityAlert(
                    raw_event_id=raw_events[2].id,
                    source_event_id="alert-3",
                    status="AGGREGATED_DUPLICATE",
                ),
            ]
        )
        db.add(
            Incident(
                wazuh_doc_id="funnel-incident",
                status="NEW",
                timestamp="2026-01-08T10:00:00Z",
                risk_score=75,
            )
        )
        db.add(
            IncidentCase(
                group_key="funnel-case",
                title="Funnel case",
                status="OPEN",
            )
        )
        db.commit()

        payload = build_detection_funnel(db)
        counts = {item["name"]: item["value"] for item in payload["items"]}
        secondary_counts = {
            item["name"]: item["value"] for item in payload["secondary_items"]
        }

        assert counts == {
            "Raw events": 3,
            "Security alerts": 3,
            "Incidents": 1,
            "Cases": 1,
        }
        assert secondary_counts["Suppressed"] == 1
        assert secondary_counts["Duplicates"] == 1
    finally:
        db.close()
