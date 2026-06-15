import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from investigation_graph import (
    build_case_graph,
    build_incident_graph,
    graph_summary_payload,
    normalize_graph_options,
)
from models import Base, CaseAIAnalysis, CaseIncident, Incident, IncidentCase, RawEvent, SecurityAlert


def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def add_graph_fixture(db):
    timestamp = datetime(2026, 6, 14, 12, 0, tzinfo=timezone.utc)
    payload = {
        "@timestamp": "2026-06-14T12:00:00Z",
        "agent": {"name": "darkstar"},
        "rule": {"id": "5710", "mitre": {"id": ["T1110"]}},
        "data": {
            "srcip": "192.168.1.10",
            "dstip": "10.0.0.5",
            "user": "lele",
            "audit": {"exe": "/usr/bin/ssh"},
        },
        "syscheck": {"path": "/etc/ssh/sshd_config"},
    }
    raw_event = RawEvent(
        source="wazuh",
        source_event_id="raw-graph-1",
        event_timestamp="2026-06-14T12:00:00Z",
        agent="darkstar",
        rule_id="5710",
        rule_description="sshd brute force attempt",
        level=10,
        payload_hash="raw-graph-hash-1",
        payload_json=json.dumps(payload),
    )
    db.add(raw_event)
    db.flush()

    alert = SecurityAlert(
        raw_event_id=raw_event.id,
        source="wazuh",
        source_event_id="alert-graph-1",
        fingerprint="fp-graph-1",
        status="INCIDENT_CREATED",
        agent="darkstar",
        rule_id="5710",
        rule_description="sshd brute force attempt",
        level=10,
        severity_bucket="HIGH",
        event_timestamp="2026-06-14T12:00:01Z",
    )
    db.add(alert)
    db.flush()

    incident = Incident(
        wazuh_doc_id="incident-graph-1",
        raw_event_id=raw_event.id,
        security_alert_id=alert.id,
        status="INVESTIGATING",
        timestamp="2026-06-14T12:00:02Z",
        agent="darkstar",
        rule="sshd brute force attempt",
        level=10,
        mitre=json.dumps(["T1110"]),
        risk_score=82,
        ai_analysis="AI assessment: validate brute-force authentication evidence.",
        raw_alert=json.dumps(payload),
        correlated=True,
        correlation_summary=json.dumps(
            {
                "related_event_details": [],
                "matched_patterns": {"credential_access": {"keywords": ["ssh"]}},
            }
        ),
        correlation_score=91,
        attack_chain="T1110",
        correlation_type="credential_access",
        escalation_reason="Multiple authentication failures from a source IP.",
        recommended_priority="CRITICAL",
    )
    db.add(incident)
    db.flush()
    alert.incident_id = incident.id

    case = IncidentCase(
        group_key="case-graph-1",
        title="Credential access investigation",
        status="OPEN",
        severity="HIGH",
        agent="darkstar",
        correlation_type="credential_access",
        risk_score=82,
        owner="analyst",
        assignee="lele",
        created_at=timestamp,
        updated_at=timestamp + timedelta(minutes=5),
    )
    db.add(case)
    db.flush()

    db.add(CaseIncident(case_id=case.id, incident_id=incident.id))
    db.add(
        CaseAIAnalysis(
            case_id=case.id,
            model="local-test",
            analysis="AI case analysis: validate host authentication timeline.",
            recommended_status="INVESTIGATING",
            recommended_severity="HIGH",
        )
    )
    db.commit()

    return incident.id, case.id


def node_ids(graph):
    return {node["id"] for node in graph["nodes"]}


def edge_types(graph):
    return {edge["type"] for edge in graph["edges"]}


def test_incident_graph_uses_real_relationships_and_stable_ids():
    db = db_session()
    try:
        incident_id, _ = add_graph_fixture(db)

        graph = build_incident_graph(
            db,
            incident_id,
            normalize_graph_options(include_raw_events=True, include_timeline=False),
            current_user={"role": "ADMIN"},
        )
        ids = node_ids(graph)

        assert f"incident:{incident_id}" in ids
        assert "security_alert:1" in ids
        assert "raw_event:1" in ids
        assert "host:darkstar" in ids
        assert "user:lele" in ids
        assert "source_ip:192.168.1.10" in ids
        assert "destination_ip:10.0.0.5" in ids
        assert "detection_rule:5710" in ids
        assert "mitre:T1110" in ids
        assert {"HAS_ALERT", "HAS_RAW_EVENT", "OBSERVED_ON", "MAPS_TO_MITRE"} <= edge_types(graph)
    finally:
        db.close()


def test_incident_graph_hides_raw_events_by_default_and_deduplicates_hosts():
    db = db_session()
    try:
        incident_id, _ = add_graph_fixture(db)

        graph = build_incident_graph(
            db,
            incident_id,
            normalize_graph_options(include_raw_events=False, include_timeline=False),
            current_user={"role": "ANALYST"},
        )
        ids = node_ids(graph)
        host = next(node for node in graph["nodes"] if node["id"] == "host:darkstar")

        assert "raw_event:1" not in ids
        assert host["count"] >= 2
    finally:
        db.close()


def test_viewer_receives_raw_event_metadata_redaction():
    db = db_session()
    try:
        incident_id, _ = add_graph_fixture(db)

        graph = build_incident_graph(
            db,
            incident_id,
            normalize_graph_options(include_raw_events=True, include_timeline=False),
            current_user={"role": "VIEWER"},
        )
        raw_node = next(node for node in graph["nodes"] if node["id"] == "raw_event:1")

        assert graph["redaction"]["applied"] is True
        assert raw_node["metadata"]["redacted"] is True
        assert "payload_json" not in raw_node["metadata"]
    finally:
        db.close()


def test_graph_limits_add_warning_and_summary_is_flat():
    db = db_session()
    try:
        incident_id, _ = add_graph_fixture(db)

        graph = build_incident_graph(
            db,
            incident_id,
            normalize_graph_options(
                include_raw_events=True,
                include_timeline=False,
                limit_nodes=3,
                limit_edges=3,
            ),
            current_user={"role": "ADMIN"},
        )
        summary = graph_summary_payload(graph)

        assert graph["summary"]["warnings"]
        assert summary["node_count"] == 3
        assert summary["graph_quality"] == "limited"
    finally:
        db.close()


def test_case_graph_links_case_incident_alerts_and_case_ai_analysis():
    db = db_session()
    try:
        incident_id, case_id = add_graph_fixture(db)

        graph = build_case_graph(
            db,
            case_id,
            normalize_graph_options(include_raw_events=False, include_timeline=False),
            current_user={"role": "ADMIN"},
        )
        ids = node_ids(graph)

        assert f"case:{case_id}" in ids
        assert f"incident:{incident_id}" in ids
        assert "security_alert:1" in ids
        assert any(node["type"] == "AI_ANALYSIS" for node in graph["nodes"])
        assert "PART_OF_CASE" in edge_types(graph)
    finally:
        db.close()


def test_missing_incident_raises_value_error():
    db = db_session()
    try:
        with pytest.raises(ValueError):
            build_incident_graph(db, 404, normalize_graph_options(), current_user={"role": "ADMIN"})
    finally:
        db.close()


def test_missing_optional_investigation_memory_tables_do_not_break_graph():
    db = db_session()
    try:
        incident_id, _ = add_graph_fixture(db)
        db.execute(text("DROP TABLE investigation_hypothesis_history"))
        db.execute(text("DROP TABLE investigation_snapshots"))
        db.execute(text("DROP TABLE investigation_sessions"))
        db.commit()

        graph = build_incident_graph(
            db,
            incident_id,
            normalize_graph_options(include_ai=True, include_timeline=False),
            current_user={"role": "ADMIN"},
        )

        assert f"incident:{incident_id}" in node_ids(graph)
        assert f"ai_analysis:incident:{incident_id}" in node_ids(graph)
        assert not any("Investigation memory tables" in item for item in graph["summary"]["warnings"])
    finally:
        db.close()
