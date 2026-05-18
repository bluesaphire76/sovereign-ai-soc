import hashlib
import json

from database import SessionLocal
from event_aggregation import build_event_fingerprint, severity_bucket
from models import RawEvent, SecurityAlert, utc_now
from timezone_utils import normalize_timestamp_utc


def _get(data: dict, *path):
    current = data

    for key in path:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

        if current is None:
            return None

    return current


def _payload_hash(alert: dict) -> str:
    payload = json.dumps(alert, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _payload_json(alert: dict) -> str:
    return json.dumps(alert, ensure_ascii=False)


def persist_event_records(alert: dict) -> dict:
    """Persist raw event and normalized security alert without creating an incident.

    This is intentionally compatible with the existing incident-first flow.
    The raw payload is still kept in incidents.raw_alert for now.
    """
    source_event_id = alert.get("_wazuh_doc_id")

    if not source_event_id:
        return {}

    source = "wazuh"
    now = utc_now()
    event_timestamp = normalize_timestamp_utc(alert.get("@timestamp"))
    fingerprint, _ = build_event_fingerprint(alert)

    rule_id = str(_get(alert, "rule", "id") or "")
    rule_description = _get(alert, "rule", "description")
    level = _get(alert, "rule", "level")
    agent = _get(alert, "agent", "name")

    db = SessionLocal()

    try:
        raw_event = (
            db.query(RawEvent)
            .filter(
                RawEvent.source == source,
                RawEvent.source_event_id == source_event_id,
            )
            .first()
        )

        if not raw_event:
            raw_event = RawEvent(
                source=source,
                source_event_id=source_event_id,
                source_index=alert.get("_wazuh_index"),
                event_timestamp=event_timestamp,
                ingested_at=now,
                agent=agent,
                rule_id=rule_id,
                rule_description=rule_description,
                level=level,
                payload_hash=_payload_hash(alert),
                payload_json=_payload_json(alert),
                created_at=now,
                updated_at=now,
            )
            db.add(raw_event)
            db.flush()
        else:
            raw_event.updated_at = now

        security_alert = (
            db.query(SecurityAlert)
            .filter(
                SecurityAlert.source == source,
                SecurityAlert.source_event_id == source_event_id,
            )
            .first()
        )

        if not security_alert:
            security_alert = SecurityAlert(
                raw_event_id=raw_event.id,
                source=source,
                source_event_id=source_event_id,
                fingerprint=fingerprint,
                status="OBSERVED",
                agent=agent,
                rule_id=rule_id,
                rule_description=rule_description,
                level=level,
                severity_bucket=severity_bucket(level),
                event_timestamp=event_timestamp,
                created_at=now,
                updated_at=now,
            )
            db.add(security_alert)
            db.flush()
        else:
            security_alert.fingerprint = fingerprint
            security_alert.agent = agent
            security_alert.rule_id = rule_id
            security_alert.rule_description = rule_description
            security_alert.level = level
            security_alert.severity_bucket = severity_bucket(level)
            security_alert.event_timestamp = event_timestamp
            security_alert.updated_at = now

        db.commit()

        return {
            "raw_event_id": raw_event.id,
            "security_alert_id": security_alert.id,
            "fingerprint": fingerprint,
        }

    finally:
        db.close()


def update_security_alert_status(security_alert_id: int | None, status: str) -> None:
    if not security_alert_id:
        return

    db = SessionLocal()

    try:
        row = (
            db.query(SecurityAlert)
            .filter(SecurityAlert.id == security_alert_id)
            .first()
        )

        if not row:
            return

        row.status = status
        row.updated_at = utc_now()
        db.commit()

    finally:
        db.close()


def link_security_alert_to_incident(
    security_alert_id: int | None,
    incident_id: int | None,
) -> None:
    if not security_alert_id or not incident_id:
        return

    db = SessionLocal()

    try:
        row = (
            db.query(SecurityAlert)
            .filter(SecurityAlert.id == security_alert_id)
            .first()
        )

        if not row:
            return

        row.incident_id = incident_id
        row.status = "INCIDENT_CREATED"
        row.updated_at = utc_now()
        db.commit()

    finally:
        db.close()
