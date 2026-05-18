import hashlib
import json
import os
import re
from datetime import datetime, timezone

from dotenv import load_dotenv

from database import SessionLocal
from models import EventAggregate, utc_now

load_dotenv()

EVENT_AGGREGATION_WINDOW_MINUTES = int(
    os.getenv("EVENT_AGGREGATION_WINDOW_MINUTES", "15")
)


def _clean(value) -> str:
    if value is None:
        return ""

    if isinstance(value, (dict, list, tuple, set)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=False)

    text = str(value).strip().lower()
    return re.sub(r"\s+", " ", text)


def _get(data: dict, *path):
    current = data

    for key in path:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

        if current is None:
            return None

    return current


def _first_present(*values):
    for value in values:
        if value not in (None, ""):
            return value

    return None


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def _event_timestamp(alert: dict) -> str:
    parsed = _parse_timestamp(alert.get("@timestamp"))

    if parsed:
        return parsed.isoformat().replace("+00:00", "Z")

    return utc_now().isoformat().replace("+00:00", "Z")


def severity_bucket(level) -> str:
    try:
        score = int(level or 0)
    except (TypeError, ValueError):
        score = 0

    if score >= 15:
        return "CRITICAL"

    if score >= 12:
        return "HIGH"

    if score >= 7:
        return "MEDIUM"

    return "LOW"


def _rule_groups(alert: dict) -> str:
    groups = _get(alert, "rule", "groups") or []

    if isinstance(groups, list):
        return ",".join(sorted(str(item) for item in groups))

    return str(groups)


def _fingerprint_components(alert: dict) -> dict:
    level = _get(alert, "rule", "level")

    return {
        "source": "wazuh",
        "rule_id": _clean(_get(alert, "rule", "id")),
        "rule_description": _clean(_get(alert, "rule", "description")),
        "rule_groups": _clean(_rule_groups(alert)),
        "agent_id": _clean(_get(alert, "agent", "id")),
        "agent_name": _clean(_get(alert, "agent", "name")),
        "manager_name": _clean(_get(alert, "manager", "name")),
        "location": _clean(alert.get("location")),
        "decoder": _clean(_get(alert, "decoder", "name")),
        "severity_bucket": severity_bucket(level),
        "srcip": _clean(
            _first_present(
                _get(alert, "data", "srcip"),
                _get(alert, "data", "src_ip"),
                _get(alert, "data", "win", "eventdata", "ipAddress"),
            )
        ),
        "dstip": _clean(
            _first_present(
                _get(alert, "data", "dstip"),
                _get(alert, "data", "dst_ip"),
            )
        ),
        "user": _clean(
            _first_present(
                _get(alert, "data", "srcuser"),
                _get(alert, "data", "dstuser"),
                _get(alert, "data", "user"),
                _get(alert, "data", "win", "eventdata", "targetUserName"),
            )
        ),
        "program": _clean(
            _first_present(
                _get(alert, "data", "program_name"),
                _get(alert, "data", "process", "name"),
                _get(alert, "data", "audit", "exe"),
                _get(alert, "syscheck", "path"),
            )
        ),
        "systemd_unit": _clean(
            _first_present(
                _get(alert, "data", "systemd", "unit"),
                _get(alert, "data", "unit"),
            )
        ),
    }


def build_event_fingerprint(alert: dict) -> tuple[str, dict]:
    components = _fingerprint_components(alert)
    payload = json.dumps(components, sort_keys=True, ensure_ascii=False)
    fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    return fingerprint, components


def _within_window(previous_timestamp: str | None, current_timestamp: str | None) -> bool:
    previous = _parse_timestamp(previous_timestamp)
    current = _parse_timestamp(current_timestamp)

    if not previous or not current:
        return False

    delta_seconds = abs((current - previous).total_seconds())
    return delta_seconds <= EVENT_AGGREGATION_WINDOW_MINUTES * 60


def aggregate_alert(alert: dict) -> dict:
    fingerprint, components = build_event_fingerprint(alert)
    event_timestamp = _event_timestamp(alert)
    now = utc_now()
    serialized_alert = json.dumps(alert, ensure_ascii=False)

    db = SessionLocal()

    try:
        aggregate = (
            db.query(EventAggregate)
            .filter(EventAggregate.fingerprint == fingerprint)
            .first()
        )

        if aggregate:
            duplicate = _within_window(
                aggregate.last_seen,
                event_timestamp,
            )

            aggregate.count = (aggregate.count or 0) + 1
            aggregate.last_seen = event_timestamp
            aggregate.last_wazuh_doc_id = alert.get("_wazuh_doc_id")
            aggregate.last_event_json = serialized_alert
            aggregate.updated_at = now

            db.commit()

            return {
                "fingerprint": fingerprint,
                "duplicate": duplicate,
                "count": aggregate.count,
                "window_minutes": EVENT_AGGREGATION_WINDOW_MINUTES,
                "last_incident_id": aggregate.last_incident_id,
            }

        aggregate = EventAggregate(
            fingerprint=fingerprint,
            source="wazuh",
            rule_id=components.get("rule_id"),
            rule_description=alert.get("rule", {}).get("description"),
            agent=alert.get("agent", {}).get("name"),
            location=alert.get("location"),
            decoder=alert.get("decoder", {}).get("name"),
            level=alert.get("rule", {}).get("level"),
            severity_bucket=components.get("severity_bucket"),
            first_seen=event_timestamp,
            last_seen=event_timestamp,
            count=1,
            first_wazuh_doc_id=alert.get("_wazuh_doc_id"),
            last_wazuh_doc_id=alert.get("_wazuh_doc_id"),
            sample_event_json=serialized_alert,
            last_event_json=serialized_alert,
            created_at=now,
            updated_at=now,
        )

        db.add(aggregate)
        db.commit()

        return {
            "fingerprint": fingerprint,
            "duplicate": False,
            "count": 1,
            "window_minutes": EVENT_AGGREGATION_WINDOW_MINUTES,
            "last_incident_id": None,
        }

    finally:
        db.close()


def record_aggregate_incident(fingerprint: str | None, incident_id: int | None) -> None:
    if not fingerprint or not incident_id:
        return

    db = SessionLocal()

    try:
        aggregate = (
            db.query(EventAggregate)
            .filter(EventAggregate.fingerprint == fingerprint)
            .first()
        )

        if not aggregate:
            return

        aggregate.last_incident_id = incident_id
        aggregate.updated_at = utc_now()
        db.commit()

    finally:
        db.close()
