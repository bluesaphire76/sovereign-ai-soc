import json
import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from correlation_engine import (
    detect_patterns,
    evaluate_attack_chains,
)
from risk_normalization import normalize_correlation_score
from database import SessionLocal
from models import SecurityAlert

load_dotenv()

CORRELATION_PRECHECK_WINDOW_MINUTES = int(
    os.getenv("CORRELATION_PRECHECK_WINDOW_MINUTES", "15")
)
CORRELATION_CREATE_INCIDENT_LEVEL = int(
    os.getenv("CORRELATION_CREATE_INCIDENT_LEVEL", "7")
)
CORRELATION_RECENT_VOLUME_THRESHOLD = int(
    os.getenv("CORRELATION_RECENT_VOLUME_THRESHOLD", "5")
)
CORRELATION_AGGREGATE_COUNT_THRESHOLD = int(
    os.getenv("CORRELATION_AGGREGATE_COUNT_THRESHOLD", "10")
)

SUSPICIOUS_PATTERNS_FOR_VOLUME = {
    "failed_login",
    "reconnaissance",
    "suspicious_download",
    "new_user",
}


def _get(data: dict, *path):
    current = data

    for key in path:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

        if current is None:
            return None

    return current


def _parse_timestamp(value):
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def _int_value(value, default=0):
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _has_mitre_mapping(alert: dict) -> bool:
    mitre = _get(alert, "rule", "mitre")

    if not mitre:
        return False

    if isinstance(mitre, dict):
        return any(bool(value) for value in mitre.values())

    if isinstance(mitre, (list, tuple, set)):
        return bool(mitre)

    text = str(mitre).strip()

    return text not in {"", "{}", "[]", "None", "null"}


def _alert_text(alert: dict) -> str:
    return " ".join(
        [
            str(_get(alert, "rule", "description") or ""),
            str(_get(alert, "rule", "groups") or ""),
            str(_get(alert, "rule", "mitre") or ""),
            str(alert.get("full_log") or ""),
            json.dumps(alert.get("data") or {}, ensure_ascii=False),
            json.dumps(alert, ensure_ascii=False),
        ]
    ).lower()


def _security_alert_text(row: SecurityAlert) -> str:
    return " ".join(
        [
            str(row.rule_description or ""),
            str(row.rule_id or ""),
            str(row.severity_bucket or ""),
            str(row.status or ""),
        ]
    ).lower()


def _recent_security_alerts(agent: str | None, current_timestamp):
    if not agent or not current_timestamp:
        return []

    window_start = current_timestamp - timedelta(
        minutes=CORRELATION_PRECHECK_WINDOW_MINUTES
    )

    db = SessionLocal()

    try:
        candidates = (
            db.query(SecurityAlert)
            .filter(SecurityAlert.agent == agent)
            .order_by(SecurityAlert.id.desc())
            .limit(200)
            .all()
        )

        recent = []

        for row in candidates:
            row_ts = _parse_timestamp(row.event_timestamp)

            if row_ts and window_start <= row_ts <= current_timestamp:
                recent.append(row)

        return recent

    finally:
        db.close()


def evaluate_correlation_precheck(
    alert: dict,
    aggregation_result: dict | None = None,
) -> dict:
    aggregation_result = aggregation_result or {}

    level = _int_value(_get(alert, "rule", "level"))
    agent = _get(alert, "agent", "name")
    current_timestamp = _parse_timestamp(alert.get("@timestamp"))
    aggregate_count = _int_value(aggregation_result.get("count"))
    aggregate_last_incident_id = aggregation_result.get("last_incident_id")
    is_duplicate = bool(aggregation_result.get("duplicate"))

    current_text = _alert_text(alert)
    current_patterns, current_pattern_score = detect_patterns(current_text)

    recent_alerts = _recent_security_alerts(
        agent=agent,
        current_timestamp=current_timestamp,
    )

    context_text = " ".join(
        [current_text] + [_security_alert_text(row) for row in recent_alerts]
    )

    context_patterns, context_pattern_score = detect_patterns(context_text)
    matched_chains = evaluate_attack_chains(context_patterns)

    suspicious_patterns = sorted(
        set(context_patterns.keys()).intersection(SUSPICIOUS_PATTERNS_FOR_VOLUME)
    )

    reasons = []
    should_create_incident = False

    if aggregate_last_incident_id:
        reasons.append(
            f"aggregate already represented by incident {aggregate_last_incident_id}"
        )

    if not aggregate_last_incident_id:
        if level >= CORRELATION_CREATE_INCIDENT_LEVEL:
            should_create_incident = True
            reasons.append(
                f"rule level {level} >= threshold {CORRELATION_CREATE_INCIDENT_LEVEL}"
            )

        if _has_mitre_mapping(alert):
            should_create_incident = True
            reasons.append("MITRE mapping present")

        if matched_chains:
            should_create_incident = True
            reasons.append("matched attack chain in recent alert context")

        if (
            aggregate_count >= CORRELATION_AGGREGATE_COUNT_THRESHOLD
            and suspicious_patterns
        ):
            should_create_incident = True
            reasons.append(
                "aggregate count threshold reached with suspicious pattern(s)"
            )

        if (
            len(recent_alerts) >= CORRELATION_RECENT_VOLUME_THRESHOLD
            and suspicious_patterns
        ):
            should_create_incident = True
            reasons.append(
                "recent alert volume threshold reached with suspicious pattern(s)"
            )

    if not reasons:
        reasons.append("low-signal alert observed without incident creation")

    base_score = min(level * 5, 40)
    volume_score = min(len(recent_alerts) * 5, 35)
    aggregate_score = min(aggregate_count * 3, 25)
    chain_bonus = sum(chain["score_bonus"] for chain in matched_chains)

    normalization = normalize_correlation_score(
        level=level,
        pattern_score=context_pattern_score,
        volume_score=volume_score,
        aggregate_score=aggregate_score,
        chain_bonus=chain_bonus,
        matched_chains=matched_chains,
    )

    final_score = normalization["final_score"]

    decision = "CREATE_INCIDENT" if should_create_incident else "OBSERVE_ONLY"

    return {
        "decision": decision,
        "should_create_incident": should_create_incident,
        "reasons": reasons,
        "level": level,
        "agent": agent,
        "is_duplicate": is_duplicate,
        "aggregate_count": aggregate_count,
        "aggregate_last_incident_id": aggregate_last_incident_id,
        "recent_alert_count": len(recent_alerts),
        "current_patterns": current_patterns,
        "context_patterns": context_patterns,
        "current_pattern_score": current_pattern_score,
        "context_pattern_score": context_pattern_score,
        "suspicious_patterns": suspicious_patterns,
        "matched_attack_chains": [
            {
                "name": chain["name"],
                "correlation_type": chain["correlation_type"],
                "priority": chain["priority"],
                "reason": chain["reason"],
                "score_bonus": chain["score_bonus"],
            }
            for chain in matched_chains
        ],
        "correlation_precheck_score": final_score,
        "recommended_priority": normalization["recommended_priority"],
        "risk_normalization": normalization,
        "window_minutes": CORRELATION_PRECHECK_WINDOW_MINUTES,
        "thresholds": {
            "create_incident_level": CORRELATION_CREATE_INCIDENT_LEVEL,
            "recent_volume": CORRELATION_RECENT_VOLUME_THRESHOLD,
            "aggregate_count": CORRELATION_AGGREGATE_COUNT_THRESHOLD,
        },
    }
