import json
from datetime import datetime, timedelta

from database import SessionLocal
from models import Incident
from rich import print


CORRELATION_WINDOW_MINUTES = 15


PATTERN_DEFINITIONS = {
    "failed_login": {
        "keywords": [
            "failed password",
            "authentication failed",
            "invalid user",
            "failed login",
            "login failed",
            "maximum authentication attempts",
        ],
        "weight": 25,
    },
    "successful_login": {
        "keywords": [
            "accepted password",
            "accepted publickey",
            "session opened",
            "login session opened",
            "pam: login session opened",
        ],
        "weight": 35,
    },
    "sudo_activity": {
        "keywords": [
            "sudo",
            "command=",
            "pam_unix(sudo",
            "session opened for user root",
        ],
        "weight": 30,
    },
    "new_user": {
        "keywords": [
            "useradd",
            "new user",
            "add user",
            "created user",
            "groupadd",
            "passwd",
        ],
        "weight": 45,
    },
    "suspicious_download": {
        "keywords": [
            "wget",
            "curl",
            "download",
            "http://",
            "https://",
            "chmod +x",
        ],
        "weight": 35,
    },
    "reconnaissance": {
        "keywords": [
            "nmap",
            "masscan",
            "port scan",
            "scanner",
            "reconnaissance",
        ],
        "weight": 30,
    },
    "root_activity": {
        "keywords": [
            "root",
            "uid=0",
            "euid=0",
        ],
        "weight": 20,
    },
}


ATTACK_CHAIN_RULES = [
    {
        "name": "Possible SSH brute force followed by successful access",
        "required_patterns": ["failed_login", "successful_login"],
        "score_bonus": 30,
        "priority": "HIGH",
        "correlation_type": "AUTHENTICATION_ATTACK_CHAIN",
        "reason": "Failed authentication activity followed by a successful login-like event on the same host.",
    },
    {
        "name": "Possible host compromise after authentication and privilege escalation",
        "required_patterns": ["failed_login", "successful_login", "sudo_activity"],
        "score_bonus": 50,
        "priority": "CRITICAL",
        "correlation_type": "POSSIBLE_HOST_COMPROMISE",
        "reason": "Authentication anomaly followed by sudo/root activity on the same host.",
    },
    {
        "name": "Possible post-compromise tool download",
        "required_patterns": ["successful_login", "suspicious_download"],
        "score_bonus": 45,
        "priority": "HIGH",
        "correlation_type": "POST_COMPROMISE_ACTIVITY",
        "reason": "Login/session activity followed by suspicious download behavior.",
    },
    {
        "name": "Possible persistence attempt",
        "required_patterns": ["successful_login", "new_user"],
        "score_bonus": 55,
        "priority": "CRITICAL",
        "correlation_type": "POSSIBLE_PERSISTENCE",
        "reason": "Login/session activity followed by user or credential modification.",
    },
    {
        "name": "Reconnaissance and authentication activity",
        "required_patterns": ["reconnaissance", "failed_login"],
        "score_bonus": 35,
        "priority": "HIGH",
        "correlation_type": "RECON_TO_AUTH_CHAIN",
        "reason": "Reconnaissance indicators correlated with authentication failures.",
    },
]


def parse_timestamp(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def normalize_text(value):
    return str(value or "").lower()


def incident_text(incident):
    return " ".join(
        [
            normalize_text(incident.rule),
            normalize_text(incident.ai_analysis),
            normalize_text(incident.raw_alert),
            normalize_text(incident.mitre),
        ]
    )


def detect_patterns(text):
    detected = {}
    total_weight = 0

    for pattern_name, definition in PATTERN_DEFINITIONS.items():
        matched_keywords = [
            keyword
            for keyword in definition["keywords"]
            if keyword in text
        ]

        if matched_keywords:
            detected[pattern_name] = {
                "keywords": matched_keywords,
                "weight": definition["weight"],
            }
            total_weight += definition["weight"]

    return detected, total_weight


def get_recent_incidents(db, agent, current_timestamp, minutes=CORRELATION_WINDOW_MINUTES):
    if not agent or not current_timestamp:
        return []

    window_start = current_timestamp - timedelta(minutes=minutes)

    candidates = (
        db.query(Incident)
        .filter(Incident.agent == agent)
        .order_by(Incident.id.desc())
        .limit(200)
        .all()
    )

    recent = []

    for item in candidates:
        ts = parse_timestamp(item.timestamp)

        if ts and window_start <= ts <= current_timestamp:
            recent.append(item)

    return recent


def evaluate_attack_chains(detected_patterns):
    detected_names = set(detected_patterns.keys())

    matched_chains = []

    for rule in ATTACK_CHAIN_RULES:
        required = set(rule["required_patterns"])

        if required.issubset(detected_names):
            matched_chains.append(rule)

    return matched_chains


def priority_from_score(score):
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


def build_correlation_summary(
    incident,
    recent_incidents,
    detected_patterns,
    pattern_score,
    volume_score,
    base_score,
    chain_bonus,
    matched_chains,
    final_score,
    recommended_priority,
):
    return {
        "agent": incident.agent,
        "window_minutes": CORRELATION_WINDOW_MINUTES,
        "related_events": len(recent_incidents),
        "related_event_details": [
            {
                "id": item.id,
                "timestamp": item.timestamp,
                "agent": item.agent,
                "rule": item.rule,
                "level": item.level,
                "risk_score": item.risk_score,
                "status": item.status,
                "correlation_score": item.correlation_score,
            }
            for item in recent_incidents
        ],
        "current_incident_id": incident.id,
        "base_score": base_score,
        "pattern_score": pattern_score,
        "volume_score": volume_score,
        "chain_bonus": chain_bonus,
        "matched_patterns": detected_patterns,
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
        "final_correlation_score": final_score,
        "recommended_priority": recommended_priority,
    }


def correlate_incident(incident_id):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            print(f"[red]Incident {incident_id} non trovato[/red]")
            return

        current_timestamp = parse_timestamp(incident.timestamp)

        recent_incidents = get_recent_incidents(
            db=db,
            agent=incident.agent,
            current_timestamp=current_timestamp,
        )

        combined_text = " ".join(
            incident_text(item)
            for item in recent_incidents
        )

        detected_patterns, pattern_score = detect_patterns(combined_text)

        matched_chains = evaluate_attack_chains(detected_patterns)

        base_score = min((incident.level or 0) * 5, 40)
        volume_score = min(len(recent_incidents) * 5, 35)
        chain_bonus = sum(chain["score_bonus"] for chain in matched_chains)

        final_score = min(
            base_score + pattern_score + volume_score + chain_bonus,
            100,
        )

        recommended_priority = priority_from_score(final_score)

        if matched_chains:
            strongest_chain = sorted(
                matched_chains,
                key=lambda item: item["score_bonus"],
                reverse=True,
            )[0]

            attack_chain = strongest_chain["name"]
            correlation_type = strongest_chain["correlation_type"]
            escalation_reason = strongest_chain["reason"]

            if strongest_chain["priority"] == "CRITICAL":
                recommended_priority = "CRITICAL"

        else:
            attack_chain = None
            correlation_type = "SINGLE_HOST_PATTERN_CORRELATION"
            escalation_reason = None

        summary = build_correlation_summary(
            incident=incident,
            recent_incidents=recent_incidents,
            detected_patterns=detected_patterns,
            pattern_score=pattern_score,
            volume_score=volume_score,
            base_score=base_score,
            chain_bonus=chain_bonus,
            matched_chains=matched_chains,
            final_score=final_score,
            recommended_priority=recommended_priority,
        )

        incident.correlated = True
        incident.correlation_score = final_score
        incident.correlation_summary = json.dumps(summary, ensure_ascii=False)

        incident.attack_chain = attack_chain
        incident.correlation_type = correlation_type
        incident.escalation_reason = escalation_reason
        incident.recommended_priority = recommended_priority

        if incident.risk_score is None or final_score > incident.risk_score:
            incident.risk_score = final_score

        if final_score >= 85 and incident.status in [None, "NEW", "TRIAGED"]:
            incident.status = "ESCALATED"

        db.commit()

        print("[green]Structured correlation completed[/green]")
        print(summary)

    finally:
        db.close()


def correlate_latest(limit=10):
    db = SessionLocal()

    try:
        incidents = (
            db.query(Incident)
            .filter(Incident.correlated == False)
            .order_by(Incident.id.desc())
            .limit(limit)
            .all()
        )

        ids = [incident.id for incident in incidents]

    finally:
        db.close()

    for incident_id in ids:
        correlate_incident(incident_id)


if __name__ == "__main__":
    correlate_latest()