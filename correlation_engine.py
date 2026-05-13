from datetime import datetime, timedelta, timezone

from database import SessionLocal
from models import Incident
from rich import print


SUSPICIOUS_KEYWORDS = {
    "ssh": 15,
    "failed": 20,
    "authentication failed": 25,
    "invalid user": 25,
    "sudo": 20,
    "session opened": 10,
    "useradd": 35,
    "new user": 35,
    "passwd": 25,
    "curl": 20,
    "wget": 20,
    "nmap": 30,
    "scanner": 30,
    "root": 20,
}


def parse_timestamp(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except Exception:
        return None


def calculate_keyword_score(text):
    if not text:
        return 0, []

    normalized = text.lower()
    score = 0
    matched = []

    for keyword, points in SUSPICIOUS_KEYWORDS.items():
        if keyword in normalized:
            score += points
            matched.append(keyword)

    return score, matched


def get_recent_incidents(db, agent, current_timestamp, minutes=15):
    if not agent or not current_timestamp:
        return []

    window_start = current_timestamp - timedelta(minutes=minutes)

    all_incidents = (
        db.query(Incident)
        .filter(Incident.agent == agent)
        .order_by(Incident.id.desc())
        .limit(100)
        .all()
    )

    recent = []

    for incident in all_incidents:
        ts = parse_timestamp(incident.timestamp)

        if ts and window_start <= ts <= current_timestamp:
            recent.append(incident)

    return recent


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
            minutes=15,
        )

        combined_text = " ".join(
            [
                str(item.rule or "")
                + " "
                + str(item.ai_analysis or "")
                + " "
                + str(item.raw_alert or "")
                for item in recent_incidents
            ]
        )

        keyword_score, matched_keywords = calculate_keyword_score(combined_text)

        volume_score = min(len(recent_incidents) * 5, 40)

        base_level = incident.level or 0

        correlation_score = min(
            base_level * 5 + keyword_score + volume_score,
            100,
        )

        summary = {
            "agent": incident.agent,
            "window_minutes": 15,
            "related_events": len(recent_incidents),
            "matched_keywords": matched_keywords,
            "base_level": base_level,
            "keyword_score": keyword_score,
            "volume_score": volume_score,
            "correlation_score": correlation_score,
        }

        incident.correlated = True
        incident.correlation_score = correlation_score
        incident.correlation_summary = str(summary)

        if incident.risk_score is None or correlation_score > incident.risk_score:
            incident.risk_score = correlation_score

        db.commit()

        print("[green]Correlation completed[/green]")
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