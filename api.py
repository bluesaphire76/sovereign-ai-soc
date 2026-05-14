from fastapi import FastAPI, HTTPException, Query
from sqlalchemy import func, or_

from database import SessionLocal
from models import Incident, IncidentAudit
from timezone_utils import APP_TIMEZONE, format_timestamp_local, normalize_timestamp_utc

from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel

app = FastAPI(
    title="Sovereign AI SOC API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

VALID_INCIDENT_STATUSES = {
    "NEW",
    "TRIAGED",
    "ESCALATED",
    "CLOSED",
    "FALSE_POSITIVE",
}


class IncidentStatusUpdate(BaseModel):
    status: str
    comment: str | None = None

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "sovereign-ai-soc-api",
    }


@app.get("/incidents")
def list_incidents(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    risk: str | None = Query(None),
    host: str | None = Query(None),
    search: str | None = Query(None),
):
    db = SessionLocal()

    try:
        offset = (page - 1) * limit

        query = db.query(Incident)

        if status and status.upper() != "ALL":
            query = query.filter(Incident.status == status.upper())

        if host:
            query = query.filter(Incident.agent.ilike(f"%{host}%"))

        if search:
            query = query.filter(Incident.rule.ilike(f"%{search}%"))

        if risk and risk.upper() != "ALL":
            risk_value = risk.lower()

            if risk_value == "low":
                query = query.filter(
                    or_(
                        Incident.risk_score.is_(None),
                        Incident.risk_score <= 30,
                    )
                )
            elif risk_value == "medium":
                query = query.filter(
                    Incident.risk_score >= 31,
                    Incident.risk_score <= 60,
                )
            elif risk_value == "high":
                query = query.filter(
                    Incident.risk_score >= 61,
                    Incident.risk_score <= 80,
                )
            elif risk_value == "critical":
                query = query.filter(Incident.risk_score >= 81)

        total = query.with_entities(func.count(Incident.id)).scalar() or 0

        incidents = (
            query.order_by(Incident.timestamp.desc().nullslast(), Incident.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        total_pages = max((total + limit - 1) // limit, 1)

        return {
            "items": [
                {
                    "id": item.id,
                    "status": item.status,
                    "timestamp": normalize_timestamp_utc(item.timestamp),
                    "timestamp_local": format_timestamp_local(item.timestamp),
                    "timezone": APP_TIMEZONE,
                    "agent": item.agent,
                    "rule": item.rule,
                    "level": item.level,
                    "risk_score": item.risk_score,
                    "correlation_score": item.correlation_score,
                    "correlated": item.correlated,
                    "correlation_type": item.correlation_type,
                    "recommended_priority": item.recommended_priority,
                }
                for item in incidents
            ],
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        }

    finally:
        db.close()


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        return {
            "id": incident.id,
            "status": incident.status,
            "wazuh_doc_id": incident.wazuh_doc_id,
            "timestamp": normalize_timestamp_utc(incident.timestamp),
            "timestamp_local": format_timestamp_local(incident.timestamp),
            "timezone": APP_TIMEZONE,
            "agent": incident.agent,
            "rule": incident.rule,
            "level": incident.level,
            "mitre": incident.mitre,
            "risk_score": incident.risk_score,
            "ai_analysis": incident.ai_analysis,
            "correlated": incident.correlated,
            "correlation_score": incident.correlation_score,
            "correlation_summary": incident.correlation_summary,
            "raw_alert": incident.raw_alert,
            "attack_chain": incident.attack_chain,
            "correlation_type": incident.correlation_type,
            "escalation_reason": incident.escalation_reason,
            "recommended_priority": incident.recommended_priority,
        }

    finally:
        db.close()

@app.patch("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
):
    requested_status = payload.status.upper()

    if requested_status not in VALID_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed values: {sorted(VALID_INCIDENT_STATUSES)}",
        )

    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        old_status = incident.status or "NEW"

        if old_status != requested_status:
            audit = IncidentAudit(
                incident_id=incident.id,
                event_type="STATUS_CHANGE",
                old_value=old_status,
                new_value=requested_status,
                comment=payload.comment,
                created_by="local_analyst",
            )

            db.add(audit)
            incident.status = requested_status

        db.commit()
        db.refresh(incident)

        return {
            "id": incident.id,
            "status": incident.status,
            "message": "Incident status updated",
        }

    finally:
        db.close()



@app.get("/incidents/{incident_id}/audit")
def get_incident_audit(incident_id: int):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        rows = (
            db.query(IncidentAudit)
            .filter(IncidentAudit.incident_id == incident_id)
            .order_by(IncidentAudit.created_at.asc(), IncidentAudit.id.asc())
            .all()
        )

        return [
            {
                "id": row.id,
                "incident_id": row.incident_id,
                "event_type": row.event_type,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment": row.comment,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]

    finally:
        db.close()

@app.get("/metrics/status-distribution")
def metrics_status_distribution():
    db = SessionLocal()

    try:
        rows = (
            db.query(
                Incident.status,
                func.count(Incident.id).label("count"),
            )
            .group_by(Incident.status)
            .all()
        )

        result = {
            "NEW": 0,
            "TRIAGED": 0,
            "ESCALATED": 0,
            "CLOSED": 0,
            "FALSE_POSITIVE": 0,
        }

        for row in rows:
            result[row.status or "NEW"] = row.count

        return result

    finally:
        db.close()

@app.get("/metrics/summary")
def metrics_summary():
    db = SessionLocal()

    try:
        total = db.query(Incident).count()

        avg_risk = (
            db.query(func.avg(Incident.risk_score))
            .scalar()
        )

        max_risk = (
            db.query(func.max(Incident.risk_score))
            .scalar()
        )

        correlated = (
            db.query(Incident)
            .filter(Incident.correlated == True)
            .count()
        )

        return {
            "total_incidents": total,
            "average_risk_score": round(float(avg_risk or 0), 2),
            "max_risk_score": int(max_risk or 0),
            "correlated_incidents": correlated,
        }

    finally:
        db.close()


@app.get("/metrics/top-hosts")
def metrics_top_hosts(limit: int = 10):
    db = SessionLocal()

    try:
        rows = (
            db.query(
                Incident.agent,
                func.count(Incident.id).label("count"),
                func.max(Incident.risk_score).label("max_risk"),
            )
            .group_by(Incident.agent)
            .order_by(func.count(Incident.id).desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "agent": row.agent,
                "count": row.count,
                "max_risk": row.max_risk,
            }
            for row in rows
        ]

    finally:
        db.close()


@app.get("/metrics/risk-distribution")
def metrics_risk_distribution():
    db = SessionLocal()

    try:
        incidents = db.query(Incident).all()

        buckets = {
            "low_0_30": 0,
            "medium_31_60": 0,
            "high_61_80": 0,
            "critical_81_100": 0,
        }

        for incident in incidents:
            score = incident.risk_score or 0

            if score <= 30:
                buckets["low_0_30"] += 1
            elif score <= 60:
                buckets["medium_31_60"] += 1
            elif score <= 80:
                buckets["high_61_80"] += 1
            else:
                buckets["critical_81_100"] += 1

        return buckets

    finally:
        db.close()

