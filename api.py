from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query, Response
from sqlalchemy import func, or_

from database import SessionLocal
from report_builder import build_case_report, build_incident_report
from case_ai_analysis import generate_case_ai_analysis
from models import Incident, IncidentAudit, IncidentNote, IncidentCase, CaseIncident, CaseAIAnalysis, CaseAudit
from timezone_utils import APP_TIMEZONE, format_timestamp_local, normalize_timestamp_utc
from platform_health import get_platform_health
from wazuh_ingest_state import get_watermark_snapshot

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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

VALID_CASE_STATUSES = {
    "OPEN",
    "TRIAGED",
    "INVESTIGATING",
    "ESCALATED",
    "CLOSED",
    "FALSE_POSITIVE",
}

VALID_CASE_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


class IncidentStatusUpdate(BaseModel):
    status: str
    comment: str | None = None


class IncidentNoteCreate(BaseModel):
    note: str
    created_by: str | None = None

class CaseWorkflowUpdate(BaseModel):
    owner: str | None = None
    status: str | None = None
    severity: str | None = None
    sla_due_at: str | None = None
    status_reason: str | None = None
    reviewed_by: str | None = None

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
    priority: str | None = Query(None),
    correlation_type: str | None = Query(None),
    correlated: str | None = Query(None),
    mitre: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
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

        if priority and priority.upper() != "ALL":
            query = query.filter(Incident.recommended_priority == priority.upper())

        if correlation_type:
            query = query.filter(Incident.correlation_type.ilike(f"%{correlation_type}%"))

        if mitre:
            query = query.filter(Incident.mitre.ilike(f"%{mitre}%"))

        if correlated and correlated.upper() != "ALL":
            correlated_value = correlated.lower()

            if correlated_value in {"true", "yes", "1"}:
                query = query.filter(Incident.correlated == True)
            elif correlated_value in {"false", "no", "0"}:
                query = query.filter(Incident.correlated == False)

        if date_from:
            query = query.filter(Incident.timestamp >= f"{date_from}T00:00:00+00:00")

        if date_to:
            query = query.filter(Incident.timestamp <= f"{date_to}T23:59:59+00:00")

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



@app.get("/incidents/{incident_id}/notes")
def get_incident_notes(incident_id: int):
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
            db.query(IncidentNote)
            .filter(IncidentNote.incident_id == incident_id)
            .order_by(IncidentNote.created_at.desc(), IncidentNote.id.desc())
            .all()
        )

        return [
            {
                "id": row.id,
                "incident_id": row.incident_id,
                "note": row.note,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]

    finally:
        db.close()


@app.post("/incidents/{incident_id}/notes")
def create_incident_note(
    incident_id: int,
    payload: IncidentNoteCreate,
):
    note_text = payload.note.strip()

    if not note_text:
        raise HTTPException(status_code=400, detail="Note cannot be empty")

    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        created_by = payload.created_by or "local_analyst"

        note = IncidentNote(
            incident_id=incident.id,
            note=note_text,
            created_by=created_by,
        )

        db.add(note)
        db.flush()

        audit = IncidentAudit(
            incident_id=incident.id,
            event_type="NOTE_ADDED",
            old_value=None,
            new_value=f"note:{note.id}",
            comment=note_text,
            created_by=created_by,
        )

        db.add(audit)
        db.commit()
        db.refresh(note)

        return {
            "id": note.id,
            "incident_id": note.incident_id,
            "note": note.note,
            "created_by": note.created_by,
            "created_at": note.created_at.isoformat() if note.created_at else None,
        }

    finally:
        db.close()



@app.get("/platform/health")
def platform_health():
    return get_platform_health()



@app.get("/platform/ingest/wazuh")
def wazuh_ingest_watermark():
    return get_watermark_snapshot()



@app.get("/executive/summary")
def executive_summary():
    db = SessionLocal()

    try:
        total_incidents = db.query(Incident).count()

        open_incidents = (
            db.query(Incident)
            .filter(~Incident.status.in_(["CLOSED", "FALSE_POSITIVE"]))
            .count()
        )

        escalated_incidents = (
            db.query(Incident)
            .filter(Incident.status == "ESCALATED")
            .count()
        )

        critical_incidents = (
            db.query(Incident)
            .filter(Incident.risk_score >= 81)
            .count()
        )

        high_or_critical_incidents = (
            db.query(Incident)
            .filter(Incident.risk_score >= 61)
            .count()
        )

        correlated_incidents = (
            db.query(Incident)
            .filter(Incident.correlated == True)
            .count()
        )

        avg_risk = db.query(func.avg(Incident.risk_score)).scalar()
        max_risk = db.query(func.max(Incident.risk_score)).scalar()

        total_cases = db.query(IncidentCase).count()

        open_cases = (
            db.query(IncidentCase)
            .filter(~IncidentCase.status.in_(["CLOSED", "FALSE_POSITIVE"]))
            .count()
        )

        escalated_cases = (
            db.query(IncidentCase)
            .filter(IncidentCase.status == "ESCALATED")
            .count()
        )

        critical_cases = (
            db.query(IncidentCase)
            .filter(IncidentCase.severity == "CRITICAL")
            .count()
        )

        latest_cases = (
            db.query(IncidentCase)
            .order_by(IncidentCase.updated_at.desc(), IncidentCase.id.desc())
            .limit(5)
            .all()
        )

        latest_high_risk_incidents = (
            db.query(Incident)
            .filter(Incident.risk_score >= 61)
            .order_by(Incident.timestamp.desc().nullslast(), Incident.id.desc())
            .limit(5)
            .all()
        )

        top_hosts_rows = (
            db.query(
                Incident.agent,
                func.count(Incident.id).label("count"),
                func.max(Incident.risk_score).label("max_risk"),
                func.avg(Incident.risk_score).label("avg_risk"),
            )
            .group_by(Incident.agent)
            .order_by(func.max(Incident.risk_score).desc(), func.count(Incident.id).desc())
            .limit(5)
            .all()
        )

        case_status_rows = (
            db.query(
                IncidentCase.status,
                func.count(IncidentCase.id).label("count"),
            )
            .group_by(IncidentCase.status)
            .all()
        )

        incident_status_rows = (
            db.query(
                Incident.status,
                func.count(Incident.id).label("count"),
            )
            .group_by(Incident.status)
            .all()
        )

        priority_rows = (
            db.query(
                Incident.recommended_priority,
                func.count(Incident.id).label("count"),
            )
            .group_by(Incident.recommended_priority)
            .all()
        )

        correlation_type_rows = (
            db.query(
                Incident.correlation_type,
                func.count(Incident.id).label("count"),
            )
            .filter(Incident.correlation_type.isnot(None))
            .group_by(Incident.correlation_type)
            .order_by(func.count(Incident.id).desc())
            .limit(5)
            .all()
        )

        latest_case_analysis = (
            db.query(CaseAIAnalysis)
            .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
            .first()
        )

        recommendations = []

        if critical_incidents > 0 or critical_cases > 0:
            recommendations.append(
                "Review critical incidents and critical cases before closing operational backlog."
            )

        if escalated_incidents > 0 or escalated_cases > 0:
            recommendations.append(
                "Escalated items require management visibility and explicit ownership."
            )

        if open_cases > 0:
            recommendations.append(
                "Keep investigation cases updated with analyst notes and AI case analysis."
            )

        if high_or_critical_incidents == 0 and open_cases == 0:
            recommendations.append(
                "No immediate high-risk backlog detected. Continue monitoring and validate ingestion health."
            )

        executive_status = "OK"

        if critical_incidents > 0 or critical_cases > 0:
            executive_status = "CRITICAL"
        elif escalated_incidents > 0 or escalated_cases > 0 or high_or_critical_incidents > 0:
            executive_status = "ATTENTION"

        return {
            "status": executive_status,
            "summary": {
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "escalated_incidents": escalated_incidents,
                "critical_incidents": critical_incidents,
                "high_or_critical_incidents": high_or_critical_incidents,
                "correlated_incidents": correlated_incidents,
                "total_cases": total_cases,
                "open_cases": open_cases,
                "escalated_cases": escalated_cases,
                "critical_cases": critical_cases,
                "average_risk_score": round(float(avg_risk or 0), 2),
                "max_risk_score": int(max_risk or 0),
            },
            "distributions": {
                "incident_status": {
                    row.status or "NEW": row.count
                    for row in incident_status_rows
                },
                "case_status": {
                    row.status or "OPEN": row.count
                    for row in case_status_rows
                },
                "priority": {
                    row.recommended_priority or "UNSPECIFIED": row.count
                    for row in priority_rows
                },
            },
            "top_hosts": [
                {
                    "agent": row.agent,
                    "count": row.count,
                    "max_risk": int(row.max_risk or 0),
                    "average_risk": round(float(row.avg_risk or 0), 2),
                }
                for row in top_hosts_rows
            ],
            "top_correlation_types": [
                {
                    "correlation_type": row.correlation_type,
                    "count": row.count,
                }
                for row in correlation_type_rows
            ],
            "latest_cases": [
                {
                    "id": item.id,
                    "title": item.title,
                    "status": item.status,
                    "severity": item.severity,
                    "agent": item.agent,
                    "correlation_type": item.correlation_type,
                    "risk_score": item.risk_score,
                    "updated_at": item.updated_at.isoformat() if item.updated_at else None,
                }
                for item in latest_cases
            ],
            "latest_high_risk_incidents": [
                {
                    "id": item.id,
                    "status": item.status,
                    "timestamp": normalize_timestamp_utc(item.timestamp),
                    "timestamp_local": format_timestamp_local(item.timestamp),
                    "agent": item.agent,
                    "rule": item.rule,
                    "risk_score": item.risk_score,
                    "recommended_priority": item.recommended_priority,
                    "correlation_type": item.correlation_type,
                }
                for item in latest_high_risk_incidents
            ],
            "latest_case_analysis": {
                "id": latest_case_analysis.id,
                "case_id": latest_case_analysis.case_id,
                "model": latest_case_analysis.model,
                "recommended_status": latest_case_analysis.recommended_status,
                "recommended_severity": latest_case_analysis.recommended_severity,
                "created_at": latest_case_analysis.created_at.isoformat()
                if latest_case_analysis.created_at
                else None,
            }
            if latest_case_analysis
            else None,
            "recommendations": recommendations,
        }

    finally:
        db.close()



@app.get("/reports/incidents/{incident_id}")
def export_incident_report(
    incident_id: int,
    format: str = Query("markdown"),
):
    if format not in {"markdown", "json"}:
        raise HTTPException(status_code=400, detail="format must be markdown or json")

    try:
        report = build_incident_report(incident_id)

    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if format == "json":
        filename = report["filename"].replace(".md", ".json")

        return JSONResponse(
            content=report["payload"],
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    return Response(
        content=report["markdown"],
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{report["filename"]}"',
        },
    )


@app.get("/reports/cases/{case_id}")
def export_case_report(
    case_id: int,
    format: str = Query("markdown"),
):
    if format not in {"markdown", "json"}:
        raise HTTPException(status_code=400, detail="format must be markdown or json")

    try:
        report = build_case_report(case_id)

    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if format == "json":
        filename = report["filename"].replace(".md", ".json")

        return JSONResponse(
            content=report["payload"],
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    return Response(
        content=report["markdown"],
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{report["filename"]}"',
        },
    )

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


def calculate_case_sla_status(case: IncidentCase) -> str:
    status = (case.status or "OPEN").upper()

    if status in {"CLOSED", "FALSE_POSITIVE"}:
        return "COMPLETED"

    if not case.sla_due_at:
        return "NOT_SET"

    due_at = case.sla_due_at

    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    if now <= due_at:
        return "WITHIN_SLA"

    return "BREACHED"


def serialize_case(case: IncidentCase, incident_count: int | None = None) -> dict:
    return {
        "id": case.id,
        "group_key": case.group_key,
        "title": case.title,
        "status": case.status,
        "severity": case.severity,
        "agent": case.agent,
        "correlation_type": case.correlation_type,
        "risk_score": case.risk_score,
        "summary": case.summary,
        "created_by": case.created_by,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "incident_count": incident_count,
        "owner": case.owner,
        "sla_due_at": case.sla_due_at.isoformat() if case.sla_due_at else None,
        "sla_status": calculate_case_sla_status(case),
        "severity_review": case.severity_review,
        "status_reason": case.status_reason,
        "last_reviewed_by": case.last_reviewed_by,
        "last_reviewed_at": case.last_reviewed_at.isoformat()
        if case.last_reviewed_at
        else None,
    }

@app.get("/cases")
def list_cases(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    host: str | None = Query(None),
):
    db = SessionLocal()

    try:
        offset = (page - 1) * limit

        incident_count_subquery = (
            db.query(
                CaseIncident.case_id.label("case_id"),
                func.count(CaseIncident.incident_id).label("incident_count"),
            )
            .group_by(CaseIncident.case_id)
            .subquery()
        )

        query = (
            db.query(
                IncidentCase,
                func.coalesce(incident_count_subquery.c.incident_count, 0).label(
                    "incident_count"
                ),
            )
            .outerjoin(
                incident_count_subquery,
                IncidentCase.id == incident_count_subquery.c.case_id,
            )
        )

        if status and status.upper() != "ALL":
            query = query.filter(IncidentCase.status == status.upper())

        if severity and severity.upper() != "ALL":
            query = query.filter(IncidentCase.severity == severity.upper())

        if host:
            query = query.filter(IncidentCase.agent.ilike(f"%{host}%"))

        total = query.with_entities(func.count(IncidentCase.id)).scalar() or 0

        rows = (
            query.order_by(IncidentCase.updated_at.desc(), IncidentCase.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        total_pages = max((total + limit - 1) // limit, 1)

        return {
            "items": [
                serialize_case(case, incident_count)
                for case, incident_count in rows
            ],
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        }

    finally:
        db.close()


@app.get("/cases/{case_id}")
def get_case(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        incident_count = (
            db.query(CaseIncident)
            .filter(CaseIncident.case_id == case.id)
            .count()
        )

        return serialize_case(case, incident_count)

    finally:
        db.close()

@app.patch("/cases/{case_id}/workflow")
def update_case_workflow(
    case_id: int,
    payload: CaseWorkflowUpdate,
):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        reviewed_by = payload.reviewed_by or "local_analyst"
        changes = {}

        if payload.owner is not None:
            owner = payload.owner.strip() or None
            if case.owner != owner:
                changes["owner"] = [case.owner, owner]
                case.owner = owner

        if payload.status is not None:
            requested_status = payload.status.upper()

            if requested_status not in VALID_CASE_STATUSES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid case status. Allowed values: {sorted(VALID_CASE_STATUSES)}",
                )

            if case.status != requested_status:
                changes["status"] = [case.status, requested_status]
                case.status = requested_status

        if payload.severity is not None:
            requested_severity = payload.severity.upper()

            if requested_severity not in VALID_CASE_SEVERITIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid case severity. Allowed values: {sorted(VALID_CASE_SEVERITIES)}",
                )

            if case.severity != requested_severity:
                changes["severity"] = [case.severity, requested_severity]
                changes["severity_review"] = [case.severity_review, requested_severity]
                case.severity = requested_severity
                case.severity_review = requested_severity

        if payload.sla_due_at is not None:
            sla_due_at = None

            if payload.sla_due_at.strip():
                try:
                    sla_due_at = datetime.fromisoformat(
                        payload.sla_due_at.replace("Z", "+00:00")
                    )
                except ValueError as exc:
                    raise HTTPException(
                        status_code=400,
                        detail="sla_due_at must be a valid ISO timestamp",
                    ) from exc

            if case.sla_due_at != sla_due_at:
                old_value = case.sla_due_at.isoformat() if case.sla_due_at else None
                new_value = sla_due_at.isoformat() if sla_due_at else None
                changes["sla_due_at"] = [old_value, new_value]
                case.sla_due_at = sla_due_at

        if payload.status_reason is not None:
            status_reason = payload.status_reason.strip() or None

            if case.status_reason != status_reason:
                changes["status_reason"] = [case.status_reason, status_reason]
                case.status_reason = status_reason

        if changes:
            now = datetime.now(timezone.utc)
            case.last_reviewed_by = reviewed_by
            case.last_reviewed_at = now
            case.updated_at = now

            audit = CaseAudit(
                case_id=case.id,
                event_type="CASE_WORKFLOW_UPDATED",
                old_value=str({key: value[0] for key, value in changes.items()}),
                new_value=str({key: value[1] for key, value in changes.items()}),
                comment=payload.status_reason,
                created_by=reviewed_by,
            )

            db.add(audit)

        db.commit()
        db.refresh(case)

        incident_count = (
            db.query(CaseIncident)
            .filter(CaseIncident.case_id == case.id)
            .count()
        )

        return serialize_case(case, incident_count)

    finally:
        db.close()


@app.get("/cases/{case_id}/audit")
def get_case_audit(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        rows = (
            db.query(CaseAudit)
            .filter(CaseAudit.case_id == case_id)
            .order_by(CaseAudit.created_at.asc(), CaseAudit.id.asc())
            .all()
        )

        return [
            {
                "id": row.id,
                "case_id": row.case_id,
                "event_type": row.event_type,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment": row.comment,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat()
                if row.created_at
                else None,
            }
            for row in rows
        ]

    finally:
        db.close()

@app.get("/cases/{case_id}/incidents")
def get_case_incidents(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        rows = (
            db.query(Incident)
            .join(CaseIncident, CaseIncident.incident_id == Incident.id)
            .filter(CaseIncident.case_id == case_id)
            .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
            .all()
        )

        return [
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
            for item in rows
        ]

    finally:
        db.close()

@app.get("/cases/{case_id}/analysis")
def get_case_analysis(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        row = (
            db.query(CaseAIAnalysis)
            .filter(CaseAIAnalysis.case_id == case_id)
            .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
            .first()
        )

        if not row:
            return {"item": None}

        return {
            "item": {
                "id": row.id,
                "case_id": row.case_id,
                "model": row.model,
                "analysis": row.analysis,
                "recommended_status": row.recommended_status,
                "recommended_severity": row.recommended_severity,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        }

    finally:
        db.close()


@app.post("/cases/{case_id}/analysis")
def create_case_analysis(case_id: int):
    try:
        row = generate_case_ai_analysis(case_id)

        return {
            "id": row.id,
            "case_id": row.case_id,
            "model": row.model,
            "analysis": row.analysis,
            "recommended_status": row.recommended_status,
            "recommended_severity": row.recommended_severity,
            "created_by": row.created_by,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

