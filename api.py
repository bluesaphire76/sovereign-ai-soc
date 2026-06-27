from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Query, Response, Depends, Request, BackgroundTasks
from sqlalchemy import func

from database import SessionLocal
from case_ai_analysis import generate_case_ai_analysis
from case_action_suggestions import generate_case_action_suggestions
from case_ai_generation_jobs import (
    create_or_get_running_generation_job,
    get_generation_job,
    get_latest_generation_job,
    run_case_generation_job,
    serialize_generation_job,
)
from case_timeline import build_case_timeline
from models import Incident, IncidentCase, CaseAIAnalysis, RawEvent, SecurityAlert, EventAggregate
from timezone_utils import APP_TIMEZONE, format_timestamp_local, normalize_timestamp_utc
from wazuh_ingest_state import get_watermark_snapshot
from routers import include_app_routers
from security.audit import security_audit_actor, write_security_audit
from security.auth import get_current_user, require_admin
from security.rbac import (
    enforce_api_authentication,
    is_request_authorized,
)

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Sovereign AI SOC API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://localhost:8443",
        "http://localhost:8443",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

include_app_routers(app)
app.middleware("http")(enforce_api_authentication)

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
            .filter(~IncidentCase.status.in_(["CLOSED", "FALSE_POSITIVE"]))
            .order_by(IncidentCase.updated_at.desc(), IncidentCase.id.desc())
            .limit(5)
            .all()
        )

        latest_high_risk_incidents = (
            db.query(Incident)
            .filter(
                Incident.risk_score >= 61,
                ~Incident.status.in_(["CLOSED", "FALSE_POSITIVE"]),
            )
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

        now = datetime.now(timezone.utc)
        due_soon_cutoff = now + timedelta(hours=24)

        open_case_query = db.query(IncidentCase).filter(
            ~IncidentCase.status.in_(["CLOSED", "FALSE_POSITIVE"])
        )

        cases_with_sla = (
            open_case_query
            .filter(IncidentCase.sla_due_at.isnot(None))
            .count()
        )

        sla_missing = (
            open_case_query
            .filter(IncidentCase.sla_due_at.is_(None))
            .count()
        )

        sla_overdue = (
            open_case_query
            .filter(
                IncidentCase.sla_due_at.isnot(None),
                IncidentCase.sla_due_at < now,
            )
            .count()
        )

        sla_due_soon = (
            open_case_query
            .filter(
                IncidentCase.sla_due_at.isnot(None),
                IncidentCase.sla_due_at >= now,
                IncidentCase.sla_due_at <= due_soon_cutoff,
            )
            .count()
        )

        sla_on_track = max(cases_with_sla - sla_overdue - sla_due_soon, 0)

        sla_status = "OK"

        if sla_overdue > 0:
            sla_status = "BREACHED"
        elif sla_due_soon > 0 or sla_missing > 0:
            sla_status = "ATTENTION"

        incident_ai_analyzed = (
            db.query(Incident)
            .filter(
                Incident.ai_analysis.isnot(None),
                Incident.ai_analysis != "",
            )
            .count()
        )

        case_ai_analyzed = (
            db.query(func.count(func.distinct(CaseAIAnalysis.case_id))).scalar()
            or 0
        )

        total_case_analyses = db.query(CaseAIAnalysis).count()
        ai_supported_items = incident_ai_analyzed + case_ai_analyzed
        ai_total_items = total_incidents + total_cases

        raw_events = db.query(RawEvent).count()
        security_alerts = db.query(SecurityAlert).count()
        incident_created_alerts = (
            db.query(SecurityAlert)
            .filter(SecurityAlert.incident_id.isnot(None))
            .count()
        )
        observed_only_alerts = max(security_alerts - incident_created_alerts, 0)
        event_aggregates = db.query(EventAggregate).count()
        duplicate_events_collapsed = (
            db.query(func.coalesce(func.sum(EventAggregate.count - 1), 0))
            .filter(EventAggregate.count > 1)
            .scalar()
            or 0
        )
        reduction_denominator = max(raw_events, security_alerts, 1)
        reduction_numerator = max(reduction_denominator - total_incidents, 0)

        decision = "Monitor"
        decision_reason = "No immediate executive escalation pressure detected."
        decision_next_action = "Continue monitoring SLA, ingestion health and high-risk queues."

        if sla_overdue > 0:
            decision = "Escalate"
            decision_reason = "One or more open cases have breached SLA."
            decision_next_action = "Assign ownership and review breached cases before closure activity."
        elif critical_incidents > 0 or critical_cases > 0:
            decision = "Escalate"
            decision_reason = "Critical incident or case exposure is present."
            decision_next_action = "Run executive review on critical exposure and confirm containment."
        elif escalated_incidents > 0 or escalated_cases > 0:
            decision = "Review"
            decision_reason = "Escalated items require management visibility."
            decision_next_action = "Confirm owner, priority and next analyst action for escalated records."
        elif high_or_critical_incidents > 0 or sla_due_soon > 0:
            decision = "Review"
            decision_reason = "High-risk exposure or near-term SLA pressure exists."
            decision_next_action = "Validate open high-risk incidents and cases due within 24 hours."

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
            "decision_brief": {
                "decision": decision,
                "reason": decision_reason,
                "next_action": decision_next_action,
            },
            "sla_posture": {
                "status": sla_status,
                "open_cases": open_cases,
                "cases_with_sla": cases_with_sla,
                "on_track": sla_on_track,
                "due_soon": sla_due_soon,
                "overdue": sla_overdue,
                "missing_sla": sla_missing,
                "coverage_percent": round(
                    (cases_with_sla / max(open_cases, 1)) * 100,
                    1,
                ),
            },
            "ai_triage_contribution": {
                "incident_ai_analyzed": incident_ai_analyzed,
                "total_incidents": total_incidents,
                "incident_coverage_percent": round(
                    (incident_ai_analyzed / max(total_incidents, 1)) * 100,
                    1,
                ),
                "case_ai_analyzed": case_ai_analyzed,
                "total_cases": total_cases,
                "case_coverage_percent": round(
                    (case_ai_analyzed / max(total_cases, 1)) * 100,
                    1,
                ),
                "total_case_analyses": total_case_analyses,
                "overall_coverage_percent": round(
                    (ai_supported_items / max(ai_total_items, 1)) * 100,
                    1,
                ),
                "latest_analysis_at": latest_case_analysis.created_at.isoformat()
                if latest_case_analysis and latest_case_analysis.created_at
                else None,
            },
            "noise_reduction": {
                "raw_events": raw_events,
                "security_alerts": security_alerts,
                "incidents_created": total_incidents,
                "incident_created_alerts": incident_created_alerts,
                "observed_only_alerts": observed_only_alerts,
                "event_aggregates": event_aggregates,
                "duplicate_events_collapsed": int(duplicate_events_collapsed),
                "incident_creation_rate_percent": round(
                    (total_incidents / max(security_alerts, 1)) * 100,
                    1,
                ),
                "reduction_percent": round(
                    (reduction_numerator / reduction_denominator) * 100,
                    1,
                ),
            },
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


@app.post("/cases/{case_id}/actions/suggestions")
def suggest_case_action_plan(case_id: int, request: Request):
    try:
        result = generate_case_action_suggestions(case_id)

        write_security_audit(
            event_type="CASE_ACTION_SUGGESTIONS_GENERATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="CASE",
            target_id=case_id,
            request=request,
            details={
                "result_type": type(result).__name__,
            },
        )

        return result

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Resource not found.")

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to generate case action suggestions.",
        )


def run_case_generation_job_with_audit(job_id: str, current_user: dict | None = None):
    result = run_case_generation_job(job_id)

    if not result:
        return

    status = result.get("status")
    write_security_audit(
        event_type="CASE_AI_GENERATION_JOB_COMPLETED",
        outcome="SUCCESS" if status == "SUCCESS" else "FAILURE",
        current_user=current_user,
        target_type="CASE",
        target_id=result.get("case_id"),
        details={
            "job_id": result.get("job_id"),
            "job_type": result.get("job_type"),
            "status": status,
            "result_reference_id": result.get("result_reference_id"),
            "error": result.get("error"),
        },
    )


@app.post("/cases/{case_id}/ai-generation/{job_type}")
def start_case_ai_generation_job(
    case_id: int,
    job_type: str,
    background_tasks: BackgroundTasks,
    request: Request,
):
    db = SessionLocal()
    current_user = security_audit_actor(request)

    try:
        job, created = create_or_get_running_generation_job(
            db,
            case_id=case_id,
            job_type=job_type,
            current_user=current_user,
        )
        payload = serialize_generation_job(job)

        if created:
            background_tasks.add_task(
                run_case_generation_job_with_audit,
                payload["job_id"],
                current_user,
            )

        write_security_audit(
            event_type="CASE_AI_GENERATION_JOB_STARTED" if created else "CASE_AI_GENERATION_JOB_REUSED",
            outcome="SUCCESS",
            current_user=current_user,
            target_type="CASE",
            target_id=case_id,
            request=request,
            details={
                "job_id": payload["job_id"],
                "job_type": payload["job_type"],
                "status": payload["status"],
            },
        )

        return payload

    except ValueError as exc:
        if "Unsupported" in str(exc):
            raise HTTPException(status_code=400, detail=str(exc))
        raise HTTPException(status_code=404, detail="Resource not found.")

    finally:
        db.close()


@app.get("/cases/{case_id}/ai-generation/{job_type}/latest")
def get_latest_case_ai_generation_job(case_id: int, job_type: str):
    db = SessionLocal()

    try:
        job = get_latest_generation_job(db, case_id=case_id, job_type=job_type)
        return {"item": serialize_generation_job(job) if job else None}

    except ValueError as exc:
        if "Unsupported" in str(exc):
            raise HTTPException(status_code=400, detail=str(exc))
        raise HTTPException(status_code=404, detail="Resource not found.")

    finally:
        db.close()


@app.get("/cases/{case_id}/ai-generation/jobs/{job_id}")
def get_case_ai_generation_job(case_id: int, job_id: str):
    db = SessionLocal()

    try:
        job = get_generation_job(db, case_id=case_id, job_id=job_id)

        if not job:
            raise HTTPException(status_code=404, detail="Job not found.")

        return serialize_generation_job(job)

    except ValueError:
        raise HTTPException(status_code=404, detail="Resource not found.")

    finally:
        db.close()


@app.get("/cases/{case_id}/timeline")
def get_case_timeline(case_id: int):
    try:
        return build_case_timeline(case_id)

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Resource not found.")


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
def create_case_analysis(case_id: int, request: Request):
    try:
        row = generate_case_ai_analysis(case_id)

        write_security_audit(
            event_type="CASE_AI_ANALYSIS_GENERATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="CASE",
            target_id=case_id,
            request=request,
            details={
                "analysis_id": row.id,
                "model": row.model,
                "recommended_status": row.recommended_status,
                "recommended_severity": row.recommended_severity,
            },
        )

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
        raise HTTPException(status_code=404, detail="Resource not found.")
