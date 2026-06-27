from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request

from case_action_suggestions import generate_case_action_suggestions
from case_ai_analysis import generate_case_ai_analysis
from case_ai_generation_jobs import (
    create_or_get_running_generation_job,
    get_generation_job,
    get_latest_generation_job,
    run_case_generation_job,
    serialize_generation_job,
)
from case_timeline import build_case_timeline
from database import SessionLocal
from models import CaseAIAnalysis, IncidentCase
from security.audit import security_audit_actor, write_security_audit


router = APIRouter()


@router.post("/cases/{case_id}/actions/suggestions")
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


@router.post("/cases/{case_id}/ai-generation/{job_type}")
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


@router.get("/cases/{case_id}/ai-generation/{job_type}/latest")
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


@router.get("/cases/{case_id}/ai-generation/jobs/{job_id}")
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


@router.get("/cases/{case_id}/timeline")
def get_case_timeline(case_id: int):
    try:
        return build_case_timeline(case_id)

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Resource not found.")


@router.get("/cases/{case_id}/analysis")
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


@router.post("/cases/{case_id}/analysis")
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
