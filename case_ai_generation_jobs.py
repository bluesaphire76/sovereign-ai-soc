from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from case_action_suggestions import generate_case_action_suggestions
from case_ai_analysis import generate_case_ai_analysis
from database import SessionLocal
from models import CaseAIAnalysis, CaseAiGenerationJob, IncidentCase, utc_now

JOB_TYPE_ANALYSIS = "analysis"
JOB_TYPE_ACTION_SUGGESTIONS = "action_suggestions"
PUBLIC_JOB_TYPE_ACTION_SUGGESTIONS = "action-suggestions"

JOB_STATUS_PENDING = "PENDING"
JOB_STATUS_RUNNING = "RUNNING"
JOB_STATUS_SUCCESS = "SUCCESS"
JOB_STATUS_ERROR = "ERROR"

RUNNING_STATUSES = {JOB_STATUS_PENDING, JOB_STATUS_RUNNING}
TERMINAL_STATUSES = {JOB_STATUS_SUCCESS, JOB_STATUS_ERROR}

DEFAULT_STALE_SECONDS = 60 * 60


def normalize_job_type(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")

    if normalized == JOB_TYPE_ANALYSIS:
        return JOB_TYPE_ANALYSIS

    if normalized == JOB_TYPE_ACTION_SUGGESTIONS:
        return JOB_TYPE_ACTION_SUGGESTIONS

    raise ValueError("Unsupported case AI generation job type.")


def public_job_type(value: str) -> str:
    normalized = normalize_job_type(value)

    if normalized == JOB_TYPE_ACTION_SUGGESTIONS:
        return PUBLIC_JOB_TYPE_ACTION_SUGGESTIONS

    return normalized


def _job_stale_seconds() -> int:
    try:
        return max(int(os.getenv("CASE_AI_GENERATION_JOB_STALE_SECONDS", DEFAULT_STALE_SECONDS)), 60)
    except Exception:
        return DEFAULT_STALE_SECONDS


def _as_aware_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _is_stale_running_job(job: CaseAiGenerationJob, *, now: datetime) -> bool:
    if job.status not in RUNNING_STATUSES:
        return False

    reference = _as_aware_utc(job.updated_at or job.started_at or job.created_at)
    if reference is None:
        return False

    return reference < now - timedelta(seconds=_job_stale_seconds())


def _json_loads(value: str | None) -> Any:
    if not value:
        return None

    try:
        return json.loads(value)
    except Exception:
        return None


def _isoformat(value: datetime | None) -> str | None:
    if not value:
        return None

    return value.isoformat()


def _safe_generation_error(exc: Exception) -> str:
    value = str(exc).strip() or exc.__class__.__name__

    if "timeout" in value.lower() or "timeout" in exc.__class__.__name__.lower():
        return (
            "AI generation timed out before the model returned a response. "
            "Retry the generation or increase CASE_AI_GENERATION_TIMEOUT_SECONDS."
        )

    return value[:1000]


def serialize_case_ai_analysis(row: CaseAIAnalysis) -> dict[str, Any]:
    return {
        "id": row.id,
        "case_id": row.case_id,
        "model": row.model,
        "analysis": row.analysis,
        "recommended_status": row.recommended_status,
        "recommended_severity": row.recommended_severity,
        "created_by": row.created_by,
        "created_at": _isoformat(row.created_at),
    }


def serialize_generation_job(job: CaseAiGenerationJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "case_id": job.case_id,
        "job_type": public_job_type(job.job_type),
        "status": job.status,
        "requested_by_username": job.requested_by_username,
        "result_reference_id": job.result_reference_id,
        "result": _json_loads(job.result_json),
        "error": job.error,
        "started_at": _isoformat(job.started_at),
        "finished_at": _isoformat(job.finished_at),
        "created_at": _isoformat(job.created_at),
        "updated_at": _isoformat(job.updated_at),
    }


def ensure_case_exists(db, case_id: int) -> IncidentCase:
    row = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()

    if not row:
        raise ValueError(f"Case {case_id} not found")

    return row


def _latest_job_query(db, *, case_id: int, job_type: str):
    return (
        db.query(CaseAiGenerationJob)
        .filter(CaseAiGenerationJob.case_id == case_id)
        .filter(CaseAiGenerationJob.job_type == normalize_job_type(job_type))
        .order_by(CaseAiGenerationJob.created_at.desc(), CaseAiGenerationJob.id.desc())
    )


def get_latest_generation_job(db, *, case_id: int, job_type: str) -> CaseAiGenerationJob | None:
    ensure_case_exists(db, case_id)
    return _latest_job_query(db, case_id=case_id, job_type=job_type).first()


def get_generation_job(db, *, case_id: int, job_id: str) -> CaseAiGenerationJob | None:
    ensure_case_exists(db, case_id)

    return (
        db.query(CaseAiGenerationJob)
        .filter(CaseAiGenerationJob.case_id == case_id)
        .filter(CaseAiGenerationJob.job_id == str(job_id))
        .first()
    )


def _mark_stale_running_jobs(db, *, case_id: int, job_type: str, now: datetime) -> None:
    rows = (
        db.query(CaseAiGenerationJob)
        .filter(CaseAiGenerationJob.case_id == case_id)
        .filter(CaseAiGenerationJob.job_type == normalize_job_type(job_type))
        .filter(CaseAiGenerationJob.status.in_(RUNNING_STATUSES))
        .all()
    )

    changed = False

    for row in rows:
        if not _is_stale_running_job(row, now=now):
            continue

        row.status = JOB_STATUS_ERROR
        row.error = "Generation job expired before completion. Start a new generation."
        row.finished_at = now
        row.updated_at = now
        changed = True

    if changed:
        db.commit()


def create_or_get_running_generation_job(
    db,
    *,
    case_id: int,
    job_type: str,
    current_user: dict[str, Any] | None,
) -> tuple[CaseAiGenerationJob, bool]:
    normalized_job_type = normalize_job_type(job_type)
    ensure_case_exists(db, case_id)

    now = utc_now()
    _mark_stale_running_jobs(db, case_id=case_id, job_type=normalized_job_type, now=now)

    existing = (
        db.query(CaseAiGenerationJob)
        .filter(CaseAiGenerationJob.case_id == case_id)
        .filter(CaseAiGenerationJob.job_type == normalized_job_type)
        .filter(CaseAiGenerationJob.status.in_(RUNNING_STATUSES))
        .order_by(CaseAiGenerationJob.created_at.desc(), CaseAiGenerationJob.id.desc())
        .first()
    )

    if existing:
        return existing, False

    job = CaseAiGenerationJob(
        job_id=str(uuid.uuid4()),
        case_id=case_id,
        job_type=normalized_job_type,
        status=JOB_STATUS_PENDING,
        requested_by_user_id=current_user.get("id") if current_user else None,
        requested_by_username=current_user.get("username") if current_user else None,
        created_at=now,
        updated_at=now,
    )

    db.add(job)
    db.commit()
    db.refresh(job)

    return job, True


def run_case_generation_job(
    job_id: str,
    *,
    session_factory=SessionLocal,
    analysis_generator: Callable[[int], CaseAIAnalysis] = generate_case_ai_analysis,
    suggestions_generator: Callable[[int], dict[str, Any]] = generate_case_action_suggestions,
) -> dict[str, Any] | None:
    db = session_factory()

    try:
        job = (
            db.query(CaseAiGenerationJob)
            .filter(CaseAiGenerationJob.job_id == str(job_id))
            .first()
        )

        if not job:
            return None

        if job.status in TERMINAL_STATUSES:
            return serialize_generation_job(job)

        now = utc_now()
        job.status = JOB_STATUS_RUNNING
        job.started_at = job.started_at or now
        job.updated_at = now
        db.commit()
        db.refresh(job)

        try:
            if job.job_type == JOB_TYPE_ANALYSIS:
                analysis = analysis_generator(job.case_id)
                result = serialize_case_ai_analysis(analysis)
                job.result_reference_id = analysis.id
            elif job.job_type == JOB_TYPE_ACTION_SUGGESTIONS:
                result = suggestions_generator(job.case_id)
                job.result_reference_id = None
            else:
                raise ValueError("Unsupported case AI generation job type.")

            finished_at = utc_now()
            job.status = JOB_STATUS_SUCCESS
            job.result_json = json.dumps(result, default=str, sort_keys=True)
            job.error = None
            job.finished_at = finished_at
            job.updated_at = finished_at
            db.commit()
            db.refresh(job)

        except Exception as exc:
            finished_at = utc_now()
            job.status = JOB_STATUS_ERROR
            job.error = _safe_generation_error(exc)
            job.finished_at = finished_at
            job.updated_at = finished_at
            db.commit()
            db.refresh(job)

        return serialize_generation_job(job)

    finally:
        db.close()
