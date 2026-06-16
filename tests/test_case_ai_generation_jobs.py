from datetime import timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from case_ai_generation_jobs import (
    JOB_STATUS_ERROR,
    JOB_STATUS_PENDING,
    JOB_STATUS_SUCCESS,
    create_or_get_running_generation_job,
    run_case_generation_job,
    serialize_generation_job,
)
from models import Base, CaseAIAnalysis, CaseAiGenerationJob, IncidentCase, utc_now


def session_factory():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def add_case(db, case_id=11):
    db.add(
        IncidentCase(
            id=case_id,
            group_key=f"case-generation-{case_id}",
            title="Case generation fixture",
            status="OPEN",
            severity="MEDIUM",
        )
    )
    db.commit()


def test_create_or_get_running_generation_job_reuses_active_job():
    factory = session_factory()
    db = factory()

    try:
        add_case(db)

        first, first_created = create_or_get_running_generation_job(
            db,
            case_id=11,
            job_type="analysis",
            current_user={"id": 7, "username": "analyst"},
        )
        second, second_created = create_or_get_running_generation_job(
            db,
            case_id=11,
            job_type="analysis",
            current_user={"id": 7, "username": "analyst"},
        )

        assert first_created is True
        assert second_created is False
        assert second.job_id == first.job_id
        assert serialize_generation_job(second)["requested_by_username"] == "analyst"
    finally:
        db.close()


def test_run_analysis_generation_job_persists_success_result():
    factory = session_factory()
    db = factory()

    try:
        add_case(db)
        job, _ = create_or_get_running_generation_job(
            db,
            case_id=11,
            job_type="analysis",
            current_user={"id": 7, "username": "analyst"},
        )
        job_id = job.job_id

        def fake_analysis_generator(case_id: int) -> CaseAIAnalysis:
            return CaseAIAnalysis(
                id=42,
                case_id=case_id,
                model="unit-test-model",
                analysis="Generated case analysis.",
                recommended_status="TRIAGED",
                recommended_severity="HIGH",
                created_by="llm",
                created_at=utc_now(),
            )

        payload = run_case_generation_job(
            job_id,
            session_factory=factory,
            analysis_generator=fake_analysis_generator,
        )

        assert payload is not None
        assert payload["status"] == JOB_STATUS_SUCCESS
        assert payload["result_reference_id"] == 42
        assert payload["result"]["analysis"] == "Generated case analysis."
        assert payload["result"]["recommended_severity"] == "HIGH"
    finally:
        db.close()


def test_run_action_suggestion_generation_job_persists_actions():
    factory = session_factory()
    db = factory()

    try:
        add_case(db)
        job, _ = create_or_get_running_generation_job(
            db,
            case_id=11,
            job_type="action-suggestions",
            current_user={"id": 7, "username": "analyst"},
        )
        job_id = job.job_id

        def fake_suggestions_generator(case_id: int) -> dict:
            return {
                "case_id": case_id,
                "model": "unit-test-model",
                "actions": [
                    {
                        "title": "Validate authentication evidence",
                        "description": "Review auth logs around the alert window.",
                        "category": "EVIDENCE_REVIEW",
                        "priority": "HIGH",
                        "due_hours": 8,
                    }
                ],
            }

        payload = run_case_generation_job(
            job_id,
            session_factory=factory,
            suggestions_generator=fake_suggestions_generator,
        )

        assert payload is not None
        assert payload["status"] == JOB_STATUS_SUCCESS
        assert payload["result"]["actions"][0]["title"] == "Validate authentication evidence"
    finally:
        db.close()


def test_stale_running_generation_job_is_marked_error_before_new_job(monkeypatch):
    monkeypatch.setenv("CASE_AI_GENERATION_JOB_STALE_SECONDS", "60")

    factory = session_factory()
    db = factory()

    try:
        add_case(db)
        stale_time = utc_now() - timedelta(minutes=10)
        stale = CaseAiGenerationJob(
            job_id="stale-job",
            case_id=11,
            job_type="analysis",
            status=JOB_STATUS_PENDING,
            created_at=stale_time,
            updated_at=stale_time,
        )
        db.add(stale)
        db.commit()

        fresh, created = create_or_get_running_generation_job(
            db,
            case_id=11,
            job_type="analysis",
            current_user={"id": 7, "username": "analyst"},
        )

        stale = db.query(CaseAiGenerationJob).filter_by(job_id="stale-job").first()

        assert created is True
        assert fresh.job_id != "stale-job"
        assert stale.status == JOB_STATUS_ERROR
        assert "expired" in stale.error
    finally:
        db.close()
