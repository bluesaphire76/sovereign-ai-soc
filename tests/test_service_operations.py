import subprocess

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import Base, SecurityAuditEvent, ServiceOperation
from service_operations import (
    get_service_status,
    preview_restart,
    restart_service,
)


def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def admin():
    return {
        "id": 1,
        "username": "admin",
        "role": "ADMIN",
    }


def analyst():
    return {
        "id": 2,
        "username": "analyst",
        "role": "ANALYST",
    }


class FakeRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if self.responses:
            return self.responses.pop(0)
        return completed(args, stdout="ActiveState=active\nSubState=running\nLoadState=loaded\nMainPID=42\n")


def completed(args, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=args,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def active_systemd(args=None):
    return completed(
        args or ["systemctl"],
        stdout="ActiveState=active\nSubState=running\nLoadState=loaded\nMainPID=42\n",
    )


def test_unknown_service_key_is_rejected():
    db = db_session()

    try:
        with pytest.raises(HTTPException) as exc:
            get_service_status(
                db,
                service_key="not_allowed",
                current_user=admin(),
                runner=FakeRunner([]),
            )

        assert exc.value.status_code == 404
    finally:
        db.close()


def test_non_admin_cannot_execute_restart_and_is_audited():
    db = db_session()

    try:
        with pytest.raises(HTTPException) as exc:
            restart_service(
                db,
                service_key="ai_soc_worker",
                reason="Apply detection config change.",
                confirm=True,
                related_config_version_id=7,
                current_user=analyst(),
                runner=FakeRunner([]),
            )

        assert exc.value.status_code == 403

        operation = db.query(ServiceOperation).one()
        assert operation.status == "denied"
        assert operation.operation_type == "restart"
        assert operation.related_config_version_id == 7

        event = db.query(SecurityAuditEvent).one()
        assert event.event_type == "SERVICE_RESTART_DENIED"
        assert event.outcome == "DENIED"
    finally:
        db.close()


def test_missing_reason_and_confirmation_are_rejected_before_restart():
    db = db_session()
    runner = FakeRunner([])

    try:
        with pytest.raises(HTTPException) as missing_reason:
            restart_service(
                db,
                service_key="ai_soc_worker",
                reason="",
                confirm=True,
                related_config_version_id=None,
                current_user=admin(),
                runner=runner,
            )

        with pytest.raises(HTTPException) as missing_confirmation:
            restart_service(
                db,
                service_key="ai_soc_worker",
                reason="Apply detection config change.",
                confirm=False,
                related_config_version_id=None,
                current_user=admin(),
                runner=runner,
            )

        assert missing_reason.value.status_code == 400
        assert missing_confirmation.value.status_code == 400
        assert runner.calls == []
        assert db.query(ServiceOperation).count() == 0
    finally:
        db.close()


def test_preview_does_not_execute_restart():
    db = db_session()
    runner = FakeRunner(
        [
            active_systemd(),
            completed(["sudo", "-n", "-l", "systemctl", "restart", "ai-soc-worker"]),
        ]
    )

    try:
        result = preview_restart(
            db,
            service_key="ai_soc_worker",
            reason="Apply detection config change.",
            related_config_version_id=10,
            current_user=analyst(),
            runner=runner,
        )

        assert result["allowed"] is True
        assert result["current_status"] == "running"
        assert all(call[-2:] != ["restart", "ai-soc-worker"] or "-l" in call for call in runner.calls)

        operation = db.query(ServiceOperation).one()
        assert operation.operation_type == "restart_preview"
        assert operation.status == "success"

        event = db.query(SecurityAuditEvent).one()
        assert event.event_type == "SERVICE_RESTART_PREVIEW"
    finally:
        db.close()


def test_preview_blocks_restart_when_noninteractive_sudo_is_missing():
    db = db_session()
    runner = FakeRunner(
        [
            active_systemd(),
            completed(
                ["sudo", "-n", "-l", "systemctl", "restart", "ai-soc-worker"],
                returncode=1,
                stderr="sudo: a password is required",
            ),
        ]
    )

    try:
        result = preview_restart(
            db,
            service_key="ai_soc_worker",
            reason="Apply detection config change.",
            related_config_version_id=10,
            current_user=admin(),
            runner=runner,
        )

        assert result["allowed"] is False
        assert "non-interactive sudo permission" in result["warnings"][0]
        assert all(call[-2:] != ["restart", "ai-soc-worker"] or "-l" in call for call in runner.calls)

        operation = db.query(ServiceOperation).one()
        assert operation.operation_type == "restart_preview"
        assert operation.status == "failed"
    finally:
        db.close()


def test_restart_uses_allowlisted_safe_command_and_persists_success():
    db = db_session()
    runner = FakeRunner(
        [
            active_systemd(),
            completed(["sudo", "-n", "-l", "systemctl", "restart", "ai-soc-worker"]),
            completed(["sudo", "-n", "systemctl", "restart", "ai-soc-worker"]),
            active_systemd(),
        ]
    )

    try:
        result = restart_service(
            db,
            service_key="ai_soc_worker",
            reason="Apply detection config change.",
            confirm=True,
            related_config_version_id=11,
            current_user=admin(),
            runner=runner,
        )

        assert any(call[-2:] == ["restart", "ai-soc-worker"] and "-l" not in call for call in runner.calls)
        assert result["status"] == "success"
        assert result["pre_status"] == "running"
        assert result["post_status"] == "running"

        operation = db.query(ServiceOperation).one()
        assert operation.status == "success"
        assert operation.related_config_version_id == 11

        events = [event.event_type for event in db.query(SecurityAuditEvent).all()]
        assert events == ["SERVICE_RESTART_REQUESTED", "SERVICE_RESTART_SUCCESS"]
    finally:
        db.close()


def test_failed_restart_returns_safe_error_and_persists_failure():
    db = db_session()
    runner = FakeRunner(
        [
            active_systemd(),
            completed(["sudo", "-n", "-l", "systemctl", "restart", "ai-soc-worker"]),
            completed(
                ["sudo", "-n", "systemctl", "restart", "ai-soc-worker"],
                returncode=1,
                stderr="Job failed. SECRET_TOKEN=do-not-store " + ("x" * 800),
            ),
            active_systemd(),
        ]
    )

    try:
        result = restart_service(
            db,
            service_key="ai_soc_worker",
            reason="Apply detection config change.",
            confirm=True,
            related_config_version_id=None,
            current_user=admin(),
            runner=runner,
        )

        assert result["status"] == "failed"
        assert result["safe_error"].startswith("Job failed.")
        assert "do-not-store" not in result["safe_error"]
        assert len(result["safe_error"]) <= 500

        operation = db.query(ServiceOperation).one()
        assert operation.status == "failed"
        assert operation.safe_error == result["safe_error"]

        events = [event.event_type for event in db.query(SecurityAuditEvent).all()]
        assert events == ["SERVICE_RESTART_REQUESTED", "SERVICE_RESTART_FAILED"]
    finally:
        db.close()
