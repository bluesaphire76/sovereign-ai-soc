from __future__ import annotations

from schemas.auth import LoginRequest
from schemas.cases import CaseActionCreate
from schemas.incidents import IncidentNoteCreate, IncidentStatusUpdate
from schemas.synthetic_tests import SyntheticTestRunCreate
from schemas.users import UserCreate


def schema_fields(model: type) -> set[str]:
    fields = model.model_fields if hasattr(model, "model_fields") else model.__fields__
    return set(fields)


def test_login_request_exposes_username_and_password() -> None:
    assert {"username", "password"} <= schema_fields(LoginRequest)


def test_user_create_defaults_are_preserved() -> None:
    payload = UserCreate(username="analyst", password="valid-password")

    assert payload.role == "ANALYST"
    assert payload.is_active is True


def test_incident_update_optional_fields_are_preserved() -> None:
    status_update = IncidentStatusUpdate(status="TRIAGED")
    note = IncidentNoteCreate(note="Reviewed evidence.")

    assert status_update.comment is None
    assert note.created_by is None


def test_case_action_create_defaults_are_preserved() -> None:
    payload = CaseActionCreate(title="Review supporting evidence")

    assert payload.category == "INVESTIGATION"
    assert payload.priority == "MEDIUM"


def test_synthetic_test_run_defaults_are_preserved() -> None:
    payload = SyntheticTestRunCreate()

    assert payload.scenario == "all"
    assert payload.count == 1
