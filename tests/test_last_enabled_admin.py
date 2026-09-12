"""Account invariants on isolated SQLite and opt-in disposable PostgreSQL."""
from concurrent.futures import ThreadPoolExecutor
import os
from threading import Barrier
from unittest.mock import Mock

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from models import AppUser
from routers import users
from schemas.users import UserCreate, UserPasswordUpdate, UserUpdate
from services.users import LAST_ADMIN_MESSAGE, lock_user_management
from test_ux_governance_auth import headers, isolated  # noqa: F401


POSTGRES = os.environ.get("UX_TEST_POSTGRES_URL")


@pytest.fixture(params=["sqlite"] + (["postgresql"] if POSTGRES else []))
def accounts(request, tmp_path, monkeypatch):
    url = POSTGRES if request.param == "postgresql" else f"sqlite:///{tmp_path / 'users.db'}"
    parsed = make_url(url)
    if request.param == "postgresql":
        # Never run destructive fixture setup against the operational database.
        assert parsed.host in {"127.0.0.1", "localhost"}
        assert parsed.database == "ux_release_fixture"
        assert parsed.username == "ux_release_fixture"
    engine = create_engine(url)
    AppUser.__table__.create(engine)
    sessions = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(users, "SessionLocal", sessions)
    writes = []
    monkeypatch.setattr(users, "write_security_audit", lambda **kw: writes.append(kw))
    monkeypatch.setattr(users, "hash_password_or_400", lambda value: "fixture-hash")
    with sessions() as db:
        db.add_all([AppUser(username=f"fixture-{i}", role=role,
                           is_active=active, password_hash="fixture-hash")
                    for i, role, active in [(1, "ADMIN", True), (2, "ADMIN", False), (3, "ANALYST", True)]])
        db.commit()
    try:
        yield sessions, writes
    finally:
        AppUser.__table__.drop(engine)
        engine.dispose()


def mutate(operation, target=1, actor=3, **extra):
    request = Request({"type": "http", "method": "PATCH", "path": f"/users/{target}", "headers": []})
    # Models a request authenticated before another transaction demoted its actor.
    current = {"id": actor, "role": "ADMIN", "username": f"fixture-{actor}"}
    if operation == "delete":
        return users.delete_user(target, request, current)
    patch = {"role": "ANALYST"} if operation == "demote" else {"is_active": False}
    return users.update_user(target, UserUpdate(**(patch | extra)), request, current)


@pytest.mark.parametrize("operation", ["demote", "disable", "delete"])
def test_direct_requests_cannot_remove_last_admin_and_roll_back(accounts, operation):
    sessions, writes = accounts
    with pytest.raises(HTTPException) as caught:
        mutate(operation, display_name="Must roll back")
    assert caught.value.status_code == 409
    assert caught.value.detail == LAST_ADMIN_MESSAGE
    with sessions() as db:
        user = db.get(AppUser, 1)
        assert (user.role, user.is_active, user.display_name) == ("ADMIN", True, None)
    assert writes == []


@pytest.mark.parametrize("operation", ["demote", "disable", "delete"])
def test_another_enabled_admin_allows_normal_management(accounts, operation):
    sessions, writes = accounts
    with sessions() as db:
        db.get(AppUser, 2).is_active = True
        db.commit()
    mutate(operation, actor=2)
    with sessions() as db:
        assert db.query(AppUser).filter_by(role="ADMIN", is_active=True).count() == 1
    assert len(writes) == 1


@pytest.mark.parametrize("operation", ["demote", "disable", "delete"])
def test_concurrent_admin_mutations_leave_one_enabled(accounts, monkeypatch, operation):
    sessions, writes = accounts
    with sessions() as db:
        db.get(AppUser, 2).is_active = True
        db.commit()
    barrier = Barrier(2)
    original = users.lock_user_management

    def simultaneous(db):
        barrier.wait(timeout=10)
        original(db)

    monkeypatch.setattr(users, "lock_user_management", simultaneous)

    def attempt(target):
        try:
            mutate(operation, target=target, actor=target if operation == "demote" else 3-target)
            return 200
        except HTTPException as exc:
            assert exc.detail == LAST_ADMIN_MESSAGE
            return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, [1, 2])) == [200, 409]
    with sessions() as db:
        assert db.query(AppUser).filter_by(role="ADMIN", is_active=True).count() == 1
    assert len(writes) == 1


@pytest.mark.parametrize("operation", ["create", "password"])
def test_other_mutations_cannot_commit_without_enabled_admin(accounts, operation):
    sessions, writes = accounts
    with sessions() as db:
        db.get(AppUser, 1).is_active = False
        db.commit()
    with pytest.raises(HTTPException, match=LAST_ADMIN_MESSAGE):
        if operation == "create":
            users.create_user(UserCreate(username="fixture-new", password="fixture-password"), None, {"id": 1})
        else:
            users.update_user_password(3, UserPasswordUpdate(password="fixture-password"), None, {"id": 3, "role": "ANALYST"})
    assert writes == []


@pytest.mark.parametrize("role", ["ANALYST", "VIEWER"])
def test_last_admin_self_demotion_is_rejected_via_authenticated_api(isolated, role):
    client, sessions, writes = isolated
    response = client.patch("/users/1", headers=headers(), json={"role": role})
    assert response.status_code == 409
    assert response.json() == {"detail": LAST_ADMIN_MESSAGE}
    assert client.get("/auth/me", headers=headers()).json()["role"] == "ADMIN"
    assert writes == []


def test_lock_contention_is_controlled_and_rolled_back():
    db = Mock()
    db.get_bind.return_value.dialect.name = "sqlite"
    db.execute.side_effect = OperationalError("BEGIN IMMEDIATE", {}, Exception("busy"))
    with pytest.raises(HTTPException) as caught:
        lock_user_management(db)
    assert caught.value.status_code == 503
    assert caught.value.detail == "User management is busy. Please retry."
    db.rollback.assert_called_once()
