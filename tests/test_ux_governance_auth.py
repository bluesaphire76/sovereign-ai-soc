"""UX-11 contract checks using real routers and an isolated in-memory database."""
from datetime import datetime
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from auth_utils import create_access_token, hash_password, verify_password
from models import AppUser, SecurityAuditEvent
from routers import auth, security_audit, users
from security import auth as auth_dependencies


@pytest.fixture
def isolated(monkeypatch):
    monkeypatch.setenv("AI_SOC_AUTH_SECRET", "ux11-isolated-secret-not-for-production-0000")
    engine = create_engine("sqlite://", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    AppUser.__table__.create(engine)
    SecurityAuditEvent.__table__.create(engine)
    sessions = sessionmaker(bind=engine)
    audit_writes = []
    for module in (auth, users, security_audit, auth_dependencies):
        monkeypatch.setattr(module, "SessionLocal", sessions)
    for module in (auth, users):
        monkeypatch.setattr(module, "write_security_audit", lambda **kw: audit_writes.append(kw))
    password_hash = hash_password("fixture-password")
    with sessions() as db:
        db.add_all([AppUser(id=i, username=role.lower(), display_name=role,
                           role=role, is_active=True, password_hash=password_hash)
                    for i, role in enumerate(("ADMIN", "ANALYST", "VIEWER"), 1)])
        db.commit()
    app = FastAPI()
    for module in (auth, users, security_audit):
        app.include_router(module.router)
    with TestClient(app) as client:
        yield client, sessions, audit_writes
    engine.dispose()


def headers(role="ADMIN", ttl=3600):
    token = create_access_token(user_id={"ADMIN": 1, "ANALYST": 2, "VIEWER": 3}[role],
                                username=role.lower(), role=role, ttl_seconds=ttl)
    return {"Authorization": "Bearer " + token["access_token"]}


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "VIEWER"])
def test_role_and_self_service_matrix(isolated, role):
    client, sessions, writes = isolated
    h = headers(role)
    own = {"ADMIN": 1, "ANALYST": 2, "VIEWER": 3}[role]
    response = client.get("/users", headers=h)
    assert response.status_code == 200
    assert [u["id"] for u in response.json()["items"]] == ([1, 2, 3] if own == 1 else [own])
    assert "password_hash" not in response.text
    assert client.get("/security-audit/events", headers=h).status_code == (200 if own == 1 else 403)
    assert client.post(f"/users/{own}/password", headers=h, json={"password": "short"}).status_code == 400
    reset = client.post(f"/users/{own}/password", headers=h, json={"password": "fixture-new-password"})
    assert reset.status_code == 200
    assert "fixture-new-password" not in reset.text
    with sessions() as db:
        assert verify_password("fixture-new-password", db.get(AppUser, own).password_hash)
    assert writes[-1]["details"]["self_service"] is True
    assert "password" not in str(writes[-1]["details"])
    if own != 1:
        assert client.post("/users/1/password", headers=h, json={"password": "fixture-other"}).status_code == 403
        assert client.patch("/users/1", headers=h, json={"role": "VIEWER"}).status_code == 403
        assert client.delete("/users/1", headers=h).status_code == 403
        assert client.post("/users", headers=h, json={"username": "test", "password": "fixture-only"}).status_code == 403


def test_admin_operations_and_current_user_guards(isolated):
    client, sessions, writes = isolated
    h = headers()
    payload = {"username": " Fixture ", "display_name": "Fixture", "role": "ANALYST",
               "password": "fixture-only-password", "is_active": True}
    created = client.post("/users", headers=h, json=payload)
    assert created.status_code == 200
    user = created.json()
    assert user["username"] == "fixture"
    assert "password" not in created.text
    assert client.post("/users", headers=h, json=payload).status_code == 409
    for patch in ({"username": " "}, {"username": "bad", "role": "OWNER"},
                  {"username": "bad", "password": "short"}):
        assert client.post("/users", headers=h, json={**payload, **patch}).status_code == 400
    url = f"/users/{user['id']}"
    for field, value in (("display_name", "Updated"), ("role", "VIEWER"),
                         ("is_active", False), ("is_active", True)):
        updated = client.patch(url, headers=h, json={field: value})
        assert updated.status_code == 200
        assert updated.json()[field] == value
    # Null display names are ignored by the existing backend, not a UX change.
    assert client.patch(url, headers=h, json={"display_name": None}).json()["display_name"] == "Updated"
    assert client.post(url + "/password", headers=h, json={"password": "fixture-admin-reset"}).status_code == 200
    assert client.delete("/users/1", headers=h).status_code == 400
    assert client.patch("/users/1", headers=h, json={"is_active": False}).status_code == 400
    assert client.delete(url, headers=h).status_code == 200
    assert client.delete(url, headers=h).status_code == 404
    assert {w["event_type"] for w in writes} >= {"USER_CREATED", "USER_UPDATED", "USER_PASSWORD_RESET", "USER_DELETED"}
    # Self-downgrade is currently allowed; stale token role must not retain ADMIN access.
    assert client.patch("/users/1", headers=h, json={"role": "VIEWER"}).status_code == 200
    assert client.get("/auth/me", headers=h).json()["role"] == "VIEWER"
    assert client.get("/security-audit/events", headers=h).status_code == 403
    with sessions() as db:
        # Known release risk: demoting the sole ADMIN leaves no active administrator.
        assert db.query(AppUser).filter(AppUser.role == "ADMIN", AppUser.is_active.is_(True)).count() == 0
    assert client.patch("/users/1", headers=h, json={"role": "ADMIN"}).status_code == 403


def test_login_tokens_expiry_and_disabled_accounts(isolated):
    client, sessions, writes = isolated
    for username, password in (("missing", "fixture-password"), ("admin", "wrong")):
        assert client.post("/auth/login", json={"username": username, "password": password}).status_code == 401
    response = client.post("/auth/login", json={"username": " ADMIN ", "password": "fixture-password"})
    assert response.status_code == 200
    assert response.json()["user"]["last_login_at"]
    assert "password" not in response.text
    token = {"Authorization": "Bearer " + response.json()["access_token"]}
    assert client.get("/auth/me", headers=token).status_code == 200
    for h in ({}, {"Authorization": "Bearer invalid"}, headers(ttl=-60)):
        for url in ("/auth/me", "/users", "/security-audit/events"):
            assert client.get(url, headers=h).status_code == 401
    with sessions() as db:
        db.get(AppUser, 1).is_active = False
        db.commit()
    assert client.get("/auth/me", headers=token).status_code == 401
    assert client.post("/auth/login", json={"username": "admin", "password": "fixture-password"}).status_code == 403
    assert writes[-1]["details"] == {"reason": "disabled_account"}


def test_audit_filters_pagination_dates_and_raw_details(isolated):
    client, sessions, _ = isolated
    with sessions() as db:
        for i, stamp in enumerate(("2026-09-08T23:59:59", "2026-09-09T00:00:00",
                                   "2026-09-09T23:59:59.999999", "2026-09-10T00:00:00"), 1):
            db.add(SecurityAuditEvent(id=i, created_at=datetime.fromisoformat(stamp),
                   event_type="USER_UPDATED", outcome="SUCCESS", actor_user_id=1,
                   actor_username="admin", actor_role="ADMIN", target_type="USER",
                   target_id="2", target_username="analyst", method="PATCH", path="/users/2",
                   client_ip="192.0.2.1", user_agent="fixture-agent", details_json='{"changed":"role"}'))
        db.add(SecurityAuditEvent(id=5, created_at=datetime(2026, 9, 10),
                                 event_type="UNCLASSIFIED", outcome="UNKNOWN", details_json="broken-json"))
        db.commit()
    def get(**params):
        result = client.get("/security-audit/events", headers=headers(), params=params)
        assert result.status_code == 200
        return result.json()
    assert [r["id"] for r in get(limit=2)["items"]] == [5, 4]
    assert get(limit=2)["total_pages"] == 3
    assert [r["id"] for r in get(limit=2, page=2)["items"]] == [3, 2]
    assert get()["items"][0]["details"] == {"raw": "broken-json"}
    assert [r["id"] for r in get(date_from="2026-09-09", date_to="2026-09-09")["items"]] == [3, 2]
    for key, value in (("event_type", "USER_UPDATED"), ("outcome", "SUCCESS"),
                       ("actor_username", "DMIN"), ("target_type", "USER"), ("target_id", "2")):
        assert get(**{key: value})["total"] == 4
    for value in ("admin", "analyst", "PATCH", "/users/2", "192.0.2.1", "changed"):
        assert get(search=value)["total"] == 4
    assert get(search="no-match")["total_pages"] == 1
    assert get(search="no-match")["items"] == []
    assert client.get("/security-audit/events", headers=headers(), params={"date_from": "invalid"}).status_code == 400
    assert client.get("/security-audit/events", headers=headers(), params={"limit": 101}).status_code == 422


def test_frontend_aliases_and_standalone_login():
    root = Path(__file__).resolve().parents[1] / "frontend/src/app"
    for alias in ("security-audit/page.tsx", "admin/security-audit/page.tsx"):
        source = (root / alias).read_text()
        assert 'redirect("/system-information/security-audit")' in source
    assert "AppShell" not in (root / "login/page.tsx").read_text()
