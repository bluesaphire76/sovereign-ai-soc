from __future__ import annotations

from datetime import datetime, timezone

import api
from routers import auth as auth_router
from routers import users as users_router
from scripts.export_api_route_inventory import iter_api_routes
from services import users as users_service


EXPECTED_USER_ROUTE_METHODS = {
    "/users": {"GET", "POST"},
    "/users/{user_id}": {"PATCH", "DELETE"},
    "/users/{user_id}/password": {"POST"},
}


class UserLike:
    id = 7
    username = "analyst"
    display_name = "SOC Analyst"
    role = "ANALYST"
    is_active = True
    last_login_at = datetime(2026, 6, 27, 8, 0, tzinfo=timezone.utc)
    created_at = datetime(2026, 6, 26, 8, 0, tzinfo=timezone.utc)
    updated_at = datetime(2026, 6, 27, 9, 30, tzinfo=timezone.utc)


def _user_route_methods() -> dict[str, set[str]]:
    route_methods: dict[str, set[str]] = {}

    for route in iter_api_routes():
        if route.path in EXPECTED_USER_ROUTE_METHODS:
            route_methods.setdefault(route.path, set()).update(route.methods or set())

    return route_methods


def test_users_router_module_imports() -> None:
    assert users_router.router is not None


def test_expected_users_routes_are_registered_once() -> None:
    assert _user_route_methods() == EXPECTED_USER_ROUTE_METHODS


def test_user_helpers_live_outside_api_module() -> None:
    assert not hasattr(api, "VALID_USER_ROLES")
    assert not hasattr(api, "serialize_user")
    assert not hasattr(api, "normalize_username")
    assert not hasattr(api, "hash_password_or_400")

    assert users_service.normalize_username(" Analyst ") == "analyst"
    assert users_service.VALID_USER_ROLES == {"ADMIN", "ANALYST", "VIEWER"}


def test_serialize_user_preserves_response_keys_and_timestamps() -> None:
    payload = users_service.serialize_user(UserLike())

    assert list(payload) == [
        "id",
        "username",
        "display_name",
        "role",
        "is_active",
        "last_login_at",
        "created_at",
        "updated_at",
    ]
    assert payload["last_login_at"] == "2026-06-27T08:00:00+00:00"
    assert payload["created_at"] == "2026-06-26T08:00:00+00:00"
    assert payload["updated_at"] == "2026-06-27T09:30:00+00:00"


def test_auth_router_reuses_shared_username_normalizer() -> None:
    assert not hasattr(auth_router, "_normalize_username")
    assert auth_router.normalize_username is users_service.normalize_username
