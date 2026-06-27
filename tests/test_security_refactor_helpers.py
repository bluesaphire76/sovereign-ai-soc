from __future__ import annotations

from fastapi import Request

from security.audit import request_client_ip, sanitize_audit_details
from security.rbac import PUBLIC_AUTH_PATHS, is_request_authorized


def make_request(headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/security-audit/events",
            "headers": headers or [],
            "client": ("198.51.100.10", 54123),
            "scheme": "http",
            "server": ("testserver", 80),
            "query_string": b"",
        }
    )


def test_sanitize_audit_details_redacts_nested_sensitive_keys() -> None:
    payload = {
        "username": "analyst",
        "password": "cleartext",
        "nested": {
            "access_token": "token-value",
            "items": [
                {"Authorization": "Bearer secret"},
                {"safe": "visible"},
            ],
        },
    }

    assert sanitize_audit_details(payload) == {
        "username": "analyst",
        "password": "[REDACTED]",
        "nested": {
            "access_token": "[REDACTED]",
            "items": [
                {"Authorization": "[REDACTED]"},
                {"safe": "visible"},
            ],
        },
    }


def test_request_client_ip_prefers_first_forwarded_for_ip() -> None:
    request = make_request(
        [(b"x-forwarded-for", b"203.0.113.42, 198.51.100.11")]
    )

    assert request_client_ip(request) == "203.0.113.42"


def test_rbac_allows_known_valid_route_for_role() -> None:
    assert is_request_authorized(
        "GET",
        "/security-audit/events",
        {"role": "ADMIN"},
    )


def test_rbac_denies_known_invalid_route_for_role() -> None:
    assert not is_request_authorized(
        "GET",
        "/security-audit/events",
        {"role": "ANALYST"},
    )


def test_public_auth_paths_include_existing_public_endpoints() -> None:
    assert {"/auth/login", "/health", "/metrics", "/openapi.json"} <= PUBLIC_AUTH_PATHS
