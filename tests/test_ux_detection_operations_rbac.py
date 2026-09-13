"""Protected UX-10 route permissions, independent of presentation controls."""

import pytest

from security.rbac import is_request_authorized


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "VIEWER"])
@pytest.mark.parametrize(
    "method,path,roles",
    [
        ("GET", "/settings/detection-control", "ADMIN ANALYST VIEWER"),
        ("GET", "/detection-control/rules", "ADMIN ANALYST VIEWER"),
        ("POST", "/detection-control/rules", "ADMIN"),
        ("PATCH", "/detection-control/rules/managed-1", "ADMIN"),
        ("DELETE", "/detection-control/rules/managed-1", "ADMIN"),
        *[("POST", f"/detection-control/rules/managed-1/{action}", "ADMIN")
          for action in ["validate", "enable", "disable"]],
        ("GET", "/detection-control/config-versions/noise_suppression/active", "ADMIN ANALYST VIEWER"),
        ("GET", "/detection-control/config-versions/noise_suppression/1", "ADMIN ANALYST VIEWER"),
        *[("POST", f"/detection-control/config-versions/noise_suppression/{action}", "ADMIN ANALYST")
          for action in ["validate", "diff"]],
        *[("POST", f"/detection-control/config-versions/noise_suppression/{action}", "ADMIN")
          for action in ["apply", "rollback"]],
        ("POST", "/detection-control/semantic-context", "ADMIN ANALYST"),
        ("GET", "/detection-control/lifecycle/items", "ADMIN ANALYST VIEWER"),
        ("POST", "/detection-control/lifecycle/items", "ADMIN ANALYST"),
        ("PATCH", "/detection-control/lifecycle/items/1", "ADMIN ANALYST"),
        ("DELETE", "/detection-control/lifecycle/items/1", "ADMIN ANALYST"),
        *[("POST", f"/detection-control/lifecycle/items/1/{action}", "ADMIN ANALYST")
          for action in ["validate", "submit", "return-to-draft", "clone"]],
        *[("POST", f"/detection-control/lifecycle/items/1/{action}", "ADMIN")
          for action in ["approve", "reject", "apply", "disable"]],
        *[("GET", f"/detection-control/operations/{category}", "ADMIN ANALYST VIEWER")
          for category in ["overview", "noise-suppression", "exceptions", "rules"]],
        ("GET", "/detection-control/operations/items/managed-1/matched-events", "ADMIN ANALYST VIEWER"),
        ("POST", "/detection-control/operations/match-preview", "ADMIN ANALYST"),
        *[("POST", f"/detection-control/operations/items/managed-1/{action}", "ADMIN ANALYST")
          for action in ["mark-reviewed", "extend-review"]],
        ("GET", "/service-operations/services", "ADMIN ANALYST VIEWER"),
        ("GET", "/service-operations/services/ai_soc_worker/status", "ADMIN ANALYST VIEWER"),
        ("POST", "/service-operations/services/ai_soc_worker/restart-preview", "ADMIN ANALYST"),
        ("POST", "/service-operations/services/ai_soc_worker/restart", "ADMIN"),
        ("GET", "/service-operations/operations", "ADMIN ANALYST VIEWER"),
        *[("GET", f"/{source}{suffix}", "ADMIN ANALYST VIEWER")
          for source in ["network-events", "dns-events"] for suffix in ["", "/summary"]],
    ],
)
def test_operational_permission_matrix(method, path, roles, role):
    assert is_request_authorized(method, path, {"role": role}) == (role in roles.split())
