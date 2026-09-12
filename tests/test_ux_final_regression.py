"""Final cross-product permission boundaries and narrow shared UX regressions."""
from pathlib import Path

import pytest

from security.rbac import is_request_authorized

ROOT = Path(__file__).resolve().parents[1]
ALL = "ADMIN ANALYST VIEWER"
OPERATORS = "ADMIN ANALYST"


@pytest.mark.parametrize("role", ["ADMIN", "ANALYST", "VIEWER", "UNKNOWN"])
@pytest.mark.parametrize("method,path,roles", [
    ("GET", "/incidents", ALL),
    ("GET", "/incidents/1", ALL),
    ("PATCH", "/incidents/1/status", OPERATORS),
    ("POST", "/incidents/1/notes", OPERATORS),
    ("POST", "/incidents/1/case", OPERATORS),
    ("POST", "/remediation/proposals/1/approve", "ADMIN"),
    ("POST", "/incidents/1/remediation-actions/test/execute-approved", OPERATORS),
    ("GET", "/cases", ALL),
    ("GET", "/cases/1", ALL),
    ("PATCH", "/cases/1/workflow", OPERATORS),
    ("PATCH", "/cases/1/closure", OPERATORS),
    ("POST", "/cases/1/actions", OPERATORS),
    ("GET", "/assistant/capabilities", OPERATORS),
    ("POST", "/assistant/query", OPERATORS),
    ("GET", "/synthetic-tests/scenarios", OPERATORS),
    ("POST", "/synthetic-tests/run", OPERATORS),
    ("POST", "/detection-quality/action-guidance", ALL),
    ("GET", "/settings/detection-control", ALL),
    ("POST", "/detection-control/config-versions/noise_suppression/diff", OPERATORS),
    ("POST", "/detection-control/config-versions/noise_suppression/apply", "ADMIN"),
    ("GET", "/semantic-memory/search", OPERATORS),
    ("POST", "/semantic-memory/retention-cleanup", "ADMIN"),
    ("GET", "/users", ALL),
    ("POST", "/users", "ADMIN"),
    ("PATCH", "/users/1", "ADMIN"),
    ("DELETE", "/users/1", "ADMIN"),
    # The router additionally enforces self-service ownership for passwords.
    ("POST", "/users/1/password", ALL),
    ("GET", "/security-audit/events", "ADMIN"),
    ("GET", "/ai-data-control/policies", ALL),
    ("POST", "/ai-data-control/evaluate-preview", OPERATORS),
    ("PATCH", "/ai-data-control/policies/soc_assistant", "ADMIN"),
    ("GET", "/ai-providers", ALL),
    ("PATCH", "/ai-providers/settings", "ADMIN"),
    ("POST", "/service-operations/services/ai_soc_worker/restart", "ADMIN"),
    ("GET", "/unclassified-operation", ""),
])
def test_cross_product_rbac(method, path, roles, role):
    assert is_request_authorized(method, path, {"role": role}) == (role in roles.split())


def test_shared_accessibility_foundation_preserves_native_semantics():
    components = ROOT / "frontend/src/components"
    shell = (components / "AppShell.tsx").read_text()
    header = (components / "enterprise/EnterprisePageHeader.tsx").read_text()
    modal = (components / "enterprise/EnterpriseModal.tsx").read_text()
    css = (ROOT / "frontend/src/app/globals.css").read_text()
    assert 'href="#soc-main"' in shell and 'id="soc-main"' in shell
    assert shell.count("<main") == 1 and shell.index("<AppNavigation") < shell.index("<main")
    assert "min-w-0 max-w-full break-words" in header
    assert "dialog.showModal()" in modal and "dialog.close()" in modal
    assert "if (!closeDisabled) onClose()" in modal
    assert "max-h-[calc(100dvh-2rem)]" in modal
    assert "prefers-reduced-motion: reduce" in css
    assert "color: var(--soc-text-subtle)" in css
