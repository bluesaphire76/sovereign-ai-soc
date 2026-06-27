from __future__ import annotations

import re

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from active_users import mark_active_user
from security.audit import write_security_audit
from security.auth import get_current_user


PUBLIC_AUTH_PATHS = {
    "/auth/login",
    "/health",
    "/metrics",
    "/docs",
    "/docs/oauth2-redirect",
    "/openapi.json",
    "/redoc",
}

PUBLIC_AUTH_PREFIXES = (
    "/docs/",
    "/redoc/",
)

ROLE_ADMIN = "ADMIN"
ROLE_ANALYST = "ANALYST"
ROLE_VIEWER = "VIEWER"

ALL_ROLES = {ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER}
OPERATOR_ROLES = {ROLE_ADMIN, ROLE_ANALYST}


RBAC_RULES: list[tuple[str, str, set[str]]] = [
    ("GET", r"^/auth/me$", ALL_ROLES),

    # Users / self-service
    ("GET", r"^/users$", ALL_ROLES),
    ("POST", r"^/users$", {ROLE_ADMIN}),
    ("PATCH", r"^/users/\d+$", {ROLE_ADMIN}),
    ("DELETE", r"^/users/\d+$", {ROLE_ADMIN}),
    ("POST", r"^/users/\d+/password$", ALL_ROLES),

    # Security audit
    ("GET", r"^/security-audit/events$", {ROLE_ADMIN}),

    # Synthetic tests
    ("GET", r"^/synthetic-tests/scenarios$", OPERATOR_ROLES),
    ("POST", r"^/synthetic-tests/run$", OPERATOR_ROLES),
    ("DELETE", r"^/demo-management/(incidents|cases)/\d+$", OPERATOR_ROLES),
    ("POST", r"^/detection-quality/action-guidance$", ALL_ROLES),
    ("POST", r"^/detection-quality/semantic-context$", OPERATOR_ROLES),

    # Incidents
    ("GET", r"^/incidents$", ALL_ROLES),
    ("GET", r"^/incidents/\d+(/(audit|notes|ai-brief))?$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/timeline(?:/(summary|capabilities))?$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/similar-incidents$", OPERATOR_ROLES),
    ("GET", r"^/incidents/\d+/recommended-playbooks$", OPERATOR_ROLES),
    ("GET", r"^/investigation-graph/(capabilities|incidents/\d+(?:/summary)?|cases/\d+(?:/summary)?)$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/remediation-plan$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/remediation-dry-run$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/remediation-rollback-readiness$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/remediation-audit-trail$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/remediation-replay$", ALL_ROLES),
    ("POST", r"^/incidents/\d+/remediation-actions/[^/]+/execute-approved$", OPERATOR_ROLES),
    ("GET", r"^/remediation/catalog/(actions|connectors|playbooks)$", ALL_ROLES),
    ("GET", r"^/remediation/(proposals(?:/\d+(?:/history)?)?|incidents/\d+/proposals|cases/\d+/proposals)$", ALL_ROLES),
    ("POST", r"^/remediation/proposals$", OPERATOR_ROLES),
    ("PATCH", r"^/remediation/proposals/\d+$", OPERATOR_ROLES),
    ("POST", r"^/remediation/proposals/(from-ai-recommendation|from-playbook)$", OPERATOR_ROLES),
    ("POST", r"^/remediation/proposals/\d+/(submit|cancel|convert)$", OPERATOR_ROLES),
    ("POST", r"^/remediation/proposals/\d+/(approve|reject)$", {ROLE_ADMIN}),
    ("PATCH", r"^/incidents/\d+/status$", OPERATOR_ROLES),
    ("POST", r"^/incidents/\d+/(notes|case|ai-brief)$", OPERATOR_ROLES),

    # Platform / operations
    ("GET", r"^/platform/health$", ALL_ROLES),
    ("GET", r"^/platform/ingest/wazuh$", ALL_ROLES),
    ("GET", r"^/ai-providers(?:/(capabilities|health|effective-policy|local-profiles))?$", ALL_ROLES),
    ("PATCH", r"^/ai-providers/settings$", {ROLE_ADMIN}),
    ("PATCH", r"^/ai-providers/[^/]+/config$", {ROLE_ADMIN}),
    ("POST", r"^/ai-providers/[^/]+/test$", {ROLE_ADMIN}),
    ("GET", r"^/semantic-memory/(capabilities|health|collection|index-status|auto-index-status|search)$", OPERATOR_ROLES),
    ("POST", r"^/semantic-memory/(historical-backfill|detection-case-backfill|retention-cleanup)$", {ROLE_ADMIN}),
    ("GET", r"^/ai-data-control/(capabilities|policies|decisions)$", ALL_ROLES),
    ("GET", r"^/ai-data-control/policies/[^/]+$", ALL_ROLES),
    ("PATCH", r"^/ai-data-control/policies/[^/]+$", {ROLE_ADMIN}),
    ("POST", r"^/ai-data-control/(evaluate-preview|redaction-preview)$", OPERATOR_ROLES),
    ("GET", r"^/service-operations/services(?:/[^/]+/status)?$", ALL_ROLES),
    ("POST", r"^/service-operations/services/[^/]+/restart-preview$", OPERATOR_ROLES),
    ("POST", r"^/service-operations/services/[^/]+/restart$", {ROLE_ADMIN}),
    ("GET", r"^/service-operations/operations(?:/\d+)?$", ALL_ROLES),

    # Settings / detection control plane
    ("GET", r"^/settings/detection-control$", ALL_ROLES),
    ("GET", r"^/detection-control/config-versions(?:/[^/]+(?:/(active|\d+))?)?$", ALL_ROLES),
    ("POST", r"^/detection-control/config-versions/[^/]+/(validate|diff)$", OPERATOR_ROLES),
    ("POST", r"^/detection-control/config-versions/[^/]+/(apply|rollback)$", {ROLE_ADMIN}),
    ("GET", r"^/detection-control/operations/(overview|noise-suppression|exceptions|rules)$", ALL_ROLES),
    ("GET", r"^/detection-control/operations/items/[^/]+/(summary|matched-events)$", ALL_ROLES),
    ("POST", r"^/detection-control/operations/match-preview$", OPERATOR_ROLES),
    ("POST", r"^/detection-control/operations/items/[^/]+/(extend-review|mark-reviewed)$", OPERATOR_ROLES),
    ("POST", r"^/detection-control/semantic-context$", OPERATOR_ROLES),
    ("GET", r"^/detection-control/lifecycle/items(?:/\d+(?:/(history|diff))?)?$", ALL_ROLES),
    ("POST", r"^/detection-control/lifecycle/items$", OPERATOR_ROLES),
    ("PATCH", r"^/detection-control/lifecycle/items/\d+$", OPERATOR_ROLES),
    ("DELETE", r"^/detection-control/lifecycle/items/\d+$", OPERATOR_ROLES),
    ("POST", r"^/detection-control/lifecycle/items/\d+/(validate|submit|return-to-draft|clone)$", OPERATOR_ROLES),
    ("POST", r"^/detection-control/lifecycle/items/\d+/(approve|reject|apply|disable)$", {ROLE_ADMIN}),
    ("GET", r"^/detection-control/rules(?:/[^/]+)?$", ALL_ROLES),
    ("POST", r"^/detection-control/rules$", {ROLE_ADMIN}),
    ("PATCH", r"^/detection-control/rules/[^/]+$", {ROLE_ADMIN}),
    ("DELETE", r"^/detection-control/rules/[^/]+$", {ROLE_ADMIN}),
    ("POST", r"^/detection-control/rules/[^/]+/(enable|disable|validate)$", {ROLE_ADMIN}),

    # Executive / reports / metrics
    ("GET", r"^/executive/summary$", ALL_ROLES),
    ("GET", r"^/reports/incidents/\d+$", ALL_ROLES),
    ("GET", r"^/reports/cases/\d+$", ALL_ROLES),
    ("GET", r"^/reports/cases/\d+/executive-pdf$", ALL_ROLES),
    ("GET", r"^/reports/cases/\d+/evidence-pack$", ALL_ROLES),
    ("GET", r"^/metrics/status-distribution$", ALL_ROLES),
    ("GET", r"^/metrics/summary$", ALL_ROLES),
    ("GET", r"^/metrics/top-hosts$", ALL_ROLES),
    ("GET", r"^/metrics/risk-distribution$", ALL_ROLES),
    ("GET", r"^/metrics/(incident-trend|queue-aging|detection-funnel)$", ALL_ROLES),

    # Cases
    ("GET", r"^/cases$", ALL_ROLES),
    ("GET", r"^/cases/\d+$", ALL_ROLES),
    ("PATCH", r"^/cases/\d+/workflow$", OPERATOR_ROLES),
    ("GET", r"^/cases/\d+/audit$", ALL_ROLES),
    ("GET", r"^/cases/\d+/closure$", ALL_ROLES),
    ("GET", r"^/cases/\d+/closure/semantic-context$", OPERATOR_ROLES),
    ("GET", r"^/cases/\d+/recommended-playbooks$", OPERATOR_ROLES),
    ("PATCH", r"^/cases/\d+/closure$", OPERATOR_ROLES),
    ("POST", r"^/cases/\d+/actions/suggestions$", OPERATOR_ROLES),
    ("GET", r"^/cases/\d+/timeline$", ALL_ROLES),
    ("GET", r"^/cases/\d+/actions$", ALL_ROLES),
    ("POST", r"^/cases/\d+/actions$", OPERATOR_ROLES),
    ("PATCH", r"^/cases/\d+/actions/\d+$", OPERATOR_ROLES),
    ("GET", r"^/cases/\d+/incidents$", ALL_ROLES),
    ("POST", r"^/cases/\d+/ai-generation/(analysis|action-suggestions)$", OPERATOR_ROLES),
    ("GET", r"^/cases/\d+/ai-generation/(analysis|action-suggestions)/latest$", ALL_ROLES),
    ("GET", r"^/cases/\d+/ai-generation/jobs/[^/]+$", ALL_ROLES),
    ("GET", r"^/cases/\d+/analysis$", ALL_ROLES),
    ("POST", r"^/cases/\d+/analysis$", OPERATOR_ROLES),
    ("GET", r"^/network-events$", ALL_ROLES),
    ("GET", r"^/network-events/recent$", ALL_ROLES),
    ("GET", r"^/network-events/summary$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/network-evidence$", ALL_ROLES),

    ("GET", r"^/dns-events$", ALL_ROLES),
    ("GET", r"^/dns-events/recent$", ALL_ROLES),
    ("GET", r"^/dns-events/summary$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/dns-evidence$", ALL_ROLES),
]


def current_user_role(current_user: dict) -> str:
    return str(current_user.get("role") or "").upper().strip()


def is_request_authorized(method: str, path: str, current_user: dict) -> bool:
    role = current_user_role(current_user)

    for rule_method, pattern, allowed_roles in RBAC_RULES:
        if method == rule_method and re.match(pattern, path):
            return role in allowed_roles

    # Secure default for authenticated but unclassified operational routes.
    return False


async def enforce_api_authentication(request: Request, call_next):
    path = request.url.path

    if request.method == "OPTIONS":
        return await call_next(request)

    if path in PUBLIC_AUTH_PATHS or any(path.startswith(prefix) for prefix in PUBLIC_AUTH_PREFIXES):
        return await call_next(request)

    try:
        current_user = get_current_user(request.headers.get("authorization"))
        mark_active_user(current_user)
    except HTTPException as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None),
        )

    if not is_request_authorized(request.method, path, current_user):
        write_security_audit(
            event_type="RBAC_DENIED",
            outcome="DENIED",
            current_user=current_user,
            request=request,
            details={
                "method": request.method,
                "path": path,
                "role": current_user_role(current_user),
            },
        )

        return JSONResponse(
            status_code=403,
            content={
                "detail": "Forbidden: insufficient role permissions.",
                "path": path,
                "method": request.method,
                "role": current_user_role(current_user),
            },
        )

    request.state.current_user = current_user
    return await call_next(request)
