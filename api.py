from datetime import datetime, timezone
import json
import uuid
import re
from fastapi import FastAPI, HTTPException, Query, Response, Depends, Header, Request
from sqlalchemy import func, or_, case as sql_case

from database import SessionLocal
from case_ai_analysis import generate_case_ai_analysis
from case_action_suggestions import generate_case_action_suggestions
from case_timeline import build_case_timeline
from models import Incident, IncidentAudit, IncidentNote, IncidentCase, CaseIncident, CaseAIAnalysis, CaseAudit, CaseAction, CaseClosureChecklist, AppUser, SecurityAuditEvent, utc_now
from timezone_utils import APP_TIMEZONE, format_timestamp_local, normalize_timestamp_utc
from wazuh_ingest_state import get_watermark_snapshot
from auth_utils import create_access_token, decode_access_token, hash_password, verify_password
from routers.health import router as health_router
from routers.reports import router as reports_router

from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from pydantic import BaseModel

app = FastAPI(
    title="Sovereign AI SOC API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://localhost:8443",
        "http://localhost:8443",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(reports_router)

VALID_INCIDENT_STATUSES = {
    "NEW",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
    "FALSE_POSITIVE",
    # Legacy-compatible status kept for existing records and executive metrics.
    "ESCALATED",
}

VALID_CASE_STATUSES = {
    "OPEN",
    "TRIAGED",
    "INVESTIGATING",
    "ESCALATED",
    "CLOSED",
    "FALSE_POSITIVE",
}

VALID_CASE_SEVERITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

VALID_CASE_ACTION_STATUSES = {
    "OPEN",
    "IN_PROGRESS",
    "DONE",
    "CANCELLED",
}

VALID_CASE_ACTION_CATEGORIES = {
    "INVESTIGATION",
    "CONTAINMENT",
    "EVIDENCE_REVIEW",
    "ESCALATION",
    "CLOSURE",
    "OTHER",
}

VALID_CASE_ACTION_PRIORITIES = {
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


TERMINAL_CASE_STATUSES = {
    "CLOSED",
    "FALSE_POSITIVE",
}

VALID_CLOSURE_DECISIONS = {
    "RESOLVED",
    "FALSE_POSITIVE",
    "ACCEPTED_RISK",
    "DUPLICATE",
    "OTHER",
}


CLOSURE_REQUIRED_FIELDS = {
    "root_cause": "Root cause / conclusion",
    "evidence_reviewed": "Evidence reviewed",
    "actions_summary": "Actions summary",
    "closure_reason": "Closure reason",
    "closure_decision": "Closure decision",
    "final_severity": "Final severity",
    "residual_risk": "Residual risk",
}


class IncidentStatusUpdate(BaseModel):
    status: str
    comment: str | None = None


class IncidentNoteCreate(BaseModel):
    note: str
    created_by: str | None = None

class CaseWorkflowUpdate(BaseModel):
    owner: str | None = None
    status: str | None = None
    severity: str | None = None
    sla_due_at: str | None = None
    status_reason: str | None = None
    reviewed_by: str | None = None


class CaseActionCreate(BaseModel):
    title: str
    description: str | None = None
    category: str = "INVESTIGATION"
    priority: str = "MEDIUM"
    status: str | None = None
    due_at: str | None = None
    created_by: str | None = None


class CaseActionUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    priority: str | None = None
    status: str | None = None
    due_at: str | None = None
    updated_by: str | None = None


class CaseClosureChecklistUpdate(BaseModel):
    root_cause: str | None = None
    evidence_reviewed: str | None = None
    actions_summary: str | None = None
    closure_reason: str | None = None
    closure_decision: str | None = None
    final_severity: str | None = None
    residual_risk: str | None = None
    reviewed_by: str | None = None


VALID_USER_ROLES = {
    "ADMIN",
    "ANALYST",
    "VIEWER",
}


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str
    password: str
    display_name: str | None = None
    role: str = "ANALYST"
    is_active: bool = True


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: str | None = None
    is_active: bool | None = None


class UserPasswordUpdate(BaseModel):
    password: str


class SyntheticTestRunCreate(BaseModel):
    scenario: str = "all"
    count: int = 1
    host: str | None = None
    created_by: str | None = None


def serialize_user(user: AppUser) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }


def normalize_username(username: str) -> str:
    return username.strip().lower()


def hash_password_or_400(password: str) -> str:
    try:
        return hash_password(password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid request.")


SENSITIVE_AUDIT_KEYS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "authorization",
}


def sanitize_audit_details(value):
    if isinstance(value, dict):
        sanitized = {}

        for key, item in value.items():
            if str(key).lower() in SENSITIVE_AUDIT_KEYS:
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = sanitize_audit_details(item)

        return sanitized

    if isinstance(value, list):
        return [sanitize_audit_details(item) for item in value]

    return value


def request_client_ip(request: Request | None) -> str | None:
    if request is None:
        return None

    forwarded_for = request.headers.get("x-forwarded-for")

    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()

    if request.client:
        return request.client.host

    return None


def write_security_audit(
    *,
    event_type: str,
    outcome: str,
    current_user: dict | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    target_username: str | None = None,
    request: Request | None = None,
    details: dict | None = None,
):
    audit_db = SessionLocal()

    try:
        audit_db.add(
            SecurityAuditEvent(
                event_type=event_type,
                outcome=outcome,
                actor_user_id=current_user.get("id") if current_user else None,
                actor_username=current_user.get("username") if current_user else None,
                actor_role=current_user.get("role") if current_user else None,
                target_type=target_type,
                target_id=str(target_id) if target_id is not None else None,
                target_username=target_username,
                method=request.method if request else None,
                path=request.url.path if request else None,
                client_ip=request_client_ip(request),
                user_agent=request.headers.get("user-agent") if request else None,
                details_json=json.dumps(
                    sanitize_audit_details(details or {}),
                    default=str,
                    sort_keys=True,
                ),
            )
        )
        audit_db.commit()
    except Exception:
        audit_db.rollback()
    finally:
        audit_db.close()



def security_audit_actor(request: Request) -> dict | None:
    return getattr(request.state, "current_user", None)



def get_current_user(authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")

    token = authorization.split(" ", 1)[1].strip()

    try:
        payload = decode_access_token(token)
        user_id = int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.id == user_id).first()

        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User is inactive or no longer exists.")

        return serialize_user(user)
    finally:
        db.close()


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "ADMIN":
        raise HTTPException(status_code=403, detail="ADMIN role required.")

    return current_user



PUBLIC_AUTH_PATHS = {
    "/auth/login",
    "/health",
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

    # Incidents
    ("GET", r"^/incidents$", ALL_ROLES),
    ("GET", r"^/incidents/\d+$", ALL_ROLES),
    ("PATCH", r"^/incidents/\d+/status$", OPERATOR_ROLES),
    ("GET", r"^/incidents/\d+/audit$", ALL_ROLES),
    ("GET", r"^/incidents/\d+/notes$", ALL_ROLES),
    ("POST", r"^/incidents/\d+/notes$", OPERATOR_ROLES),
    ("POST", r"^/incidents/\d+/case$", OPERATOR_ROLES),

    # Platform / operations
    ("GET", r"^/platform/health$", ALL_ROLES),
    ("GET", r"^/platform/ingest/wazuh$", ALL_ROLES),

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

    # Cases
    ("GET", r"^/cases$", ALL_ROLES),
    ("GET", r"^/cases/\d+$", ALL_ROLES),
    ("PATCH", r"^/cases/\d+/workflow$", OPERATOR_ROLES),
    ("GET", r"^/cases/\d+/audit$", ALL_ROLES),
    ("GET", r"^/cases/\d+/closure$", ALL_ROLES),
    ("PATCH", r"^/cases/\d+/closure$", OPERATOR_ROLES),
    ("POST", r"^/cases/\d+/actions/suggestions$", OPERATOR_ROLES),
    ("GET", r"^/cases/\d+/timeline$", ALL_ROLES),
    ("GET", r"^/cases/\d+/actions$", ALL_ROLES),
    ("POST", r"^/cases/\d+/actions$", OPERATOR_ROLES),
    ("PATCH", r"^/cases/\d+/actions/\d+$", OPERATOR_ROLES),
    ("GET", r"^/cases/\d+/incidents$", ALL_ROLES),
    ("GET", r"^/cases/\d+/analysis$", ALL_ROLES),
    ("POST", r"^/cases/\d+/analysis$", OPERATOR_ROLES),
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


@app.middleware("http")
async def enforce_api_authentication(request: Request, call_next):
    path = request.url.path

    if request.method == "OPTIONS":
        return await call_next(request)

    if path in PUBLIC_AUTH_PATHS or any(path.startswith(prefix) for prefix in PUBLIC_AUTH_PREFIXES):
        return await call_next(request)

    try:
        current_user = get_current_user(request.headers.get("authorization"))
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


@app.post("/auth/login")
def login(payload: LoginRequest, request: Request):
    username = normalize_username(payload.username)

    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.username == username).first()

        if not user or not verify_password(payload.password, user.password_hash):
            write_security_audit(
                event_type="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                target_type="USER",
                target_username=username,
                request=request,
                details={"reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=401, detail="Invalid username or password.")

        if not user.is_active:
            write_security_audit(
                event_type="AUTH_LOGIN_FAILURE",
                outcome="FAILURE",
                target_type="USER",
                target_id=user.id,
                target_username=user.username,
                request=request,
                details={"reason": "disabled_account"},
            )
            raise HTTPException(status_code=403, detail="User account is disabled.")

        user.last_login_at = datetime.now(timezone.utc)
        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)

        token = create_access_token(
            user_id=user.id,
            username=user.username,
            role=user.role,
        )

        write_security_audit(
            event_type="AUTH_LOGIN_SUCCESS",
            outcome="SUCCESS",
            current_user=serialize_user(user),
            target_type="USER",
            target_id=user.id,
            target_username=user.username,
            request=request,
        )

        return {
            **token,
            "user": serialize_user(user),
        }
    finally:
        db.close()


@app.get("/auth/me")
def auth_me(current_user: dict = Depends(get_current_user)):
    return current_user


@app.get("/users")
def list_users(current_user: dict = Depends(get_current_user)):
    db = SessionLocal()

    try:
        if current_user_role(current_user) == ROLE_ADMIN:
            users = db.query(AppUser).order_by(AppUser.username.asc()).all()
        else:
            users = (
                db.query(AppUser)
                .filter(AppUser.id == current_user["id"])
                .order_by(AppUser.username.asc())
                .all()
            )

        return {
            "items": [serialize_user(user) for user in users],
        }
    finally:
        db.close()


@app.post("/users")
def create_user(payload: UserCreate, request: Request, current_user: dict = Depends(require_admin)):
    username = normalize_username(payload.username)

    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")

    role = payload.role.upper().strip()

    if role not in VALID_USER_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Allowed: {sorted(VALID_USER_ROLES)}")

    db = SessionLocal()

    try:
        existing = db.query(AppUser).filter(AppUser.username == username).first()

        if existing:
            raise HTTPException(status_code=409, detail="Username already exists.")

        user = AppUser(
            username=username,
            display_name=payload.display_name,
            role=role,
            password_hash=hash_password_or_400(payload.password),
            is_active=payload.is_active,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        write_security_audit(
            event_type="USER_CREATED",
            outcome="SUCCESS",
            current_user=current_user,
            target_type="USER",
            target_id=user.id,
            target_username=user.username,
            request=request,
            details={
                "role": user.role,
                "is_active": user.is_active,
            },
        )

        return serialize_user(user)
    finally:
        db.close()


@app.patch("/users/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    current_user: dict = Depends(require_admin),
):
    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.id == user_id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        changes = {}

        if payload.display_name is not None and user.display_name != payload.display_name:
            changes["display_name"] = [user.display_name, payload.display_name]
            user.display_name = payload.display_name

        if payload.role is not None:
            role = payload.role.upper().strip()

            if role not in VALID_USER_ROLES:
                raise HTTPException(status_code=400, detail=f"Invalid role. Allowed: {sorted(VALID_USER_ROLES)}")

            if user.role != role:
                changes["role"] = [user.role, role]
                user.role = role

        if payload.is_active is not None:
            if user.id == current_user["id"] and payload.is_active is False:
                raise HTTPException(status_code=400, detail="You cannot disable your own account.")

            if user.is_active != payload.is_active:
                changes["is_active"] = [user.is_active, payload.is_active]
                user.is_active = payload.is_active

        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)

        if changes:
            write_security_audit(
                event_type="USER_UPDATED",
                outcome="SUCCESS",
                current_user=current_user,
                target_type="USER",
                target_id=user.id,
                target_username=user.username,
                request=request,
                details={"changes": changes},
            )

        return serialize_user(user)
    finally:
        db.close()


@app.post("/users/{user_id}/password")
def update_user_password(
    user_id: int,
    payload: UserPasswordUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.id == user_id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        if current_user_role(current_user) != ROLE_ADMIN and user.id != current_user["id"]:
            raise HTTPException(status_code=403, detail="You can reset only your own password.")

        user.password_hash = hash_password_or_400(payload.password)
        user.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(user)

        write_security_audit(
            event_type="USER_PASSWORD_RESET",
            outcome="SUCCESS",
            current_user=current_user,
            target_type="USER",
            target_id=user.id,
            target_username=user.username,
            request=request,
            details={
                "self_service": user.id == current_user["id"],
                "performed_by_role": current_user_role(current_user),
            },
        )

        return {
            "status": "password_updated",
            "user": serialize_user(user),
        }
    finally:
        db.close()


@app.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request, current_user: dict = Depends(require_admin)):
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    db = SessionLocal()

    try:
        user = db.query(AppUser).filter(AppUser.id == user_id).first()

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        deleted_username = user.username
        deleted_role = user.role
        deleted_is_active = user.is_active

        db.delete(user)
        db.commit()

        write_security_audit(
            event_type="USER_DELETED",
            outcome="SUCCESS",
            current_user=current_user,
            target_type="USER",
            target_id=user_id,
            target_username=deleted_username,
            request=request,
            details={
                "role": deleted_role,
                "is_active": deleted_is_active,
            },
        )

        return {
            "status": "deleted",
            "user_id": user_id,
        }
    finally:
        db.close()


def serialize_security_audit_event(row: SecurityAuditEvent) -> dict:
    details = None

    if row.details_json:
        try:
            details = json.loads(row.details_json)
        except json.JSONDecodeError:
            details = {"raw": row.details_json}

    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "event_type": row.event_type,
        "outcome": row.outcome,
        "actor_user_id": row.actor_user_id,
        "actor_username": row.actor_username,
        "actor_role": row.actor_role,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "target_username": row.target_username,
        "method": row.method,
        "path": row.path,
        "client_ip": row.client_ip,
        "user_agent": row.user_agent,
        "details": details,
    }


def parse_security_audit_datetime(value: str | None) -> datetime | None:
    if not value:
        return None

    normalized = value.strip()

    if not normalized:
        return None

    try:
        if len(normalized) == 10:
            normalized = f"{normalized}T00:00:00+00:00"

        return datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="date_from/date_to must be ISO timestamps or YYYY-MM-DD dates.",
        ) from exc


@app.get("/security-audit/events")
def list_security_audit_events(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    event_type: str | None = Query(None),
    outcome: str | None = Query(None),
    actor_username: str | None = Query(None),
    target_type: str | None = Query(None),
    target_id: str | None = Query(None),
    search: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    current_user: dict = Depends(require_admin),
):
    db = SessionLocal()

    try:
        offset = (page - 1) * limit
        query = db.query(SecurityAuditEvent)

        if event_type and event_type.upper() != "ALL":
            query = query.filter(SecurityAuditEvent.event_type == event_type.upper().strip())

        if outcome and outcome.upper() != "ALL":
            query = query.filter(SecurityAuditEvent.outcome == outcome.upper().strip())

        if actor_username:
            query = query.filter(SecurityAuditEvent.actor_username.ilike(f"%{actor_username.strip()}%"))

        if target_type and target_type.upper() != "ALL":
            query = query.filter(SecurityAuditEvent.target_type == target_type.upper().strip())

        if target_id:
            query = query.filter(SecurityAuditEvent.target_id == target_id.strip())

        parsed_date_from = parse_security_audit_datetime(date_from)
        parsed_date_to = parse_security_audit_datetime(date_to)

        if parsed_date_from:
            query = query.filter(SecurityAuditEvent.created_at >= parsed_date_from)

        if parsed_date_to:
            if date_to and len(date_to.strip()) == 10:
                parsed_date_to = parsed_date_to.replace(
                    hour=23,
                    minute=59,
                    second=59,
                    microsecond=999999,
                )

            query = query.filter(SecurityAuditEvent.created_at <= parsed_date_to)

        if search:
            value = f"%{search.strip()}%"
            query = query.filter(
                or_(
                    SecurityAuditEvent.event_type.ilike(value),
                    SecurityAuditEvent.outcome.ilike(value),
                    SecurityAuditEvent.actor_username.ilike(value),
                    SecurityAuditEvent.actor_role.ilike(value),
                    SecurityAuditEvent.target_type.ilike(value),
                    SecurityAuditEvent.target_id.ilike(value),
                    SecurityAuditEvent.target_username.ilike(value),
                    SecurityAuditEvent.method.ilike(value),
                    SecurityAuditEvent.path.ilike(value),
                    SecurityAuditEvent.client_ip.ilike(value),
                    SecurityAuditEvent.details_json.ilike(value),
                )
            )

        total = query.with_entities(func.count(SecurityAuditEvent.id)).scalar() or 0

        rows = (
            query.order_by(
                SecurityAuditEvent.created_at.desc().nullslast(),
                SecurityAuditEvent.id.desc(),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

        total_pages = max((total + limit - 1) // limit, 1)

        return {
            "items": [serialize_security_audit_event(row) for row in rows],
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        }
    finally:
        db.close()



SYNTHETIC_SCENARIOS = {
    "ssh_bruteforce": {
        "title": "SYNTHETIC ssh_bruteforce: repeated authentication failures",
        "rule": "SYNTHETIC ssh_bruteforce - repeated failed SSH login attempts",
        "level": 10,
        "mitre": ["T1110", "T1021.004"],
        "risk_score": 76,
        "correlation_score": 84,
        "correlation_type": "SYNTHETIC_SSH_BRUTEFORCE",
        "recommended_priority": "HIGH",
        "attack_chain": "Initial Access -> Credential Access",
        "escalation_reason": "Synthetic brute force scenario generated repeated failed SSH authentication events.",
        "ai_analysis": "Synthetic SSH brute-force test. Validate detection, correlation, priority assignment and MITRE mapping.",
        "matched_patterns": {
            "ssh_bruteforce": {
                "keywords": ["ssh", "failed password", "authentication failure", "bruteforce"],
                "weight": 40,
            }
        },
    },
    "privilege_escalation": {
        "title": "SYNTHETIC privilege_escalation: suspicious sudo/root activity",
        "rule": "SYNTHETIC privilege_escalation - suspicious sudo/root command execution",
        "level": 12,
        "mitre": ["T1068", "T1548"],
        "risk_score": 88,
        "correlation_score": 91,
        "correlation_type": "SYNTHETIC_PRIVILEGE_ESCALATION",
        "recommended_priority": "CRITICAL",
        "attack_chain": "Execution -> Privilege Escalation",
        "escalation_reason": "Synthetic privilege escalation scenario generated suspicious root-level activity.",
        "ai_analysis": "Synthetic privilege-escalation test. Validate escalation logic, critical priority and MITRE coverage.",
        "matched_patterns": {
            "privilege_escalation": {
                "keywords": ["sudo", "root", "privilege escalation", "setuid"],
                "weight": 50,
            }
        },
    },
    "malware_indicator": {
        "title": "SYNTHETIC malware_indicator: suspicious process and persistence signal",
        "rule": "SYNTHETIC malware_indicator - suspicious process persistence indicator",
        "level": 11,
        "mitre": ["T1059", "T1547"],
        "risk_score": 82,
        "correlation_score": 87,
        "correlation_type": "SYNTHETIC_MALWARE_INDICATOR",
        "recommended_priority": "HIGH",
        "attack_chain": "Execution -> Persistence",
        "escalation_reason": "Synthetic malware indicator scenario generated suspicious execution and persistence evidence.",
        "ai_analysis": "Synthetic malware-indicator test. Validate detection quality, correlation score and persistence classification.",
        "matched_patterns": {
            "malware_indicator": {
                "keywords": ["malware", "persistence", "suspicious process", "autorun"],
                "weight": 45,
            }
        },
    },
}


def build_synthetic_incident(
    *,
    scenario_name: str,
    index: int,
    host: str,
    created_by: str,
) -> Incident:
    scenario = SYNTHETIC_SCENARIOS[scenario_name]
    now = datetime.now(timezone.utc)
    timestamp = now.isoformat()
    synthetic_id = f"synthetic-{scenario_name}-{now.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"

    raw_alert = {
        "synthetic": True,
        "source": "sovereign-ai-soc-synthetic",
        "scenario": scenario_name,
        "scenario_index": index,
        "created_by": created_by,
        "generated_at": timestamp,
        "agent": {
            "name": host,
        },
        "rule": {
            "description": scenario["rule"],
            "level": scenario["level"],
            "mitre": {
                "id": scenario["mitre"],
            },
        },
        "data": {
            "test_type": "gui_synthetic_test",
            "expected_priority": scenario["recommended_priority"],
            "expected_correlation_type": scenario["correlation_type"],
        },
    }

    correlation_summary = {
        "agent": host,
        "window_minutes": 60,
        "related_events": 1,
        "current_incident_id": None,
        "base_score": scenario["risk_score"],
        "pattern_score": 35,
        "volume_score": 10,
        "chain_bonus": 10,
        "final_correlation_score": scenario["correlation_score"],
        "recommended_priority": scenario["recommended_priority"],
        "matched_patterns": scenario["matched_patterns"],
        "matched_attack_chains": [
            {
                "name": scenario["attack_chain"],
                "correlation_type": scenario["correlation_type"],
                "priority": scenario["recommended_priority"],
                "reason": scenario["escalation_reason"],
                "score_bonus": 10,
            }
        ],
        "related_event_details": [],
    }

    return Incident(
        wazuh_doc_id=synthetic_id,
        status="NEW",
        timestamp=timestamp,
        agent=host,
        rule=scenario["rule"],
        level=scenario["level"],
        mitre=json.dumps(scenario["mitre"]),
        risk_score=scenario["risk_score"],
        ai_analysis=scenario["ai_analysis"],
        raw_alert=json.dumps(raw_alert),
        correlated=True,
        correlation_summary=json.dumps(correlation_summary),
        correlation_score=scenario["correlation_score"],
        attack_chain=scenario["attack_chain"],
        correlation_type=scenario["correlation_type"],
        escalation_reason=scenario["escalation_reason"],
        recommended_priority=scenario["recommended_priority"],
    )


@app.get("/synthetic-tests/scenarios")
def list_synthetic_test_scenarios():
    return {
        "items": [
            {
                "id": key,
                "title": value["title"],
                "rule": value["rule"],
                "recommended_priority": value["recommended_priority"],
                "risk_score": value["risk_score"],
                "correlation_type": value["correlation_type"],
                "mitre": value["mitre"],
            }
            for key, value in SYNTHETIC_SCENARIOS.items()
        ]
    }


@app.post("/synthetic-tests/run")
def run_synthetic_tests(payload: SyntheticTestRunCreate, request: Request):
    requested_scenario = payload.scenario.lower().strip()
    count = max(1, min(payload.count, 10))
    host = (payload.host or "synthetic-sensor-01").strip() or "synthetic-sensor-01"
    created_by = (payload.created_by or "local_analyst").strip() or "local_analyst"

    if requested_scenario == "all":
        scenarios = list(SYNTHETIC_SCENARIOS.keys())
    elif requested_scenario in SYNTHETIC_SCENARIOS:
        scenarios = [requested_scenario]
    else:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Unknown synthetic scenario.",
                "requested_scenario": requested_scenario,
                "available_scenarios": ["all", *SYNTHETIC_SCENARIOS.keys()],
            },
        )

    db = SessionLocal()

    try:
        created_incidents: list[Incident] = []

        for scenario_name in scenarios:
            for index in range(1, count + 1):
                incident = build_synthetic_incident(
                    scenario_name=scenario_name,
                    index=index,
                    host=host,
                    created_by=created_by,
                )
                db.add(incident)
                db.flush()

                db.add(
                    IncidentAudit(
                        incident_id=incident.id,
                        event_type="SYNTHETIC_TEST_CREATED",
                        old_value=None,
                        new_value=scenario_name,
                        comment=(
                            f"Synthetic test incident generated from GUI. "
                            f"Scenario={scenario_name}; host={host}; created_by={created_by}"
                        ),
                        created_by=created_by,
                    )
                )

                created_incidents.append(incident)

        db.commit()

        write_security_audit(
            event_type="SYNTHETIC_TEST_RUN",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="SYNTHETIC_TEST",
            target_id=requested_scenario,
            request=request,
            details={
                "requested_scenario": requested_scenario,
                "scenarios": scenarios,
                "host": host,
                "count_per_scenario": count,
                "created": len(created_incidents),
                "created_by": created_by,
                "incident_ids": [incident.id for incident in created_incidents],
            },
        )

        return {
            "status": "created",
            "scenario": requested_scenario,
            "host": host,
            "count_per_scenario": count,
            "created": len(created_incidents),
            "incidents": [
                {
                    "id": incident.id,
                    "scenario": incident.correlation_type,
                    "rule": incident.rule,
                    "risk_score": incident.risk_score,
                    "recommended_priority": incident.recommended_priority,
                    "correlation_score": incident.correlation_score,
                }
                for incident in created_incidents
            ],
        }
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@app.get("/incidents")
def list_incidents(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    risk: str | None = Query(None),
    host: str | None = Query(None),
    search: str | None = Query(None),
    priority: str | None = Query(None),
    correlation_type: str | None = Query(None),
    correlated: str | None = Query(None),
    mitre: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
):
    db = SessionLocal()

    try:
        offset = (page - 1) * limit

        query = db.query(Incident)

        if status and status.upper() != "ALL":
            query = query.filter(Incident.status == status.upper())

        if host:
            query = query.filter(Incident.agent.ilike(f"%{host}%"))

        if search:
            query = query.filter(Incident.rule.ilike(f"%{search}%"))

        if priority and priority.upper() != "ALL":
            query = query.filter(Incident.recommended_priority == priority.upper())

        if correlation_type:
            query = query.filter(Incident.correlation_type.ilike(f"%{correlation_type}%"))

        if mitre:
            query = query.filter(Incident.mitre.ilike(f"%{mitre}%"))

        if correlated and correlated.upper() != "ALL":
            correlated_value = correlated.lower()

            if correlated_value in {"true", "yes", "1"}:
                query = query.filter(Incident.correlated == True)
            elif correlated_value in {"false", "no", "0"}:
                query = query.filter(Incident.correlated == False)

        if date_from:
            query = query.filter(Incident.timestamp >= f"{date_from}T00:00:00+00:00")

        if date_to:
            query = query.filter(Incident.timestamp <= f"{date_to}T23:59:59+00:00")

        if risk and risk.upper() != "ALL":
            risk_value = risk.lower()

            if risk_value == "low":
                query = query.filter(
                    or_(
                        Incident.risk_score.is_(None),
                        Incident.risk_score <= 39,
                    )
                )
            elif risk_value == "medium":
                query = query.filter(
                    Incident.risk_score >= 40,
                    Incident.risk_score <= 59,
                )
            elif risk_value == "high":
                query = query.filter(
                    Incident.risk_score >= 60,
                    Incident.risk_score <= 79,
                )
            elif risk_value == "critical":
                query = query.filter(Incident.risk_score >= 80)

        total = query.with_entities(func.count(Incident.id)).scalar() or 0

        incidents = (
            query.order_by(Incident.timestamp.desc().nullslast(), Incident.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        total_pages = max((total + limit - 1) // limit, 1)

        return {
            "items": [
                {
                    "id": item.id,
                    "status": item.status,
                    "timestamp": normalize_timestamp_utc(item.timestamp),
                    "timestamp_local": format_timestamp_local(item.timestamp),
                    "timezone": APP_TIMEZONE,
                    "agent": item.agent,
                    "rule": item.rule,
                    "level": item.level,
                    "risk_score": item.risk_score,
                    "correlation_score": item.correlation_score,
                    "correlated": item.correlated,
                    "correlation_type": item.correlation_type,
                    "recommended_priority": item.recommended_priority,
                }
                for item in incidents
            ],
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        }

    finally:
        db.close()


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        return {
            "id": incident.id,
            "status": incident.status,
            "wazuh_doc_id": incident.wazuh_doc_id,
            "timestamp": normalize_timestamp_utc(incident.timestamp),
            "timestamp_local": format_timestamp_local(incident.timestamp),
            "timezone": APP_TIMEZONE,
            "agent": incident.agent,
            "rule": incident.rule,
            "level": incident.level,
            "mitre": incident.mitre,
            "risk_score": incident.risk_score,
            "ai_analysis": incident.ai_analysis,
            "correlated": incident.correlated,
            "correlation_score": incident.correlation_score,
            "correlation_summary": incident.correlation_summary,
            "raw_alert": incident.raw_alert,
            "attack_chain": incident.attack_chain,
            "correlation_type": incident.correlation_type,
            "escalation_reason": incident.escalation_reason,
            "recommended_priority": incident.recommended_priority,
        }

    finally:
        db.close()

@app.patch("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    payload: IncidentStatusUpdate,
    request: Request,
):
    requested_status = payload.status.upper()

    if requested_status not in VALID_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed values: {sorted(VALID_INCIDENT_STATUSES)}",
        )

    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        old_status = incident.status or "NEW"

        if old_status != requested_status:
            audit = IncidentAudit(
                incident_id=incident.id,
                event_type="STATUS_CHANGE",
                old_value=old_status,
                new_value=requested_status,
                comment=payload.comment,
                created_by="local_analyst",
            )

            db.add(audit)
            incident.status = requested_status

        db.commit()
        db.refresh(incident)

        if old_status != requested_status:
            write_security_audit(
                event_type="INCIDENT_STATUS_UPDATED",
                outcome="SUCCESS",
                current_user=security_audit_actor(request),
                target_type="INCIDENT",
                target_id=incident.id,
                request=request,
                details={
                    "old_status": old_status,
                    "new_status": requested_status,
                    "comment_present": bool(payload.comment),
                },
            )

        return {
            "id": incident.id,
            "status": incident.status,
            "message": "Incident status updated",
        }

    finally:
        db.close()




@app.post("/incidents/{incident_id}/case")
def create_case_from_incident(incident_id: int, request: Request):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found.")

        existing_link = (
            db.query(CaseIncident)
            .filter(CaseIncident.incident_id == incident.id)
            .order_by(CaseIncident.id.desc())
            .first()
        )

        if existing_link:
            existing_case = (
                db.query(IncidentCase)
                .filter(IncidentCase.id == existing_link.case_id)
                .first()
            )

            if existing_case:
                incident_count = (
                    db.query(CaseIncident)
                    .filter(CaseIncident.case_id == existing_case.id)
                    .count()
                )

                return {
                    "created": False,
                    "case_id": existing_case.id,
                    "item": serialize_case(existing_case, incident_count),
                }

        actor = security_audit_actor(request) or {}
        actor_username = actor.get("username") or "local_analyst"
        now = utc_now()

        risk_score = incident.risk_score or incident.level or 0
        group_key = f"incident:{incident.id}"

        existing_case_by_group = (
            db.query(IncidentCase)
            .filter(IncidentCase.group_key == group_key)
            .first()
        )

        if existing_case_by_group:
            incident_count = (
                db.query(CaseIncident)
                .filter(CaseIncident.case_id == existing_case_by_group.id)
                .count()
            )

            return {
                "created": False,
                "case_id": existing_case_by_group.id,
                "item": serialize_case(existing_case_by_group, incident_count),
            }

        if risk_score >= 81:
            severity = "CRITICAL"
        elif risk_score >= 61:
            severity = "HIGH"
        elif risk_score >= 31:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        case_fields = {}

        def set_case_field(name, value):
            if hasattr(IncidentCase, name):
                case_fields[name] = value

        set_case_field("group_key", group_key)
        set_case_field("title", f"Incident #{incident.id} investigation")
        set_case_field("status", "OPEN")
        set_case_field("severity", severity)
        set_case_field("severity_review", severity)
        set_case_field("agent", incident.agent)
        set_case_field("correlation_type", incident.correlation_type or "manual_incident_escalation")
        set_case_field("risk_score", risk_score)
        set_case_field("owner", actor_username)
        set_case_field("created_by", actor_username)
        set_case_field("created_at", now)
        set_case_field("updated_at", now)
        set_case_field(
            "summary",
            f"Case created from incident #{incident.id}: {incident.rule or 'Wazuh alert'}",
        )

        case_row = IncidentCase(**case_fields)
        db.add(case_row)
        db.flush()

        link_fields = {
            "case_id": case_row.id,
            "incident_id": incident.id,
        }

        if hasattr(CaseIncident, "created_at"):
            link_fields["created_at"] = now

        db.add(CaseIncident(**link_fields))

        if hasattr(CaseClosureChecklist, "case_id"):
            closure_fields = {"case_id": case_row.id}

            if hasattr(CaseClosureChecklist, "created_at"):
                closure_fields["created_at"] = now

            if hasattr(CaseClosureChecklist, "updated_at"):
                closure_fields["updated_at"] = now

            db.add(CaseClosureChecklist(**closure_fields))

        write_security_audit(
            event_type="CASE_CREATED_FROM_INCIDENT",
            outcome="SUCCESS",
            current_user=actor,
            target_type="CASE",
            target_id=case_row.id,
            request=request,
            details={
                "incident_id": incident.id,
                "case_id": case_row.id,
                "severity": severity,
                "risk_score": risk_score,
            },
        )

        db.commit()
        db.refresh(case_row)

        return {
            "created": True,
            "case_id": case_row.id,
            "item": serialize_case(case_row, 1),
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception as exc:
        db.rollback()
        write_security_audit(
            event_type="CASE_CREATED_FROM_INCIDENT",
            outcome="FAILURE",
            current_user=security_audit_actor(request),
            target_type="INCIDENT",
            target_id=incident_id,
            request=request,
            details={"error": "internal_error"},
        )
        raise

    finally:
        db.close()


@app.get("/incidents/{incident_id}/audit")
def get_incident_audit(incident_id: int):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        rows = (
            db.query(IncidentAudit)
            .filter(IncidentAudit.incident_id == incident_id)
            .order_by(IncidentAudit.created_at.asc(), IncidentAudit.id.asc())
            .all()
        )

        return [
            {
                "id": row.id,
                "incident_id": row.incident_id,
                "event_type": row.event_type,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment": row.comment,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]

    finally:
        db.close()



@app.get("/incidents/{incident_id}/notes")
def get_incident_notes(incident_id: int):
    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        rows = (
            db.query(IncidentNote)
            .filter(IncidentNote.incident_id == incident_id)
            .order_by(IncidentNote.created_at.desc(), IncidentNote.id.desc())
            .all()
        )

        return [
            {
                "id": row.id,
                "incident_id": row.incident_id,
                "note": row.note,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]

    finally:
        db.close()


@app.post("/incidents/{incident_id}/notes")
def create_incident_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    request: Request,
):
    note_text = payload.note.strip()

    if not note_text:
        raise HTTPException(status_code=400, detail="Note cannot be empty")

    db = SessionLocal()

    try:
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        created_by = payload.created_by or "local_analyst"

        note = IncidentNote(
            incident_id=incident.id,
            note=note_text,
            created_by=created_by,
        )

        db.add(note)
        db.flush()

        audit = IncidentAudit(
            incident_id=incident.id,
            event_type="NOTE_ADDED",
            old_value=None,
            new_value=f"note:{note.id}",
            comment=note_text,
            created_by=created_by,
        )

        db.add(audit)
        db.commit()
        db.refresh(note)

        write_security_audit(
            event_type="INCIDENT_NOTE_CREATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="INCIDENT",
            target_id=incident.id,
            request=request,
            details={
                "note_id": note.id,
                "created_by": created_by,
                "note_length": len(note.note or ""),
            },
        )

        return {
            "id": note.id,
            "incident_id": note.incident_id,
            "note": note.note,
            "created_by": note.created_by,
            "created_at": note.created_at.isoformat() if note.created_at else None,
        }

    finally:
        db.close()



@app.get("/platform/ingest/wazuh")
def wazuh_ingest_watermark():
    return get_watermark_snapshot()



@app.get("/executive/summary")
def executive_summary():
    db = SessionLocal()

    try:
        total_incidents = db.query(Incident).count()

        open_incidents = (
            db.query(Incident)
            .filter(~Incident.status.in_(["CLOSED", "FALSE_POSITIVE"]))
            .count()
        )

        escalated_incidents = (
            db.query(Incident)
            .filter(Incident.status == "ESCALATED")
            .count()
        )

        critical_incidents = (
            db.query(Incident)
            .filter(Incident.risk_score >= 81)
            .count()
        )

        high_or_critical_incidents = (
            db.query(Incident)
            .filter(Incident.risk_score >= 61)
            .count()
        )

        correlated_incidents = (
            db.query(Incident)
            .filter(Incident.correlated == True)
            .count()
        )

        avg_risk = db.query(func.avg(Incident.risk_score)).scalar()
        max_risk = db.query(func.max(Incident.risk_score)).scalar()

        total_cases = db.query(IncidentCase).count()

        open_cases = (
            db.query(IncidentCase)
            .filter(~IncidentCase.status.in_(["CLOSED", "FALSE_POSITIVE"]))
            .count()
        )

        escalated_cases = (
            db.query(IncidentCase)
            .filter(IncidentCase.status == "ESCALATED")
            .count()
        )

        critical_cases = (
            db.query(IncidentCase)
            .filter(IncidentCase.severity == "CRITICAL")
            .count()
        )

        latest_cases = (
            db.query(IncidentCase)
            .order_by(IncidentCase.updated_at.desc(), IncidentCase.id.desc())
            .limit(5)
            .all()
        )

        latest_high_risk_incidents = (
            db.query(Incident)
            .filter(Incident.risk_score >= 61)
            .order_by(Incident.timestamp.desc().nullslast(), Incident.id.desc())
            .limit(5)
            .all()
        )

        top_hosts_rows = (
            db.query(
                Incident.agent,
                func.count(Incident.id).label("count"),
                func.max(Incident.risk_score).label("max_risk"),
                func.avg(Incident.risk_score).label("avg_risk"),
            )
            .group_by(Incident.agent)
            .order_by(func.max(Incident.risk_score).desc(), func.count(Incident.id).desc())
            .limit(5)
            .all()
        )

        case_status_rows = (
            db.query(
                IncidentCase.status,
                func.count(IncidentCase.id).label("count"),
            )
            .group_by(IncidentCase.status)
            .all()
        )

        incident_status_rows = (
            db.query(
                Incident.status,
                func.count(Incident.id).label("count"),
            )
            .group_by(Incident.status)
            .all()
        )

        priority_rows = (
            db.query(
                Incident.recommended_priority,
                func.count(Incident.id).label("count"),
            )
            .group_by(Incident.recommended_priority)
            .all()
        )

        correlation_type_rows = (
            db.query(
                Incident.correlation_type,
                func.count(Incident.id).label("count"),
            )
            .filter(Incident.correlation_type.isnot(None))
            .group_by(Incident.correlation_type)
            .order_by(func.count(Incident.id).desc())
            .limit(5)
            .all()
        )

        latest_case_analysis = (
            db.query(CaseAIAnalysis)
            .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
            .first()
        )

        recommendations = []

        if critical_incidents > 0 or critical_cases > 0:
            recommendations.append(
                "Review critical incidents and critical cases before closing operational backlog."
            )

        if escalated_incidents > 0 or escalated_cases > 0:
            recommendations.append(
                "Escalated items require management visibility and explicit ownership."
            )

        if open_cases > 0:
            recommendations.append(
                "Keep investigation cases updated with analyst notes and AI case analysis."
            )

        if high_or_critical_incidents == 0 and open_cases == 0:
            recommendations.append(
                "No immediate high-risk backlog detected. Continue monitoring and validate ingestion health."
            )

        executive_status = "OK"

        if critical_incidents > 0 or critical_cases > 0:
            executive_status = "CRITICAL"
        elif escalated_incidents > 0 or escalated_cases > 0 or high_or_critical_incidents > 0:
            executive_status = "ATTENTION"

        return {
            "status": executive_status,
            "summary": {
                "total_incidents": total_incidents,
                "open_incidents": open_incidents,
                "escalated_incidents": escalated_incidents,
                "critical_incidents": critical_incidents,
                "high_or_critical_incidents": high_or_critical_incidents,
                "correlated_incidents": correlated_incidents,
                "total_cases": total_cases,
                "open_cases": open_cases,
                "escalated_cases": escalated_cases,
                "critical_cases": critical_cases,
                "average_risk_score": round(float(avg_risk or 0), 2),
                "max_risk_score": int(max_risk or 0),
            },
            "distributions": {
                "incident_status": {
                    row.status or "NEW": row.count
                    for row in incident_status_rows
                },
                "case_status": {
                    row.status or "OPEN": row.count
                    for row in case_status_rows
                },
                "priority": {
                    row.recommended_priority or "UNSPECIFIED": row.count
                    for row in priority_rows
                },
            },
            "top_hosts": [
                {
                    "agent": row.agent,
                    "count": row.count,
                    "max_risk": int(row.max_risk or 0),
                    "average_risk": round(float(row.avg_risk or 0), 2),
                }
                for row in top_hosts_rows
            ],
            "top_correlation_types": [
                {
                    "correlation_type": row.correlation_type,
                    "count": row.count,
                }
                for row in correlation_type_rows
            ],
            "latest_cases": [
                {
                    "id": item.id,
                    "title": item.title,
                    "status": item.status,
                    "severity": item.severity,
                    "agent": item.agent,
                    "correlation_type": item.correlation_type,
                    "risk_score": item.risk_score,
                    "updated_at": item.updated_at.isoformat() if item.updated_at else None,
                }
                for item in latest_cases
            ],
            "latest_high_risk_incidents": [
                {
                    "id": item.id,
                    "status": item.status,
                    "timestamp": normalize_timestamp_utc(item.timestamp),
                    "timestamp_local": format_timestamp_local(item.timestamp),
                    "agent": item.agent,
                    "rule": item.rule,
                    "risk_score": item.risk_score,
                    "recommended_priority": item.recommended_priority,
                    "correlation_type": item.correlation_type,
                }
                for item in latest_high_risk_incidents
            ],
            "latest_case_analysis": {
                "id": latest_case_analysis.id,
                "case_id": latest_case_analysis.case_id,
                "model": latest_case_analysis.model,
                "recommended_status": latest_case_analysis.recommended_status,
                "recommended_severity": latest_case_analysis.recommended_severity,
                "created_at": latest_case_analysis.created_at.isoformat()
                if latest_case_analysis.created_at
                else None,
            }
            if latest_case_analysis
            else None,
            "recommendations": recommendations,
        }

    finally:
        db.close()



@app.get("/metrics/status-distribution")
def metrics_status_distribution():
    db = SessionLocal()

    try:
        rows = (
            db.query(
                Incident.status,
                func.count(Incident.id).label("count"),
            )
            .group_by(Incident.status)
            .all()
        )

        result = {
            "NEW": 0,
            "TRIAGED": 0,
            "ESCALATED": 0,
            "CLOSED": 0,
            "FALSE_POSITIVE": 0,
        }

        for row in rows:
            result[row.status or "NEW"] = row.count

        return result

    finally:
        db.close()

@app.get("/metrics/summary")
def metrics_summary():
    db = SessionLocal()

    try:
        total = db.query(Incident).count()

        avg_risk = (
            db.query(func.avg(Incident.risk_score))
            .scalar()
        )

        max_risk = (
            db.query(func.max(Incident.risk_score))
            .scalar()
        )

        correlated = (
            db.query(Incident)
            .filter(Incident.correlated == True)
            .count()
        )

        return {
            "total_incidents": total,
            "average_risk_score": round(float(avg_risk or 0), 2),
            "max_risk_score": int(max_risk or 0),
            "correlated_incidents": correlated,
        }

    finally:
        db.close()


@app.get("/metrics/top-hosts")
def metrics_top_hosts(limit: int = 10):
    db = SessionLocal()

    try:
        rows = (
            db.query(
                Incident.agent,
                func.count(Incident.id).label("count"),
                func.max(Incident.risk_score).label("max_risk"),
            )
            .group_by(Incident.agent)
            .order_by(func.count(Incident.id).desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "agent": row.agent,
                "count": row.count,
                "max_risk": row.max_risk,
            }
            for row in rows
        ]

    finally:
        db.close()


@app.get("/metrics/risk-distribution")
def metrics_risk_distribution():
    db = SessionLocal()

    try:
        incidents = db.query(Incident).all()

        buckets = {
            "low_0_30": 0,
            "medium_31_60": 0,
            "high_61_80": 0,
            "critical_81_100": 0,
        }

        for incident in incidents:
            score = incident.risk_score or 0

            if score <= 30:
                buckets["low_0_30"] += 1
            elif score <= 60:
                buckets["medium_31_60"] += 1
            elif score <= 80:
                buckets["high_61_80"] += 1
            else:
                buckets["critical_81_100"] += 1

        return buckets

    finally:
        db.close()


def calculate_case_sla_status(case: IncidentCase) -> str:
    status = (case.status or "OPEN").upper()

    if status in {"CLOSED", "FALSE_POSITIVE"}:
        return "COMPLETED"

    if not case.sla_due_at:
        return "NOT_SET"

    due_at = case.sla_due_at

    if due_at.tzinfo is None:
        due_at = due_at.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    if now <= due_at:
        return "WITHIN_SLA"

    return "BREACHED"


def serialize_case(
    case: IncidentCase,
    incident_count: int | None = None,
    queue_enrichment: dict | None = None,
) -> dict:
    payload = {
        "id": case.id,
        "group_key": case.group_key,
        "title": case.title,
        "status": case.status,
        "severity": case.severity,
        "agent": case.agent,
        "correlation_type": case.correlation_type,
        "risk_score": case.risk_score,
        "summary": case.summary,
        "created_by": case.created_by,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "incident_count": incident_count,
        "owner": case.owner,
        "sla_due_at": case.sla_due_at.isoformat() if case.sla_due_at else None,
        "sla_status": calculate_case_sla_status(case),
        "severity_review": case.severity_review,
        "status_reason": case.status_reason,
        "last_reviewed_by": case.last_reviewed_by,
        "last_reviewed_at": case.last_reviewed_at.isoformat()
        if case.last_reviewed_at
        else None,
    }

    if queue_enrichment:
        payload.update(queue_enrichment)

    return payload

def parse_optional_iso_datetime(value: str | None):
    if value is None:
        return None

    cleaned = value.strip()

    if not cleaned:
        return None

    try:
        return datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Datetime values must be valid ISO timestamps",
        ) from exc


def serialize_case_action(action: CaseAction) -> dict:
    return {
        "id": action.id,
        "case_id": action.case_id,
        "title": action.title,
        "description": action.description,
        "category": action.category,
        "priority": action.priority,
        "status": action.status,
        "due_at": action.due_at.isoformat() if action.due_at else None,
        "completed_at": action.completed_at.isoformat()
        if action.completed_at
        else None,
        "created_by": action.created_by,
        "created_at": action.created_at.isoformat() if action.created_at else None,
        "updated_at": action.updated_at.isoformat() if action.updated_at else None,
    }


def ensure_case_exists(db, case_id: int) -> IncidentCase:
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id)
        .first()
    )

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return case



def serialize_case_closure_checklist(row: CaseClosureChecklist | None) -> dict | None:
    if not row:
        return None

    return {
        "id": row.id,
        "case_id": row.case_id,
        "root_cause": row.root_cause,
        "evidence_reviewed": row.evidence_reviewed,
        "actions_summary": row.actions_summary,
        "closure_reason": row.closure_reason,
        "closure_decision": row.closure_decision,
        "final_severity": row.final_severity,
        "residual_risk": row.residual_risk,
        "reviewed_by": row.reviewed_by,
        "reviewed_at": row.reviewed_at.isoformat() if row.reviewed_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def get_case_closure_checklist(db, case_id: int) -> CaseClosureChecklist | None:
    return (
        db.query(CaseClosureChecklist)
        .filter(CaseClosureChecklist.case_id == case_id)
        .first()
    )


def validate_case_closure_readiness(
    db,
    case: IncidentCase,
    requested_status: str | None = None,
) -> dict:
    checklist = get_case_closure_checklist(db, case.id)

    open_action_count = (
        db.query(CaseAction)
        .filter(
            CaseAction.case_id == case.id,
            ~CaseAction.status.in_(["DONE", "CANCELLED"]),
        )
        .count()
    )

    missing_items = []

    if open_action_count > 0:
        missing_items.append(
            f"{open_action_count} action(s) are still OPEN or IN_PROGRESS"
        )

    required_fields = {
        "root_cause": "Root cause / conclusion",
        "evidence_reviewed": "Evidence reviewed",
        "actions_summary": "Actions summary",
        "closure_reason": "Closure reason",
        "closure_decision": "Closure decision",
        "final_severity": "Final severity",
        "residual_risk": "Residual risk",
    }

    if not checklist:
        missing_items.extend(required_fields.values())
    else:
        for field, label in required_fields.items():
            value = getattr(checklist, field, None)
            if not value or not str(value).strip():
                missing_items.append(label)

        if checklist.final_severity and checklist.final_severity not in VALID_CASE_SEVERITIES:
            missing_items.append(
                f"Final severity must be one of {sorted(VALID_CASE_SEVERITIES)}"
            )

        if checklist.closure_decision and checklist.closure_decision not in VALID_CLOSURE_DECISIONS:
            missing_items.append(
                f"Closure decision must be one of {sorted(VALID_CLOSURE_DECISIONS)}"
            )

        if requested_status == "FALSE_POSITIVE" and checklist.closure_decision != "FALSE_POSITIVE":
            missing_items.append(
                "FALSE_POSITIVE status requires closure_decision FALSE_POSITIVE"
            )

        if requested_status == "CLOSED" and checklist.closure_decision == "FALSE_POSITIVE":
            missing_items.append(
                "CLOSED status cannot use closure_decision FALSE_POSITIVE"
            )

    return {
        "ready": len(missing_items) == 0,
        "missing_items": missing_items,
        "open_action_count": open_action_count,
        "checklist": serialize_case_closure_checklist(checklist),
    }

def safe_isoformat(value):
    if not value:
        return None

    if hasattr(value, "isoformat"):
        return value.isoformat()

    return str(value)


def build_closure_missing_items_from_row(
    checklist: CaseClosureChecklist | None,
    open_action_count: int,
) -> list[str]:
    missing_items = []

    if open_action_count > 0:
        missing_items.append(
            f"{open_action_count} action(s) are still OPEN or IN_PROGRESS"
        )

    if not checklist:
        missing_items.extend(CLOSURE_REQUIRED_FIELDS.values())
        return missing_items

    for field, label in CLOSURE_REQUIRED_FIELDS.items():
        value = getattr(checklist, field, None)
        if not value or not str(value).strip():
            missing_items.append(label)

    if checklist.final_severity and checklist.final_severity not in VALID_CASE_SEVERITIES:
        missing_items.append(
            f"Final severity must be one of {sorted(VALID_CASE_SEVERITIES)}"
        )

    if checklist.closure_decision and checklist.closure_decision not in VALID_CLOSURE_DECISIONS:
        missing_items.append(
            f"Closure decision must be one of {sorted(VALID_CLOSURE_DECISIONS)}"
        )

    return missing_items


def build_case_queue_flags(
    case: IncidentCase,
    *,
    action_stats: dict,
    latest_analysis: CaseAIAnalysis | None,
    closure_checklist: CaseClosureChecklist | None,
    ready_to_close: bool,
) -> list[str]:
    flags = []
    status = (case.status or "OPEN").upper()
    severity = (case.severity_review or case.severity or "LOW").upper()
    sla_status = calculate_case_sla_status(case)
    open_action_count = int(action_stats.get("open_action_count") or 0)

    if status not in TERMINAL_CASE_STATUSES and not case.owner:
        flags.append("NO_OWNER")

    if sla_status == "BREACHED":
        flags.append("SLA_BREACHED")

    if status == "ESCALATED":
        flags.append("ESCALATED")

    if severity in {"CRITICAL", "HIGH"}:
        flags.append("HIGH_RISK")

    if open_action_count > 0:
        flags.append("OPEN_ACTIONS")

    if status not in TERMINAL_CASE_STATUSES and not latest_analysis:
        flags.append("NO_AI_ANALYSIS")

    if status not in TERMINAL_CASE_STATUSES and not closure_checklist:
        flags.append("NO_CLOSURE_CHECKLIST")

    if ready_to_close and status not in TERMINAL_CASE_STATUSES:
        flags.append("READY_TO_CLOSE")

    return flags


def build_case_queue_enrichment(
    case: IncidentCase,
    *,
    action_stats: dict | None = None,
    latest_analysis: CaseAIAnalysis | None = None,
    closure_checklist: CaseClosureChecklist | None = None,
) -> dict:
    stats = action_stats or {}

    action_count = int(stats.get("action_count") or 0)
    open_action_count = int(stats.get("open_action_count") or 0)
    completed_action_count = int(stats.get("completed_action_count") or 0)
    cancelled_action_count = int(stats.get("cancelled_action_count") or 0)

    missing_items = build_closure_missing_items_from_row(
        closure_checklist,
        open_action_count,
    )
    ready_to_close = len(missing_items) == 0

    latest_action_at = stats.get("latest_action_at")

    enrichment = {
        "action_count": action_count,
        "open_action_count": open_action_count,
        "completed_action_count": completed_action_count,
        "cancelled_action_count": cancelled_action_count,
        "latest_action_at": safe_isoformat(latest_action_at),
        "has_ai_analysis": latest_analysis is not None,
        "latest_ai_analysis_at": safe_isoformat(latest_analysis.created_at)
        if latest_analysis
        else None,
        "latest_ai_model": latest_analysis.model if latest_analysis else None,
        "latest_ai_recommended_status": latest_analysis.recommended_status
        if latest_analysis
        else None,
        "latest_ai_recommended_severity": latest_analysis.recommended_severity
        if latest_analysis
        else None,
        "has_closure_checklist": closure_checklist is not None,
        "ready_to_close": ready_to_close,
        "closure_missing_count": len(missing_items),
        "closure_missing_items": missing_items,
        "closure_decision": closure_checklist.closure_decision
        if closure_checklist
        else None,
        "final_severity": closure_checklist.final_severity
        if closure_checklist
        else None,
        "closure_reviewed_at": safe_isoformat(closure_checklist.reviewed_at)
        if closure_checklist
        else None,
    }

    enrichment["queue_flags"] = build_case_queue_flags(
        case,
        action_stats=stats,
        latest_analysis=latest_analysis,
        closure_checklist=closure_checklist,
        ready_to_close=ready_to_close,
    )

    return enrichment


@app.get("/cases")
def list_cases(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    host: str | None = Query(None),
):
    db = SessionLocal()

    try:
        offset = (page - 1) * limit

        incident_count_subquery = (
            db.query(
                CaseIncident.case_id.label("case_id"),
                func.count(CaseIncident.incident_id).label("incident_count"),
            )
            .group_by(CaseIncident.case_id)
            .subquery()
        )

        query = (
            db.query(
                IncidentCase,
                func.coalesce(incident_count_subquery.c.incident_count, 0).label(
                    "incident_count"
                ),
            )
            .outerjoin(
                incident_count_subquery,
                IncidentCase.id == incident_count_subquery.c.case_id,
            )
        )

        if status and status.upper() != "ALL":
            query = query.filter(IncidentCase.status == status.upper())

        if severity and severity.upper() != "ALL":
            query = query.filter(IncidentCase.severity == severity.upper())

        if host:
            query = query.filter(IncidentCase.agent.ilike(f"%{host}%"))

        total = query.with_entities(func.count(IncidentCase.id)).scalar() or 0

        rows = (
            query.order_by(IncidentCase.updated_at.desc(), IncidentCase.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        total_pages = max((total + limit - 1) // limit, 1)

        case_ids = [case_row.id for case_row, _ in rows]

        action_stats_by_case = {}
        latest_analysis_by_case = {}
        closure_checklist_by_case = {}

        if case_ids:
            action_rows = (
                db.query(
                    CaseAction.case_id.label("case_id"),
                    func.count(CaseAction.id).label("action_count"),
                    func.sum(
                        sql_case(
                            (
                                CaseAction.status.in_(["OPEN", "IN_PROGRESS"]),
                                1,
                            ),
                            else_=0,
                        )
                    ).label("open_action_count"),
                    func.sum(
                        sql_case((CaseAction.status == "DONE", 1), else_=0)
                    ).label("completed_action_count"),
                    func.sum(
                        sql_case((CaseAction.status == "CANCELLED", 1), else_=0)
                    ).label("cancelled_action_count"),
                    func.max(CaseAction.updated_at).label("latest_action_at"),
                )
                .filter(CaseAction.case_id.in_(case_ids))
                .group_by(CaseAction.case_id)
                .all()
            )

            for row in action_rows:
                action_stats_by_case[row.case_id] = {
                    "action_count": row.action_count,
                    "open_action_count": row.open_action_count,
                    "completed_action_count": row.completed_action_count,
                    "cancelled_action_count": row.cancelled_action_count,
                    "latest_action_at": row.latest_action_at,
                }

            analysis_rows = (
                db.query(CaseAIAnalysis)
                .filter(CaseAIAnalysis.case_id.in_(case_ids))
                .order_by(
                    CaseAIAnalysis.case_id.asc(),
                    CaseAIAnalysis.created_at.desc().nullslast(),
                    CaseAIAnalysis.id.desc(),
                )
                .all()
            )

            for row in analysis_rows:
                if row.case_id not in latest_analysis_by_case:
                    latest_analysis_by_case[row.case_id] = row

            closure_rows = (
                db.query(CaseClosureChecklist)
                .filter(CaseClosureChecklist.case_id.in_(case_ids))
                .all()
            )

            for row in closure_rows:
                closure_checklist_by_case[row.case_id] = row

        items = []

        for case_row, incident_count in rows:
            enrichment = build_case_queue_enrichment(
                case_row,
                action_stats=action_stats_by_case.get(case_row.id),
                latest_analysis=latest_analysis_by_case.get(case_row.id),
                closure_checklist=closure_checklist_by_case.get(case_row.id),
            )

            items.append(
                serialize_case(
                    case_row,
                    incident_count,
                    queue_enrichment=enrichment,
                )
            )

        return {
            "items": items,
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages,
        }

    finally:
        db.close()


@app.get("/cases/{case_id}")
def get_case(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        incident_count = (
            db.query(CaseIncident)
            .filter(CaseIncident.case_id == case.id)
            .count()
        )

        return serialize_case(case, incident_count)

    finally:
        db.close()

@app.patch("/cases/{case_id}/workflow")
def update_case_workflow(
    case_id: int,
    payload: CaseWorkflowUpdate,
    request: Request,
):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        reviewed_by = payload.reviewed_by or "local_analyst"
        changes = {}

        if payload.owner is not None:
            owner = payload.owner.strip() or None
            if case.owner != owner:
                changes["owner"] = [case.owner, owner]
                case.owner = owner

        if payload.status is not None:
            requested_status = payload.status.upper()

            if requested_status not in VALID_CASE_STATUSES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid case status. Allowed values: {sorted(VALID_CASE_STATUSES)}",
                )

            if requested_status in TERMINAL_CASE_STATUSES:
                validation = validate_case_closure_readiness(
                    db,
                    case,
                    requested_status=requested_status,
                )

                if not validation["ready"]:
                    raise HTTPException(
                        status_code=409,
                        detail={
                            "message": "Case cannot be closed until closure checklist is complete and all actions are resolved.",
                            "missing_items": validation["missing_items"],
                            "open_action_count": validation["open_action_count"],
                        },
                    )

            if case.status != requested_status:
                changes["status"] = [case.status, requested_status]
                case.status = requested_status

        if payload.severity is not None:
            requested_severity = payload.severity.upper()

            if requested_severity not in VALID_CASE_SEVERITIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid case severity. Allowed values: {sorted(VALID_CASE_SEVERITIES)}",
                )

            if case.severity != requested_severity:
                changes["severity"] = [case.severity, requested_severity]
                changes["severity_review"] = [case.severity_review, requested_severity]
                case.severity = requested_severity
                case.severity_review = requested_severity

        if payload.sla_due_at is not None:
            sla_due_at = None

            if payload.sla_due_at.strip():
                try:
                    sla_due_at = datetime.fromisoformat(
                        payload.sla_due_at.replace("Z", "+00:00")
                    )
                except ValueError as exc:
                    raise HTTPException(
                        status_code=400,
                        detail="sla_due_at must be a valid ISO timestamp",
                    ) from exc

            if case.sla_due_at != sla_due_at:
                old_value = case.sla_due_at.isoformat() if case.sla_due_at else None
                new_value = sla_due_at.isoformat() if sla_due_at else None
                changes["sla_due_at"] = [old_value, new_value]
                case.sla_due_at = sla_due_at

        if payload.status_reason is not None:
            status_reason = payload.status_reason.strip() or None

            if case.status_reason != status_reason:
                changes["status_reason"] = [case.status_reason, status_reason]
                case.status_reason = status_reason

        if changes:
            now = datetime.now(timezone.utc)
            case.last_reviewed_by = reviewed_by
            case.last_reviewed_at = now
            case.updated_at = now

            audit = CaseAudit(
                case_id=case.id,
                event_type="CASE_WORKFLOW_UPDATED",
                old_value=str({key: value[0] for key, value in changes.items()}),
                new_value=str({key: value[1] for key, value in changes.items()}),
                comment=payload.status_reason,
                created_by=reviewed_by,
            )

            db.add(audit)

        db.commit()
        db.refresh(case)

        if changes:
            write_security_audit(
                event_type="CASE_WORKFLOW_UPDATED",
                outcome="SUCCESS",
                current_user=security_audit_actor(request),
                target_type="CASE",
                target_id=case.id,
                request=request,
                details={
                    "reviewed_by": reviewed_by,
                    "changed_fields": sorted(changes.keys()),
                    "changes": changes,
                },
            )

        incident_count = (
            db.query(CaseIncident)
            .filter(CaseIncident.case_id == case.id)
            .count()
        )

        return serialize_case(case, incident_count)

    finally:
        db.close()


@app.get("/cases/{case_id}/audit")
def get_case_audit(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        rows = (
            db.query(CaseAudit)
            .filter(CaseAudit.case_id == case_id)
            .order_by(CaseAudit.created_at.asc(), CaseAudit.id.asc())
            .all()
        )

        return [
            {
                "id": row.id,
                "case_id": row.case_id,
                "event_type": row.event_type,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "comment": row.comment,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat()
                if row.created_at
                else None,
            }
            for row in rows
        ]

    finally:
        db.close()



@app.get("/cases/{case_id}/closure")
def get_case_closure(case_id: int):
    db = SessionLocal()

    try:
        case = ensure_case_exists(db, case_id)
        validation = validate_case_closure_readiness(db, case)

        return {
            "case_id": case.id,
            "case_status": case.status,
            "ready_to_close": validation["ready"],
            "missing_items": validation["missing_items"],
            "open_action_count": validation["open_action_count"],
            "checklist": validation["checklist"],
        }

    finally:
        db.close()


@app.patch("/cases/{case_id}/closure")
def update_case_closure(
    case_id: int,
    payload: CaseClosureChecklistUpdate,
    request: Request,
):
    db = SessionLocal()

    try:
        case = ensure_case_exists(db, case_id)
        checklist = get_case_closure_checklist(db, case.id)
        now = datetime.now(timezone.utc)
        reviewed_by = payload.reviewed_by or "local_analyst"

        old_value = serialize_case_closure_checklist(checklist)

        if not checklist:
            checklist = CaseClosureChecklist(
                case_id=case.id,
                reviewed_by=reviewed_by,
                reviewed_at=now,
                updated_at=now,
            )
            db.add(checklist)
            db.flush()

        text_fields = [
            "root_cause",
            "evidence_reviewed",
            "actions_summary",
            "closure_reason",
            "residual_risk",
        ]

        for field in text_fields:
            value = getattr(payload, field)
            if value is not None:
                setattr(checklist, field, value.strip() or None)

        if payload.final_severity is not None:
            final_severity = payload.final_severity.upper().strip()

            if final_severity and final_severity not in VALID_CASE_SEVERITIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid final severity. Allowed values: {sorted(VALID_CASE_SEVERITIES)}",
                )

            checklist.final_severity = final_severity or None

        if payload.closure_decision is not None:
            closure_decision = payload.closure_decision.upper().strip()

            if closure_decision and closure_decision not in VALID_CLOSURE_DECISIONS:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid closure decision. Allowed values: {sorted(VALID_CLOSURE_DECISIONS)}",
                )

            checklist.closure_decision = closure_decision or None

        checklist.reviewed_by = reviewed_by
        checklist.reviewed_at = now
        checklist.updated_at = now
        case.updated_at = now

        db.flush()

        new_value = serialize_case_closure_checklist(checklist)

        audit = CaseAudit(
            case_id=case.id,
            event_type="CASE_CLOSURE_CHECKLIST_UPDATED",
            old_value=str(old_value),
            new_value=str(new_value),
            comment=checklist.closure_reason,
            created_by=reviewed_by,
        )

        db.add(audit)
        db.commit()
        db.refresh(checklist)

        write_security_audit(
            event_type="CASE_CLOSURE_UPDATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="CASE",
            target_id=case.id,
            request=request,
            details={
                "checklist_id": checklist.id,
                "reviewed_by": reviewed_by,
                "closure_decision": checklist.closure_decision,
                "final_severity": checklist.final_severity,
            },
        )

        validation = validate_case_closure_readiness(db, case)

        return {
            "case_id": case.id,
            "case_status": case.status,
            "ready_to_close": validation["ready"],
            "missing_items": validation["missing_items"],
            "open_action_count": validation["open_action_count"],
            "checklist": serialize_case_closure_checklist(checklist),
        }

    finally:
        db.close()


@app.post("/cases/{case_id}/actions/suggestions")
def suggest_case_action_plan(case_id: int, request: Request):
    try:
        result = generate_case_action_suggestions(case_id)

        write_security_audit(
            event_type="CASE_ACTION_SUGGESTIONS_GENERATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="CASE",
            target_id=case_id,
            request=request,
            details={
                "result_type": type(result).__name__,
            },
        )

        return result

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Resource not found.")

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to generate case action suggestions.",
        )


@app.get("/cases/{case_id}/timeline")
def get_case_timeline(case_id: int):
    try:
        return build_case_timeline(case_id)

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Resource not found.")


@app.get("/cases/{case_id}/actions")
def list_case_actions(case_id: int):
    db = SessionLocal()

    try:
        ensure_case_exists(db, case_id)

        actions = (
            db.query(CaseAction)
            .filter(CaseAction.case_id == case_id)
            .order_by(CaseAction.created_at.asc(), CaseAction.id.asc())
            .all()
        )

        return [serialize_case_action(action) for action in actions]

    finally:
        db.close()


@app.post("/cases/{case_id}/actions")
def create_case_action(
    case_id: int,
    payload: CaseActionCreate,
    request: Request,
):
    title = payload.title.strip()

    if not title:
        raise HTTPException(status_code=400, detail="Action title cannot be empty")

    category = payload.category.upper()
    priority = payload.priority.upper()
    status = (payload.status or "OPEN").upper()

    if category not in VALID_CASE_ACTION_CATEGORIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action category. Allowed values: {sorted(VALID_CASE_ACTION_CATEGORIES)}",
        )

    if priority not in VALID_CASE_ACTION_PRIORITIES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action priority. Allowed values: {sorted(VALID_CASE_ACTION_PRIORITIES)}",
        )

    if status not in VALID_CASE_ACTION_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action status. Allowed values: {sorted(VALID_CASE_ACTION_STATUSES)}",
        )

    db = SessionLocal()

    try:
        case = ensure_case_exists(db, case_id)
        created_by = payload.created_by or "local_analyst"
        now = datetime.now(timezone.utc)

        action = CaseAction(
            case_id=case.id,
            title=title,
            description=payload.description.strip()
            if payload.description
            else None,
            category=category,
            priority=priority,
            status=status,
            due_at=parse_optional_iso_datetime(payload.due_at),
            completed_at=now if status == "DONE" else None,
            created_by=created_by,
            updated_at=now,
        )

        db.add(action)
        db.flush()

        case.updated_at = now

        audit = CaseAudit(
            case_id=case.id,
            event_type="CASE_ACTION_CREATED",
            old_value=None,
            new_value=f"action:{action.id}:{action.title}",
            comment=action.description,
            created_by=created_by,
        )

        db.add(audit)
        db.commit()
        db.refresh(action)

        write_security_audit(
            event_type="CASE_ACTION_CREATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="CASE_ACTION",
            target_id=action.id,
            request=request,
            details={
                "case_id": case.id,
                "category": action.category,
                "priority": action.priority,
                "status": action.status,
                "created_by": created_by,
            },
        )

        return serialize_case_action(action)

    finally:
        db.close()


@app.patch("/cases/{case_id}/actions/{action_id}")
def update_case_action(
    case_id: int,
    action_id: int,
    payload: CaseActionUpdate,
    request: Request,
):
    db = SessionLocal()

    try:
        case = ensure_case_exists(db, case_id)

        action = (
            db.query(CaseAction)
            .filter(
                CaseAction.id == action_id,
                CaseAction.case_id == case_id,
            )
            .first()
        )

        if not action:
            raise HTTPException(status_code=404, detail="Case action not found")

        updated_by = payload.updated_by or "local_analyst"
        now = datetime.now(timezone.utc)
        changes = {}

        if payload.title is not None:
            title = payload.title.strip()

            if not title:
                raise HTTPException(
                    status_code=400,
                    detail="Action title cannot be empty",
                )

            if action.title != title:
                changes["title"] = [action.title, title]
                action.title = title

        if payload.description is not None:
            description = payload.description.strip() or None

            if action.description != description:
                changes["description"] = [action.description, description]
                action.description = description

        if payload.category is not None:
            category = payload.category.upper()

            if category not in VALID_CASE_ACTION_CATEGORIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid action category. Allowed values: {sorted(VALID_CASE_ACTION_CATEGORIES)}",
                )

            if action.category != category:
                changes["category"] = [action.category, category]
                action.category = category

        if payload.priority is not None:
            priority = payload.priority.upper()

            if priority not in VALID_CASE_ACTION_PRIORITIES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid action priority. Allowed values: {sorted(VALID_CASE_ACTION_PRIORITIES)}",
                )

            if action.priority != priority:
                changes["priority"] = [action.priority, priority]
                action.priority = priority

        if payload.status is not None:
            status = payload.status.upper()

            if status not in VALID_CASE_ACTION_STATUSES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid action status. Allowed values: {sorted(VALID_CASE_ACTION_STATUSES)}",
                )

            if action.status != status:
                changes["status"] = [action.status, status]
                action.status = status
                action.completed_at = now if status == "DONE" else None

        if payload.due_at is not None:
            due_at = parse_optional_iso_datetime(payload.due_at)
            old_due_at = action.due_at.isoformat() if action.due_at else None
            new_due_at = due_at.isoformat() if due_at else None

            if old_due_at != new_due_at:
                changes["due_at"] = [old_due_at, new_due_at]
                action.due_at = due_at

        if changes:
            action.updated_at = now
            case.updated_at = now

            audit = CaseAudit(
                case_id=case.id,
                event_type="CASE_ACTION_UPDATED",
                old_value=str({key: value[0] for key, value in changes.items()}),
                new_value=str({key: value[1] for key, value in changes.items()}),
                comment=payload.description,
                created_by=updated_by,
            )

            db.add(audit)

        db.commit()
        db.refresh(action)

        if changes:
            write_security_audit(
                event_type="CASE_ACTION_UPDATED",
                outcome="SUCCESS",
                current_user=security_audit_actor(request),
                target_type="CASE_ACTION",
                target_id=action.id,
                request=request,
                details={
                    "case_id": case.id,
                    "updated_by": updated_by,
                    "changed_fields": sorted(changes.keys()),
                    "changes": changes,
                },
            )

        return serialize_case_action(action)

    finally:
        db.close()


@app.get("/cases/{case_id}/incidents")
def get_case_incidents(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        rows = (
            db.query(Incident)
            .join(CaseIncident, CaseIncident.incident_id == Incident.id)
            .filter(CaseIncident.case_id == case_id)
            .order_by(Incident.timestamp.asc().nullslast(), Incident.id.asc())
            .all()
        )

        return [
            {
                "id": item.id,
                "status": item.status,
                "timestamp": normalize_timestamp_utc(item.timestamp),
                "timestamp_local": format_timestamp_local(item.timestamp),
                "timezone": APP_TIMEZONE,
                "agent": item.agent,
                "rule": item.rule,
                "level": item.level,
                "risk_score": item.risk_score,
                "correlation_score": item.correlation_score,
                "correlated": item.correlated,
                "correlation_type": item.correlation_type,
                "recommended_priority": item.recommended_priority,
            }
            for item in rows
        ]

    finally:
        db.close()

@app.get("/cases/{case_id}/analysis")
def get_case_analysis(case_id: int):
    db = SessionLocal()

    try:
        case = (
            db.query(IncidentCase)
            .filter(IncidentCase.id == case_id)
            .first()
        )

        if not case:
            raise HTTPException(status_code=404, detail="Case not found")

        row = (
            db.query(CaseAIAnalysis)
            .filter(CaseAIAnalysis.case_id == case_id)
            .order_by(CaseAIAnalysis.created_at.desc(), CaseAIAnalysis.id.desc())
            .first()
        )

        if not row:
            return {"item": None}

        return {
            "item": {
                "id": row.id,
                "case_id": row.case_id,
                "model": row.model,
                "analysis": row.analysis,
                "recommended_status": row.recommended_status,
                "recommended_severity": row.recommended_severity,
                "created_by": row.created_by,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        }

    finally:
        db.close()


@app.post("/cases/{case_id}/analysis")
def create_case_analysis(case_id: int, request: Request):
    try:
        row = generate_case_ai_analysis(case_id)

        write_security_audit(
            event_type="CASE_AI_ANALYSIS_GENERATED",
            outcome="SUCCESS",
            current_user=security_audit_actor(request),
            target_type="CASE",
            target_id=case_id,
            request=request,
            details={
                "analysis_id": row.id,
                "model": row.model,
                "recommended_status": row.recommended_status,
                "recommended_severity": row.recommended_severity,
            },
        )

        return {
            "id": row.id,
            "case_id": row.case_id,
            "model": row.model,
            "analysis": row.analysis,
            "recommended_status": row.recommended_status,
            "recommended_severity": row.recommended_severity,
            "created_by": row.created_by,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }

    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Resource not found.")

