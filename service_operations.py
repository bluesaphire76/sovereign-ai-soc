from __future__ import annotations

import re
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from fastapi import HTTPException, Request
from sqlalchemy import or_

from detection_control_plane import _request_client_ip, _sanitize_audit_details
from models import SecurityAuditEvent, ServiceOperation


CommandRunner = Callable[..., subprocess.CompletedProcess]

SERVICE_STATUS_RUNNING = "running"
SERVICE_STATUS_STOPPED = "stopped"
SERVICE_STATUS_FAILED = "failed"
SERVICE_STATUS_UNKNOWN = "unknown"
SERVICE_STATUS_NOT_FOUND = "not_found"
SERVICE_STATUS_DEGRADED = "degraded"
SERVICE_STATUS_UNSUPPORTED = "unsupported"

OPERATION_STATUS_RUNNING = "running"
OPERATION_STATUS_SUCCESS = "success"
OPERATION_STATUS_FAILED = "failed"
OPERATION_STATUS_DENIED = "denied"

OUTPUT_LIMIT = 500
STATUS_TIMEOUT_SECONDS = 5
RESTART_TIMEOUT_SECONDS = 35
SENSITIVE_OUTPUT_PATTERN = re.compile(
    r"(?i)\b((?:password|token|authorization|secret|api[_-]?key)[\w.-]*\s*[=:]\s*)\S+"
)
SYSTEMD_RESTART_PERMISSION_MESSAGE = (
    "Systemd restart requires non-interactive sudo permission for the API service user. "
    "Configure sudoers for the allowlisted systemctl restart command."
)


@dataclass(frozen=True)
class ServiceDefinition:
    key: str
    display_name: str
    kind: str
    risk_level: str
    description: str
    impact: str
    post_restart_check: str
    command_family: str
    restart_allowed: bool = True
    unit: str | None = None
    container: str | None = None
    restart_disabled_reason: str | None = None


@dataclass(frozen=True)
class CommandResult:
    args: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    unsupported: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.unsupported


@dataclass(frozen=True)
class ServiceStatus:
    service_key: str
    display_name: str
    kind: str
    status: str
    message: str
    checked_at: datetime
    details: dict[str, Any]
    safe_error: str | None = None


SERVICE_REGISTRY: dict[str, ServiceDefinition] = {
    "ai_soc_worker": ServiceDefinition(
        key="ai_soc_worker",
        display_name="AI SOC Worker",
        kind="systemd",
        unit="ai-soc-worker",
        risk_level="medium",
        description="Background ingestion, triage and enrichment worker.",
        impact="Temporarily pauses ingestion, enrichment and AI triage while the worker restarts.",
        post_restart_check="Worker heartbeat should become fresh after restart.",
        command_family="systemd",
    ),
    "ai_soc_api": ServiceDefinition(
        key="ai_soc_api",
        display_name="AI SOC API",
        kind="systemd",
        unit="ai-soc-api",
        risk_level="high",
        description="FastAPI backend service.",
        impact="Temporarily interrupts API requests and authenticated GUI calls.",
        post_restart_check="The API health endpoint should return OK after restart.",
        command_family="systemd",
        restart_allowed=False,
        restart_disabled_reason=(
            "The API cannot safely restart itself from the same request path. "
            "Use host-level operations for this high-impact service."
        ),
    ),
    "ai_soc_frontend": ServiceDefinition(
        key="ai_soc_frontend",
        display_name="AI SOC Frontend",
        kind="systemd",
        unit="ai-soc-frontend",
        risk_level="medium",
        description="Next.js frontend service.",
        impact="Temporarily interrupts GUI sessions while the frontend restarts.",
        post_restart_check="The frontend should become reachable after restart.",
        command_family="systemd",
    ),
    "wazuh_manager": ServiceDefinition(
        key="wazuh_manager",
        display_name="Wazuh Manager",
        kind="docker",
        container="single-node-wazuh.manager-1",
        risk_level="high",
        description="Wazuh detection manager container.",
        impact="May temporarily interrupt alert processing and manager-side rule evaluation.",
        post_restart_check="The Wazuh manager container should return to running state.",
        command_family="docker",
    ),
    "suricata": ServiceDefinition(
        key="suricata",
        display_name="Suricata IDS",
        kind="docker",
        container="ai-soc-suricata",
        risk_level="medium",
        description="Network IDS sensor container.",
        impact="May temporarily pause network IDS event generation while Suricata restarts.",
        post_restart_check="The Suricata container should return to running state and resume EVE output.",
        command_family="docker",
    ),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def current_user_role(current_user: Mapping[str, Any] | None) -> str:
    return str((current_user or {}).get("role") or "").upper().strip()


def _require_reason(reason: str | None) -> str:
    cleaned = str(reason or "").strip()

    if not cleaned:
        raise HTTPException(status_code=400, detail="Reason is required for service operations.")

    return cleaned


def _service(service_key: str) -> ServiceDefinition:
    key = str(service_key or "").strip()
    service = SERVICE_REGISTRY.get(key)

    if not service:
        raise HTTPException(status_code=404, detail="Service is not allowlisted for managed operations.")

    return service


def _sanitize_output(value: str | bytes | None) -> str:
    if value is None:
        return ""

    text = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)
    text = text.replace("\x00", "").strip()
    text = SENSITIVE_OUTPUT_PATTERN.sub(r"\1[REDACTED]", text)

    return text[:OUTPUT_LIMIT]


def _safe_error(result: CommandResult) -> str | None:
    if _is_non_interactive_auth_error(result.stdout) or _is_non_interactive_auth_error(result.stderr):
        return SYSTEMD_RESTART_PERMISSION_MESSAGE

    if result.unsupported:
        return _sanitize_output(result.stderr) or "Runtime command is not available."

    if result.timed_out:
        return "Runtime command timed out."

    return _sanitize_output(result.stderr or result.stdout) or None


def _is_non_interactive_auth_error(value: str | None) -> bool:
    lowered = str(value or "").lower()

    return any(
        marker in lowered
        for marker in (
            "interactive authentication",
            "access denied",
            "a password is required",
            "a terminal is required",
            "not in the sudoers file",
            "may not run sudo",
        )
    )


def _runtime_unsupported_error(text: str | None) -> bool:
    lowered = str(text or "").lower()

    return any(
        marker in lowered
        for marker in (
            "system has not been booted with systemd",
            "failed to connect to bus",
            "cannot connect to the docker daemon",
            "permission denied",
            "got permission denied",
            "is the docker daemon running",
        )
    )


def _command_path(name: str) -> str | None:
    return shutil.which(name)


def _run_command(
    args: list[str],
    *,
    timeout: int,
    runner: CommandRunner | None = None,
) -> CommandResult:
    if not args:
        return CommandResult(args=[], returncode=None, stderr="No command configured.", unsupported=True)

    if runner is None and shutil.which(args[0]) is None:
        return CommandResult(
            args=args,
            returncode=None,
            stderr=f"{args[0]} command is not available in this runtime.",
            unsupported=True,
        )

    try:
        result = (runner or subprocess.run)(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(
            args=args,
            returncode=None,
            stderr=f"{args[0]} command is not available in this runtime.",
            unsupported=True,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            args=args,
            returncode=None,
            stdout=_sanitize_output(exc.stdout),
            stderr=_sanitize_output(exc.stderr),
            timed_out=True,
        )
    except Exception as exc:
        return CommandResult(
            args=args,
            returncode=None,
            stderr=f"Command execution failed: {type(exc).__name__}",
            unsupported=True,
        )

    stdout = _sanitize_output(result.stdout)
    stderr = _sanitize_output(result.stderr)
    return CommandResult(
        args=args,
        returncode=result.returncode,
        stdout=stdout,
        stderr=stderr,
        unsupported=_runtime_unsupported_error(stdout) or _runtime_unsupported_error(stderr),
    )


def _parse_systemd_show(value: str) -> dict[str, str]:
    result: dict[str, str] = {}

    for line in value.splitlines():
        if "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        result[key.strip()] = raw_value.strip()

    return result


def _map_systemd_status(properties: Mapping[str, str]) -> str:
    load_state = properties.get("LoadState")
    active_state = properties.get("ActiveState")

    if load_state == "not-found":
        return SERVICE_STATUS_NOT_FOUND

    if active_state == "active":
        return SERVICE_STATUS_RUNNING

    if active_state in {"inactive", "dead"}:
        return SERVICE_STATUS_STOPPED

    if active_state == "failed":
        return SERVICE_STATUS_FAILED

    if active_state in {"activating", "deactivating", "reloading"}:
        return SERVICE_STATUS_DEGRADED

    return SERVICE_STATUS_UNKNOWN


def _systemd_status(service: ServiceDefinition, runner: CommandRunner | None = None) -> ServiceStatus:
    assert service.unit
    result = _run_command(
        [
            "systemctl",
            "show",
            service.unit,
            "--property=ActiveState",
            "--property=SubState",
            "--property=LoadState",
            "--property=MainPID",
        ],
        timeout=STATUS_TIMEOUT_SECONDS,
        runner=runner,
    )
    checked_at = utc_now()

    if result.unsupported:
        return ServiceStatus(
            service_key=service.key,
            display_name=service.display_name,
            kind=service.kind,
            status=SERVICE_STATUS_UNSUPPORTED,
            message="Service operation is not available in this runtime.",
            checked_at=checked_at,
            details={"unit": service.unit, "command_family": service.command_family},
            safe_error=_safe_error(result),
        )

    if not result.ok:
        return ServiceStatus(
            service_key=service.key,
            display_name=service.display_name,
            kind=service.kind,
            status=SERVICE_STATUS_UNKNOWN,
            message="Service status command failed.",
            checked_at=checked_at,
            details={"unit": service.unit, "command_family": service.command_family},
            safe_error=_safe_error(result),
        )

    properties = _parse_systemd_show(result.stdout)
    status = _map_systemd_status(properties)

    return ServiceStatus(
        service_key=service.key,
        display_name=service.display_name,
        kind=service.kind,
        status=status,
        message=_status_message(service, status),
        checked_at=checked_at,
        details={
            "unit": service.unit,
            "command_family": service.command_family,
            "active_state": properties.get("ActiveState"),
            "sub_state": properties.get("SubState"),
            "load_state": properties.get("LoadState"),
            "main_pid": properties.get("MainPID"),
        },
    )


def _map_docker_status(status: str) -> str:
    normalized = status.strip().lower()

    if normalized == "running":
        return SERVICE_STATUS_RUNNING

    if normalized in {"created", "exited", "paused"}:
        return SERVICE_STATUS_STOPPED

    if normalized == "dead":
        return SERVICE_STATUS_FAILED

    if normalized in {"restarting", "removing"}:
        return SERVICE_STATUS_DEGRADED

    return SERVICE_STATUS_UNKNOWN


def _docker_status(service: ServiceDefinition, runner: CommandRunner | None = None) -> ServiceStatus:
    assert service.container
    result = _run_command(
        ["docker", "inspect", "--format", "{{.State.Status}}", service.container],
        timeout=STATUS_TIMEOUT_SECONDS,
        runner=runner,
    )
    checked_at = utc_now()

    if result.unsupported:
        return ServiceStatus(
            service_key=service.key,
            display_name=service.display_name,
            kind=service.kind,
            status=SERVICE_STATUS_UNSUPPORTED,
            message="Service operation is not available in this runtime.",
            checked_at=checked_at,
            details={"container": service.container, "command_family": service.command_family},
            safe_error=_safe_error(result),
        )

    if result.returncode != 0 and "no such object" in (result.stderr or result.stdout).lower():
        return ServiceStatus(
            service_key=service.key,
            display_name=service.display_name,
            kind=service.kind,
            status=SERVICE_STATUS_NOT_FOUND,
            message="Allowlisted container was not found.",
            checked_at=checked_at,
            details={"container": service.container, "command_family": service.command_family},
            safe_error=_safe_error(result),
        )

    if not result.ok:
        return ServiceStatus(
            service_key=service.key,
            display_name=service.display_name,
            kind=service.kind,
            status=SERVICE_STATUS_UNKNOWN,
            message="Container status command failed.",
            checked_at=checked_at,
            details={"container": service.container, "command_family": service.command_family},
            safe_error=_safe_error(result),
        )

    status = _map_docker_status(result.stdout)

    return ServiceStatus(
        service_key=service.key,
        display_name=service.display_name,
        kind=service.kind,
        status=status,
        message=_status_message(service, status),
        checked_at=checked_at,
        details={
            "container": service.container,
            "command_family": service.command_family,
            "container_state": result.stdout.strip(),
        },
    )


def _status_message(service: ServiceDefinition, status: str) -> str:
    if status == SERVICE_STATUS_RUNNING:
        return f"{service.display_name} is running."
    if status == SERVICE_STATUS_STOPPED:
        return f"{service.display_name} is stopped."
    if status == SERVICE_STATUS_FAILED:
        return f"{service.display_name} is failed."
    if status == SERVICE_STATUS_NOT_FOUND:
        return f"{service.display_name} was not found in this runtime."
    if status == SERVICE_STATUS_DEGRADED:
        return f"{service.display_name} is changing state."
    if status == SERVICE_STATUS_UNSUPPORTED:
        return "Service operation is not available in this runtime."

    return f"{service.display_name} status is unknown."


def _status_dict(status: ServiceStatus) -> dict[str, Any]:
    return {
        "service_key": status.service_key,
        "display_name": status.display_name,
        "kind": status.kind,
        "status": status.status,
        "message": status.message,
        "checked_at": status.checked_at.isoformat(),
        "details": status.details,
        "safe_error": status.safe_error,
    }


def _get_status(service: ServiceDefinition, runner: CommandRunner | None = None) -> ServiceStatus:
    if service.kind == "systemd":
        return _systemd_status(service, runner=runner)

    if service.kind == "docker":
        return _docker_status(service, runner=runner)

    return ServiceStatus(
        service_key=service.key,
        display_name=service.display_name,
        kind=service.kind,
        status=SERVICE_STATUS_UNSUPPORTED,
        message="Service operation is not available in this runtime.",
        checked_at=utc_now(),
        details={"command_family": service.command_family},
        safe_error="Unsupported service kind.",
    )


def _restart_command(service: ServiceDefinition) -> list[str]:
    if service.kind == "systemd" and service.unit:
        systemctl = _command_path("systemctl") or "systemctl"

        if os.geteuid() == 0:
            return [systemctl, "restart", service.unit]

        sudo = _command_path("sudo") or "sudo"
        return [sudo, "-n", systemctl, "restart", service.unit]

    if service.kind == "docker" and service.container:
        return ["docker", "restart", service.container]

    return []


def _run_restart(service: ServiceDefinition, runner: CommandRunner | None = None) -> CommandResult:
    return _run_command(
        _restart_command(service),
        timeout=RESTART_TIMEOUT_SECONDS,
        runner=runner,
    )


def _restart_permission_error(
    service: ServiceDefinition,
    runner: CommandRunner | None = None,
) -> str | None:
    if service.kind != "systemd" or os.geteuid() == 0:
        return None

    sudo = _command_path("sudo")
    systemctl = _command_path("systemctl")

    if runner is None and not sudo:
        return SYSTEMD_RESTART_PERMISSION_MESSAGE

    if runner is None and not systemctl:
        return "systemctl command is not available in this runtime."

    restart_command = _restart_command(service)

    if restart_command[:2] != [sudo or "sudo", "-n"]:
        return None

    permission_check = _run_command(
        [restart_command[0], "-n", "-l", *restart_command[2:]],
        timeout=STATUS_TIMEOUT_SECONDS,
        runner=runner,
    )

    if permission_check.ok:
        return None

    return _safe_error(permission_check) or SYSTEMD_RESTART_PERMISSION_MESSAGE


def _operation_to_dict(row: ServiceOperation | None) -> dict[str, Any] | None:
    if row is None:
        return None

    return {
        "operation_id": row.id,
        "service_key": row.service_key,
        "display_name": row.display_name,
        "operation_type": row.operation_type,
        "action": row.operation_type,
        "status": row.status,
        "reason": row.reason,
        "requested_by_user_id": row.requested_by_user_id,
        "requested_by_username": row.requested_by_username,
        "related_config_version_id": row.related_config_version_id,
        "pre_status": row.pre_status,
        "post_status": row.post_status,
        "safe_message": row.safe_message,
        "safe_error": row.safe_error,
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        "created_by": row.requested_by_username,
    }


def _last_operation(db, service_key: str) -> dict[str, Any] | None:
    row = (
        db.query(ServiceOperation)
        .filter(ServiceOperation.service_key == service_key)
        .order_by(ServiceOperation.id.desc())
        .first()
    )

    return _operation_to_dict(row)


def _create_operation(
    db,
    *,
    service: ServiceDefinition,
    operation_type: str,
    status: str,
    current_user: Mapping[str, Any] | None,
    reason: str | None,
    related_config_version_id: int | None,
    pre_status: str | None = None,
    post_status: str | None = None,
    safe_message: str | None = None,
    safe_error: str | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> ServiceOperation:
    now = utc_now()
    row = ServiceOperation(
        service_key=service.key,
        display_name=service.display_name,
        operation_type=operation_type,
        status=status,
        reason=reason,
        requested_by_user_id=(current_user or {}).get("id"),
        requested_by_username=(current_user or {}).get("username"),
        related_config_version_id=related_config_version_id,
        pre_status=pre_status,
        post_status=post_status,
        safe_message=safe_message,
        safe_error=safe_error,
        started_at=started_at,
        finished_at=finished_at,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    return row


def _update_operation(
    row: ServiceOperation,
    *,
    status: str,
    post_status: str | None,
    safe_message: str,
    safe_error: str | None = None,
) -> None:
    row.status = status
    row.post_status = post_status
    row.safe_message = safe_message
    row.safe_error = safe_error
    row.finished_at = utc_now()
    row.updated_at = row.finished_at


def record_service_operation_audit(
    db,
    *,
    event_type: str,
    outcome: str,
    current_user: Mapping[str, Any] | None,
    service: ServiceDefinition,
    request: Request | None = None,
    operation_id: int | None = None,
    reason: str | None = None,
    related_config_version_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    row = SecurityAuditEvent(
        event_type=event_type,
        outcome=outcome,
        actor_user_id=(current_user or {}).get("id"),
        actor_username=(current_user or {}).get("username"),
        actor_role=(current_user or {}).get("role"),
        target_type="SERVICE_OPERATION",
        target_id=str(operation_id) if operation_id is not None else service.key,
        method=request.method if request else None,
        path=request.url.path if request else None,
        client_ip=_request_client_ip(request),
        user_agent=request.headers.get("user-agent") if request else None,
        details_json=json.dumps(
            _sanitize_audit_details(
                {
                    "service_key": service.key,
                    "display_name": service.display_name,
                    "reason": reason,
                    "related_config_version_id": related_config_version_id,
                    **(details or {}),
                }
            ),
            default=str,
            sort_keys=True,
        ),
    )
    db.add(row)
    db.flush()


def _service_to_dict(
    db,
    service: ServiceDefinition,
    *,
    include_status: bool = True,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    status = _get_status(service, runner=runner) if include_status else None

    return {
        "key": service.key,
        "display_name": service.display_name,
        "description": service.description,
        "kind": service.kind,
        "risk_level": service.risk_level,
        "restart_allowed": service.restart_allowed,
        "restart_disabled_reason": service.restart_disabled_reason,
        "requires_admin": True,
        "impact": service.impact,
        "post_restart_check": service.post_restart_check,
        "command_family": service.command_family,
        "unit": service.unit,
        "container": service.container,
        "status": status.status if status else SERVICE_STATUS_UNKNOWN,
        "status_details": _status_dict(status) if status else None,
        "last_operation": _last_operation(db, service.key),
    }


def list_services(db, *, runner: CommandRunner | None = None) -> dict[str, Any]:
    return {
        "services": [
            _service_to_dict(db, service, runner=runner)
            for service in SERVICE_REGISTRY.values()
        ],
        "supported_statuses": [
            SERVICE_STATUS_RUNNING,
            SERVICE_STATUS_STOPPED,
            SERVICE_STATUS_FAILED,
            SERVICE_STATUS_UNKNOWN,
            SERVICE_STATUS_NOT_FOUND,
            SERVICE_STATUS_DEGRADED,
            SERVICE_STATUS_UNSUPPORTED,
        ],
    }


def get_service_status(
    db,
    *,
    service_key: str,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
    runner: CommandRunner | None = None,
    record_operation: bool = True,
) -> dict[str, Any]:
    service = _service(service_key)
    status = _get_status(service, runner=runner)

    if not record_operation:
        return _status_dict(status)

    operation_status = (
        OPERATION_STATUS_FAILED
        if status.status in {SERVICE_STATUS_UNKNOWN, SERVICE_STATUS_UNSUPPORTED}
        else OPERATION_STATUS_SUCCESS
    )
    operation = _create_operation(
        db,
        service=service,
        operation_type="status_check",
        status=operation_status,
        current_user=current_user,
        reason=None,
        related_config_version_id=None,
        pre_status=status.status,
        post_status=status.status,
        safe_message=status.message,
        safe_error=status.safe_error,
        started_at=status.checked_at,
        finished_at=utc_now(),
    )
    record_service_operation_audit(
        db,
        event_type="SERVICE_STATUS_CHECK",
        outcome="SUCCESS" if operation_status == OPERATION_STATUS_SUCCESS else "FAILURE",
        current_user=current_user,
        service=service,
        request=request,
        operation_id=operation.id,
        details={"status": status.status, "message": status.message},
    )
    db.commit()

    result = _status_dict(status)
    result["operation"] = _operation_to_dict(operation)
    return result


def preview_restart(
    db,
    *,
    service_key: str,
    reason: str | None,
    related_config_version_id: int | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    service = _service(service_key)
    cleaned_reason = _require_reason(reason)

    if current_user_role(current_user) not in {"ADMIN", "ANALYST"}:
        operation = _create_operation(
            db,
            service=service,
            operation_type="restart_preview",
            status=OPERATION_STATUS_DENIED,
            current_user=current_user,
            reason=cleaned_reason,
            related_config_version_id=related_config_version_id,
            safe_message="Restart preview denied.",
            safe_error="Insufficient role permissions.",
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        record_service_operation_audit(
            db,
            event_type="SERVICE_RESTART_DENIED",
            outcome="DENIED",
            current_user=current_user,
            service=service,
            request=request,
            operation_id=operation.id,
            reason=cleaned_reason,
            related_config_version_id=related_config_version_id,
            details={"action": "restart_preview", "role": current_user_role(current_user)},
        )
        db.commit()
        raise HTTPException(status_code=403, detail="Insufficient role permissions.")

    current_status = _get_status(service, runner=runner)
    allowed = service.restart_allowed and current_status.status not in {
        SERVICE_STATUS_UNSUPPORTED,
        SERVICE_STATUS_NOT_FOUND,
    }
    warnings = []

    if service.risk_level == "high":
        warnings.append(
            f"{service.display_name} is a high-impact service. Restart may interrupt security operations."
        )

    if not service.restart_allowed and service.restart_disabled_reason:
        warnings.append(service.restart_disabled_reason)

    if current_status.status in {SERVICE_STATUS_UNSUPPORTED, SERVICE_STATUS_NOT_FOUND}:
        warnings.append(current_status.message)

    permission_error = (
        _restart_permission_error(service, runner=runner)
        if service.restart_allowed
        and current_status.status not in {SERVICE_STATUS_UNSUPPORTED, SERVICE_STATUS_NOT_FOUND}
        else None
    )

    if permission_error:
        allowed = False
        warnings.append(permission_error)

    operation = _create_operation(
        db,
        service=service,
        operation_type="restart_preview",
        status=OPERATION_STATUS_SUCCESS if allowed else OPERATION_STATUS_FAILED,
        current_user=current_user,
        reason=cleaned_reason,
        related_config_version_id=related_config_version_id,
        pre_status=current_status.status,
        post_status=current_status.status,
        safe_message="Restart preview generated.",
        safe_error=permission_error or current_status.safe_error,
        started_at=current_status.checked_at,
        finished_at=utc_now(),
    )
    record_service_operation_audit(
        db,
        event_type="SERVICE_RESTART_PREVIEW",
        outcome="SUCCESS" if allowed else "FAILURE",
        current_user=current_user,
        service=service,
        request=request,
        operation_id=operation.id,
        reason=cleaned_reason,
        related_config_version_id=related_config_version_id,
        details={
            "allowed": allowed,
            "current_status": current_status.status,
            "warnings": warnings,
            "command_family": service.command_family,
            "permission_check": "failed" if permission_error else "passed",
        },
    )
    db.commit()

    return {
        "service_key": service.key,
        "display_name": service.display_name,
        "allowed": allowed,
        "risk_level": service.risk_level,
        "current_status": current_status.status,
        "current_status_details": _status_dict(current_status),
        "requires_confirmation": True,
        "reason_required": True,
        "impact": service.impact,
        "post_restart_check": service.post_restart_check,
        "command_family": service.command_family,
        "warnings": warnings,
        "operation": _operation_to_dict(operation),
    }


def restart_service(
    db,
    *,
    service_key: str,
    reason: str | None,
    confirm: bool,
    related_config_version_id: int | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
    runner: CommandRunner | None = None,
) -> dict[str, Any]:
    service = _service(service_key)
    cleaned_reason = _require_reason(reason)

    if current_user_role(current_user) != "ADMIN":
        operation = _create_operation(
            db,
            service=service,
            operation_type="restart",
            status=OPERATION_STATUS_DENIED,
            current_user=current_user,
            reason=cleaned_reason,
            related_config_version_id=related_config_version_id,
            safe_message="Restart denied.",
            safe_error="ADMIN role required.",
            started_at=utc_now(),
            finished_at=utc_now(),
        )
        record_service_operation_audit(
            db,
            event_type="SERVICE_RESTART_DENIED",
            outcome="DENIED",
            current_user=current_user,
            service=service,
            request=request,
            operation_id=operation.id,
            reason=cleaned_reason,
            related_config_version_id=related_config_version_id,
            details={"role": current_user_role(current_user)},
        )
        db.commit()
        raise HTTPException(status_code=403, detail="ADMIN role required.")

    if not confirm:
        raise HTTPException(status_code=400, detail="Explicit restart confirmation is required.")

    if not service.restart_allowed:
        raise HTTPException(
            status_code=400,
            detail=service.restart_disabled_reason or "Restart is not enabled for this service.",
        )

    started_at = utc_now()
    pre_status = _get_status(service, runner=runner)
    operation = _create_operation(
        db,
        service=service,
        operation_type="restart",
        status=OPERATION_STATUS_RUNNING,
        current_user=current_user,
        reason=cleaned_reason,
        related_config_version_id=related_config_version_id,
        pre_status=pre_status.status,
        safe_message="Restart requested.",
        safe_error=pre_status.safe_error,
        started_at=started_at,
    )
    record_service_operation_audit(
        db,
        event_type="SERVICE_RESTART_REQUESTED",
        outcome="REQUESTED",
        current_user=current_user,
        service=service,
        request=request,
        operation_id=operation.id,
        reason=cleaned_reason,
        related_config_version_id=related_config_version_id,
        details={"pre_status": pre_status.status, "command_family": service.command_family},
    )

    if pre_status.status in {SERVICE_STATUS_UNSUPPORTED, SERVICE_STATUS_NOT_FOUND}:
        message = "Restart could not run because the service runtime is unavailable."
        _update_operation(
            operation,
            status=OPERATION_STATUS_FAILED,
            post_status=pre_status.status,
            safe_message=message,
            safe_error=pre_status.safe_error,
        )
        record_service_operation_audit(
            db,
            event_type="SERVICE_RESTART_FAILED",
            outcome="FAILURE",
            current_user=current_user,
            service=service,
            request=request,
            operation_id=operation.id,
            reason=cleaned_reason,
            related_config_version_id=related_config_version_id,
            details={"pre_status": pre_status.status, "safe_error": pre_status.safe_error},
        )
        db.commit()
        return _restart_response(operation, service, message)

    permission_error = _restart_permission_error(service, runner=runner)

    if permission_error:
        message = "Restart permission check failed."
        _update_operation(
            operation,
            status=OPERATION_STATUS_FAILED,
            post_status=pre_status.status,
            safe_message=message,
            safe_error=permission_error,
        )
        record_service_operation_audit(
            db,
            event_type="SERVICE_RESTART_FAILED",
            outcome="FAILURE",
            current_user=current_user,
            service=service,
            request=request,
            operation_id=operation.id,
            reason=cleaned_reason,
            related_config_version_id=related_config_version_id,
            details={"pre_status": pre_status.status, "safe_error": permission_error},
        )
        db.commit()
        return _restart_response(operation, service, message)

    restart_result = _run_restart(service, runner=runner)
    post_status = _get_status(service, runner=runner)
    success = restart_result.ok and post_status.status == SERVICE_STATUS_RUNNING
    message = (
        f"{service.display_name} restarted successfully."
        if success
        else "Restart command failed or service did not return to running state."
    )
    safe_error = None if success else (_safe_error(restart_result) or post_status.safe_error or message)

    _update_operation(
        operation,
        status=OPERATION_STATUS_SUCCESS if success else OPERATION_STATUS_FAILED,
        post_status=post_status.status,
        safe_message=message,
        safe_error=safe_error,
    )
    record_service_operation_audit(
        db,
        event_type="SERVICE_RESTART_SUCCESS" if success else "SERVICE_RESTART_FAILED",
        outcome="SUCCESS" if success else "FAILURE",
        current_user=current_user,
        service=service,
        request=request,
        operation_id=operation.id,
        reason=cleaned_reason,
        related_config_version_id=related_config_version_id,
        details={
            "pre_status": pre_status.status,
            "post_status": post_status.status,
            "command_family": service.command_family,
        },
    )
    db.commit()

    return _restart_response(operation, service, message)


def _restart_response(
    operation: ServiceOperation,
    service: ServiceDefinition,
    message: str,
) -> dict[str, Any]:
    return {
        "operation_id": operation.id,
        "service_key": service.key,
        "display_name": service.display_name,
        "action": "restart",
        "status": operation.status,
        "pre_status": operation.pre_status,
        "post_status": operation.post_status,
        "started_at": operation.started_at.isoformat() if operation.started_at else None,
        "finished_at": operation.finished_at.isoformat() if operation.finished_at else None,
        "message": message,
        "safe_error": operation.safe_error,
        "related_config_version_id": operation.related_config_version_id,
    }


def list_operations(
    db,
    *,
    service_key: str | None = None,
    operation_type: str | None = None,
    status: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    query = _operations_query(
        db,
        service_key=service_key,
        operation_type=operation_type,
        status=status,
        search=search,
    )

    rows = (
        query.order_by(ServiceOperation.id.desc())
        .offset(max(0, offset))
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [_operation_to_dict(row) for row in rows]


def count_operations(
    db,
    *,
    service_key: str | None = None,
    operation_type: str | None = None,
    status: str | None = None,
    search: str | None = None,
) -> int:
    return _operations_query(
        db,
        service_key=service_key,
        operation_type=operation_type,
        status=status,
        search=search,
    ).count()


def _operations_query(
    db,
    *,
    service_key: str | None,
    operation_type: str | None,
    status: str | None,
    search: str | None,
):
    query = db.query(ServiceOperation)

    if service_key:
        query = query.filter(ServiceOperation.service_key == _service(service_key).key)

    if operation_type:
        query = query.filter(ServiceOperation.operation_type == operation_type.strip().lower())

    if status:
        query = query.filter(ServiceOperation.status == status.strip().lower())

    term = str(search or "").strip()

    if term:
        like_term = f"%{term}%"
        search_filters = [
            ServiceOperation.service_key.ilike(like_term),
            ServiceOperation.display_name.ilike(like_term),
            ServiceOperation.operation_type.ilike(like_term),
            ServiceOperation.status.ilike(like_term),
            ServiceOperation.reason.ilike(like_term),
            ServiceOperation.requested_by_username.ilike(like_term),
            ServiceOperation.pre_status.ilike(like_term),
            ServiceOperation.post_status.ilike(like_term),
            ServiceOperation.safe_message.ilike(like_term),
            ServiceOperation.safe_error.ilike(like_term),
        ]
        numeric_term = term.removeprefix("#")

        if numeric_term.isdigit():
            numeric_value = int(numeric_term)
            search_filters.extend(
                [
                    ServiceOperation.id == numeric_value,
                    ServiceOperation.related_config_version_id == numeric_value,
                ]
            )

        query = query.filter(or_(*search_filters))

    return query


def get_operation(db, operation_id: int) -> dict[str, Any]:
    row = db.query(ServiceOperation).filter(ServiceOperation.id == operation_id).first()

    if not row:
        raise HTTPException(status_code=404, detail="Service operation not found.")

    return _operation_to_dict(row)
