from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Request

from database import SessionLocal
from demo_data_management import (
    DemoDeletionResult,
    DemoDependencyError,
    DemoOwnershipError,
    DemoRecordNotFound,
    delete_demo_case,
    delete_demo_incident,
)
from models import SecurityAuditEvent
from qdrant_auto_index import (
    schedule_case_closure_auto_index,
    schedule_incident_auto_index,
)


router = APIRouter(prefix="/demo-management", tags=["Demo Management"])
OPERATOR_ROLES = {"ADMIN", "ANALYST"}


def _current_user(request: Request) -> dict:
    return getattr(request.state, "current_user", None) or {}


def _require_operator(request: Request) -> dict:
    current_user = _current_user(request)
    if str(current_user.get("role") or "").upper() not in OPERATOR_ROLES:
        raise HTTPException(
            status_code=403,
            detail="ADMIN or ANALYST role is required.",
        )
    return current_user


def _audit_deletion(
    db,
    *,
    request: Request,
    current_user: dict,
    result: DemoDeletionResult,
) -> None:
    db.add(
        SecurityAuditEvent(
            event_type=f"DEMO_{result.record_type.upper()}_DELETED",
            outcome="SUCCESS",
            actor_user_id=current_user.get("id"),
            actor_username=current_user.get("username"),
            actor_role=current_user.get("role"),
            target_type=f"DEMO_{result.record_type.upper()}",
            target_id=str(result.record_id),
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details_json=json.dumps(
                {
                    "demo_origin": result.demo_origin,
                    "deleted_counts": result.deleted_counts,
                },
                sort_keys=True,
            ),
        )
    )


def _delete_response(result: DemoDeletionResult) -> dict:
    return {
        "result": "DEMO_RECORD_DELETED",
        "record_type": result.record_type,
        "record_id": result.record_id,
        "demo_origin": result.demo_origin,
        "deleted_counts": result.deleted_counts,
    }


def _translate_error(exc: Exception) -> HTTPException:
    if isinstance(exc, DemoRecordNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, DemoOwnershipError):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, DemoDependencyError):
        return HTTPException(
            status_code=409,
            detail={
                "message": str(exc),
                "blockers": exc.blockers,
            },
        )
    return HTTPException(status_code=500, detail="Demo deletion failed safely.")


@router.delete("/incidents/{incident_id}")
def remove_demo_incident(
    incident_id: int,
    request: Request,
):
    current_user = _require_operator(request)
    db = SessionLocal()
    try:
        result = delete_demo_incident(db, incident_id)
        _audit_deletion(
            db,
            request=request,
            current_user=current_user,
            result=result,
        )
        db.commit()
    except (DemoRecordNotFound, DemoOwnershipError, DemoDependencyError) as exc:
        db.rollback()
        raise _translate_error(exc) from exc
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc
    finally:
        db.close()

    schedule_incident_auto_index(
        incident_id,
        reason="demo_incident_deleted",
    )
    return _delete_response(result)


@router.delete("/cases/{case_id}")
def remove_demo_case(
    case_id: int,
    request: Request,
):
    current_user = _require_operator(request)
    db = SessionLocal()
    try:
        result = delete_demo_case(db, case_id)
        _audit_deletion(
            db,
            request=request,
            current_user=current_user,
            result=result,
        )
        db.commit()
    except (DemoRecordNotFound, DemoOwnershipError, DemoDependencyError) as exc:
        db.rollback()
        raise _translate_error(exc) from exc
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc
    finally:
        db.close()

    schedule_case_closure_auto_index(
        case_id,
        reason="demo_case_deleted",
    )
    return _delete_response(result)
