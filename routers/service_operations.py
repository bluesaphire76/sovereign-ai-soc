from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel

from database import SessionLocal
from service_operations import (
    count_operations,
    get_operation,
    get_service_status,
    list_operations,
    list_services,
    preview_restart,
    restart_service,
)


router = APIRouter(tags=["Service Operations"])


class ServiceRestartPreviewRequest(BaseModel):
    reason: str | None = None
    related_config_version_id: int | None = None


class ServiceRestartRequest(BaseModel):
    reason: str | None = None
    confirm: bool = False
    related_config_version_id: int | None = None


def _current_user(request: Request) -> dict[str, Any]:
    return getattr(request.state, "current_user", None) or {}


@router.get("/service-operations/services")
def service_operation_services():
    db = SessionLocal()

    try:
        return list_services(db)
    finally:
        db.close()


@router.get("/service-operations/services/{service_key}/status")
def service_operation_status(service_key: str, request: Request):
    db = SessionLocal()

    try:
        return get_service_status(
            db,
            service_key=service_key,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/service-operations/services/{service_key}/restart-preview")
def service_operation_restart_preview(
    service_key: str,
    payload: ServiceRestartPreviewRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return preview_restart(
            db,
            service_key=service_key,
            reason=payload.reason,
            related_config_version_id=payload.related_config_version_id,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/service-operations/services/{service_key}/restart")
def service_operation_restart(
    service_key: str,
    payload: ServiceRestartRequest,
    request: Request,
):
    db = SessionLocal()

    try:
        return restart_service(
            db,
            service_key=service_key,
            reason=payload.reason,
            confirm=payload.confirm,
            related_config_version_id=payload.related_config_version_id,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.get("/service-operations/operations")
def service_operation_history(
    service_key: str | None = Query(default=None),
    operation_type: str | None = Query(default=None),
    status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    db = SessionLocal()

    try:
        total = count_operations(
            db,
            service_key=service_key,
            operation_type=operation_type,
            status=status,
            search=search,
        )
        items = list_operations(
            db,
            service_key=service_key,
            operation_type=operation_type,
            status=status,
            search=search,
            limit=limit,
            offset=offset,
        )
        total_pages = max(1, (total + limit - 1) // limit)

        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "page": (offset // limit) + 1,
            "total_pages": total_pages,
        }
    finally:
        db.close()


@router.get("/service-operations/operations/{operation_id}")
def service_operation_detail(operation_id: int):
    db = SessionLocal()

    try:
        return get_operation(db, operation_id)
    finally:
        db.close()
