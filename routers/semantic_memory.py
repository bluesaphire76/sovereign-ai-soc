from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from qdrant_knowledge import QdrantKnowledgeBase, config_from_env
from scripts.index_detection_case_memory_to_qdrant import run_indexing as run_detection_case_indexing
from scripts.index_historical_incidents_to_qdrant import run_indexing
from scripts.qdrant_memory_retention import run_retention


router = APIRouter(prefix="/semantic-memory", tags=["Semantic Memory"])


def _knowledge_base() -> QdrantKnowledgeBase:
    return QdrantKnowledgeBase(config_from_env())


def _current_user(request: Request) -> dict[str, Any]:
    return getattr(request.state, "current_user", None) or {}


def _is_admin(request: Request) -> bool:
    return str(_current_user(request).get("role") or "").upper() == "ADMIN"


def _require_apply_confirmation(*, apply: bool, confirm: bool) -> None:
    if apply and not confirm:
        raise HTTPException(
            status_code=400,
            detail="confirm=true is required for semantic memory apply operations.",
        )


class HistoricalBackfillRequest(BaseModel):
    apply: bool = False
    confirm: bool = False
    limit: int = Field(default=10000, ge=1, le=50000)
    since_days: int | None = Field(default=None, ge=0, le=3650)
    include_open: bool = False


class DetectionCaseBackfillRequest(BaseModel):
    apply: bool = False
    confirm: bool = False
    limit: int = Field(default=1000, ge=1, le=50000)
    include_detection_control: bool = True
    include_case_closure: bool = True


class RetentionCleanupRequest(BaseModel):
    apply: bool = False
    confirm: bool = False
    retention_days: int = Field(default=180, ge=1, le=3650)
    max_records: int = Field(default=5000, ge=1, le=50000)
    include_open: bool = False


@router.get("/capabilities")
def semantic_memory_capabilities() -> dict[str, Any]:
    return _knowledge_base().capabilities()


@router.get("/health")
def semantic_memory_health() -> dict[str, Any]:
    return _knowledge_base().health_check()


@router.get("/collection")
def semantic_memory_collection() -> dict[str, Any]:
    return _knowledge_base().collection_info()


@router.get("/index-status")
def semantic_memory_index_status(
    max_points: int = Query(default=5000, ge=1, le=20000),
) -> dict[str, Any]:
    """Return read-only semantic memory index governance metadata.

    This endpoint does not trigger indexing. Indexing remains an explicit
    manual CLI operation through rag_index.py.
    """

    return _knowledge_base().index_status(max_points=max_points)


@router.get("/search")
def semantic_memory_search(
    query: str = Query(..., min_length=1, max_length=500),
    limit: int = Query(default=4, ge=1, le=25),
    source_type: str | None = Query(default=None, max_length=80),
) -> dict[str, Any]:
    """Run a read-only semantic search against the configured Qdrant collection.

    This endpoint is intentionally support-only. It does not change incident
    state, severity, deduplication, suppression, closure or correlation.
    """

    kb = _knowledge_base()

    if not kb.config.enabled:
        return {
            "enabled": False,
            "query": query,
            "collection": kb.config.collection_name,
            "source_type": source_type,
            "result_count": 0,
            "results": [],
            "decision_boundary": (
                "Semantic memory is disabled. No operational decision was made."
            ),
        }

    try:
        results = kb.retrieve_contexts(query, limit=limit, source_type=source_type)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Semantic memory search failed.",
                "error_type": exc.__class__.__name__,
            },
        ) from exc

    return {
        "enabled": True,
        "query": query,
        "collection": kb.config.collection_name,
        "limit": limit,
        "source_type": source_type,
        "result_count": len(results),
        "results": results,
        "decision_boundary": (
            "Qdrant results are semantic context only. They must not be used as "
            "primary deduplication, final severity, automatic suppression, "
            "incident closure or replacement for deterministic correlation rules."
        ),
    }


@router.post("/historical-backfill")
def semantic_memory_historical_backfill(
    payload: HistoricalBackfillRequest,
    request: Request,
) -> dict[str, Any]:
    """Run governed historical incident memory backfill.

    Dry-run is the default. Apply is restricted to ADMIN by RBAC and requires
    confirm=true. Open/non-terminal incidents stay excluded unless explicitly
    requested.
    """

    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="ADMIN role is required.")

    _require_apply_confirmation(apply=payload.apply, confirm=payload.confirm)

    try:
        result = run_indexing(
            limit=payload.limit,
            since_days=payload.since_days,
            include_open=payload.include_open,
            apply=payload.apply,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Historical incident semantic memory backfill failed.",
                "error_type": exc.__class__.__name__,
            },
        ) from exc

    return {
        **result,
        "operation": "historical_backfill",
        "applied": payload.apply,
        "confirm_required_for_apply": True,
        "requested_by": _current_user(request).get("username"),
    }


@router.post("/detection-case-backfill")
def semantic_memory_detection_case_backfill(
    payload: DetectionCaseBackfillRequest,
    request: Request,
) -> dict[str, Any]:
    """Run governed Detection Control and Case Closure semantic memory backfill."""

    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="ADMIN role is required.")

    _require_apply_confirmation(apply=payload.apply, confirm=payload.confirm)

    try:
        result = run_detection_case_indexing(
            limit=payload.limit,
            include_detection_control=payload.include_detection_control,
            include_case_closure=payload.include_case_closure,
            apply=payload.apply,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Detection Control and Case Closure semantic memory backfill failed.",
                "error_type": exc.__class__.__name__,
            },
        ) from exc

    return {
        **result,
        "operation": "detection_case_backfill",
        "applied": payload.apply,
        "confirm_required_for_apply": True,
        "requested_by": _current_user(request).get("username"),
    }


@router.post("/retention-cleanup")
def semantic_memory_retention_cleanup(
    payload: RetentionCleanupRequest,
    request: Request,
) -> dict[str, Any]:
    """Run governed historical incident memory retention cleanup.

    Dry-run is the default. Apply is restricted to ADMIN by RBAC and requires
    confirm=true. The cleanup script never deletes knowledge_base points.
    """

    if not _is_admin(request):
        raise HTTPException(status_code=403, detail="ADMIN role is required.")

    _require_apply_confirmation(apply=payload.apply, confirm=payload.confirm)

    try:
        result = run_retention(
            apply=payload.apply,
            retention_days=payload.retention_days,
            max_records=payload.max_records,
            include_open=payload.include_open,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "message": "Historical incident semantic memory retention cleanup failed.",
                "error_type": exc.__class__.__name__,
            },
        ) from exc

    return {
        **result,
        "operation": "retention_cleanup",
        "applied": payload.apply,
        "confirm_required_for_apply": True,
        "requested_by": _current_user(request).get("username"),
    }
