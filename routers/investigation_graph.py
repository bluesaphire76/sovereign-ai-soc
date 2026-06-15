from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from database import SessionLocal
from investigation_graph import (
    build_case_graph,
    build_incident_graph,
    graph_summary_payload,
    investigation_graph_capabilities,
    normalize_graph_options,
)


router = APIRouter(prefix="/investigation-graph", tags=["Investigation Graph"])


def _current_user(request: Request) -> dict:
    return getattr(request.state, "current_user", None) or {}


def _options(
    *,
    depth: int,
    include_raw_events: bool,
    include_timeline: bool,
    include_ai: bool,
    include_detection_rules: bool,
    include_suppression: bool,
    limit_nodes: int,
    limit_edges: int,
):
    return normalize_graph_options(
        depth=depth,
        include_raw_events=include_raw_events,
        include_timeline=include_timeline,
        include_ai=include_ai,
        include_detection_rules=include_detection_rules,
        include_suppression=include_suppression,
        limit_nodes=limit_nodes,
        limit_edges=limit_edges,
    )


@router.get("/capabilities")
def capabilities():
    return investigation_graph_capabilities()


@router.get("/incidents/{incident_id}")
def incident_graph(
    incident_id: int,
    request: Request,
    depth: int = Query(default=1, ge=1, le=2),
    include_raw_events: bool = Query(default=False),
    include_timeline: bool = Query(default=True),
    include_ai: bool = Query(default=True),
    include_detection_rules: bool = Query(default=True),
    include_suppression: bool = Query(default=True),
    limit_nodes: int = Query(default=80, ge=1, le=200),
    limit_edges: int = Query(default=160, ge=1, le=400),
):
    db = SessionLocal()

    try:
        return build_incident_graph(
            db,
            incident_id,
            _options(
                depth=depth,
                include_raw_events=include_raw_events,
                include_timeline=include_timeline,
                include_ai=include_ai,
                include_detection_rules=include_detection_rules,
                include_suppression=include_suppression,
                limit_nodes=limit_nodes,
                limit_edges=limit_edges,
            ),
            current_user=_current_user(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Incident not found.") from exc
    finally:
        db.close()


@router.get("/incidents/{incident_id}/summary")
def incident_graph_summary(
    incident_id: int,
    request: Request,
    include_raw_events: bool = Query(default=False),
    include_timeline: bool = Query(default=True),
    include_ai: bool = Query(default=True),
    include_detection_rules: bool = Query(default=True),
    include_suppression: bool = Query(default=True),
):
    db = SessionLocal()

    try:
        graph = build_incident_graph(
            db,
            incident_id,
            normalize_graph_options(
                include_raw_events=include_raw_events,
                include_timeline=include_timeline,
                include_ai=include_ai,
                include_detection_rules=include_detection_rules,
                include_suppression=include_suppression,
                limit_nodes=200,
                limit_edges=400,
            ),
            current_user=_current_user(request),
        )
        return graph_summary_payload(graph)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Incident not found.") from exc
    finally:
        db.close()


@router.get("/cases/{case_id}")
def case_graph(
    case_id: int,
    request: Request,
    depth: int = Query(default=1, ge=1, le=2),
    include_raw_events: bool = Query(default=False),
    include_timeline: bool = Query(default=True),
    include_ai: bool = Query(default=True),
    include_detection_rules: bool = Query(default=True),
    include_suppression: bool = Query(default=True),
    limit_nodes: int = Query(default=80, ge=1, le=200),
    limit_edges: int = Query(default=160, ge=1, le=400),
):
    db = SessionLocal()

    try:
        return build_case_graph(
            db,
            case_id,
            _options(
                depth=depth,
                include_raw_events=include_raw_events,
                include_timeline=include_timeline,
                include_ai=include_ai,
                include_detection_rules=include_detection_rules,
                include_suppression=include_suppression,
                limit_nodes=limit_nodes,
                limit_edges=limit_edges,
            ),
            current_user=_current_user(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Case not found.") from exc
    finally:
        db.close()


@router.get("/cases/{case_id}/summary")
def case_graph_summary(
    case_id: int,
    request: Request,
    include_raw_events: bool = Query(default=False),
    include_timeline: bool = Query(default=True),
    include_ai: bool = Query(default=True),
    include_detection_rules: bool = Query(default=True),
    include_suppression: bool = Query(default=True),
):
    db = SessionLocal()

    try:
        graph = build_case_graph(
            db,
            case_id,
            normalize_graph_options(
                include_raw_events=include_raw_events,
                include_timeline=include_timeline,
                include_ai=include_ai,
                include_detection_rules=include_detection_rules,
                include_suppression=include_suppression,
                limit_nodes=200,
                limit_edges=400,
            ),
            current_user=_current_user(request),
        )
        return graph_summary_payload(graph)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Case not found.") from exc
    finally:
        db.close()
