from __future__ import annotations

from fastapi import APIRouter, Query

from dashboard_metrics import (
    build_detection_funnel,
    build_incident_trend,
    build_queue_aging,
)
from database import SessionLocal


router = APIRouter(tags=["Dashboard Metrics"])


@router.get("/metrics/incident-trend")
def dashboard_incident_trend(days: int = Query(default=7, ge=1, le=30)):
    db = SessionLocal()

    try:
        return build_incident_trend(db, days=days)
    finally:
        db.close()


@router.get("/metrics/queue-aging")
def dashboard_queue_aging():
    db = SessionLocal()

    try:
        return build_queue_aging(db)
    finally:
        db.close()


@router.get("/metrics/detection-funnel")
def dashboard_detection_funnel():
    db = SessionLocal()

    try:
        return build_detection_funnel(db)
    finally:
        db.close()
