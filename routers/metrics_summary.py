from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import func

from database import SessionLocal
from models import Incident


router = APIRouter()


@router.get("/metrics/status-distribution")
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


@router.get("/metrics/summary")
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


@router.get("/metrics/top-hosts")
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


@router.get("/metrics/risk-distribution")
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
