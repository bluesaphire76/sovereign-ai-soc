from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from database import SessionLocal
from investigation_ai.adapters import safe_text
from models import Incident
from qdrant_knowledge import QdrantKnowledgeBase


HISTORICAL_INCIDENT_SOURCE_TYPE = "historical_incident"
PROTECTED_SOURCE_TYPES = {"knowledge_base"}
OPEN_INCIDENT_STATUSES = {"NEW", "OPEN", "TRIAGED", "ESCALATED", "IN_PROGRESS"}

DEFAULT_RETENTION_DAYS = int(os.getenv("QDRANT_INCIDENT_MEMORY_RETENTION_DAYS", "180"))
DEFAULT_MAX_RECORDS = int(os.getenv("QDRANT_INCIDENT_MEMORY_MAX_RECORDS", "5000"))
DEFAULT_INCLUDE_OPEN = str(
    os.getenv("QDRANT_INCIDENT_MEMORY_INCLUDE_OPEN", "false")
).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class QdrantMemoryPoint:
    point_id: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class RetentionCandidate:
    point_id: str
    incident_id: int | None
    source: str
    reason: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Dry-run by default Qdrant historical incident memory retention cleanup. "
            "Only source_type=historical_incident can be deleted."
        )
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Delete eligible historical incident memory points. Default is dry-run.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview eligible points without deleting. This is the default.",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=DEFAULT_RETENTION_DAYS,
        help=f"Retention window for historical incident memory. Default: {DEFAULT_RETENTION_DAYS}",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=DEFAULT_MAX_RECORDS,
        help=f"Maximum Qdrant points to scan. Default: {DEFAULT_MAX_RECORDS}",
    )
    parser.add_argument(
        "--include-open",
        action="store_true",
        default=DEFAULT_INCLUDE_OPEN,
        help="Allow retention cleanup to evaluate open/non-terminal incident memory.",
    )
    return parser.parse_args()


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _source_type(payload: dict[str, Any]) -> str:
    return safe_text(payload.get("source_type")) or "unknown"


def _point_source(payload: dict[str, Any]) -> str:
    return safe_text(payload.get("source")) or "unknown"


def _parse_datetime(value: Any) -> datetime | None:
    text = safe_text(value)
    if not text:
        return None

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _payload_timestamp(payload: dict[str, Any]) -> datetime | None:
    for key in ["indexed_at", "updated_at", "created_at"]:
        parsed = _parse_datetime(payload.get(key))
        if parsed is not None:
            return parsed
    return None


def _payload_status(payload: dict[str, Any], incident_statuses: dict[int, str]) -> str:
    incident_id = _int_or_none(payload.get("incident_id"))
    return safe_text(incident_statuses.get(incident_id or -1) or payload.get("status")).upper()


def _historical_filter():
    from qdrant_client.models import FieldCondition, Filter, MatchValue

    return Filter(
        must=[
            FieldCondition(
                key="source_type",
                match=MatchValue(value=HISTORICAL_INCIDENT_SOURCE_TYPE),
            )
        ]
    )


def scroll_historical_memory_points(
    client,
    *,
    collection_name: str,
    max_records: int,
) -> list[QdrantMemoryPoint]:
    points: list[QdrantMemoryPoint] = []
    next_offset: Any = None

    while len(points) < max_records:
        batch_limit = min(250, max_records - len(points))
        batch, next_offset = client.scroll(
            collection_name=collection_name,
            scroll_filter=_historical_filter(),
            limit=batch_limit,
            offset=next_offset,
            with_payload=True,
            with_vectors=False,
        )

        if not batch:
            break

        for point in batch:
            payload = getattr(point, "payload", None) or {}
            points.append(
                QdrantMemoryPoint(
                    point_id=str(getattr(point, "id", "")),
                    payload=dict(payload),
                )
            )

        if next_offset is None:
            break

    return points


def load_incident_statuses(db, incident_ids: set[int]) -> dict[int, str]:
    if not incident_ids:
        return {}

    rows = (
        db.query(Incident.id, Incident.status)
        .filter(Incident.id.in_(sorted(incident_ids)))
        .all()
    )
    return {int(row[0]): safe_text(row[1]) for row in rows}


def build_retention_plan(
    points: list[QdrantMemoryPoint],
    *,
    incident_statuses: dict[int, str],
    retention_days: int,
    include_open: bool,
    now: datetime | None = None,
) -> tuple[list[RetentionCandidate], dict[str, int]]:
    reference = now or datetime.now(timezone.utc)
    cutoff = reference - timedelta(days=max(1, retention_days))
    candidates: list[RetentionCandidate] = []
    skipped = {
        "protected_source_type": 0,
        "invalid_payload": 0,
        "open_incident": 0,
        "retained": 0,
    }
    historical_by_incident: dict[int, list[QdrantMemoryPoint]] = {}

    for point in points:
        source_type = _source_type(point.payload)
        if source_type in PROTECTED_SOURCE_TYPES:
            skipped["protected_source_type"] += 1
            continue
        if source_type != HISTORICAL_INCIDENT_SOURCE_TYPE:
            skipped["invalid_payload"] += 1
            continue

        incident_id = _int_or_none(point.payload.get("incident_id"))
        if incident_id is None:
            skipped["invalid_payload"] += 1
            continue

        status = _payload_status(point.payload, incident_statuses)
        if not include_open and status in OPEN_INCIDENT_STATUSES:
            skipped["open_incident"] += 1
            continue

        historical_by_incident.setdefault(incident_id, []).append(point)

        timestamp = _payload_timestamp(point.payload)
        if incident_id not in incident_statuses:
            candidates.append(
                RetentionCandidate(
                    point_id=point.point_id,
                    incident_id=incident_id,
                    source=_point_source(point.payload),
                    reason="incident_missing_in_db",
                )
            )
        elif timestamp is not None and timestamp < cutoff:
            candidates.append(
                RetentionCandidate(
                    point_id=point.point_id,
                    incident_id=incident_id,
                    source=_point_source(point.payload),
                    reason="older_than_retention_window",
                )
            )
        else:
            skipped["retained"] += 1

    candidate_ids = {candidate.point_id for candidate in candidates}
    for incident_id, incident_points in historical_by_incident.items():
        if len(incident_points) <= 1:
            continue

        ordered = sorted(
            incident_points,
            key=lambda item: _payload_timestamp(item.payload) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        for stale_point in ordered[1:]:
            if stale_point.point_id in candidate_ids:
                continue
            candidates.append(
                RetentionCandidate(
                    point_id=stale_point.point_id,
                    incident_id=incident_id,
                    source=_point_source(stale_point.payload),
                    reason="duplicate_incident_memory",
                )
            )
            candidate_ids.add(stale_point.point_id)

    return candidates, skipped


def delete_candidates(
    client,
    *,
    collection_name: str,
    candidates: list[RetentionCandidate],
    apply: bool,
) -> int:
    if not apply or not candidates:
        return 0

    point_ids = [candidate.point_id for candidate in candidates]
    client.delete(
        collection_name=collection_name,
        points_selector=point_ids,
        wait=True,
    )
    return len(point_ids)


def run_retention(
    *,
    apply: bool,
    retention_days: int,
    max_records: int,
    include_open: bool,
    db_factory=SessionLocal,
    knowledge_base_factory=QdrantKnowledgeBase,
) -> dict[str, Any]:
    kb = knowledge_base_factory()
    collection_name = kb.config.collection_name
    points = scroll_historical_memory_points(
        kb.client,
        collection_name=collection_name,
        max_records=max(1, max_records),
    )
    incident_ids = {
        incident_id
        for point in points
        if (incident_id := _int_or_none(point.payload.get("incident_id"))) is not None
    }

    db = db_factory()
    try:
        incident_statuses = load_incident_statuses(db, incident_ids)
    finally:
        db.close()

    candidates, skipped = build_retention_plan(
        points,
        incident_statuses=incident_statuses,
        retention_days=retention_days,
        include_open=include_open,
    )
    deleted = delete_candidates(
        kb.client,
        collection_name=collection_name,
        candidates=candidates,
        apply=apply,
    )

    return {
        "mode": "APPLY" if apply else "DRY_RUN",
        "collection": collection_name,
        "source_type": HISTORICAL_INCIDENT_SOURCE_TYPE,
        "retention_days": retention_days,
        "max_records": max_records,
        "include_open": include_open,
        "scanned_points": len(points),
        "candidates": len(candidates),
        "deleted": deleted,
        "skipped": skipped,
        "candidate_reasons": {
            reason: sum(1 for item in candidates if item.reason == reason)
            for reason in sorted({item.reason for item in candidates})
        },
        "candidate_point_ids": [candidate.point_id for candidate in candidates[:50]],
        "decision_boundary": (
            "Qdrant retention cleanup targets only source_type=historical_incident. "
            "Knowledge base semantic memory is never deleted by this script."
        ),
    }


def main() -> None:
    args = parse_args()
    result = run_retention(
        apply=bool(args.apply),
        retention_days=args.retention_days,
        max_records=args.max_records,
        include_open=bool(args.include_open),
    )

    print(
        "Qdrant historical memory retention {mode}: scanned={scanned_points}, "
        "candidates={candidates}, deleted={deleted}, source_type={source_type}.".format(
            **result
        )
    )
    print(f"Candidate reasons: {result['candidate_reasons']}")
    print(f"Skipped: {result['skipped']}")
    print(f"Decision boundary: {result['decision_boundary']}")


if __name__ == "__main__":
    main()
