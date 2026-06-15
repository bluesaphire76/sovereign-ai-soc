import json
import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from database import SessionLocal
from models import WazuhIngestWatermark, utc_now

load_dotenv()

WAZUH_INGEST_COMPONENT = "wazuh_alerts"

WAZUH_BATCH_SIZE = int(os.getenv("WAZUH_BATCH_SIZE", "500"))
WAZUH_INITIAL_LOOKBACK_MINUTES = int(
    os.getenv("WAZUH_INITIAL_LOOKBACK_MINUTES", "60")
)
WAZUH_WATERMARK_OVERLAP_SECONDS = int(
    os.getenv("WAZUH_WATERMARK_OVERLAP_SECONDS", "15")
)
WAZUH_WATERMARK_FLUSH_EVERY = int(
    os.getenv("WAZUH_WATERMARK_FLUSH_EVERY", "10")
)
WAZUH_MAX_CATCHUP_MINUTES = int(
    os.getenv("WAZUH_MAX_CATCHUP_MINUTES", "30")
)


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_wazuh_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def get_or_create_watermark(db) -> WazuhIngestWatermark:
    watermark = (
        db.query(WazuhIngestWatermark)
        .filter(WazuhIngestWatermark.component == WAZUH_INGEST_COMPONENT)
        .first()
    )

    if watermark:
        return watermark

    now = utc_now()

    watermark = WazuhIngestWatermark(
        component=WAZUH_INGEST_COMPONENT,
        details=json.dumps(
            {
                "created_reason": "initial_ingest_watermark",
                "initial_lookback_minutes": WAZUH_INITIAL_LOOKBACK_MINUTES,
                "overlap_seconds": WAZUH_WATERMARK_OVERLAP_SECONDS,
                "batch_size": WAZUH_BATCH_SIZE,
            },
            ensure_ascii=False,
        ),
        created_at=now,
        updated_at=now,
    )

    db.add(watermark)
    db.commit()
    db.refresh(watermark)

    return watermark


def _build_query_range(watermark: WazuhIngestWatermark) -> tuple[dict[str, str], str]:
    now = datetime.now(timezone.utc)
    max_catchup_from = now - timedelta(minutes=WAZUH_MAX_CATCHUP_MINUTES)

    if watermark.last_timestamp:
        last_dt = parse_wazuh_timestamp(watermark.last_timestamp)

        if last_dt:
            if last_dt < max_catchup_from:
                return {"gte": iso_utc(max_catchup_from)}, "max_catchup_window"

            return {"gt": iso_utc(last_dt)}, "watermark_strict"

    initial_from = now - timedelta(minutes=WAZUH_INITIAL_LOOKBACK_MINUTES)

    if initial_from < max_catchup_from:
        return {"gte": iso_utc(max_catchup_from)}, "initial_max_catchup_window"

    return {"gte": iso_utc(initial_from)}, "initial_lookback_window"


def compute_query_from_timestamp(watermark: WazuhIngestWatermark) -> str:
    query_range, _ = _build_query_range(watermark)
    return next(iter(query_range.values()))


def build_wazuh_alert_query(watermark: WazuhIngestWatermark, limit: int | None = None):
    size = limit or WAZUH_BATCH_SIZE
    query_range, query_strategy = _build_query_range(watermark)
    query_from = next(iter(query_range.values()))

    query = {
        "size": size,
        "sort": [
            {"@timestamp": {"order": "asc"}},
            {"_id": {"order": "asc"}},
        ],
        "query": {
            "range": {
                "@timestamp": query_range,
            }
        },
    }

    query_info = {
        "query_from": query_from,
        "batch_size": size,
        "last_timestamp": watermark.last_timestamp,
        "last_doc_id": watermark.last_doc_id,
        "overlap_seconds": WAZUH_WATERMARK_OVERLAP_SECONDS,
        "query_strategy": query_strategy,
        "query_range": query_range,
        "initial_lookback_minutes": WAZUH_INITIAL_LOOKBACK_MINUTES,
        "max_catchup_minutes": WAZUH_MAX_CATCHUP_MINUTES,
    }

    return query, query_info


def update_watermark_progress(
    alerts: list[dict],
    processed_count: int,
    skipped_count: int,
    query_info: dict | None = None,
    result_counts: dict | None = None,
    batch_metrics: dict | None = None,
):
    """Persist partial ingest progress during a long worker batch.

    This intentionally does not increment total_processed, because the final
    update_watermark_success call accounts for the full batch once completed.
    """
    if not alerts:
        return

    db = SessionLocal()

    try:
        now = utc_now()
        watermark = get_or_create_watermark(db)

        newest = sorted(
            alerts,
            key=lambda item: (
                item.get("@timestamp") or "",
                item.get("_wazuh_doc_id") or "",
            ),
        )[-1]

        watermark.last_poll_at = now
        watermark.last_success_at = now
        watermark.updated_at = now
        watermark.alerts_seen = len(alerts)
        watermark.alerts_processed = processed_count
        watermark.alerts_skipped = skipped_count
        watermark.last_timestamp = newest.get("@timestamp")
        watermark.last_doc_id = newest.get("_wazuh_doc_id")
        watermark.last_error = None
        watermark.last_error_at = None
        watermark.details = json.dumps(
            {
                "query": query_info or {},
                "partial_progress": {
                    "alerts_seen": len(alerts),
                    "alerts_processed": processed_count,
                    "alerts_skipped": skipped_count,
                    "result_counts": result_counts or {},
                    "batch_metrics": batch_metrics or {},
                    "latest_timestamp": watermark.last_timestamp,
                    "latest_doc_id": watermark.last_doc_id,
                },
            },
            ensure_ascii=False,
        )

        db.commit()

    finally:
        db.close()


def update_watermark_success(
    alerts: list[dict],
    processed_count: int,
    skipped_count: int,
    query_info: dict | None = None,
    result_counts: dict | None = None,
    batch_metrics: dict | None = None,
):
    db = SessionLocal()

    try:
        now = utc_now()
        watermark = get_or_create_watermark(db)

        watermark.last_poll_at = now
        watermark.last_success_at = now
        watermark.updated_at = now
        watermark.alerts_seen = len(alerts)
        watermark.alerts_processed = processed_count
        watermark.alerts_skipped = skipped_count
        watermark.total_processed = (watermark.total_processed or 0) + processed_count

        if alerts:
            newest = sorted(
                alerts,
                key=lambda item: (
                    item.get("@timestamp") or "",
                    item.get("_wazuh_doc_id") or "",
                ),
            )[-1]

            watermark.last_timestamp = newest.get("@timestamp")
            watermark.last_doc_id = newest.get("_wazuh_doc_id")

        watermark.details = json.dumps(
            {
                "query": query_info or {},
                "last_run": {
                    "alerts_seen": len(alerts),
                    "alerts_processed": processed_count,
                    "alerts_skipped": skipped_count,
                    "result_counts": result_counts or {},
                    "batch_metrics": batch_metrics or {},
                },
            },
            ensure_ascii=False,
        )

        db.commit()

    finally:
        db.close()


def update_watermark_error(error: str, query_info: dict | None = None):
    db = SessionLocal()

    try:
        now = utc_now()
        watermark = get_or_create_watermark(db)

        watermark.last_poll_at = now
        watermark.last_error_at = now
        watermark.last_error = str(error)
        watermark.updated_at = now
        watermark.details = json.dumps(
            {
                "query": query_info or {},
                "last_error": str(error),
            },
            ensure_ascii=False,
        )

        db.commit()

    finally:
        db.close()


def get_watermark_snapshot():
    db = SessionLocal()

    try:
        watermark = get_or_create_watermark(db)

        return {
            "component": watermark.component,
            "last_timestamp": watermark.last_timestamp,
            "last_doc_id": watermark.last_doc_id,
            "last_poll_at": watermark.last_poll_at.isoformat()
            if watermark.last_poll_at
            else None,
            "last_success_at": watermark.last_success_at.isoformat()
            if watermark.last_success_at
            else None,
            "last_error_at": watermark.last_error_at.isoformat()
            if watermark.last_error_at
            else None,
            "last_error": watermark.last_error,
            "alerts_seen": watermark.alerts_seen,
            "alerts_processed": watermark.alerts_processed,
            "alerts_skipped": watermark.alerts_skipped,
            "total_processed": watermark.total_processed,
            "details": watermark.details,
            "updated_at": watermark.updated_at.isoformat()
            if watermark.updated_at
            else None,
        }

    finally:
        db.close()
