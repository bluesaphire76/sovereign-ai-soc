import os
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

WORKER_REALTIME_MAX_LAG_SECONDS = int(
    os.getenv("WORKER_REALTIME_MAX_LAG_SECONDS", "120")
)
WORKER_CATCHUP_MAX_LAG_SECONDS = int(
    os.getenv("WORKER_CATCHUP_MAX_LAG_SECONDS", "900")
)


RESULT_COUNT_KEYS = [
    "processed",
    "suppressed_noise",
    "observed_no_incident",
    "aggregated_duplicate",
    "duplicate_doc_id",
    "no_doc_id",
    "other_skipped",
]


def parse_event_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except Exception:
        return None


def build_result_counts() -> dict:
    return {key: 0 for key in RESULT_COUNT_KEYS}


def classify_result(result: str | None) -> str:
    if result == "processed":
        return "processed"

    if result == "suppressed_noise":
        return "suppressed_noise"

    if result == "observed_no_incident":
        return "observed_no_incident"

    if result == "skipped_aggregated_duplicate":
        return "aggregated_duplicate"

    if result == "skipped_duplicate":
        return "duplicate_doc_id"

    if result == "skipped_no_doc_id":
        return "no_doc_id"

    return "other_skipped"


def record_result(result_counts: dict, result: str | None) -> dict:
    key = classify_result(result)

    if key not in result_counts:
        result_counts[key] = 0

    result_counts[key] += 1
    return result_counts


def newest_alert_metadata(alerts: list[dict]) -> dict:
    if not alerts:
        return {
            "latest_event_timestamp": None,
            "latest_doc_id": None,
        }

    newest = sorted(
        alerts,
        key=lambda item: (
            item.get("@timestamp") or "",
            item.get("_wazuh_doc_id") or "",
        ),
    )[-1]

    return {
        "latest_event_timestamp": newest.get("@timestamp"),
        "latest_doc_id": newest.get("_wazuh_doc_id"),
    }


def lag_seconds_from_timestamp(timestamp_value: str | None) -> float | None:
    parsed = parse_event_timestamp(timestamp_value)

    if not parsed:
        return None

    lag = (datetime.now(timezone.utc) - parsed).total_seconds()

    if lag < 0:
        return 0.0

    return round(lag, 2)


def classify_ingest_mode(
    alerts_seen: int,
    latest_event_lag_seconds: float | None,
) -> str:
    if alerts_seen <= 0:
        return "IDLE"

    if latest_event_lag_seconds is None:
        return "UNKNOWN"

    if latest_event_lag_seconds <= WORKER_REALTIME_MAX_LAG_SECONDS:
        return "REALTIME"

    if latest_event_lag_seconds <= WORKER_CATCHUP_MAX_LAG_SECONDS:
        return "CATCHING_UP"

    return "LAGGING"


def build_batch_metrics(
    alerts: list[dict],
    processed_count: int,
    skipped_count: int,
    result_counts: dict | None = None,
    query_info: dict | None = None,
) -> dict:
    query_info = query_info or {}
    result_counts = result_counts or build_result_counts()
    newest = newest_alert_metadata(alerts)

    latest_event_timestamp = newest.get("latest_event_timestamp")
    latest_event_lag_seconds = lag_seconds_from_timestamp(latest_event_timestamp)
    watermark_lag_seconds = lag_seconds_from_timestamp(query_info.get("last_timestamp"))

    alerts_seen = len(alerts)
    ingest_mode = classify_ingest_mode(
        alerts_seen=alerts_seen,
        latest_event_lag_seconds=latest_event_lag_seconds,
    )

    return {
        "ingest_mode": ingest_mode,
        "alerts_seen": alerts_seen,
        "alerts_processed": processed_count,
        "alerts_skipped": skipped_count,
        "result_counts": result_counts,
        "latest_event_timestamp": latest_event_timestamp,
        "latest_doc_id": newest.get("latest_doc_id"),
        "latest_event_lag_seconds": latest_event_lag_seconds,
        "latest_event_lag_minutes": round(latest_event_lag_seconds / 60, 2)
        if latest_event_lag_seconds is not None
        else None,
        "watermark_last_timestamp": query_info.get("last_timestamp"),
        "watermark_last_doc_id": query_info.get("last_doc_id"),
        "watermark_lag_seconds": watermark_lag_seconds,
        "watermark_lag_minutes": round(watermark_lag_seconds / 60, 2)
        if watermark_lag_seconds is not None
        else None,
        "query_from": query_info.get("query_from"),
        "batch_size": query_info.get("batch_size"),
        "overlap_seconds": query_info.get("overlap_seconds"),
        "max_catchup_minutes": query_info.get("max_catchup_minutes"),
        "thresholds": {
            "realtime_max_lag_seconds": WORKER_REALTIME_MAX_LAG_SECONDS,
            "catchup_max_lag_seconds": WORKER_CATCHUP_MAX_LAG_SECONDS,
        },
    }
