from __future__ import annotations

import time
import subprocess
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from platform_health import get_platform_health
from active_users import get_active_users_snapshot


metrics_router = APIRouter(tags=["metrics"])



ACTIVE_USERS = Gauge(
    "ai_soc_active_users",
    "Number of authenticated users active in the recent activity window.",
)

ACTIVE_USERS_WINDOW_SECONDS = Gauge(
    "ai_soc_active_users_window_seconds",
    "Active users calculation window in seconds.",
)

ACTIVE_USERS_BY_ROLE = Gauge(
    "ai_soc_active_users_by_role",
    "Number of authenticated users active in the recent activity window by role.",
    ["role"],
)

HTTP_REQUESTS_TOTAL = Counter(
    "ai_soc_http_requests_total",
    "Total HTTP requests handled by the AI SOC API.",
    ["method", "path", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "ai_soc_http_request_duration_seconds",
    "HTTP request latency in seconds for the AI SOC API.",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

PLATFORM_HEALTH_COLLECTION_SUCCESS = Gauge(
    "ai_soc_platform_health_collection_success",
    "Whether the latest platform health metrics collection succeeded.",
)

PLATFORM_HEALTH_COLLECTION_DURATION_SECONDS = Gauge(
    "ai_soc_platform_health_collection_duration_seconds",
    "Duration in seconds of the latest platform health metrics collection.",
)

PLATFORM_HEALTH_STATUS = Gauge(
    "ai_soc_platform_health_status",
    "Overall AI SOC platform health status as a numeric code: ok=1, warning=0.5, error=0, unknown=-1.",
    ["status"],
)

COMPONENT_UP = Gauge(
    "ai_soc_component_up",
    "Whether an AI SOC platform component is considered up/healthy.",
    ["component"],
)

COMPONENT_STATUS_CODE = Gauge(
    "ai_soc_component_status_code",
    "AI SOC platform component status as a numeric code: ok=1, warning=0.5, error=0, unknown=-1.",
    ["component", "status"],
)

COMPONENT_AGE_SECONDS = Gauge(
    "ai_soc_component_age_seconds",
    "Age, freshness, or lag in seconds reported by AI SOC platform health components when available.",
    ["component"],
)

WORKER_HEARTBEAT_AGE_SECONDS = Gauge(
    "ai_soc_worker_heartbeat_age_seconds",
    "Age in seconds of the latest AI SOC worker heartbeat when available.",
)

AI_RUNTIME_UP = Gauge(
    "ai_soc_ai_runtime_up",
    "Whether the configured local AI runtime is reachable according to platform health.",
)

AI_RUNTIME_TAGS_LATENCY_SECONDS = Gauge(
    "ai_soc_ai_runtime_tags_latency_seconds",
    "Latency in seconds of the latest AI runtime tags/model availability check.",
)

AI_RUNTIME_AVAILABLE_MODELS = Gauge(
    "ai_soc_ai_runtime_available_models",
    "Number of models available in the configured local AI runtime.",
)

AI_RUNTIME_CONFIGURED_MODEL_SIZE_BYTES = Gauge(
    "ai_soc_ai_runtime_configured_model_size_bytes",
    "Size in bytes of the configured AI model when reported by the runtime.",
)

LATEST_RAW_EVENT_FRESHNESS_SECONDS = Gauge(
    "ai_soc_latest_raw_event_freshness_seconds",
    "Freshness age in seconds of the latest raw event when available.",
)

LATEST_SECURITY_ALERT_FRESHNESS_SECONDS = Gauge(
    "ai_soc_latest_security_alert_freshness_seconds",
    "Freshness age in seconds of the latest security alert when available.",
)

LATEST_NETWORK_EVENT_FRESHNESS_SECONDS = Gauge(
    "ai_soc_latest_network_event_freshness_seconds",
    "Freshness age in seconds of the latest network event when available.",
)

LATEST_INCIDENT_FRESHNESS_SECONDS = Gauge(
    "ai_soc_latest_incident_freshness_seconds",
    "Freshness age in seconds of the latest incident when available.",
)

LATEST_INCIDENT_RISK_SCORE = Gauge(
    "ai_soc_latest_incident_risk_score",
    "Risk score of the latest incident when available.",
)

LATEST_INCIDENT_SECURITY_ALERT_AGE_SECONDS = Gauge(
    "ai_soc_latest_incident_security_alert_age_seconds",
    "Age in seconds of the latest security alert considered by incident freshness logic.",
)

EVENT_QUEUE_PENDING_EVENTS = Gauge(
    "ai_soc_event_queue_pending_events",
    "Number of Wazuh events newer than the current ingest watermark.",
)

ACTIVE_EVENT_SOURCES = Gauge(
    "ai_soc_active_event_sources",
    "Number of active event sources in the health check window.",
)

WAZUH_INGEST_ALERTS = Gauge(
    "ai_soc_wazuh_ingest_alerts",
    "Wazuh ingest alert counts reported by platform health.",
    ["outcome"],
)

WAZUH_INGEST_TOTAL_PROCESSED = Gauge(
    "ai_soc_wazuh_ingest_total_processed",
    "Total Wazuh alerts processed according to the ingest watermark.",
)

WORKER_ALERTS = Gauge(
    "ai_soc_worker_alerts",
    "AI SOC worker alert counts reported by the latest heartbeat details.",
    ["outcome"],
)

WORKER_LATEST_EVENT_LAG_SECONDS = Gauge(
    "ai_soc_worker_latest_event_lag_seconds",
    "Lag in seconds of the latest event observed by the AI SOC worker.",
)

WORKER_POLL_INTERVAL_SECONDS = Gauge(
    "ai_soc_worker_poll_interval_seconds",
    "Configured poll interval in seconds reported by the AI SOC worker.",
)

WORKER_RESULT_COUNTS = Gauge(
    "ai_soc_worker_result_counts",
    "AI SOC worker result counts from the latest heartbeat details.",
    ["result"],
)

WORKER_BATCH_METRICS = Gauge(
    "ai_soc_worker_batch_metrics",
    "AI SOC worker batch metrics from the latest heartbeat details.",
    ["metric"],
)

LLM_MODEL_IN_USE = Gauge(
    "ai_soc_llm_model_in_use",
    "Effective AI SOC LLM model in use according to the latest worker heartbeat.",
    ["profile", "model", "fallback"],
)

SURICATA_INGEST_EVENTS = Gauge(
    "ai_soc_suricata_ingest_events",
    "Suricata ingest event counts from the latest worker details.",
    ["outcome"],
)


GPU_COLLECTION_SUCCESS = Gauge(
    "ai_soc_gpu_collection_success",
    "Whether the latest NVIDIA GPU metrics collection via nvidia-smi succeeded.",
)

GPU_UTILIZATION_PERCENT = Gauge(
    "ai_soc_gpu_utilization_percent",
    "GPU utilization percentage reported by nvidia-smi.",
    ["gpu", "name"],
)

GPU_MEMORY_UTILIZATION_PERCENT = Gauge(
    "ai_soc_gpu_memory_utilization_percent",
    "GPU memory utilization percentage reported by nvidia-smi.",
    ["gpu", "name"],
)

GPU_MEMORY_USED_BYTES = Gauge(
    "ai_soc_gpu_memory_used_bytes",
    "GPU memory used in bytes reported by nvidia-smi.",
    ["gpu", "name"],
)

GPU_MEMORY_TOTAL_BYTES = Gauge(
    "ai_soc_gpu_memory_total_bytes",
    "GPU memory total in bytes reported by nvidia-smi.",
    ["gpu", "name"],
)

GPU_POWER_DRAW_WATTS = Gauge(
    "ai_soc_gpu_power_draw_watts",
    "GPU power draw in watts reported by nvidia-smi.",
    ["gpu", "name"],
)

GPU_POWER_LIMIT_WATTS = Gauge(
    "ai_soc_gpu_power_limit_watts",
    "GPU power limit in watts reported by nvidia-smi.",
    ["gpu", "name"],
)

GPU_TEMPERATURE_CELSIUS = Gauge(
    "ai_soc_gpu_temperature_celsius",
    "GPU temperature in Celsius reported by nvidia-smi.",
    ["gpu", "name"],
)

GPU_SM_CLOCK_HZ = Gauge(
    "ai_soc_gpu_sm_clock_hz",
    "GPU SM clock in Hertz reported by nvidia-smi.",
    ["gpu", "name"],
)

GPU_MEMORY_CLOCK_HZ = Gauge(
    "ai_soc_gpu_memory_clock_hz",
    "GPU memory clock in Hertz reported by nvidia-smi.",
    ["gpu", "name"],
)

SURICATA_INGEST_BYTE_OFFSET = Gauge(
    "ai_soc_suricata_ingest_byte_offset",
    "Current Suricata ingest byte offset.",
)



def _collect_active_user_metrics() -> None:
    snapshot = get_active_users_snapshot()

    ACTIVE_USERS.set(float(snapshot.get("count", 0)))
    ACTIVE_USERS_WINDOW_SECONDS.set(float(snapshot.get("window_seconds", 0)))

    roles = snapshot.get("roles")
    if isinstance(roles, dict):
        for role, count in roles.items():
            if isinstance(count, bool):
                continue
            if isinstance(count, int | float):
                ACTIVE_USERS_BY_ROLE.labels(role=str(role)).set(float(count))


def _normalize_path(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if path:
        return str(path)

    return request.url.path


def _status_code(status: Any) -> float:
    normalized = str(status or "unknown").strip().lower()

    if normalized in {"ok", "up", "healthy", "success", "running", "available"}:
        return 1.0

    if normalized in {"warn", "warning", "degraded", "partial"}:
        return 0.5

    if normalized in {"error", "critical", "down", "unhealthy", "failed", "failure"}:
        return 0.0

    return -1.0


def _is_up(status: Any) -> float:
    return 1.0 if _status_code(status) > 0.0 else 0.0


def _first_number(mapping: dict[str, Any], keys: tuple[str, ...]) -> float | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, int | float):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                continue

    return None


def _set_number(gauge: Gauge, value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int | float):
        gauge.set(float(value))
        return
    if isinstance(value, str):
        try:
            gauge.set(float(value))
        except ValueError:
            return


def _set_labeled_number(gauge: Gauge, label: str, value: Any) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int | float):
        gauge.labels(label).set(float(value))
        return
    if isinstance(value, str):
        try:
            gauge.labels(label).set(float(value))
        except ValueError:
            return


def _details(item: dict[str, Any]) -> dict[str, Any]:
    details = item.get("details")
    return details if isinstance(details, dict) else {}


def _nested(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}


def _component_name(item: dict[str, Any]) -> str:
    value = item.get("component") or item.get("name") or item.get("id") or "unknown"
    return str(value)


def _collect_ai_runtime_metrics(details: dict[str, Any]) -> None:
    tags_latency_ms = _first_number(details, ("tags_latency_ms",))
    if tags_latency_ms is not None:
        AI_RUNTIME_TAGS_LATENCY_SECONDS.set(tags_latency_ms / 1000.0)

    _set_number(AI_RUNTIME_AVAILABLE_MODELS, details.get("available_model_count"))

    configured_model_details = _nested(details, "configured_model_details")
    _set_number(
        AI_RUNTIME_CONFIGURED_MODEL_SIZE_BYTES,
        configured_model_details.get("size_bytes"),
    )


def _collect_wazuh_ingest_metrics(details: dict[str, Any]) -> None:
    _set_labeled_number(WAZUH_INGEST_ALERTS, "seen", details.get("alerts_seen"))
    _set_labeled_number(WAZUH_INGEST_ALERTS, "processed", details.get("alerts_processed"))
    _set_labeled_number(WAZUH_INGEST_ALERTS, "skipped", details.get("alerts_skipped"))
    _set_number(WAZUH_INGEST_TOTAL_PROCESSED, details.get("total_processed"))


def _collect_suricata_ingest_metrics(details: dict[str, Any]) -> None:
    _set_number(SURICATA_INGEST_BYTE_OFFSET, details.get("byte_offset"))

    worker_details = _nested(details, "worker_details")
    for key in (
        "inserted",
        "duplicates",
        "lines_read",
        "skipped_invalid_json",
        "skipped_unsupported_type",
        "supported_events",
    ):
        _set_labeled_number(SURICATA_INGEST_EVENTS, key, worker_details.get(key))


def _collect_worker_metrics(details: dict[str, Any]) -> None:
    _set_labeled_number(WORKER_ALERTS, "seen", details.get("alerts_seen"))
    _set_labeled_number(WORKER_ALERTS, "processed", details.get("alerts_processed"))
    _set_labeled_number(WORKER_ALERTS, "skipped", details.get("alerts_skipped"))

    _set_number(WORKER_LATEST_EVENT_LAG_SECONDS, details.get("latest_event_lag_seconds"))
    _set_number(WORKER_POLL_INTERVAL_SECONDS, details.get("poll_interval_seconds"))

    result_counts = _nested(details, "result_counts")
    for key, value in result_counts.items():
        _set_labeled_number(WORKER_RESULT_COUNTS, str(key), value)

    batch_metrics = _nested(details, "batch_metrics")
    for key, value in batch_metrics.items():
        _set_labeled_number(WORKER_BATCH_METRICS, str(key), value)

    profile = str(
        details.get("llm_last_profile")
        or details.get("llm_configured_profile")
        or "unknown"
    ).strip() or "unknown"
    model = str(
        details.get("llm_last_model")
        or details.get("llm_configured_model")
        or details.get("ollama_model")
        or "unknown"
    ).strip() or "unknown"
    fallback_value = details.get("llm_last_fallback_used")

    if isinstance(fallback_value, bool):
        fallback = str(fallback_value).lower()
    elif fallback_value is None:
        fallback = "unknown"
    else:
        fallback = str(fallback_value).strip().lower() or "unknown"

    if hasattr(LLM_MODEL_IN_USE, "clear"):
        LLM_MODEL_IN_USE.clear()

    LLM_MODEL_IN_USE.labels(
        profile=profile,
        model=model,
        fallback=fallback,
    ).set(1)



def _to_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        normalized = value.strip()
        if normalized in {"", "N/A", "[N/A]", "nan"}:
            return None
        try:
            return float(normalized)
        except ValueError:
            return None
    return None


def _collect_gpu_metrics() -> None:
    command = [
        "/usr/lib/wsl/lib/nvidia-smi",
        "--query-gpu=index,name,utilization.gpu,utilization.memory,memory.used,memory.total,power.draw,power.limit,temperature.gpu,clocks.sm,clocks.mem",
        "--format=csv,noheader,nounits",
    ]

    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except Exception:
        GPU_COLLECTION_SUCCESS.set(0)
        return

    output = completed.stdout.strip()
    if not output:
        GPU_COLLECTION_SUCCESS.set(0)
        return

    GPU_COLLECTION_SUCCESS.set(1)

    for line in output.splitlines():
        parts = [part.strip() for part in line.split(",")]
        if len(parts) < 11:
            continue

        (
            gpu_index,
            gpu_name,
            gpu_util,
            mem_util,
            mem_used_mib,
            mem_total_mib,
            power_draw,
            power_limit,
            temperature,
            sm_clock_mhz,
            mem_clock_mhz,
        ) = parts[:11]

        labels = {"gpu": gpu_index, "name": gpu_name}

        values = [
            (GPU_UTILIZATION_PERCENT, gpu_util, 1.0),
            (GPU_MEMORY_UTILIZATION_PERCENT, mem_util, 1.0),
            (GPU_MEMORY_USED_BYTES, mem_used_mib, 1024.0 * 1024.0),
            (GPU_MEMORY_TOTAL_BYTES, mem_total_mib, 1024.0 * 1024.0),
            (GPU_POWER_DRAW_WATTS, power_draw, 1.0),
            (GPU_POWER_LIMIT_WATTS, power_limit, 1.0),
            (GPU_TEMPERATURE_CELSIUS, temperature, 1.0),
            (GPU_SM_CLOCK_HZ, sm_clock_mhz, 1_000_000.0),
            (GPU_MEMORY_CLOCK_HZ, mem_clock_mhz, 1_000_000.0),
        ]

        for gauge, raw_value, multiplier in values:
            parsed = _to_float(raw_value)
            if parsed is not None:
                gauge.labels(**labels).set(parsed * multiplier)


def _collect_platform_health_metrics() -> None:
    started_at = time.perf_counter()

    try:
        payload = get_platform_health()
        PLATFORM_HEALTH_COLLECTION_SUCCESS.set(1)
    except Exception:
        PLATFORM_HEALTH_COLLECTION_SUCCESS.set(0)
        raise
    finally:
        PLATFORM_HEALTH_COLLECTION_DURATION_SECONDS.set(time.perf_counter() - started_at)

    overall_status = str(payload.get("status", "unknown")).strip().lower()
    PLATFORM_HEALTH_STATUS.labels(status=overall_status).set(_status_code(overall_status))

    components = payload.get("components", [])
    if not isinstance(components, list):
        return

    for item in components:
        if not isinstance(item, dict):
            continue

        component = _component_name(item)
        status = str(item.get("status", "unknown")).strip().lower()
        status_code = _status_code(status)

        COMPONENT_UP.labels(component=component).set(_is_up(status))
        COMPONENT_STATUS_CODE.labels(component=component, status=status).set(status_code)

        details = _details(item)

        age_seconds = _first_number(
            details,
            (
                "age_seconds",
                "freshness_seconds",
                "lag_seconds",
                "latest_event_lag_seconds",
                "latest_raw_event_lag_seconds",
                "latest_security_alert_lag_seconds",
                "latest_incident_lag_seconds",
                "watermark_lag_seconds",
            ),
        )

        if age_seconds is not None:
            COMPONENT_AGE_SECONDS.labels(component=component).set(age_seconds)

            if component == "ai_soc_worker":
                WORKER_HEARTBEAT_AGE_SECONDS.set(age_seconds)
            elif component == "latest_raw_event_freshness":
                LATEST_RAW_EVENT_FRESHNESS_SECONDS.set(age_seconds)
            elif component == "latest_security_alert_freshness":
                LATEST_SECURITY_ALERT_FRESHNESS_SECONDS.set(age_seconds)
            elif component == "latest_network_event_freshness":
                LATEST_NETWORK_EVENT_FRESHNESS_SECONDS.set(age_seconds)
            elif component == "latest_incident_freshness":
                LATEST_INCIDENT_FRESHNESS_SECONDS.set(age_seconds)

        if component == "ai_runtime":
            AI_RUNTIME_UP.set(_is_up(status))
            _collect_ai_runtime_metrics(details)
        elif component == "wazuh_ingest":
            _collect_wazuh_ingest_metrics(details)
        elif component == "suricata_ingest":
            _collect_suricata_ingest_metrics(details)
        elif component == "event_processing_queue":
            _set_number(EVENT_QUEUE_PENDING_EVENTS, details.get("pending_events"))
        elif component == "active_event_sources":
            _set_number(ACTIVE_EVENT_SOURCES, details.get("active_sources"))
        elif component == "latest_incident_freshness":
            _set_number(LATEST_INCIDENT_RISK_SCORE, details.get("risk_score"))
            _set_number(
                LATEST_INCIDENT_SECURITY_ALERT_AGE_SECONDS,
                details.get("security_alert_age_seconds"),
            )
        elif component == "ai_soc_worker":
            _collect_worker_metrics(_nested(details, "details"))


async def prometheus_metrics_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    if request.url.path == "/metrics":
        return await call_next(request)

    method = request.method
    path = _normalize_path(request)
    started_at = time.perf_counter()
    status_code = "500"

    try:
        response = await call_next(request)
        status_code = str(response.status_code)
        return response
    finally:
        elapsed = time.perf_counter() - started_at

        HTTP_REQUESTS_TOTAL.labels(
            method=method,
            path=path,
            status_code=status_code,
        ).inc()

        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=method,
            path=path,
        ).observe(elapsed)


@metrics_router.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    _collect_platform_health_metrics()
    _collect_active_user_metrics()
    _collect_gpu_metrics()

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
