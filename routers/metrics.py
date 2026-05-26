from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import APIRouter, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from platform_health import get_platform_health


metrics_router = APIRouter(tags=["metrics"])


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


def _details(item: dict[str, Any]) -> dict[str, Any]:
    details = item.get("details")
    return details if isinstance(details, dict) else {}


def _component_name(item: dict[str, Any]) -> str:
    value = item.get("component") or item.get("name") or item.get("id") or "unknown"
    return str(value)


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

            if component == "worker_heartbeat":
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

    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
