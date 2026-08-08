from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram


QUEUE_DEPTH = Gauge(
    "ai_execution_queue_depth",
    "Number of queued AI execution requests.",
)
QUEUE_WAIT = Histogram(
    "ai_execution_queue_wait_seconds",
    "Time spent waiting in the AI execution queue.",
    labelnames=("task",),
)
REQUEST_DURATION = Histogram(
    "ai_execution_request_duration_seconds",
    "End-to-end AI execution duration.",
    labelnames=("task",),
)
ACTIVE_REQUESTS = Gauge(
    "ai_execution_active_requests",
    "Number of active model generations.",
)
REQUESTS_TOTAL = Counter(
    "ai_execution_requests_total",
    "AI execution requests by task and safe status.",
    labelnames=("task", "status"),
)
DEADLINE_EXCEEDED = Counter(
    "ai_execution_deadline_exceeded_total",
    "AI execution requests that exceeded a deadline.",
    labelnames=("task",),
)
GROUNDING_REJECTIONS = Counter(
    "ai_execution_grounding_rejections_total",
    "Assistant grounding rejections by safe reason.",
    labelnames=("reason",),
)
FALLBACK_TOTAL = Counter(
    "ai_execution_fallback_total",
    "Assistant deterministic fallbacks by safe reason.",
    labelnames=("reason",),
)
PROFILE_SWITCH_TOTAL = Counter(
    "ai_execution_profile_switch_total",
    "llama.cpp profile actions initiated by the gateway.",
)
ASSISTANT_SEMANTIC_DURATION = Histogram(
    "assistant_semantic_duration_seconds",
    "Assistant semantic retrieval duration.",
)
ASSISTANT_SEMANTIC_DEGRADED = Counter(
    "assistant_semantic_degraded_total",
    "Assistant semantic retrieval degradation by safe reason.",
    labelnames=("reason",),
)
ASSISTANT_V3_CONTEXT_DURATION = Histogram(
    "assistant_v3_context_build_seconds",
    "Non-generative Assistant V3 analytical context build duration.",
    labelnames=("intent", "scope"),
)
ASSISTANT_V3_CONTEXT_PACKAGES = Counter(
    "assistant_v3_context_packages_total",
    "Assistant V3 analytical context packages built by intent and scope.",
    labelnames=("intent", "scope"),
)
