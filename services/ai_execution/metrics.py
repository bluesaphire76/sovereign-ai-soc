from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram


QUEUE_DEPTH = Gauge(
    "ai_execution_queue_depth",
    "Number of queued AI execution requests.",
)
QUEUE_CAPACITY = Gauge(
    "ai_execution_queue_capacity",
    "Maximum number of queued AI execution requests.",
)
QUEUE_WAIT = Histogram(
    "ai_execution_queue_wait_seconds",
    "Time spent waiting in the AI execution queue.",
    labelnames=("task",),
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 45, 60),
)
REQUEST_DURATION = Histogram(
    "ai_execution_request_duration_seconds",
    "AI execution duration after queue admission.",
    labelnames=("task",),
    buckets=(0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 20, 30, 45, 60, 90, 120),
)
ACTIVE_REQUESTS = Gauge(
    "ai_execution_active_requests",
    "Number of active model generations.",
)
GATEWAY_READY = Gauge(
    "ai_execution_gateway_ready",
    "Whether the inference gateway runtime is ready to accept generation requests.",
)
GATEWAY_INFO = Gauge(
    "ai_execution_gateway_info",
    "Current bounded inference gateway runtime identity and state.",
    labelnames=("state", "profile", "model"),
)
REQUESTS_TOTAL = Counter(
    "ai_execution_requests_total",
    "AI execution requests by task and safe status.",
    labelnames=("task", "status"),
)
GENERATIONS_TOTAL = Counter(
    "ai_execution_generations_total",
    "Inference runtime invocations by bounded task.",
    labelnames=("task",),
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
GENERATION_DURATION = Histogram(
    "ai_execution_generation_duration_seconds",
    "Provider generation duration reported by the inference runtime.",
    labelnames=("task", "status"),
    buckets=(0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15, 20, 30, 45, 60, 90, 120),
)
TOKENS_TOTAL = Counter(
    "ai_execution_tokens_total",
    "Inference tokens processed by task and bounded direction.",
    labelnames=("task", "direction"),
)
TRUNCATED_TOTAL = Counter(
    "ai_execution_truncated_total",
    "Inference responses terminated by a provider token or length limit.",
    labelnames=("task",),
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
ASSISTANT_V3_PLAN_DURATION = Histogram(
    "assistant_v3_plan_validation_seconds",
    "Assistant V3 plan schema build and semantic validation duration.",
    labelnames=("stage", "status"),
)
ASSISTANT_V3_PLAN_UNITS = Histogram(
    "assistant_v3_plan_units",
    "Validated analytical units in an Assistant V3 answer plan.",
)
ASSISTANT_V3_RENDER_DURATION = Histogram(
    "assistant_v3_render_seconds",
    "Deterministic Assistant V3 discourse rendering duration.",
)
ASSISTANT_V3_RESPONSES = Counter(
    "assistant_v3_responses_total",
    "Assistant V3 responses by generation kind and validation status.",
    labelnames=("generation_kind", "validation_status"),
)
ASSISTANT_V3_SEMANTIC_INDEX_DURATION = Histogram(
    "assistant_v3_semantic_index_query_seconds",
    "Dedicated incident semantic candidate query duration.",
    labelnames=("status",),
)
ASSISTANT_V3_STAGE_DURATION = Histogram(
    "assistant_v3_stage_duration_seconds",
    "Assistant V3 request phase duration by bounded stage and status.",
    labelnames=("stage", "status"),
)
ASSISTANT_V3_CONTEXT_ITEMS = Histogram(
    "assistant_v3_context_items",
    "Assistant V3 bounded context item counts by closed item class.",
    labelnames=("item_class",),
    buckets=(0, 1, 2, 4, 8, 12, 16, 24, 32, 48, 80, 120, 160),
)
ASSISTANT_V32_PROOF_DURATION = Histogram(
    "assistant_v32_semantic_proof_seconds",
    "Assistant V3.2 whole-response semantic proof duration.",
    labelnames=("status",),
)
ASSISTANT_V32_PROOF_PAIRS = Histogram(
    "assistant_v32_semantic_proof_pairs",
    "Assistant V3.2 proposition proof obligations per response.",
    buckets=(1, 2, 3, 4, 6, 8, 10, 12),
)
ASSISTANT_V32_PROOF_DECISIONS = Counter(
    "assistant_v32_semantic_proof_decisions_total",
    "Assistant V3.2 proposition proof decisions by closed proof reason.",
    labelnames=("reason",),
)
