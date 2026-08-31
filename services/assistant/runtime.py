from __future__ import annotations

from contextlib import asynccontextmanager
import os
from typing import Any

from qdrant_knowledge import start_embedding_prewarm, stop_embedding_prewarm
from services.assistant.analytics.interpreter import start_semantic_nlu_prewarm
from services.ai_execution.client import AiExecutionClient
from services.ai_execution.errors import AiExecutionError
from services.assistant.v3.semantic_proof.runtime import (
    prewarm_semantic_proof_runtime,
)


def semantic_proof_prewarm_enabled() -> bool:
    assistant_enabled = os.getenv("AI_SOC_ASSISTANT_ENABLED", "false").strip().lower()
    architecture = os.getenv(
        "AI_ASSISTANT_RESPONSE_ARCHITECTURE",
        "v3_2",
    ).strip().lower()
    prewarm_enabled = os.getenv(
        "AI_SOC_ASSISTANT_V32_NLI_PREWARM",
        "true",
    ).strip().lower()
    return (
        assistant_enabled in {"1", "true", "yes", "on"}
        and architecture == "v3_2"
        and prewarm_enabled in {"1", "true", "yes", "on"}
    )


def assistant_runtime_snapshot(
    *,
    client: AiExecutionClient | None = None,
) -> dict[str, Any]:
    selected = client or AiExecutionClient()
    try:
        status = selected.status()
    except AiExecutionError:
        return {
            "runtime_state": "failed",
            "default_profile": "standard",
            "loaded_profile": None,
            "runtime_message": "The inference gateway is unavailable.",
        }
    return {
        "runtime_state": status.state,
        "default_profile": "standard",
        "loaded_profile": "standard" if status.state == "ready" else None,
        "runtime_message": status.message,
    }


@asynccontextmanager
async def assistant_lifespan(app):
    del app
    if semantic_proof_prewarm_enabled():
        prewarm_semantic_proof_runtime()
    start_embedding_prewarm()
    start_semantic_nlu_prewarm()
    try:
        yield
    finally:
        stop_embedding_prewarm()
