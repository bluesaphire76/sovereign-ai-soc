from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from qdrant_knowledge import start_embedding_prewarm, stop_embedding_prewarm
from services.ai_execution.client import AiExecutionClient
from services.ai_execution.errors import AiExecutionError


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
    start_embedding_prewarm()
    try:
        yield
    finally:
        stop_embedding_prewarm()
