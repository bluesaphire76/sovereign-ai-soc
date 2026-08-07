from __future__ import annotations

import asyncio

from services.ai_execution.contracts import GatewayStatus
from services.ai_execution.errors import GatewayUnavailable
from services.assistant.runtime import (
    assistant_lifespan,
    assistant_runtime_snapshot,
)


class _ReadyClient:
    def status(self) -> GatewayStatus:
        return GatewayStatus(
            state="ready",
            queue_depth=0,
            active_requests=0,
            max_queue=50,
            message="Standard inference model is ready.",
        )


class _UnavailableClient:
    def status(self) -> GatewayStatus:
        raise GatewayUnavailable()


def test_runtime_snapshot_only_reads_gateway_status() -> None:
    ready = assistant_runtime_snapshot(client=_ReadyClient())
    assert ready == {
        "runtime_state": "ready",
        "default_profile": "standard",
        "loaded_profile": "standard",
        "runtime_message": "Standard inference model is ready.",
    }

    failed = assistant_runtime_snapshot(client=_UnavailableClient())
    assert failed["runtime_state"] == "failed"
    assert failed["loaded_profile"] is None
    assert "gateway" in failed["runtime_message"].lower()


def test_api_lifespan_only_owns_local_embedding_prewarm(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(
        "services.assistant.runtime.start_embedding_prewarm",
        lambda: calls.append("start"),
    )
    monkeypatch.setattr(
        "services.assistant.runtime.stop_embedding_prewarm",
        lambda: calls.append("stop"),
    )

    async def exercise() -> None:
        async with assistant_lifespan(object()):
            calls.append("running")

    asyncio.run(exercise())
    assert calls == ["start", "running", "stop"]
