from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from starlette.responses import Response

from services.ai_execution.contracts import (
    AiExecutionRequest,
    AiExecutionResponse,
)
from services.ai_execution.coordinator import AiExecutionCoordinator
from services.ai_execution.errors import (
    GatewayDeadlineExceeded,
    GatewayQueueFull,
    GatewayShuttingDown,
)
from services.ai_execution.metrics import (
    ACTIVE_REQUESTS,
    GATEWAY_INFO,
    GATEWAY_READY,
    QUEUE_CAPACITY,
    QUEUE_DEPTH,
)
from services.ai_execution.runtime import GatewayModelRuntime


def _max_queue() -> int:
    try:
        value = int(os.getenv("AI_INFERENCE_MAX_QUEUE", "50"))
    except (TypeError, ValueError):
        value = 50
    return min(max(value, 1), 500)


def create_gateway_app(
    *,
    runtime: GatewayModelRuntime | None = None,
    coordinator: AiExecutionCoordinator | None = None,
) -> FastAPI:
    selected_runtime = runtime or GatewayModelRuntime()
    selected_coordinator = coordinator or AiExecutionCoordinator(
        selected_runtime.generate,
        max_queue=_max_queue(),
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await selected_runtime.start()
        await selected_coordinator.start()
        try:
            yield
        finally:
            await selected_coordinator.shutdown()
            await selected_runtime.stop()

    application = FastAPI(
        title="Sovereign AI SOC Inference Gateway",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    application.state.runtime = selected_runtime
    application.state.coordinator = selected_coordinator

    def status_payload():
        return selected_runtime.status(
            queue_depth=selected_coordinator.queue_depth,
            active_requests=selected_coordinator.active_requests,
            max_queue=selected_coordinator.max_queue,
        )

    @application.get("/health")
    async def health():
        status = status_payload()
        return {
            "status": "ok" if status.state == "ready" else "degraded",
            "component": "ai_inference_gateway",
            "state": status.state,
            "profile": status.profile,
            "model": status.model,
        }

    @application.get("/status")
    async def status():
        return status_payload()

    @application.post(
        "/v1/generate",
        response_model=AiExecutionResponse,
    )
    async def generate(
        payload: AiExecutionRequest,
        request: Request,
    ):
        if not selected_runtime.ready:
            raise HTTPException(
                status_code=503,
                detail="Inference gateway is not ready.",
            )
        execution: asyncio.Task[AiExecutionResponse] | None = None
        try:
            execution = asyncio.create_task(
                selected_coordinator.execute(payload)
            )
            while not execution.done():
                if await request.is_disconnected():
                    execution.cancel()
                    raise HTTPException(
                        status_code=499,
                        detail="Inference request was cancelled.",
                    )
                await asyncio.sleep(0.1)
            return await execution
        except GatewayQueueFull as exc:
            raise HTTPException(
                status_code=429,
                detail="Inference queue is full.",
            ) from exc
        except GatewayDeadlineExceeded as exc:
            raise HTTPException(
                status_code=504,
                detail="Inference request deadline exceeded.",
            ) from exc
        except GatewayShuttingDown as exc:
            raise HTTPException(
                status_code=503,
                detail="Inference gateway is shutting down.",
            ) from exc
        finally:
            if execution is not None and not execution.done():
                execution.cancel()

    @application.get("/metrics")
    async def metrics():
        gateway_status = status_payload()
        GATEWAY_READY.set(1 if gateway_status.state == "ready" else 0)
        GATEWAY_INFO.clear()
        GATEWAY_INFO.labels(
            state=gateway_status.state,
            profile=gateway_status.profile,
            model=gateway_status.model,
        ).set(1)
        QUEUE_DEPTH.set(gateway_status.queue_depth)
        QUEUE_CAPACITY.set(gateway_status.max_queue)
        ACTIVE_REQUESTS.set(gateway_status.active_requests)
        return Response(
            content=generate_latest(),
            media_type=CONTENT_TYPE_LATEST,
        )

    return application


app = create_gateway_app()
