from __future__ import annotations

import asyncio
import time

import pytest
from prometheus_client import generate_latest
from pydantic import ValidationError

from services.ai_execution.contracts import (
    AiExecutionRequest,
    AiExecutionResponse,
)
from services.ai_execution.coordinator import (
    AiExecutionCoordinator,
    _QueueItem,
)
from services.ai_execution.errors import (
    GatewayDeadlineExceeded,
    GatewayQueueFull,
)
from services.ai_execution.metrics import PROFILE_SWITCH_TOTAL
from services.ai_execution.validation import normalize_gateway_output


def _request(
    task: str,
    priority: str,
    *,
    deadline_ms: int = 5000,
) -> AiExecutionRequest:
    return AiExecutionRequest(
        task=task,
        priority=priority,
        request_id=f"request-{task}",
        deadline_ms=deadline_ms,
        system_instructions="Return only the final answer.",
        input=f"Run {task}.",
        max_output_tokens=64,
        temperature=0,
    )


def _success(request: AiExecutionRequest) -> AiExecutionResponse:
    return AiExecutionResponse(
        status="success",
        task=request.task,
        output=request.task,
        generation_ms=1,
    )


def test_contract_forbids_provider_profile_model_and_nonzero_temperature() -> None:
    base = _request("soc_assistant", "interactive").model_dump()
    for key, value in (
        ("provider", "local_ollama"),
        ("profile", "quality"),
        ("model_path", "/tmp/model.gguf"),
        ("router_url", "http://127.0.0.1:8081"),
    ):
        with pytest.raises(ValidationError):
            AiExecutionRequest.model_validate(base | {key: value})
    with pytest.raises(ValidationError):
        AiExecutionRequest.model_validate(base | {"temperature": 0.1})


def test_priority_fifo_and_single_active_generation() -> None:
    async def exercise() -> tuple[list[str], int]:
        order = []
        active = 0
        max_active = 0
        first_started = asyncio.Event()
        release_first = asyncio.Event()

        async def executor(request, deadline):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            order.append(request.task)
            if request.task == "active":
                first_started.set()
                await release_first.wait()
            await asyncio.sleep(0)
            active -= 1
            return _success(request)

        coordinator = AiExecutionCoordinator(executor, max_queue=10)
        await coordinator.start()
        active_task = asyncio.create_task(
            coordinator.execute(_request("active", "background"))
        )
        await first_started.wait()
        queued = [
            asyncio.create_task(
                coordinator.execute(_request("background", "background"))
            ),
            asyncio.create_task(
                coordinator.execute(_request("playbook_a", "playbook"))
            ),
            asyncio.create_task(
                coordinator.execute(_request("assistant", "interactive"))
            ),
            asyncio.create_task(
                coordinator.execute(_request("analysis", "user_analysis"))
            ),
            asyncio.create_task(
                coordinator.execute(_request("playbook_b", "playbook"))
            ),
        ]
        await asyncio.sleep(0)
        release_first.set()
        await asyncio.gather(active_task, *queued)
        await coordinator.shutdown()
        return order, max_active

    order, max_active = asyncio.run(exercise())
    assert order == [
        "active",
        "assistant",
        "analysis",
        "playbook_a",
        "playbook_b",
        "background",
    ]
    assert max_active == 1


def test_queue_limit_and_queued_deadline_cleanup() -> None:
    async def exercise() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        async def executor(request, deadline):
            if request.task == "active":
                started.set()
                await release.wait()
            return _success(request)

        coordinator = AiExecutionCoordinator(executor, max_queue=1)
        active = asyncio.create_task(
            coordinator.execute(_request("active", "background"))
        )
        await started.wait()
        expiring = asyncio.create_task(
            coordinator.execute(
                _request("expiring", "background", deadline_ms=100)
            )
        )
        await asyncio.sleep(0)
        with pytest.raises(GatewayQueueFull):
            await coordinator.execute(_request("overflow", "interactive"))
        await asyncio.sleep(0.12)
        release.set()
        await active
        with pytest.raises(GatewayDeadlineExceeded):
            await expiring
        await coordinator.shutdown()
        assert coordinator.queue_depth == 0
        assert coordinator.active_requests == 0

    asyncio.run(exercise())


def test_running_deadline_does_not_start_next_job_early() -> None:
    async def exercise() -> list[tuple[str, float]]:
        events = []

        async def executor(request, deadline):
            events.append((f"start:{request.task}", time.monotonic()))
            if request.task == "slow":
                await asyncio.sleep(0.16)
            events.append((f"end:{request.task}", time.monotonic()))
            return _success(request)

        coordinator = AiExecutionCoordinator(executor, max_queue=4)
        slow = asyncio.create_task(
            coordinator.execute(
                _request("slow", "interactive", deadline_ms=100)
            )
        )
        await asyncio.sleep(0.01)
        next_job = asyncio.create_task(
            coordinator.execute(_request("next", "interactive"))
        )
        with pytest.raises(GatewayDeadlineExceeded):
            await slow
        await next_job
        await coordinator.shutdown()
        return events

    events = asyncio.run(exercise())
    names = [name for name, _ in events]
    assert names == ["start:slow", "end:slow", "start:next", "end:next"]


def test_cancelled_queued_job_is_removed_without_lost_future() -> None:
    async def exercise() -> None:
        started = asyncio.Event()
        release = asyncio.Event()
        executed = []

        async def executor(request, deadline):
            executed.append(request.task)
            if request.task == "active":
                started.set()
                await release.wait()
            return _success(request)

        coordinator = AiExecutionCoordinator(executor, max_queue=4)
        active = asyncio.create_task(
            coordinator.execute(_request("active", "background"))
        )
        await started.wait()
        cancelled = asyncio.create_task(
            coordinator.execute(_request("cancelled", "interactive"))
        )
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        release.set()
        await active
        await asyncio.sleep(0)
        await coordinator.shutdown()
        assert executed == ["active"]
        assert coordinator.queue_depth == 0

    asyncio.run(exercise())


def test_priority_aging_is_bounded() -> None:
    coordinator = AiExecutionCoordinator(
        lambda request, deadline: _success(request),
        aging_interval_seconds=1,
        max_aging_points=25,
        clock=lambda: 0,
    )
    request = _request("background", "background")

    async def item_priority() -> tuple[int, int]:
        item = _QueueItem(
            sort_key=(-10, 0),
            sequence=0,
            request=request,
            enqueued_at=0,
            deadline_at=5000,
            future=asyncio.get_running_loop().create_future(),
        )
        initial = coordinator._effective_priority(item, 0)
        aged = coordinator._effective_priority(item, 1000)
        return initial, aged

    assert asyncio.run(item_priority()) == (10, 35)


def test_hidden_reasoning_is_never_returned() -> None:
    visible, error = normalize_gateway_output(
        "<think>private reasoning</think>\nFinal answer.",
        output_schema="text_v1",
    )
    assert visible is None
    assert error == "invalid_visible_output"

    hidden_only, error = normalize_gateway_output(
        "<think>private reasoning</think>",
        output_schema="text_v1",
    )
    assert hidden_only is None
    assert error == "invalid_visible_output"


def test_required_metrics_exist_and_profile_switch_invariant_is_zero() -> None:
    metrics = generate_latest().decode("utf-8")
    for name in (
        "ai_execution_queue_depth",
        "ai_execution_queue_wait_seconds",
        "ai_execution_request_duration_seconds",
        "ai_execution_active_requests",
        "ai_execution_requests_total",
        "ai_execution_deadline_exceeded_total",
        "ai_execution_grounding_rejections_total",
        "ai_execution_fallback_total",
        "ai_execution_profile_switch_total",
        "assistant_semantic_duration_seconds",
        "assistant_semantic_degraded_total",
    ):
        assert name in metrics
    assert PROFILE_SWITCH_TOTAL._value.get() == 0
