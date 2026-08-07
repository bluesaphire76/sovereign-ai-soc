from __future__ import annotations

import asyncio
import inspect
import logging
import time
from dataclasses import dataclass, field
from itertools import count
from typing import Any, Awaitable, Callable

from services.ai_execution.contracts import (
    AiExecutionRequest,
    AiExecutionResponse,
)
from services.ai_execution.errors import (
    GatewayDeadlineExceeded,
    GatewayQueueFull,
    GatewayShuttingDown,
)
from services.ai_execution.metrics import (
    ACTIVE_REQUESTS,
    DEADLINE_EXCEEDED,
    PROFILE_SWITCH_TOTAL,
    QUEUE_DEPTH,
    QUEUE_WAIT,
    REQUEST_DURATION,
    REQUESTS_TOTAL,
)
from services.ai_execution.priorities import priority_value


logger = logging.getLogger(__name__)
Executor = Callable[
    [AiExecutionRequest, float],
    AiExecutionResponse | Awaitable[AiExecutionResponse],
]


@dataclass(order=True)
class _QueueItem:
    sort_key: tuple[int, int]
    sequence: int = field(compare=False)
    request: AiExecutionRequest = field(compare=False)
    enqueued_at: float = field(compare=False)
    deadline_at: float = field(compare=False)
    future: asyncio.Future[AiExecutionResponse] = field(compare=False)


class AiExecutionCoordinator:
    def __init__(
        self,
        executor: Executor,
        *,
        max_queue: int = 50,
        aging_interval_seconds: float = 1.0,
        max_aging_points: int = 100,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._executor = executor
        self._queue: asyncio.PriorityQueue[_QueueItem] = asyncio.PriorityQueue(
            maxsize=max(1, max_queue)
        )
        self._max_queue = max(1, max_queue)
        self._aging_interval_seconds = max(0.01, aging_interval_seconds)
        self._max_aging_points = max(0, max_aging_points)
        self._clock = clock
        self._sequence = count()
        self._worker: asyncio.Task[None] | None = None
        self._closing = False
        self._active_requests = 0

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    @property
    def active_requests(self) -> int:
        return self._active_requests

    @property
    def max_queue(self) -> int:
        return self._max_queue

    async def start(self) -> None:
        if self._worker is not None and not self._worker.done():
            return
        self._closing = False
        self._worker = asyncio.create_task(
            self._run(),
            name="ai-execution-coordinator",
        )

    async def shutdown(self) -> None:
        self._closing = True
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if not item.future.done():
                item.future.set_exception(GatewayShuttingDown())
            self._queue.task_done()
        QUEUE_DEPTH.set(0)
        worker = self._worker
        if worker is not None:
            worker.cancel()
            try:
                await worker
            except asyncio.CancelledError:
                pass
        self._worker = None

    async def execute(self, request: AiExecutionRequest) -> AiExecutionResponse:
        if self._closing:
            raise GatewayShuttingDown()
        if self._worker is None or self._worker.done():
            await self.start()

        loop = asyncio.get_running_loop()
        now = self._clock()
        sequence = next(self._sequence)
        future: asyncio.Future[AiExecutionResponse] = loop.create_future()
        item = _QueueItem(
            sort_key=(-priority_value(request.priority), sequence),
            sequence=sequence,
            request=request,
            enqueued_at=now,
            deadline_at=now + (request.deadline_ms / 1000),
            future=future,
        )
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull as exc:
            REQUESTS_TOTAL.labels(request.task, "queue_full").inc()
            raise GatewayQueueFull() from exc
        QUEUE_DEPTH.set(self._queue.qsize())

        try:
            return await future
        except asyncio.CancelledError:
            future.cancel()
            raise

    def _effective_priority(self, item: _QueueItem, now: float) -> int:
        age_points = min(
            int((now - item.enqueued_at) / self._aging_interval_seconds),
            self._max_aging_points,
        )
        return priority_value(item.request.priority) + age_points

    async def _next_item(self) -> _QueueItem:
        first = await self._queue.get()
        items = [first]
        while True:
            try:
                items.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        now = self._clock()
        selected = max(
            items,
            key=lambda item: (
                self._effective_priority(item, now),
                -item.sequence,
            ),
        )
        for item in items:
            if item is selected:
                continue
            self._queue.task_done()
            self._queue.put_nowait(item)
        QUEUE_DEPTH.set(self._queue.qsize())
        return selected

    async def _invoke(
        self,
        request: AiExecutionRequest,
        deadline_at: float,
    ) -> AiExecutionResponse:
        result = self._executor(request, deadline_at)
        if inspect.isawaitable(result):
            return await result
        return result

    async def _run(self) -> None:
        while True:
            item = await self._next_item()
            try:
                await self._execute_item(item)
            finally:
                self._queue.task_done()

    async def _execute_item(self, item: _QueueItem) -> None:
        if item.future.cancelled():
            return
        now = self._clock()
        if now >= item.deadline_at:
            DEADLINE_EXCEEDED.labels(item.request.task).inc()
            REQUESTS_TOTAL.labels(
                item.request.task,
                "deadline_exceeded",
            ).inc()
            item.future.set_exception(GatewayDeadlineExceeded())
            return

        queue_wait = max(0.0, now - item.enqueued_at)
        QUEUE_WAIT.labels(item.request.task).observe(queue_wait)
        started = self._clock()
        self._active_requests = 1
        ACTIVE_REQUESTS.set(1)
        execution_task = asyncio.create_task(
            self._invoke(item.request, item.deadline_at)
        )
        try:
            remaining = max(0.001, item.deadline_at - self._clock())
            try:
                response = await asyncio.wait_for(
                    asyncio.shield(execution_task),
                    timeout=remaining,
                )
            except TimeoutError:
                DEADLINE_EXCEEDED.labels(item.request.task).inc()
                REQUESTS_TOTAL.labels(
                    item.request.task,
                    "deadline_exceeded",
                ).inc()
                if not item.future.done():
                    item.future.set_exception(GatewayDeadlineExceeded())
                try:
                    await execution_task
                except Exception:
                    pass
                return
            except asyncio.CancelledError:
                try:
                    await execution_task
                except Exception:
                    pass
                raise

            response.queue_wait_ms = int(queue_wait * 1000)
            response.total_ms = int((self._clock() - item.enqueued_at) * 1000)
            switch_count = max(0, int(response.profile_switch_count))
            if switch_count:
                PROFILE_SWITCH_TOTAL.inc(switch_count)
            REQUESTS_TOTAL.labels(item.request.task, response.status).inc()
            if not item.future.done():
                item.future.set_result(response)
            logger.info(
                "ai_execution task=%s priority=%s queue_wait_ms=%s "
                "generation_ms=%s status=%s safe_error=%s profile=standard "
                "model=ai-soc-standard",
                item.request.task,
                item.request.priority.value,
                response.queue_wait_ms,
                response.generation_ms,
                response.status,
                response.safe_error,
            )
        except Exception:
            REQUESTS_TOTAL.labels(item.request.task, "failed").inc()
            if not item.future.done():
                item.future.set_result(
                    AiExecutionResponse(
                        status="failed",
                        task=item.request.task,
                        safe_error="generation_failed",
                        total_ms=int(
                            (self._clock() - item.enqueued_at) * 1000
                        ),
                    )
                )
        finally:
            REQUEST_DURATION.labels(item.request.task).observe(
                max(0.0, self._clock() - started)
            )
            self._active_requests = 0
            ACTIVE_REQUESTS.set(0)
