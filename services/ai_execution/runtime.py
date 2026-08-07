from __future__ import annotations

import asyncio
import logging
import os
import time
from threading import Lock
from typing import Any

from ai_provider_abstraction import build_provider_client
from ai_provider_registry import (
    PROVIDER_LOCAL_LLAMA_CPP,
    load_provider_registry,
)
from llm_client import generate_ai_response as generate_with_provider
from services.ai_execution.contracts import (
    AiExecutionRequest,
    AiExecutionResponse,
    GatewayStatus,
)
from services.ai_execution.validation import normalize_gateway_output


logger = logging.getLogger(__name__)


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return min(max(value, minimum), maximum)


class GatewayModelRuntime:
    def __init__(
        self,
        *,
        startup_timeout_seconds: float | None = None,
        monitor_interval_seconds: float = 5.0,
    ) -> None:
        execution_mode = os.getenv(
            "AI_EXECUTION_MODE",
            "gateway",
        ).strip().lower()
        if execution_mode != "gateway":
            raise ValueError("AI_EXECUTION_MODE must be gateway")
        configured_profile = os.getenv(
            "AI_INFERENCE_PROFILE",
            "standard",
        ).strip().lower()
        if configured_profile != "standard":
            raise ValueError("AI_INFERENCE_PROFILE must be standard")
        self.profile = "standard"
        self.model = "ai-soc-standard"
        self.startup_timeout_seconds = (
            startup_timeout_seconds
            if startup_timeout_seconds is not None
            else _env_float(
                "AI_INFERENCE_STARTUP_TIMEOUT_SECONDS",
                180,
                minimum=5,
                maximum=600,
            )
        )
        self.monitor_interval_seconds = max(
            0.1,
            monitor_interval_seconds,
        )
        self._state = "stopped"
        self._message = "Inference gateway is stopped."
        self._last_safe_error: str | None = None
        self._monitor: asyncio.Task[None] | None = None
        self._lock = Lock()
        self._reconciliation_cycle = 0
        self._last_logged_failure_reason: str | None = None

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._state == "ready"

    def status(
        self,
        *,
        queue_depth: int = 0,
        active_requests: int = 0,
        max_queue: int = 0,
    ) -> GatewayStatus:
        with self._lock:
            return GatewayStatus(
                state=self._state,
                queue_depth=queue_depth,
                active_requests=active_requests,
                max_queue=max_queue,
                message=self._message,
                last_safe_error=self._last_safe_error,
            )

    def _set_state(
        self,
        state: str,
        message: str,
        safe_error: str | None = None,
        *,
        reconciliation_cycle: int | None = None,
        inspection_state: str | None = None,
        retryable: bool | None = None,
        elapsed_ms: int | None = None,
        model_load_state: str | None = None,
        profile_load_count: int = 0,
        profile_unload_count: int = 0,
    ) -> None:
        with self._lock:
            previous_state = self._state
            self._state = state
            self._message = message
            self._last_safe_error = safe_error
            state_changed = previous_state != state
            if state == "failed":
                should_log = safe_error != self._last_logged_failure_reason
                if should_log:
                    self._last_logged_failure_reason = safe_error
            elif state == "ready":
                should_log = state_changed
                if state_changed:
                    self._last_logged_failure_reason = None
            elif state == "warming" and previous_state == "failed":
                should_log = False
            else:
                should_log = state_changed
                if state == "stopped":
                    self._last_logged_failure_reason = None

        if should_log:
            logger.log(
                logging.WARNING if state == "failed" else logging.INFO,
                "gateway_readiness_transition profile=%s model=%s "
                "previous_state=%s result_state=%s inspection_state=%s "
                "safe_reason=%s retryable=%s attempt=%s elapsed_ms=%s "
                "model_load_state=%s profile_load_count=%s "
                "profile_unload_count=%s",
                self.profile,
                self.model,
                previous_state,
                state,
                inspection_state or "not_available",
                safe_error or "none",
                retryable,
                reconciliation_cycle,
                elapsed_ms,
                model_load_state or "not_available",
                profile_load_count,
                profile_unload_count,
            )

    def _next_reconciliation_cycle(self) -> int:
        with self._lock:
            self._reconciliation_cycle += 1
            return self._reconciliation_cycle

    def _provider(self):
        registry = load_provider_registry()
        config = registry.providers.get("local_llama_cpp")
        if (
            config is None
            or not config.enabled
            or config.provider_type != PROVIDER_LOCAL_LLAMA_CPP
        ):
            raise RuntimeError("GatewayProviderUnavailable")
        return build_provider_client(config)

    def _ensure_ready_sync(self, reconciliation_cycle: int) -> None:
        started = time.monotonic()
        client = self._provider()
        inspection = client.inspect_profile_state(
            "standard",
            timeout_seconds=2,
        )
        if (
            inspection.get("state") == "ready"
            and inspection.get("profile") == "standard"
            and inspection.get("model") == self.model
        ):
            self._set_state(
                "ready",
                "Standard inference model is ready.",
                reconciliation_cycle=reconciliation_cycle,
                inspection_state="ready",
                retryable=False,
                elapsed_ms=int((time.monotonic() - started) * 1000),
                model_load_state="already_loaded",
            )
            return
        inspection_state = str(inspection.get("state") or "unknown")
        self._set_state(
            "warming",
            "Standard inference model is warming.",
            reconciliation_cycle=reconciliation_cycle,
            inspection_state=inspection_state,
            retryable=bool(inspection.get("retryable", True)),
            elapsed_ms=int(inspection.get("elapsed_ms") or 0),
        )
        result = client.prewarm_gateway_standard(
            timeout_seconds=self.startup_timeout_seconds,
        )
        diagnostics = (
            result.get("diagnostics")
            if isinstance(result.get("diagnostics"), dict)
            else {}
        )
        log_fields = {
            "reconciliation_cycle": reconciliation_cycle,
            "inspection_state": inspection_state,
            "retryable": bool(result.get("retryable", True)),
            "elapsed_ms": int(
                result.get("elapsed_ms")
                or (time.monotonic() - started) * 1000
            ),
            "model_load_state": str(
                diagnostics.get("model_load_state") or "unknown"
            ),
            "profile_load_count": int(
                diagnostics.get("profile_load_count") or 0
            ),
            "profile_unload_count": int(
                diagnostics.get("profile_unload_count") or 0
            ),
        }
        if (
            result.get("state") == "ready"
            and result.get("profile") == "standard"
            and result.get("model") == self.model
        ):
            self._set_state(
                "ready",
                "Standard inference model is ready.",
                **log_fields,
            )
            return
        if result.get("state") == "ready":
            reason = "gateway_standard_contract_violation"
        else:
            reason = str(result.get("reason") or "model_not_ready")
        self._set_state(
            "failed",
            "Standard inference model is not ready.",
            reason,
            **log_fields,
        )

    async def ensure_ready(self, *, startup: bool = False) -> None:
        reconciliation_cycle = self._next_reconciliation_cycle()
        started = time.monotonic()
        if startup:
            self._set_state(
                "warming",
                "Standard inference model is warming.",
                reconciliation_cycle=reconciliation_cycle,
                inspection_state="startup",
                retryable=True,
                elapsed_ms=0,
            )
        try:
            await asyncio.to_thread(
                self._ensure_ready_sync,
                reconciliation_cycle,
            )
        except Exception as exc:
            self._set_state(
                "failed",
                "Standard inference model is not ready.",
                exc.__class__.__name__,
                reconciliation_cycle=reconciliation_cycle,
                inspection_state="unknown",
                retryable=True,
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )

    async def start(self) -> None:
        await self.ensure_ready(startup=True)
        if self._monitor is None or self._monitor.done():
            self._monitor = asyncio.create_task(
                self._monitor_readiness(),
                name="ai-inference-readiness-monitor",
            )

    async def stop(self) -> None:
        monitor = self._monitor
        if monitor is not None:
            monitor.cancel()
            try:
                await monitor
            except asyncio.CancelledError:
                pass
        self._monitor = None
        self._set_state("stopped", "Inference gateway is stopped.")

    async def _monitor_readiness(self) -> None:
        while True:
            await asyncio.sleep(self.monitor_interval_seconds)
            await self.ensure_ready()

    async def generate(
        self,
        request: AiExecutionRequest,
        deadline_monotonic: float,
    ) -> AiExecutionResponse:
        if not self.ready:
            return AiExecutionResponse(
                status="unavailable",
                task=request.task,
                safe_error="gateway_not_ready",
            )
        started = time.monotonic()
        remaining = max(0.1, deadline_monotonic - started)

        def invoke() -> dict[str, Any]:
            return generate_with_provider(
                messages=[
                    {
                        "role": "system",
                        "content": request.system_instructions,
                    },
                    {"role": "user", "content": request.input},
                ],
                task=request.task,
                requested_mode="standard",
                user_triggered=request.priority.value != "background",
                timeout_seconds=remaining,
                deadline_monotonic=deadline_monotonic,
                fallback_timeout_seconds=0,
                max_visible_tokens=request.max_output_tokens,
                context={
                    "caller_kind": "other_ai_task",
                    "request_id_hash": request.request_id[-16:].lower(),
                    "disable_reasoning": True,
                },
                allow_provider_fallback=False,
                force_local_llama_cpp=True,
                temperature=request.temperature,
            )

        result = await asyncio.to_thread(invoke)
        text = str(result.get("text") or "")
        output, validation_error = normalize_gateway_output(
            text,
            output_schema=request.output_schema,
        )
        diagnostics = (
            result.get("provider_diagnostics")
            if isinstance(result.get("provider_diagnostics"), dict)
            else {}
        )
        if validation_error:
            status = "invalid_response"
            safe_error = validation_error
        elif result.get("safe_error") or result.get("error_type"):
            status = (
                "deadline_exceeded"
                if result.get("timeout_reason")
                else "failed"
            )
            safe_error = (
                "generation_timeout"
                if status == "deadline_exceeded"
                else "generation_failed"
            )
        else:
            status = "success"
            safe_error = None
        return AiExecutionResponse(
            status=status,
            task=request.task,
            model=self.model,
            output=output,
            finish_reason=result.get("finish_reason"),
            generation_ms=int((time.monotonic() - started) * 1000),
            degraded=False,
            safe_error=safe_error,
            profile_switch_count=int(
                diagnostics.get("profile_switch_count") or 0
            ),
            profile_load_count=int(diagnostics.get("profile_load_count") or 0),
            profile_unload_count=int(
                diagnostics.get("profile_unload_count") or 0
            ),
        )
