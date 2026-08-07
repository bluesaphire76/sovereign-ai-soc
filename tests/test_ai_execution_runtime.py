from __future__ import annotations

import asyncio
import logging
import time

import pytest

from services.ai_execution.contracts import AiExecutionRequest
from services.ai_execution.runtime import GatewayModelRuntime


class _Provider:
    def __init__(
        self,
        inspections: list[dict],
        gateway_results: list[dict],
    ) -> None:
        self.inspections = list(inspections)
        self.gateway_results = list(gateway_results)
        self.inspected = []
        self.gateway_prewarmed = []
        self.legacy_prewarmed = []

    def inspect_profile_state(self, profile, timeout_seconds):
        self.inspected.append((profile, timeout_seconds))
        if self.inspections:
            return self.inspections.pop(0)
        return {
            "state": "ready",
            "profile": "standard",
            "model": "ai-soc-standard",
            "retryable": False,
        }

    def prewarm_gateway_standard(
        self,
        timeout_seconds,
    ):
        self.gateway_prewarmed.append(timeout_seconds)
        return self.gateway_results.pop(0)

    def prewarm_profile(self, *args, **kwargs):
        self.legacy_prewarmed.append((args, kwargs))
        raise AssertionError("gateway runtime used legacy prewarm")


def _inspection(state: str, *, reason: str | None = None) -> dict:
    return {
        "state": state,
        "profile": "standard",
        "model": "ai-soc-standard",
        "reason": reason or f"target_{state}",
        "retryable": state != "ready",
        "elapsed_ms": 1,
    }


def _prewarm_result(
    state: str,
    *,
    reason: str,
    load_count: int = 0,
) -> dict:
    return {
        "state": state,
        "profile": "standard",
        "model": "ai-soc-standard",
        "reason": reason,
        "retryable": state != "ready",
        "elapsed_ms": 2,
        "diagnostics": {
            "model_load_state": "loaded" if state == "ready" else "unknown",
            "profile_load_count": load_count,
            "profile_unload_count": 0,
        },
    }


def _request() -> AiExecutionRequest:
    return AiExecutionRequest(
        task="soc_assistant",
        priority="interactive",
        request_id="assistant-runtime",
        deadline_ms=30000,
        system_instructions="Return JSON only.",
        input="Explain.",
        output_schema="assistant_grounded_v1",
        max_output_tokens=384,
        temperature=0,
    )


def test_runtime_rejects_non_gateway_or_nonstandard_configuration(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AI_EXECUTION_MODE", "direct")
    with pytest.raises(ValueError, match="AI_EXECUTION_MODE"):
        GatewayModelRuntime()

    monkeypatch.setenv("AI_EXECUTION_MODE", "gateway")
    monkeypatch.setenv("AI_INFERENCE_PROFILE", "quality")
    with pytest.raises(ValueError, match="AI_INFERENCE_PROFILE"):
        GatewayModelRuntime()


def test_startup_uses_only_gateway_standard_prewarm(
    monkeypatch,
    caplog,
) -> None:
    monkeypatch.setenv("AI_EXECUTION_MODE", "gateway")
    monkeypatch.setenv("AI_INFERENCE_PROFILE", "standard")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    provider = _Provider(
        [_inspection("unloaded")],
        [_prewarm_result("ready", reason="target_ready", load_count=1)],
    )
    runtime = GatewayModelRuntime(
        startup_timeout_seconds=10,
        monitor_interval_seconds=60,
    )
    monkeypatch.setattr(runtime, "_provider", lambda: provider)
    caplog.set_level(
        logging.INFO,
        logger="services.ai_execution.runtime",
    )

    async def exercise() -> None:
        await runtime.start()
        assert runtime.ready is True
        await runtime.stop()

    asyncio.run(exercise())
    assert provider.inspected == [("standard", 2)]
    assert provider.gateway_prewarmed == [10]
    assert provider.legacy_prewarmed == []
    readiness_log = "\n".join(record.getMessage() for record in caplog.records)
    assert "result_state=ready" in readiness_log
    assert "model_load_state=loaded" in readiness_log
    assert "profile_load_count=1" in readiness_log


def test_monitor_recovers_same_runtime_after_router_unavailable(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AI_EXECUTION_MODE", "gateway")
    monkeypatch.setenv("AI_INFERENCE_PROFILE", "standard")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    provider = _Provider(
        [
            _inspection("unknown", reason="router_unavailable"),
            _inspection("unloaded"),
        ],
        [
            _prewarm_result("failed", reason="router_unavailable"),
            _prewarm_result("ready", reason="target_ready", load_count=1),
        ],
    )
    runtime = GatewayModelRuntime(
        startup_timeout_seconds=10,
        monitor_interval_seconds=0.1,
    )
    runtime_identity = id(runtime)
    monkeypatch.setattr(runtime, "_provider", lambda: provider)

    async def exercise() -> None:
        await runtime.start()
        assert runtime.ready is False
        assert runtime.status().last_safe_error == "router_unavailable"
        deadline = time.monotonic() + 1
        while not runtime.ready and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        assert runtime.ready is True
        assert id(runtime) == runtime_identity
        await runtime.stop()

    asyncio.run(exercise())
    assert provider.inspected == [("standard", 2), ("standard", 2)]
    assert provider.gateway_prewarmed == [10, 10]
    assert provider.legacy_prewarmed == []


def test_readiness_logging_is_safe_and_deduplicates_repeated_warning(
    monkeypatch,
    caplog,
) -> None:
    monkeypatch.setenv("AI_EXECUTION_MODE", "gateway")
    monkeypatch.setenv("AI_INFERENCE_PROFILE", "standard")
    monkeypatch.setenv("LLAMA_CPP_AUTO_PROFILE_SWITCH", "false")
    provider = _Provider(
        [
            _inspection("unknown", reason="router_unavailable"),
            _inspection("unknown", reason="router_unavailable"),
        ],
        [
            _prewarm_result("failed", reason="router_unavailable"),
            _prewarm_result("failed", reason="router_unavailable"),
        ],
    )
    runtime = GatewayModelRuntime(
        startup_timeout_seconds=10,
        monitor_interval_seconds=60,
    )
    monkeypatch.setattr(runtime, "_provider", lambda: provider)
    caplog.set_level(
        logging.INFO,
        logger="services.ai_execution.runtime",
    )

    async def exercise() -> None:
        await runtime.start()
        await runtime.ensure_ready()
        await runtime.stop()

    asyncio.run(exercise())
    readiness_records = [
        record
        for record in caplog.records
        if "gateway_readiness_transition" in record.getMessage()
    ]
    warning_records = [
        record for record in readiness_records if record.levelno == logging.WARNING
    ]
    messages = "\n".join(record.getMessage() for record in readiness_records)
    assert len(warning_records) == 1
    assert "profile=standard" in messages
    assert "model=ai-soc-standard" in messages
    assert "safe_reason=router_unavailable" in messages
    assert "attempt=1" in messages
    assert "prompt" not in messages.lower()
    assert "output" not in messages.lower()


def test_generation_forces_local_llama_standard_zero_temperature(
    monkeypatch,
) -> None:
    monkeypatch.setenv("AI_EXECUTION_MODE", "gateway")
    monkeypatch.setenv("AI_INFERENCE_PROFILE", "standard")
    calls = []

    def generate(**kwargs):
        calls.append(kwargs)
        return {
            "text": (
                '{"direct_answer":"Grounded","analysis":"Recorded facts",'
                '"next_check":null,"limitations":null,'
                '"used_advisory_context":false}'
            ),
            "finish_reason": "stop",
            "provider_diagnostics": {
                "profile_switch_count": 0,
                "profile_load_count": 0,
                "profile_unload_count": 0,
            },
        }

    monkeypatch.setattr(
        "services.ai_execution.runtime.generate_with_provider",
        generate,
    )
    runtime = GatewayModelRuntime()
    runtime._set_state("ready", "ready")

    response = asyncio.run(
        runtime.generate(_request(), time.monotonic() + 5)
    )

    assert response.status == "success"
    assert response.profile == "standard"
    assert response.model == "ai-soc-standard"
    assert response.profile_switch_count == 0
    assert calls[0]["requested_mode"] == "standard"
    assert calls[0]["allow_provider_fallback"] is False
    assert calls[0]["force_local_llama_cpp"] is True
    assert calls[0]["temperature"] == 0
    assert calls[0]["context"]["disable_reasoning"] is True
