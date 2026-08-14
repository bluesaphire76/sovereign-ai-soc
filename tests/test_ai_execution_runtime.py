from __future__ import annotations

import asyncio
import logging
import time

import pytest

from services.assistant.claims import grounded_claim_output_schema
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


def _request(
    *,
    output_schema: str = "assistant_grounded_v1",
) -> AiExecutionRequest:
    return AiExecutionRequest(
        task="soc_assistant",
        priority="interactive",
        request_id="assistant-runtime",
        deadline_ms=30000,
        system_instructions="Return JSON only.",
        input="Explain.",
        output_schema=output_schema,
        structured_output_schema=(
            {
                "name": output_schema,
                "schema_document": grounded_claim_output_schema(),
            }
            if output_schema
            in {
                "assistant_grounded_v2",
                "assistant_grounded_v3",
                "assistant_grounded_v31",
            }
            else None
        ),
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
    assert calls[0]["response_format"] == {"type": "json_object"}


@pytest.mark.parametrize(
    "output_schema",
    ["assistant_grounded_v2", "assistant_grounded_v3", "assistant_grounded_v31"],
)
def test_grounded_generation_passes_closed_json_schema_once(
    monkeypatch,
    output_schema,
) -> None:
    monkeypatch.setenv("AI_EXECUTION_MODE", "gateway")
    monkeypatch.setenv("AI_INFERENCE_PROFILE", "standard")
    calls = []
    model_output = {
        "claims": [
            {
                "claim_type": "RECORDED_FACT",
                "field": "risk_score",
                "value": 35,
                "provenance": "recorded_operational",
                "source_ids": ["S1"],
            }
        ],
        "next_check": None,
        "limitations": [],
        "used_advisory_context": False,
    }

    def generate(**kwargs):
        calls.append(kwargs)
        import json

        return {
            "text": json.dumps(model_output),
            "finish_reason": "stop",
            "provider_diagnostics": {
                "prompt_tokens": 144,
                "completion_tokens": 31,
            },
        }

    monkeypatch.setattr(
        "services.ai_execution.runtime.generate_with_provider",
        generate,
    )
    runtime = GatewayModelRuntime()
    runtime._set_state("ready", "ready")

    response = asyncio.run(
        runtime.generate(
            _request(output_schema=output_schema),
            time.monotonic() + 5,
        )
    )

    assert response.status == "success"
    assert response.output == model_output
    assert response.prompt_tokens == 144
    assert response.completion_tokens == 31
    assert len(calls) == 1
    response_format = calls[0]["response_format"]
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["name"] == output_schema
    assert response_format["json_schema"]["strict"] is True
    assert response_format["json_schema"]["schema"] == (
        grounded_claim_output_schema()
    )


@pytest.mark.parametrize(
    ("output_schema", "model_text", "expected_output", "expected_format"),
    [
        ("text_v1", "Visible answer.", "Visible answer.", None),
        ("json_v1", '{"ok":true}', {"ok": True}, {"type": "json_object"}),
        (
            "assistant_grounded_v1",
            '{"direct_answer":"ok"}',
            {"direct_answer": "ok"},
            {"type": "json_object"},
        ),
    ],
)
def test_legacy_output_schemas_remain_compatible(
    monkeypatch,
    output_schema,
    model_text,
    expected_output,
    expected_format,
) -> None:
    calls = []

    def generate(**kwargs):
        calls.append(kwargs)
        return {
            "text": model_text,
            "finish_reason": "stop",
            "provider_diagnostics": {},
        }

    monkeypatch.setattr(
        "services.ai_execution.runtime.generate_with_provider",
        generate,
    )
    runtime = GatewayModelRuntime()
    runtime._set_state("ready", "ready")

    response = asyncio.run(
        runtime.generate(
            _request(output_schema=output_schema),
            time.monotonic() + 5,
        )
    )

    assert response.status == "success"
    assert response.output == expected_output
    assert calls[0]["response_format"] == expected_format


def test_malformed_and_provider_failed_outputs_remain_fail_closed(
    monkeypatch,
) -> None:
    results = iter(
        [
            {
                "text": "{not-json",
                "finish_reason": "stop",
                "provider_diagnostics": {},
            },
            {
                "text": '{"claims":[]}',
                "finish_reason": "stop",
                "safe_error": "LlamaCppStructuredOutputRejected",
                "error_type": "LlamaCppStructuredOutputRejected",
                "provider_status": "invalid_response",
                "provider_diagnostics": {},
            },
        ]
    )
    calls = 0

    def generate(**kwargs):
        nonlocal calls
        calls += 1
        return next(results)

    monkeypatch.setattr(
        "services.ai_execution.runtime.generate_with_provider",
        generate,
    )
    runtime = GatewayModelRuntime()
    runtime._set_state("ready", "ready")
    request = _request(output_schema="assistant_grounded_v2")

    malformed = asyncio.run(
        runtime.generate(request, time.monotonic() + 5)
    )
    provider_failed = asyncio.run(
        runtime.generate(request, time.monotonic() + 5)
    )

    assert malformed.status == "invalid_response"
    assert malformed.safe_error == "invalid_json"
    assert malformed.output is None
    assert provider_failed.status == "failed"
    assert provider_failed.safe_error == "invalid_visible_output"
    assert provider_failed.output is None
    assert calls == 2
