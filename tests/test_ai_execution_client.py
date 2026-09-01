from __future__ import annotations

import httpx
import pytest
from pydantic import ValidationError

from services.assistant.claims import (
    GroundedClaimOutput,
    grounded_claim_output_schema,
)
from services.ai_execution.client import (
    AiExecutionClient,
    generate_ai_response,
)
from services.ai_execution.contracts import AiExecutionRequest
from services.ai_execution.errors import (
    GatewayInvalidRequest,
    GatewayMalformedResponse,
    GatewayQueueFull,
    GatewayUnavailable,
)


def _success_payload(request: dict) -> dict:
    return {
        "status": "success",
        "task": request["task"],
        "profile": "standard",
        "model": "ai-soc-standard",
        "output": {"direct_answer": "ok"},
        "finish_reason": "stop",
        "queue_wait_ms": 3,
        "generation_ms": 10,
        "total_ms": 13,
        "prompt_tokens": 120,
        "completion_tokens": 24,
        "degraded": False,
        "safe_error": None,
        "profile_switch_count": 0,
        "profile_load_count": 0,
        "profile_unload_count": 0,
    }


def test_client_sends_closed_request_over_gateway_transport() -> None:
    calls = []

    def sender(path, payload, timeout):
        calls.append((path, payload, timeout))
        return _success_payload(payload)

    result = generate_ai_response(
        messages=[
            {"role": "system", "content": "Return JSON."},
            {"role": "user", "content": "Explain."},
        ],
        task="soc_assistant",
        requested_mode="standard",
        user_triggered=True,
        timeout_seconds=12,
        max_visible_tokens=384,
        output_schema="assistant_grounded_v1",
        client=AiExecutionClient(
            socket_path="/tmp/test-inference.sock",
            sender=sender,
        ),
    )

    path, payload, timeout = calls[0]
    assert path == "/v1/generate"
    assert timeout == pytest.approx(13)
    assert payload["priority"] == "interactive"
    assert payload["temperature"] == 0
    assert result["prompt_tokens"] == 120
    assert result["completion_tokens"] == 24
    assert payload["output_schema"] == "assistant_grounded_v1"
    assert payload["max_output_tokens"] == 384
    assert set(payload).isdisjoint(
        {"provider", "profile", "model", "model_path", "router_url"}
    )
    assert result["structured_output"] == {"direct_answer": "ok"}
    assert result["profile"] == "standard"
    assert result["provider_key"] == "ai_execution_gateway"


def test_gateway_contract_accepts_assistant_grounded_v2() -> None:
    schema_document = grounded_claim_output_schema()
    request = AiExecutionRequest(
        task="soc_assistant",
        priority="interactive",
        request_id="assistant-v2",
        deadline_ms=1000,
        system_instructions="Return typed claims.",
        input="Explain.",
        output_schema="assistant_grounded_v2",
        structured_output_schema={
            "name": "assistant_grounded_v2",
            "schema_document": schema_document,
        },
        max_output_tokens=384,
        temperature=0,
    )

    assert request.output_schema == "assistant_grounded_v2"
    assert request.structured_output_schema is not None
    assert request.structured_output_schema.schema_document == (
        GroundedClaimOutput.model_json_schema()
    )


def test_gateway_contract_accepts_closed_assistant_grounded_v3_schema() -> None:
    schema_document = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"answer_intent": {"const": "EXPLAIN"}},
        "required": ["answer_intent"],
    }
    request = AiExecutionRequest(
        task="soc_assistant",
        priority="interactive",
        request_id="assistant-v3",
        deadline_ms=1000,
        system_instructions="Return a typed answer plan.",
        input="Explain.",
        output_schema="assistant_grounded_v3",
        structured_output_schema={
            "name": "assistant_grounded_v3",
            "schema_document": schema_document,
        },
        max_output_tokens=1536,
        temperature=0,
    )

    assert request.output_schema == "assistant_grounded_v3"
    assert request.structured_output_schema is not None
    assert request.structured_output_schema.schema_document == schema_document


def test_gateway_contract_requires_closed_schema_for_assistant_grounded_v2() -> None:
    with pytest.raises(ValidationError, match="requires a structured output schema"):
        AiExecutionRequest(
            task="soc_assistant",
            priority="interactive",
            request_id="assistant-v2",
            deadline_ms=1000,
            system_instructions="Return typed claims.",
            input="Explain.",
            output_schema="assistant_grounded_v2",
            max_output_tokens=384,
            temperature=0,
        )

    schema_document = grounded_claim_output_schema()

    def assert_closed(node) -> None:
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
            if node.get("type") == "array":
                assert "items" in node or "prefixItems" in node
            for value in node.values():
                assert_closed(value)
        elif isinstance(node, list):
            for value in node:
                assert_closed(value)

    assert_closed(schema_document)


def test_client_transports_authoritative_v2_schema() -> None:
    calls = []
    schema_document = grounded_claim_output_schema()

    def sender(path, payload, timeout):
        calls.append(payload)
        return _success_payload(payload)

    generate_ai_response(
        prompt="Explain.",
        task="soc_assistant",
        requested_mode="standard",
        output_schema="assistant_grounded_v2",
        structured_output_schema=schema_document,
        client=AiExecutionClient(sender=sender),
    )

    transported = calls[0]["structured_output_schema"]
    assert transported["name"] == "assistant_grounded_v2"
    assert transported["schema_document"] == schema_document


def test_http_client_uses_configured_unix_socket(monkeypatch) -> None:
    captured = {}

    class Transport:
        def __init__(self, *, uds):
            captured["uds"] = uds

    class Client:
        def __init__(self, *, transport, base_url, timeout):
            captured["base_url"] = base_url
            captured["timeout"] = timeout

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def request(self, method, path, json):
            captured["method"] = method
            captured["path"] = path
            return httpx.Response(
                200,
                json=_success_payload(json),
                request=httpx.Request(method, f"http://gateway{path}"),
            )

    monkeypatch.setattr(
        "services.ai_execution.client.httpx.HTTPTransport",
        Transport,
    )
    monkeypatch.setattr(
        "services.ai_execution.client.httpx.Client",
        Client,
    )
    client = AiExecutionClient(socket_path="/run/test/gateway.sock")
    response = client.generate(
        AiExecutionRequest(
            task="worker_triage",
            priority="incident_triage",
            request_id="worker-triage",
            deadline_ms=1000,
            system_instructions="Return the final answer.",
            input="Analyze.",
            max_output_tokens=64,
            temperature=0,
        )
    )

    assert response.status == "success"
    assert captured["uds"] == "/run/test/gateway.sock"
    assert captured["base_url"] == "http://ai-soc-inference-gateway"
    assert captured["path"] == "/v1/generate"


def test_http_422_is_not_classified_as_gateway_unavailable(monkeypatch) -> None:
    class Transport:
        def __init__(self, *, uds):
            pass

    class Client:
        def __init__(self, *, transport, base_url, timeout):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def request(self, method, path, json):
            return httpx.Response(
                422,
                json={"detail": "invalid internal contract"},
                request=httpx.Request(method, f"http://gateway{path}"),
            )

    monkeypatch.setattr(
        "services.ai_execution.client.httpx.HTTPTransport",
        Transport,
    )
    monkeypatch.setattr(
        "services.ai_execution.client.httpx.Client",
        Client,
    )
    client = AiExecutionClient(socket_path="/run/test/gateway.sock")

    with pytest.raises(GatewayInvalidRequest):
        client.generate(
            AiExecutionRequest(
                task="worker_triage",
                priority="incident_triage",
                request_id="worker-triage",
                deadline_ms=1000,
                system_instructions="Return the final answer.",
                input="Analyze.",
                max_output_tokens=64,
                temperature=0,
            )
        )


def test_task_priorities_are_mapped_for_api_and_worker_callers() -> None:
    priorities = {}

    def sender(path, payload, timeout):
        priorities[payload["task"]] = payload["priority"]
        return _success_payload(payload)

    client = AiExecutionClient(sender=sender)
    for task, user_triggered in (
        ("case_analysis", True),
        ("recommended_playbooks", True),
        ("remediation_explanation", True),
        ("incident_triage", False),
        ("worker_enrichment", False),
    ):
        generate_ai_response(
            prompt="Run.",
            task=task,
            user_triggered=user_triggered,
            client=client,
        )

    assert priorities == {
        "case_analysis": "user_analysis",
        "recommended_playbooks": "playbook",
        "remediation_explanation": "remediation",
        "incident_triage": "incident_triage",
        "worker_enrichment": "background",
    }


def test_gateway_unavailable_queue_full_and_malformed_are_safe() -> None:
    def unavailable(path, payload, timeout):
        raise OSError("socket missing")

    result = generate_ai_response(
        prompt="Run.",
        task="incident_triage",
        client=AiExecutionClient(sender=unavailable),
    )
    assert result["safe_error"] == "gateway_unavailable"
    assert result["text"] == ""

    def full(path, payload, timeout):
        raise GatewayQueueFull()

    result = generate_ai_response(
        prompt="Run.",
        task="incident_triage",
        client=AiExecutionClient(sender=full),
    )
    assert result["safe_error"] == "queue_full"

    result = generate_ai_response(
        prompt="Run.",
        task="incident_triage",
        client=AiExecutionClient(sender=lambda *args: {"unexpected": True}),
    )
    assert result["safe_error"] == "malformed_gateway_response"


def test_client_rejects_malformed_response_without_provider_fallback() -> None:
    client = AiExecutionClient(sender=lambda *args: ["not", "an", "object"])
    request = AiExecutionRequest(
        task="provider_test",
        priority="user_analysis",
        request_id="provider-test",
        deadline_ms=1000,
        system_instructions="Return only OK.",
        input="Run.",
        max_output_tokens=16,
        temperature=0,
    )
    with pytest.raises(GatewayMalformedResponse):
        client.generate(request)


def test_client_reads_prometheus_metrics_over_dedicated_raw_transport() -> None:
    calls = []

    def metrics_sender(path, timeout):
        calls.append((path, timeout))
        return "# TYPE ai_execution_gateway_ready gauge\nai_execution_gateway_ready 1\n"

    content = AiExecutionClient(
        metrics_sender=metrics_sender
    ).prometheus_metrics(timeout_seconds=3)

    assert calls == [("/metrics", 3)]
    assert content.startswith(b"# TYPE ai_execution_gateway_ready")


def test_client_metrics_transport_fails_closed() -> None:
    with pytest.raises(GatewayMalformedResponse):
        AiExecutionClient(metrics_sender=lambda *args: b"").prometheus_metrics()

    def unavailable(path, timeout):
        raise OSError("socket missing")

    with pytest.raises(GatewayUnavailable):
        AiExecutionClient(
            metrics_sender=unavailable
        ).prometheus_metrics()


def test_nonstandard_profile_is_rejected_before_transport() -> None:
    called = False

    def sender(path, payload, timeout):
        nonlocal called
        called = True
        return _success_payload(payload)

    result = generate_ai_response(
        prompt="Run.",
        task="case_analysis",
        requested_mode="quality",
        client=AiExecutionClient(sender=sender),
    )
    assert result["safe_error"] == "NonStandardProfileRejected"
    assert called is False
