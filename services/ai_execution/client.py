from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable
from uuid import uuid4

import httpx

from services.ai_execution.contracts import (
    AiExecutionRequest,
    AiExecutionResponse,
    GatewayStatus,
    StructuredOutputSchema,
)
from services.ai_execution.errors import (
    AiExecutionError,
    GatewayDeadlineExceeded,
    GatewayInvalidRequest,
    GatewayMalformedResponse,
    GatewayQueueFull,
    GatewayUnavailable,
)
from services.ai_execution.priorities import priority_for_task


DEFAULT_SOCKET = "/run/ai-soc/inference-gateway.sock"
Sender = Callable[[str, dict[str, Any], float], dict[str, Any]]


def _env_timeout() -> float:
    try:
        value = float(
            os.getenv("AI_INFERENCE_REQUEST_TIMEOUT_SECONDS", "35")
        )
    except (TypeError, ValueError):
        value = 35
    return min(max(value, 1), 300)


def _max_output_tokens(value: int | None) -> int:
    if value is None:
        try:
            value = int(
                os.getenv("AI_INFERENCE_MAX_OUTPUT_TOKENS", "384")
            )
        except (TypeError, ValueError):
            value = 384
    return min(max(int(value), 16), 2048)


class AiExecutionClient:
    def __init__(
        self,
        *,
        socket_path: str | None = None,
        sender: Sender | None = None,
    ) -> None:
        self.socket_path = socket_path or os.getenv(
            "AI_INFERENCE_GATEWAY_SOCKET",
            DEFAULT_SOCKET,
        )
        self._sender = sender

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        timeout = timeout_seconds or _env_timeout()
        if self._sender is not None:
            try:
                data = self._sender(path, payload or {}, timeout)
            except AiExecutionError:
                raise
            except (OSError, TimeoutError, ValueError) as exc:
                raise GatewayUnavailable() from exc
            if not isinstance(data, dict):
                raise GatewayMalformedResponse()
            return data
        transport = httpx.HTTPTransport(uds=self.socket_path)
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://ai-soc-inference-gateway",
                timeout=timeout,
            ) as client:
                response = client.request(method, path, json=payload)
                if response.status_code == 429:
                    raise GatewayQueueFull()
                if response.status_code == 504:
                    raise GatewayDeadlineExceeded()
                if response.status_code == 422:
                    raise GatewayInvalidRequest()
                response.raise_for_status()
                data = response.json()
        except (
            GatewayQueueFull,
            GatewayDeadlineExceeded,
            GatewayInvalidRequest,
        ):
            raise
        except (httpx.HTTPError, OSError, ValueError) as exc:
            raise GatewayUnavailable() from exc
        if not isinstance(data, dict):
            raise GatewayMalformedResponse()
        return data

    def generate(self, request: AiExecutionRequest) -> AiExecutionResponse:
        data = self._request(
            "POST",
            "/v1/generate",
            payload=request.model_dump(mode="json"),
            timeout_seconds=(request.deadline_ms / 1000) + 1,
        )
        try:
            return AiExecutionResponse.model_validate(data)
        except Exception as exc:
            raise GatewayMalformedResponse() from exc

    def status(self) -> GatewayStatus:
        data = self._request("GET", "/status")
        try:
            return GatewayStatus.model_validate(data)
        except Exception as exc:
            raise GatewayMalformedResponse() from exc

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")


def _messages_for_gateway(
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
) -> tuple[str, str]:
    system_parts: list[str] = []
    input_parts: list[str] = []
    for message in messages or []:
        role = str(message.get("role") or "user").strip().lower()
        content = str(message.get("content") or "").strip()
        if not content:
            continue
        if role == "system":
            system_parts.append(content)
        else:
            input_parts.append(f"{role}: {content}")
    if prompt:
        input_parts.append(str(prompt))
    system = "\n\n".join(system_parts).strip() or (
        "Return only the requested final output. Do not expose hidden reasoning."
    )
    user_input = "\n\n".join(input_parts).strip()
    if not user_input:
        raise ValueError("prompt or messages is required")
    return system, user_input


def generate_ai_response(
    *,
    prompt: str | None = None,
    messages: list[dict[str, Any]] | None = None,
    task: Any,
    severity: str | None = None,
    requested_mode: str | None = None,
    user_triggered: bool = False,
    timeout_seconds: float | None = None,
    deadline_monotonic: float | None = None,
    fallback_timeout_seconds: float | None = None,
    availability_timeout_seconds: float | None = None,
    max_visible_tokens: int | None = None,
    context: dict[str, Any] | None = None,
    current_user: dict[str, Any] | None = None,
    output_schema: str = "text_v1",
    structured_output_schema: dict[str, Any] | None = None,
    client: AiExecutionClient | None = None,
) -> dict[str, Any]:
    del severity, fallback_timeout_seconds, availability_timeout_seconds
    del current_user
    if requested_mode not in {None, "", "auto", "standard"}:
        return {
            "text": "",
            "safe_error": "NonStandardProfileRejected",
            "error_type": "NonStandardProfileRejected",
            "provider_status": "policy_blocked",
            "profile": "standard",
            "model": "ai-soc-standard",
        }
    task_value = str(getattr(task, "value", task) or "").strip().lower()
    system, input_text = _messages_for_gateway(prompt, messages)
    timeout = min(
        max(float(timeout_seconds or _env_timeout()), 0.1),
        300,
    )
    if deadline_monotonic is not None:
        timeout = min(
            timeout,
            max(0.1, deadline_monotonic - time.monotonic()),
        )
    request_hash = str((context or {}).get("request_id_hash") or "")
    request_id = (
        request_hash
        if re.fullmatch(r"[A-Za-z0-9_.:-]{8,80}", request_hash)
        else uuid4().hex
    )
    request = AiExecutionRequest(
        task=task_value,
        priority=priority_for_task(
            task_value,
            user_triggered=user_triggered,
        ),
        request_id=request_id,
        deadline_ms=max(100, int(timeout * 1000)),
        system_instructions=system,
        input=input_text,
        output_schema=output_schema,
        structured_output_schema=(
            StructuredOutputSchema(
                name=output_schema,
                schema_document=structured_output_schema,
            )
            if structured_output_schema is not None
            else None
        ),
        max_output_tokens=_max_output_tokens(max_visible_tokens),
        temperature=0,
    )
    selected_client = client or AiExecutionClient()
    try:
        response = selected_client.generate(request)
    except (
        GatewayUnavailable,
        GatewayQueueFull,
        GatewayDeadlineExceeded,
        GatewayInvalidRequest,
        GatewayMalformedResponse,
    ) as exc:
        safe_error = exc.safe_error
        return {
            "text": "",
            "safe_error": safe_error,
            "error_type": safe_error,
            "provider_status": safe_error,
            "profile": "standard",
            "model": "ai-soc-standard",
            "gateway_status": "unavailable",
        }
    output = response.output
    text = (
        output
        if isinstance(output, str)
        else json.dumps(output, ensure_ascii=False)
        if output is not None
        else ""
    )
    return {
        "text": text,
        "structured_output": output if isinstance(output, dict) else None,
        "profile": "standard",
        "effective_profile": "standard" if response.status == "success" else None,
        "model": response.model,
        "effective_model": (
            response.model if response.status == "success" else None
        ),
        "provider_key": "ai_execution_gateway",
        "effective_provider": (
            "ai_execution_gateway"
            if response.status == "success"
            else None
        ),
        "provider_type": "INFERENCE_GATEWAY",
        "provider_status": (
            "ok" if response.status == "success" else response.status
        ),
        "finish_reason": response.finish_reason,
        "latency_ms": response.total_ms,
        "primary_elapsed_ms": response.generation_ms,
        "queue_wait_ms": response.queue_wait_ms,
        "generation_ms": response.generation_ms,
        "total_ms": response.total_ms,
        "prompt_tokens": response.prompt_tokens,
        "completion_tokens": response.completion_tokens,
        "safe_error": response.safe_error,
        "error_type": response.safe_error,
        "fallback_used": False,
        "fallback_attempted": False,
        "provider_diagnostics": {
            "selected_profile": "standard",
            "profile_switch_count": response.profile_switch_count,
            "profile_load_count": response.profile_load_count,
            "profile_unload_count": response.profile_unload_count,
            "queue_wait_ms": response.queue_wait_ms,
            "generation_ms": response.generation_ms,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
        },
    }
