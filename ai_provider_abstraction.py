from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol

import requests

from ai_provider_redaction import (
    REDACTION_BLOCK_EXTERNAL,
    REDACTION_LOCAL_ONLY,
    prepare_external_prompt,
)
from ai_provider_registry import (
    PROVIDER_LOCAL_OLLAMA,
    PROVIDER_OPENAI_COMPATIBLE,
    ProviderConfig,
)


@dataclass(frozen=True)
class AIProviderResponse:
    provider_key: str
    provider_type: str
    model: str | None
    text: str
    finish_reason: str | None
    latency_ms: int | None
    used_external_provider: bool
    redaction_applied: bool
    fallback_used: bool
    safe_error: str | None
    usage: dict[str, Any] | None
    redaction_mode: str = REDACTION_LOCAL_ONLY
    input_character_count_after_redaction: int | None = None
    output_character_count: int | None = None


@dataclass(frozen=True)
class AIProviderHealth:
    provider_key: str
    provider_type: str
    configured: bool
    enabled: bool
    reachable: bool | None
    model_available: bool | None
    latency_ms: int | None
    safe_message: str
    safe_error: str | None


class AIProviderClient(Protocol):
    provider_key: str
    provider_type: str

    def generate(
        self,
        *,
        feature: str,
        prompt: str | None,
        messages: list[dict[str, Any]] | None,
        context: dict[str, Any] | None,
        options: dict[str, Any] | None,
        data_control: dict[str, Any] | None,
    ) -> AIProviderResponse:
        ...

    def health_check(self) -> AIProviderHealth:
        ...


class LocalOllamaProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.provider_key = config.key
        self.provider_type = config.provider_type

    def generate(
        self,
        *,
        feature: str,
        prompt: str | None,
        messages: list[dict[str, Any]] | None,
        context: dict[str, Any] | None,
        options: dict[str, Any] | None,
        data_control: dict[str, Any] | None,
    ) -> AIProviderResponse:
        if not self.config.enabled:
            return AIProviderResponse(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                model=self.config.model,
                text="",
                finish_reason=None,
                latency_ms=0,
                used_external_provider=False,
                redaction_applied=False,
                fallback_used=False,
                safe_error="ProviderDisabled",
                usage=None,
                redaction_mode=REDACTION_LOCAL_ONLY,
                input_character_count_after_redaction=0,
                output_character_count=0,
            )

        started = time.monotonic()
        opts = options or {}
        controls = data_control or {}
        model = str(opts.get("model") or self.config.model or "")
        timeout = float(opts.get("timeout_seconds") or self.config.timeout_seconds)
        keep_alive = opts.get("keep_alive")
        request_options = {
            "num_ctx": opts.get("num_ctx"),
            "temperature": opts.get("temperature"),
        }
        request_options = {key: value for key, value in request_options.items() if value is not None}

        try:
            if messages:
                payload = {
                    "model": model,
                    "messages": messages,
                    "stream": False,
                    "options": request_options,
                }
                if keep_alive:
                    payload["keep_alive"] = keep_alive
                response = requests.post(
                    f"{str(self.config.base_url).rstrip('/')}/api/chat",
                    json=payload,
                    timeout=timeout,
                )
                response.raise_for_status()
                data = response.json()
                message = data.get("message") or {}
                text = str(message.get("content") or "")
                finish_reason = data.get("done_reason") or ("stop" if data.get("done") else None)
            else:
                payload = {
                    "model": model,
                    "prompt": prompt or "",
                    "stream": False,
                    "options": request_options,
                }
                if keep_alive:
                    payload["keep_alive"] = keep_alive
                response = requests.post(
                    f"{str(self.config.base_url).rstrip('/')}/api/generate",
                    json=payload,
                    timeout=timeout,
                )
                response.raise_for_status()
                data = response.json()
                text = str(data.get("response") or "")
                finish_reason = data.get("done_reason") or ("stop" if data.get("done") else None)

            latency_ms = int((time.monotonic() - started) * 1000)
            return AIProviderResponse(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                model=model,
                text=text,
                finish_reason=finish_reason,
                latency_ms=latency_ms,
                used_external_provider=False,
                redaction_applied=bool(controls.get("policy_redaction_applied", False)),
                fallback_used=False,
                safe_error=None,
                usage=None,
                redaction_mode=str(controls.get("redaction_mode") or REDACTION_LOCAL_ONLY),
                input_character_count_after_redaction=int(
                    controls.get("policy_output_character_count")
                    or (len(prompt or "") + len(str(messages or "")))
                ),
                output_character_count=len(text),
            )
        except Exception as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            return AIProviderResponse(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                model=model or self.config.model,
                text="",
                finish_reason=None,
                latency_ms=latency_ms,
                used_external_provider=False,
                redaction_applied=False,
                fallback_used=False,
                safe_error=type(exc).__name__,
                usage=None,
                redaction_mode=str(controls.get("redaction_mode") or REDACTION_LOCAL_ONLY),
                input_character_count_after_redaction=int(
                    controls.get("policy_output_character_count")
                    or (len(prompt or "") + len(str(messages or "")))
                ),
                output_character_count=0,
            )

    def health_check(self) -> AIProviderHealth:
        started = time.monotonic()
        if not self.config.enabled:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured=self.config.configured,
                enabled=False,
                reachable=None,
                model_available=None,
                latency_ms=None,
                safe_message="Local Ollama provider is disabled.",
                safe_error=None,
            )

        try:
            response = requests.get(
                f"{str(self.config.base_url).rstrip('/')}/api/tags",
                timeout=min(self.config.timeout_seconds, 5),
            )
            response.raise_for_status()
            payload = response.json()
            models = [
                item.get("name") or item.get("model")
                for item in payload.get("models", [])
                if isinstance(item, dict)
            ]
            model_available = any(
                name == self.config.model or str(name or "").split(":")[0] == str(self.config.model or "").split(":")[0]
                for name in models
            )
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured=self.config.configured,
                enabled=self.config.enabled,
                reachable=True,
                model_available=model_available,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="Local Ollama provider is reachable.",
                safe_error=None,
            )
        except Exception as exc:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured=self.config.configured,
                enabled=self.config.enabled,
                reachable=False,
                model_available=None,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="Local Ollama provider is unavailable.",
                safe_error=type(exc).__name__,
            )


class OpenAICompatibleProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.provider_key = config.key
        self.provider_type = config.provider_type

    def generate(
        self,
        *,
        feature: str,
        prompt: str | None,
        messages: list[dict[str, Any]] | None,
        context: dict[str, Any] | None,
        options: dict[str, Any] | None,
        data_control: dict[str, Any] | None,
    ) -> AIProviderResponse:
        started = time.monotonic()
        controls = data_control or {}
        redaction_mode = str(controls.get("redaction_mode") or self.config.redaction_mode)
        try:
            if controls.get("policy_preprocessed"):
                redacted_prompt = prompt
                redacted_messages = messages
                redaction_applied = bool(controls.get("policy_redaction_applied", False))
                redaction_output_count = int(
                    controls.get("policy_output_character_count")
                    or (len(prompt or "") + len(str(messages or "")))
                )
            else:
                redacted_prompt, redacted_messages, redaction = prepare_external_prompt(
                    feature=feature,
                    prompt=prompt,
                    messages=messages,
                    context=context,
                    redaction_mode=redaction_mode,
                )
                redaction_applied = redaction.applied
                redaction_output_count = redaction.output_character_count
            chat_messages = redacted_messages or [{"role": "user", "content": redacted_prompt or ""}]
            payload = {
                "model": self.config.model,
                "messages": chat_messages,
                "temperature": (options or {}).get("temperature", 0.2),
            }
            max_tokens = (options or {}).get("max_tokens") or self.config.max_tokens
            if max_tokens:
                payload["max_tokens"] = max_tokens

            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            }
            response = requests.post(
                f"{str(self.config.base_url).rstrip('/')}/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.config.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
            choice = (data.get("choices") or [{}])[0] or {}
            message = choice.get("message") or {}
            text = str(message.get("content") or "")
            latency_ms = int((time.monotonic() - started) * 1000)
            return AIProviderResponse(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                model=self.config.model,
                text=text,
                finish_reason=choice.get("finish_reason"),
                latency_ms=latency_ms,
                used_external_provider=True,
                redaction_applied=redaction_applied,
                fallback_used=False,
                safe_error=None,
                usage=data.get("usage") if isinstance(data.get("usage"), dict) else None,
                redaction_mode=redaction_mode,
                input_character_count_after_redaction=redaction_output_count,
                output_character_count=len(text),
            )
        except Exception as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            return AIProviderResponse(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                model=self.config.model,
                text="",
                finish_reason=None,
                latency_ms=latency_ms,
                used_external_provider=True,
                redaction_applied=True,
                fallback_used=False,
                safe_error=type(exc).__name__,
                usage=None,
                redaction_mode=redaction_mode,
                input_character_count_after_redaction=None,
                output_character_count=0,
            )

    def health_check(self) -> AIProviderHealth:
        if not self.config.enabled:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured=self.config.configured,
                enabled=False,
                reachable=None,
                model_available=None,
                latency_ms=None,
                safe_message="External provider is disabled.",
                safe_error=None,
            )

        if not self.config.configured:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured=False,
                enabled=True,
                reachable=None,
                model_available=None,
                latency_ms=None,
                safe_message="External provider is enabled but not fully configured.",
                safe_error=None,
            )

        started = time.monotonic()
        try:
            response = requests.get(
                f"{str(self.config.base_url).rstrip('/')}/models",
                headers={"Authorization": f"Bearer {self.config.api_key}"},
                timeout=min(self.config.timeout_seconds, 5),
            )
            response.raise_for_status()
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured=True,
                enabled=True,
                reachable=True,
                model_available=None,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="External provider models endpoint is reachable.",
                safe_error=None,
            )
        except Exception as exc:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured=True,
                enabled=True,
                reachable=False,
                model_available=None,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="External provider health check failed safely.",
                safe_error=type(exc).__name__,
            )


class UnsupportedProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.provider_key = config.key
        self.provider_type = config.provider_type

    def generate(
        self,
        *,
        feature: str,
        prompt: str | None,
        messages: list[dict[str, Any]] | None,
        context: dict[str, Any] | None,
        options: dict[str, Any] | None,
        data_control: dict[str, Any] | None,
    ) -> AIProviderResponse:
        return AIProviderResponse(
            provider_key=self.provider_key,
            provider_type=self.provider_type,
            model=self.config.model,
            text="",
            finish_reason=None,
            latency_ms=0,
            used_external_provider=self.config.external,
            redaction_applied=False,
            fallback_used=False,
            safe_error="ProviderAdapterNotImplemented",
            usage=None,
            redaction_mode=self.config.redaction_mode,
            input_character_count_after_redaction=0,
            output_character_count=0,
        )

    def health_check(self) -> AIProviderHealth:
        return AIProviderHealth(
            provider_key=self.provider_key,
            provider_type=self.provider_type,
            configured=self.config.configured,
            enabled=self.config.enabled,
            reachable=None,
            model_available=None,
            latency_ms=None,
            safe_message="Provider type is configuration-visible but adapter is not implemented in Step 11.",
            safe_error=None,
        )


def build_provider_client(config: ProviderConfig) -> AIProviderClient:
    if config.provider_type == PROVIDER_LOCAL_OLLAMA:
        return LocalOllamaProvider(config)

    if config.provider_type == PROVIDER_OPENAI_COMPATIBLE:
        return OpenAICompatibleProvider(config)

    return UnsupportedProvider(config)
