from __future__ import annotations

import fcntl
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import requests

from llama_cpp_profiles import (
    LLAMA_CPP_DEFAULT_LOCK_PATH,
    LLAMA_CPP_DEFAULT_ROUTER_BASE_URL,
    llama_cpp_profile_models,
    normalize_llama_cpp_profile,
    resolve_llama_cpp_profile,
)
from ai_provider_redaction import (
    REDACTION_BLOCK_EXTERNAL,
    REDACTION_LOCAL_ONLY,
    prepare_external_prompt,
)
from ai_provider_registry import (
    PROVIDER_LOCAL_LLAMA_CPP,
    PROVIDER_LOCAL_OLLAMA,
    PROVIDER_OPENAI_COMPATIBLE,
    ProviderConfig,
)


LLAMA_CPP_ACTIVE_STATUSES = {"loaded", "running"}
LLAMA_CPP_NONFATAL_UNLOAD_MARKERS = {
    "model is not running",
    "model is not loaded",
    "not running",
    "not loaded",
}


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
    profile: str | None = None


@dataclass(frozen=True)
class AIProviderHealth:
    provider_key: str
    provider_type: str
    configured_model: str | None
    configured: bool
    enabled: bool
    reachable: bool | None
    model_available: bool | None
    latency_ms: int | None
    safe_message: str
    safe_error: str | None
    details: dict[str, Any] | None = None


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


def _openai_compatible_model_names(payload: Any) -> tuple[bool, list[str]]:
    if isinstance(payload, dict):
        raw_models = payload.get("data")
    elif isinstance(payload, list):
        raw_models = payload
    else:
        return False, []

    if not isinstance(raw_models, list):
        return False, []

    model_names: list[str] = []
    for item in raw_models:
        if isinstance(item, dict):
            name = item.get("id") or item.get("name") or item.get("model")
        else:
            name = item
        if name:
            model_names.append(str(name))

    return True, model_names


def _configured_model_available(configured_model: str | None, model_names: list[str]) -> bool:
    model = str(configured_model or "").strip()
    if not model:
        return False

    return any(str(name or "").strip() == model for name in model_names)


def llama_cpp_managed_models(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        raw_models = payload.get("data") or payload.get("models") or payload.get("items") or []
    elif isinstance(payload, list):
        raw_models = payload
    else:
        return []

    if not isinstance(raw_models, list):
        return []

    managed: list[dict[str, Any]] = []
    for item in raw_models:
        if isinstance(item, dict):
            model_id = item.get("id") or item.get("name") or item.get("model")
            status = item.get("status")
            if isinstance(status, dict):
                status_value = status.get("value")
            else:
                status_value = status
            raw_item = item
        else:
            model_id = item
            status_value = None
            raw_item = {"id": item}

        model_id = str(model_id or "").strip()
        if not model_id.startswith("ai-soc-"):
            continue

        managed.append(
            {
                "id": model_id,
                "status": str(status_value or "").strip().lower() or None,
                "raw": raw_item,
            }
        )

    return managed


def _llama_cpp_error_text(exc: Exception) -> str:
    parts = [str(exc)]
    response = getattr(exc, "response", None)
    if response is not None:
        text = getattr(response, "text", None)
        if text:
            parts.append(str(text))
        try:
            payload = response.json()
            parts.append(str(payload))
        except Exception:
            pass
    return " ".join(parts).lower()


def is_nonfatal_llama_cpp_unload_error(exc: Exception | str) -> bool:
    text = str(exc).lower() if isinstance(exc, str) else _llama_cpp_error_text(exc)
    return any(marker in text for marker in LLAMA_CPP_NONFATAL_UNLOAD_MARKERS)


@contextmanager
def _profile_switch_lock(path: str):
    lock_path = Path(path or LLAMA_CPP_DEFAULT_LOCK_PATH)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
                configured_model=self.config.model,
                configured=self.config.configured,
                enabled=False,
                reachable=None,
                model_available=None,
                latency_ms=None,
                safe_message="Ollama provider is disabled.",
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
                configured_model=self.config.model,
                configured=self.config.configured,
                enabled=self.config.enabled,
                reachable=True,
                model_available=model_available,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="Ollama provider is reachable.",
                safe_error=None,
            )
        except Exception as exc:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured_model=self.config.model,
                configured=self.config.configured,
                enabled=self.config.enabled,
                reachable=False,
                model_available=None,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="Ollama provider is unavailable.",
                safe_error=type(exc).__name__,
            )


class LocalLlamaCppProvider:
    def __init__(self, config: ProviderConfig) -> None:
        self.config = config
        self.provider_key = config.key
        self.provider_type = config.provider_type

    def _router_base_url(self) -> str:
        return str(
            self.config.metadata.get("router_base_url")
            or os.getenv("LLAMA_CPP_BASE_URL")
            or LLAMA_CPP_DEFAULT_ROUTER_BASE_URL
        ).rstrip("/")

    def _api_base_url(self) -> str:
        return str(self.config.base_url or "").rstrip("/")

    def _router_enabled(self) -> bool:
        raw = os.getenv(str(self.config.metadata.get("router_enabled_env") or "LLAMA_CPP_ROUTER_ENABLED"))
        if raw is None:
            return True
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def _auto_profile_switch(self) -> bool:
        raw = os.getenv(str(self.config.metadata.get("auto_profile_switch_env") or "LLAMA_CPP_AUTO_PROFILE_SWITCH"))
        if raw is None:
            return True
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def _exclusive_model(self) -> bool:
        raw = os.getenv(str(self.config.metadata.get("exclusive_model_env") or "LLAMA_CPP_EXCLUSIVE_MODEL"))
        if raw is None:
            return True
        return raw.strip().lower() in {"1", "true", "yes", "on"}

    def _lock_path(self) -> str:
        return str(
            os.getenv(str(self.config.metadata.get("profile_switch_lock_env") or "LLAMA_CPP_PROFILE_SWITCH_LOCK"))
            or self.config.metadata.get("profile_switch_lock")
            or LLAMA_CPP_DEFAULT_LOCK_PATH
        )

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def _request_timeout(self, opts: dict[str, Any]) -> float:
        return float(opts.get("timeout_seconds") or self.config.timeout_seconds)

    def _router_health(self, *, timeout: float) -> dict[str, Any]:
        response = requests.get(
            f"{self._router_base_url()}/health",
            timeout=min(timeout, 5),
        )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else {}

    def _router_models(self, *, timeout: float) -> list[dict[str, Any]]:
        response = requests.get(
            f"{self._router_base_url()}/models",
            timeout=min(timeout, 5),
        )
        response.raise_for_status()
        return llama_cpp_managed_models(response.json())

    def _post_router_action(self, action: str, model: str, *, timeout: float) -> None:
        try:
            response = requests.post(
                f"{self._router_base_url()}/models/{action}",
                json={"model": model},
                timeout=timeout,
            )
            response.raise_for_status()
            try:
                payload = response.json()
            except Exception:
                payload = {}
            if isinstance(payload, dict) and payload.get("success") is False:
                message = str(payload.get("error") or payload.get("message") or "")
                if action == "unload" and is_nonfatal_llama_cpp_unload_error(message):
                    return
                raise RuntimeError(message or f"LlamaCppModel{action.title()}Failed")
        except Exception as exc:
            if action == "unload" and is_nonfatal_llama_cpp_unload_error(exc):
                return
            raise

    def _wait_until_active(self, model: str, *, timeout: float) -> list[dict[str, Any]]:
        deadline = time.monotonic() + max(timeout, 1)
        last_models: list[dict[str, Any]] = []
        while True:
            last_models = self._router_models(timeout=timeout)
            for item in last_models:
                if item["id"] == model and item.get("status") in LLAMA_CPP_ACTIVE_STATUSES:
                    return last_models
            if time.monotonic() >= deadline:
                raise RuntimeError("LlamaCppModelNotLoaded")
            time.sleep(0.5)

    def _resolve_and_prepare_model(
        self,
        *,
        requested_profile: str,
        timeout: float,
    ) -> tuple[str, str, str | None]:
        with _profile_switch_lock(self._lock_path()):
            models = self._router_models(timeout=timeout)
            available_ids = {item["id"] for item in models}
            resolved = resolve_llama_cpp_profile(requested_profile, available_ids)
            target_model = resolved.model

            if self._exclusive_model():
                for item in models:
                    if item["id"] != target_model and item.get("status") in LLAMA_CPP_ACTIVE_STATUSES:
                        self._post_router_action("unload", item["id"], timeout=timeout)

            if not self._auto_profile_switch():
                target = next((item for item in models if item["id"] == target_model), None)
                if not target or target.get("status") not in LLAMA_CPP_ACTIVE_STATUSES:
                    raise RuntimeError("LlamaCppModelNotLoaded")
                return resolved.profile, target_model, resolved.degraded_from

            target = next((item for item in models if item["id"] == target_model), None)
            if not target or target.get("status") not in LLAMA_CPP_ACTIVE_STATUSES:
                self._post_router_action("load", target_model, timeout=timeout)
                self._wait_until_active(target_model, timeout=timeout)

            return resolved.profile, target_model, resolved.degraded_from

    def _profile_details(self, models: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_id = {item["id"]: item for item in models}
        profile_models = llama_cpp_profile_models()
        details = []
        for profile in ("fast", "standard", "quality"):
            model = profile_models[profile]
            item = by_id.get(model)
            status = item.get("status") if item else None
            details.append(
                {
                    "profile": profile,
                    "model": model,
                    "available": item is not None,
                    "active": status in LLAMA_CPP_ACTIVE_STATUSES,
                    "status": status,
                }
            )
        return details

    def _disabled_response(self, safe_error: str) -> AIProviderResponse:
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
            safe_error=safe_error,
            usage=None,
            redaction_mode=REDACTION_LOCAL_ONLY,
            input_character_count_after_redaction=0,
            output_character_count=0,
        )

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
            return self._disabled_response("ProviderDisabled")
        if not self._router_enabled():
            return self._disabled_response("LlamaCppRouterDisabled")

        started = time.monotonic()
        opts = options or {}
        controls = data_control or {}
        timeout = self._request_timeout(opts)
        requested_profile = normalize_llama_cpp_profile(str(opts.get("llm_profile") or "standard"))
        selected_profile = requested_profile
        selected_model = str(opts.get("model") or self.config.model or "")

        try:
            selected_profile, selected_model, degraded_from = self._resolve_and_prepare_model(
                requested_profile=requested_profile,
                timeout=timeout,
            )
            chat_messages = messages or [{"role": "user", "content": prompt or ""}]
            payload: dict[str, Any] = {
                "model": selected_model,
                "messages": chat_messages,
                "temperature": opts.get("temperature", 0.2),
            }
            max_tokens = opts.get("max_tokens") or self.config.max_tokens
            if max_tokens:
                payload["max_tokens"] = max_tokens
            if opts.get("response_format") is not None:
                payload["response_format"] = opts["response_format"]

            response = requests.post(
                f"{self._api_base_url()}/chat/completions",
                json=payload,
                headers=self._headers(),
                timeout=timeout,
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
                model=str(data.get("model") or selected_model),
                text=text,
                finish_reason=choice.get("finish_reason"),
                latency_ms=latency_ms,
                used_external_provider=False,
                redaction_applied=bool(controls.get("policy_redaction_applied", False)),
                fallback_used=bool(degraded_from),
                safe_error=None,
                usage=data.get("usage") if isinstance(data.get("usage"), dict) else None,
                redaction_mode=str(controls.get("redaction_mode") or REDACTION_LOCAL_ONLY),
                input_character_count_after_redaction=int(
                    controls.get("policy_output_character_count")
                    or (len(prompt or "") + len(str(messages or "")))
                ),
                output_character_count=len(text),
                profile=selected_profile,
            )
        except Exception as exc:
            latency_ms = int((time.monotonic() - started) * 1000)
            return AIProviderResponse(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                model=selected_model or self.config.model,
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
                profile=selected_profile,
            )

    def health_check(self) -> AIProviderHealth:
        base_details = {
            "router_enabled": self._router_enabled(),
            "router_base_url": self._router_base_url(),
            "api_base_url": self._api_base_url(),
            "native_ui_url": str(self.config.metadata.get("native_ui_url") or self._router_base_url()),
            "profile_switch_lock": self._lock_path(),
        }
        if not self.config.enabled:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured_model=self.config.model,
                configured=self.config.configured,
                enabled=False,
                reachable=None,
                model_available=None,
                latency_ms=None,
                safe_message="llama.cpp provider is disabled.",
                safe_error=None,
                details=base_details,
            )

        started = time.monotonic()
        try:
            health_payload = self._router_health(timeout=self.config.timeout_seconds)
            models = self._router_models(timeout=self.config.timeout_seconds)
            configured_model = self.config.model
            model_available = any(item["id"] == configured_model for item in models)
            details = {
                **base_details,
                "router_health": health_payload,
                "profiles": self._profile_details(models),
                "loaded_models": [
                    item["id"]
                    for item in models
                    if item.get("status") in LLAMA_CPP_ACTIVE_STATUSES
                ],
            }
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured_model=configured_model,
                configured=self.config.configured,
                enabled=self.config.enabled,
                reachable=True,
                model_available=model_available,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="llama.cpp router is reachable.",
                safe_error=None,
                details=details,
            )
        except Exception as exc:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured_model=self.config.model,
                configured=self.config.configured,
                enabled=self.config.enabled,
                reachable=False,
                model_available=None,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="llama.cpp router health check failed safely.",
                safe_error=type(exc).__name__,
                details=base_details,
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
            if (options or {}).get("response_format") is not None:
                payload["response_format"] = (options or {})["response_format"]

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
                configured_model=self.config.model,
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
                configured_model=self.config.model,
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
            models_listed, model_names = _openai_compatible_model_names(response.json())
            model_available = (
                _configured_model_available(self.config.model, model_names)
                if models_listed
                else None
            )
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured_model=self.config.model,
                configured=True,
                enabled=True,
                reachable=True,
                model_available=model_available,
                latency_ms=int((time.monotonic() - started) * 1000),
                safe_message="External provider models endpoint is reachable.",
                safe_error=None,
            )
        except Exception as exc:
            return AIProviderHealth(
                provider_key=self.provider_key,
                provider_type=self.provider_type,
                configured_model=self.config.model,
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
            configured_model=self.config.model,
            configured=self.config.configured,
            enabled=self.config.enabled,
            reachable=None,
            model_available=None,
            latency_ms=None,
            safe_message="",
            safe_error=None,
        )


def build_provider_client(config: ProviderConfig) -> AIProviderClient:
    if config.provider_type == PROVIDER_LOCAL_OLLAMA:
        return LocalOllamaProvider(config)

    if config.provider_type == PROVIDER_LOCAL_LLAMA_CPP:
        return LocalLlamaCppProvider(config)

    if config.provider_type == PROVIDER_OPENAI_COMPATIBLE:
        return OpenAICompatibleProvider(config)

    return UnsupportedProvider(config)
