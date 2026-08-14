from __future__ import annotations

import fcntl
import logging
import os
import re
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

import requests

from llama_cpp_profiles import (
    LLAMA_CPP_DEFAULT_LOCK_PATH,
    LLAMA_CPP_DEFAULT_ROUTER_BASE_URL,
    llama_cpp_profile_models,
    llama_cpp_profile_model_family,
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


logger = logging.getLogger(__name__)


LLAMA_CPP_ACTIVE_STATUSES = {"loaded", "running"}
LLAMA_CPP_WARMING_STATUSES = {"initializing", "loading", "starting", "warming"}
LLAMA_CPP_INACTIVE_STATUSES = {"stopped", "unloaded"}
LLAMA_CPP_BUSY_STATUSES = LLAMA_CPP_ACTIVE_STATUSES | LLAMA_CPP_WARMING_STATUSES
LLAMA_CPP_GATEWAY_STANDARD_MODEL = "ai-soc-standard"
LLAMA_CPP_NONFATAL_UNLOAD_MARKERS = {
    "model is not running",
    "model is not loaded",
    "not running",
    "not loaded",
}


def _safe_nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return int(value)


def _safe_nonnegative_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return float(value)


def _llama_cpp_timing_diagnostics(payload: dict[str, Any]) -> dict[str, Any]:
    timings = payload.get("timings")
    timings = timings if isinstance(timings, dict) else {}
    usage = payload.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    prompt_details = usage.get("prompt_tokens_details")
    prompt_details = prompt_details if isinstance(prompt_details, dict) else {}

    processed_prompt_tokens = _safe_nonnegative_int(timings.get("prompt_n"))
    cached_prompt_tokens = _safe_nonnegative_int(
        prompt_details.get("cached_tokens")
    )
    if cached_prompt_tokens is None:
        cached_prompt_tokens = _safe_nonnegative_int(timings.get("cache_n"))

    prompt_tokens = _safe_nonnegative_int(usage.get("prompt_tokens"))
    if (
        prompt_tokens is None
        and processed_prompt_tokens is not None
        and cached_prompt_tokens is not None
    ):
        prompt_tokens = processed_prompt_tokens + cached_prompt_tokens
    elif prompt_tokens is None:
        prompt_tokens = processed_prompt_tokens

    completion_tokens = _safe_nonnegative_int(usage.get("completion_tokens"))
    predicted_tokens = _safe_nonnegative_int(timings.get("predicted_n"))
    if completion_tokens is None:
        completion_tokens = predicted_tokens

    if cached_prompt_tokens is None:
        cache_state = "unknown"
    elif cached_prompt_tokens == 0:
        cache_state = "cold"
    elif processed_prompt_tokens is not None:
        cache_state = "warm" if processed_prompt_tokens <= 1 else "partial"
    elif prompt_tokens is not None:
        cache_state = "warm" if cached_prompt_tokens >= prompt_tokens else "partial"
    else:
        cache_state = "warm"

    prompt_ms = _safe_nonnegative_float(timings.get("prompt_ms"))
    predicted_ms = _safe_nonnegative_float(timings.get("predicted_ms"))
    return {
        "prompt_n": processed_prompt_tokens,
        "prompt_ms": prompt_ms,
        "cached_tokens": cached_prompt_tokens,
        "predicted_n": predicted_tokens,
        "predicted_ms": predicted_ms,
        "prompt_tokens": prompt_tokens,
        "cached_prompt_tokens": cached_prompt_tokens,
        "prompt_cache_state": cache_state,
        "completion_tokens": completion_tokens,
        "prompt_eval_ms": prompt_ms,
        "generation_ms": predicted_ms,
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
    diagnostics: dict[str, Any] | None = None


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


class LlamaCppAvailabilityTimeout(Exception):
    pass


class LlamaCppModelLoadTimeout(Exception):
    pass


class LlamaCppModelWarmingTimeout(Exception):
    pass


class LlamaCppModelLoadRejected(Exception):
    pass


class LlamaCppModelStatusUnknown(Exception):
    pass


class LlamaCppGenerationTimeout(Exception):
    pass


class LlamaCppProfileSwitchTimeout(Exception):
    pass


class LlamaCppProfileNotConfigured(Exception):
    pass


class LlamaCppProviderUnavailable(Exception):
    pass


class LlamaCppInvalidResponse(Exception):
    pass


class LlamaCppStructuredOutputRejected(Exception):
    pass


class LlamaCppEmptyVisibleContent(Exception):
    pass


class LlamaCppPrewarmDeferred(Exception):
    pass


class LlamaCppPrewarmStopped(Exception):
    pass


def _messages_with_no_think(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    updated = [dict(message) for message in messages]
    for index in range(len(updated) - 1, -1, -1):
        message = updated[index]
        if message.get("role") != "user" or not isinstance(message.get("content"), str):
            continue
        content = str(message["content"]).rstrip()
        message["content"] = f"{content}\n\n/no_think" if content else "/no_think"
        return updated
    return updated


@contextmanager
def _profile_switch_lock(
    path: str,
    *,
    timeout: float | None = None,
    stop_requested: Callable[[], bool] | None = None,
):
    lock_path = Path(path or LLAMA_CPP_DEFAULT_LOCK_PATH)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        if timeout is None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        else:
            deadline = time.monotonic() + max(float(timeout), 0.0)
            while True:
                if stop_requested is not None and stop_requested():
                    raise LlamaCppPrewarmStopped()
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError as exc:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LlamaCppProfileSwitchTimeout() from exc
                    time.sleep(min(0.05, remaining))
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

    def _remaining_timeout(
        self,
        *,
        deadline: float,
        maximum: float | None = None,
    ) -> float:
        remaining = deadline - time.monotonic()
        if remaining < 0.05:
            raise LlamaCppGenerationTimeout()
        return min(remaining, maximum) if maximum else remaining

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

    def _wait_until_active(
        self,
        model: str,
        *,
        deadline: float,
        stop_requested: Callable[[], bool] | None = None,
    ) -> list[dict[str, Any]]:
        last_models: list[dict[str, Any]] = []
        while True:
            if stop_requested is not None and stop_requested():
                raise LlamaCppPrewarmStopped()
            try:
                last_models = self._router_models(
                    timeout=self._remaining_timeout(deadline=deadline, maximum=2),
                )
            except requests.Timeout as exc:
                raise LlamaCppModelLoadTimeout() from exc
            for item in last_models:
                if item["id"] == model and item.get("status") in LLAMA_CPP_ACTIVE_STATUSES:
                    return last_models
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LlamaCppModelLoadTimeout()
            time.sleep(min(0.5, remaining))

    def _resolve_and_prepare_model(
        self,
        *,
        requested_profile: str,
        deadline: float,
        availability_timeout: float,
        diagnostics: dict[str, Any],
        allow_active_profile_switch: bool = True,
        gateway_standard_owner: bool = False,
        stop_requested: Callable[[], bool] | None = None,
        router_action_timeout: float | None = None,
    ) -> tuple[str, str, str | None]:
        lock_started = time.monotonic()
        with _profile_switch_lock(
            self._lock_path(),
            timeout=self._remaining_timeout(deadline=deadline),
            stop_requested=stop_requested,
        ):
            diagnostics["profile_switch_lock_elapsed_ms"] = int(
                (time.monotonic() - lock_started) * 1000
            )
            availability_started = time.monotonic()
            try:
                models = self._router_models(
                    timeout=self._remaining_timeout(
                        deadline=deadline,
                        maximum=availability_timeout,
                    )
                )
            except requests.Timeout as exc:
                diagnostics["availability_status"] = "provider_unavailable"
                diagnostics["timeout_phase"] = "provider_availability"
                raise LlamaCppAvailabilityTimeout() from exc
            except requests.RequestException as exc:
                diagnostics["availability_status"] = "provider_unavailable"
                raise LlamaCppProviderUnavailable() from exc
            finally:
                diagnostics["availability_elapsed_ms"] = int(
                    (time.monotonic() - availability_started) * 1000
                )
                diagnostics["provider_health_elapsed_ms"] = diagnostics[
                    "availability_elapsed_ms"
                ]

            diagnostics["availability_status"] = "router_reachable"
            available_ids = {item["id"] for item in models}
            resolution_started = time.monotonic()
            try:
                if gateway_standard_owner:
                    if (
                        requested_profile != "standard"
                        or llama_cpp_profile_models().get("standard")
                        != LLAMA_CPP_GATEWAY_STANDARD_MODEL
                    ):
                        raise LlamaCppProfileNotConfigured()
                    resolved_profile = "standard"
                    target_model = LLAMA_CPP_GATEWAY_STANDARD_MODEL
                    degraded_from = None
                else:
                    resolved = resolve_llama_cpp_profile(
                        requested_profile,
                        available_ids,
                    )
                    resolved_profile = resolved.profile
                    target_model = resolved.model
                    degraded_from = resolved.degraded_from
            finally:
                diagnostics["profile_resolution_elapsed_ms"] = int(
                    (time.monotonic() - resolution_started) * 1000
                )
            if target_model not in available_ids:
                diagnostics["availability_status"] = "profile_not_configured"
                diagnostics["model_load_state"] = "not_applicable"
                raise LlamaCppProfileNotConfigured()

            diagnostics["availability_status"] = "profile_configured"
            target = next((item for item in models if item["id"] == target_model), None)
            target_status = target.get("status") if target else None
            if (
                gateway_standard_owner
                and target_status not in LLAMA_CPP_BUSY_STATUSES
                and target_status not in LLAMA_CPP_INACTIVE_STATUSES
            ):
                diagnostics["model_load_state"] = "unknown_status"
                raise LlamaCppModelStatusUnknown()

            if (
                not allow_active_profile_switch
                and target_status not in LLAMA_CPP_ACTIVE_STATUSES
                and any(
                    item["id"] != target_model
                    and item.get("status") in LLAMA_CPP_BUSY_STATUSES
                    for item in models
                )
            ):
                diagnostics["model_load_state"] = "prewarm_deferred"
                raise LlamaCppPrewarmDeferred()

            if self._exclusive_model() and allow_active_profile_switch:
                for item in models:
                    if item["id"] != target_model and item.get("status") in LLAMA_CPP_ACTIVE_STATUSES:
                        self._post_router_action(
                            "unload",
                            item["id"],
                            timeout=self._remaining_timeout(deadline=deadline),
                        )
                        diagnostics["profile_unload_count"] += 1
                        diagnostics["profile_switch_count"] += 1
                        diagnostics["action"] = "unload"
                        diagnostics["reason"] = "exclusive_profile_conflict"
                        logger.info(
                            "llama_cpp_profile_action request_id_hash=%s "
                            "caller_kind=%s task=%s requested_profile=%s "
                            "effective_profile=%s action=%s reason=%s",
                            diagnostics.get("request_id_hash"),
                            diagnostics.get("caller_kind"),
                            diagnostics.get("task"),
                            diagnostics.get("requested_profile"),
                            diagnostics.get("effective_profile"),
                            "unload",
                            "exclusive_profile_conflict",
                        )

            if not self._auto_profile_switch() and not gateway_standard_owner:
                if not target or target.get("status") not in LLAMA_CPP_ACTIVE_STATUSES:
                    diagnostics["model_load_state"] = "model_not_loaded"
                    diagnostics["model_was_loaded"] = False
                    raise LlamaCppProviderUnavailable()
                diagnostics["model_load_state"] = "already_loaded"
                diagnostics["model_was_loaded"] = True
                return resolved_profile, target_model, degraded_from

            if target_status in LLAMA_CPP_WARMING_STATUSES:
                diagnostics["model_load_state"] = "warming"
                diagnostics["model_was_loaded"] = False
                load_started = time.monotonic()
                try:
                    self._wait_until_active(
                        target_model,
                        deadline=deadline,
                        stop_requested=stop_requested,
                    )
                except (
                    requests.Timeout,
                    LlamaCppGenerationTimeout,
                    LlamaCppModelLoadTimeout,
                ) as exc:
                    diagnostics["model_load_state"] = "warming_timeout"
                    diagnostics["timeout_phase"] = "model_warmup"
                    raise LlamaCppModelWarmingTimeout() from exc
                finally:
                    diagnostics["profile_load_elapsed_ms"] = int(
                        (time.monotonic() - load_started) * 1000
                    )
                diagnostics["model_load_state"] = "loaded"
            elif not target or target_status not in LLAMA_CPP_ACTIVE_STATUSES:
                diagnostics["model_load_state"] = "load_required"
                diagnostics["model_was_loaded"] = False
                load_started = time.monotonic()
                try:
                    self._post_router_action(
                        "load",
                        target_model,
                        timeout=self._remaining_timeout(
                            deadline=deadline,
                            maximum=router_action_timeout,
                        ),
                    )
                    diagnostics["profile_load_count"] += 1
                    diagnostics["profile_switch_count"] += 1
                    diagnostics["action"] = "load"
                    diagnostics["reason"] = "target_not_active"
                    logger.info(
                        "llama_cpp_profile_action request_id_hash=%s "
                        "caller_kind=%s task=%s requested_profile=%s "
                        "effective_profile=%s action=%s reason=%s",
                        diagnostics.get("request_id_hash"),
                        diagnostics.get("caller_kind"),
                        diagnostics.get("task"),
                        diagnostics.get("requested_profile"),
                        diagnostics.get("effective_profile"),
                        "load",
                        "target_not_active",
                    )
                    self._wait_until_active(
                        target_model,
                        deadline=deadline,
                        stop_requested=stop_requested,
                    )
                except (
                    requests.Timeout,
                    LlamaCppGenerationTimeout,
                    LlamaCppModelLoadTimeout,
                ) as exc:
                    diagnostics["model_load_state"] = "load_timeout"
                    diagnostics["timeout_phase"] = "model_load"
                    raise LlamaCppModelLoadTimeout() from exc
                except requests.RequestException as exc:
                    diagnostics["model_load_state"] = "load_failed"
                    if gateway_standard_owner:
                        raise LlamaCppModelLoadRejected() from exc
                    raise LlamaCppProviderUnavailable() from exc
                except RuntimeError as exc:
                    diagnostics["model_load_state"] = "load_failed"
                    if gateway_standard_owner:
                        raise LlamaCppModelLoadRejected() from exc
                    raise
                finally:
                    diagnostics["profile_load_elapsed_ms"] = int(
                        (time.monotonic() - load_started) * 1000
                    )
                diagnostics["model_load_state"] = "loaded"
            else:
                diagnostics["model_load_state"] = "already_loaded"
                diagnostics["model_was_loaded"] = True
                diagnostics["profile_load_elapsed_ms"] = 0

            return resolved_profile, target_model, degraded_from

    @staticmethod
    def _new_diagnostics() -> dict[str, Any]:
        return {
            "availability_status": "not_checked",
            "model_load_state": "unknown",
            "model_was_loaded": None,
            "availability_elapsed_ms": None,
            "provider_health_elapsed_ms": None,
            "profile_resolution_elapsed_ms": None,
            "profile_load_elapsed_ms": None,
            "profile_switch_lock_elapsed_ms": 0,
            "generation_elapsed_ms": None,
            "generation_result": None,
            "thinking_disabled": None,
            "reasoning_retry_performed": False,
            "timeout_phase": None,
            "request_id_hash": None,
            "caller_kind": "other_ai_task",
            "task": None,
            "requested_profile": None,
            "effective_profile": None,
            "action": "none",
            "reason": "already_loaded",
            "profile_switch_count": 0,
            "profile_load_count": 0,
            "profile_unload_count": 0,
        }

    def inspect_profile_state(
        self,
        profile: str,
        *,
        timeout_seconds: float = 2,
    ) -> dict[str, Any]:
        started = time.monotonic()
        requested_profile = normalize_llama_cpp_profile(profile)
        target_model = llama_cpp_profile_models()[requested_profile]
        result: dict[str, Any] = {
            "state": "unknown",
            "router_reachable": False,
            "profile": requested_profile,
            "model": target_model,
            "target_status": "unknown",
            "active_profiles": [],
            "reason": "router_unavailable",
            "retryable": True,
            "elapsed_ms": 0,
        }

        if not self.config.enabled:
            result.update(
                state="failed",
                reason="provider_disabled",
                retryable=False,
            )
            return result
        if not self._router_enabled():
            result.update(
                state="failed",
                reason="router_disabled",
                retryable=False,
            )
            return result

        deadline = started + max(0.25, min(float(timeout_seconds), 5))
        try:
            with _profile_switch_lock(
                self._lock_path(),
                timeout=self._remaining_timeout(deadline=deadline),
            ):
                models = self._router_models(
                    timeout=self._remaining_timeout(
                        deadline=deadline,
                        maximum=2,
                    )
                )
        except LlamaCppProfileSwitchTimeout:
            result["reason"] = "profile_lock_busy"
        except (requests.RequestException, LlamaCppGenerationTimeout):
            result["reason"] = "router_unavailable"
        else:
            profile_by_model = {
                model: name for name, model in llama_cpp_profile_models().items()
            }
            active_profiles = sorted(
                {
                    profile_by_model.get(item["id"], "unknown")
                    for item in models
                    if item.get("status") in LLAMA_CPP_BUSY_STATUSES
                }
            )
            target = next(
                (item for item in models if item["id"] == target_model),
                None,
            )
            target_router_status = target.get("status") if target else None
            if target_router_status in LLAMA_CPP_ACTIVE_STATUSES:
                target_status = "loaded"
                state = "ready"
                reason = "target_ready"
                retryable = False
            elif target_router_status in LLAMA_CPP_WARMING_STATUSES:
                target_status = "loading"
                state = "warming"
                reason = "target_loading"
                retryable = True
            elif any(
                active_profile != requested_profile
                for active_profile in active_profiles
            ):
                target_status = "unloaded" if target is not None else "unknown"
                state = "unloaded"
                reason = "active_profile_conflict"
                retryable = True
            elif target is not None:
                target_status = "unloaded"
                state = "unloaded"
                reason = "target_unloaded"
                retryable = True
            else:
                target_status = "unknown"
                state = "unknown"
                reason = "target_unknown"
                retryable = True

            result.update(
                state=state,
                router_reachable=True,
                target_status=target_status,
                active_profiles=active_profiles,
                reason=reason,
                retryable=retryable,
            )
        finally:
            result["elapsed_ms"] = int((time.monotonic() - started) * 1000)

        return result

    def prewarm_profile(
        self,
        profile: str,
        *,
        timeout_seconds: float,
        stop_requested: Callable[[], bool] | None = None,
        allow_active_profile_switch: bool = False,
    ) -> dict[str, Any]:
        return self._prewarm_profile(
            profile,
            timeout_seconds=timeout_seconds,
            stop_requested=stop_requested,
            allow_active_profile_switch=allow_active_profile_switch,
        )

    def prewarm_gateway_standard(
        self,
        *,
        timeout_seconds: float,
        stop_requested: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        return self._prewarm_profile(
            "standard",
            timeout_seconds=timeout_seconds,
            stop_requested=stop_requested,
            allow_active_profile_switch=True,
            gateway_standard_owner=True,
        )

    def _prewarm_profile(
        self,
        profile: str,
        *,
        timeout_seconds: float,
        stop_requested: Callable[[], bool] | None = None,
        allow_active_profile_switch: bool = False,
        gateway_standard_owner: bool = False,
    ) -> dict[str, Any]:
        started = time.monotonic()
        diagnostics = self._new_diagnostics()
        requested_profile = normalize_llama_cpp_profile(profile)
        diagnostics.update(
            {
                "caller_kind": (
                    "inference_gateway"
                    if gateway_standard_owner
                    else "assistant_prewarm"
                ),
                "task": (
                    "gateway_readiness"
                    if gateway_standard_owner
                    else "soc_assistant"
                ),
                "requested_profile": requested_profile,
                "effective_profile": requested_profile,
            }
        )
        if gateway_standard_owner and (
            requested_profile != "standard"
            or llama_cpp_profile_models().get("standard")
            != LLAMA_CPP_GATEWAY_STANDARD_MODEL
        ):
            diagnostics["availability_status"] = "profile_not_configured"
            diagnostics["model_load_state"] = "not_applicable"
            return {
                "state": "failed",
                "profile": "standard",
                "model": LLAMA_CPP_GATEWAY_STANDARD_MODEL,
                "router_reachable": False,
                "target_status": "unknown",
                "active_profiles": [],
                "reason": "standard_profile_not_configured",
                "retryable": False,
                "safe_error": "LlamaCppProfileNotConfigured",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "diagnostics": diagnostics,
            }
        inspection = self.inspect_profile_state(
            requested_profile,
            timeout_seconds=min(max(float(timeout_seconds), 0.25), 2),
        )
        base_result = {
            "profile": requested_profile,
            "model": inspection.get("model"),
            "router_reachable": bool(inspection.get("router_reachable")),
            "target_status": inspection.get("target_status") or "unknown",
            "active_profiles": list(inspection.get("active_profiles") or []),
            "diagnostics": diagnostics,
        }
        inspection_reason = str(inspection.get("reason") or "unknown")
        if inspection_reason == "provider_disabled":
            return {
                **base_result,
                "state": "failed",
                "reason": "provider_disabled",
                "retryable": False,
                "safe_error": "ProviderDisabled",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        if inspection_reason == "router_disabled":
            return {
                **base_result,
                "state": "failed",
                "reason": "router_disabled",
                "retryable": False,
                "safe_error": "LlamaCppRouterDisabled",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        if not inspection.get("router_reachable"):
            return {
                **base_result,
                "state": "unknown",
                "reason": inspection_reason,
                "retryable": True,
                "safe_error": "LlamaCppProviderUnavailable",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        if inspection_reason == "target_ready":
            return {
                **base_result,
                "state": "ready",
                "reason": "target_ready",
                "retryable": False,
                "safe_error": None,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        if (
            inspection_reason == "active_profile_conflict"
            and not gateway_standard_owner
        ):
            diagnostics["model_load_state"] = "prewarm_deferred"
            return {
                **base_result,
                "state": "unloaded",
                "reason": "active_profile_conflict",
                "retryable": True,
                "safe_error": "PrewarmDeferred",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }
        if inspection_reason == "target_unknown":
            reason = (
                "standard_profile_not_configured"
                if gateway_standard_owner
                else "target_unknown"
            )
            return {
                **base_result,
                "state": "unknown",
                "reason": reason,
                "retryable": not gateway_standard_owner,
                "safe_error": "LlamaCppProfileNotConfigured",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
            }

        selected_model = str(inspection.get("model") or "") or None
        try:
            selected_profile, selected_model, _ = self._resolve_and_prepare_model(
                requested_profile=requested_profile,
                deadline=started + max(0.25, float(timeout_seconds)),
                availability_timeout=min(max(float(timeout_seconds), 0.25), 2),
                diagnostics=diagnostics,
                allow_active_profile_switch=allow_active_profile_switch,
                gateway_standard_owner=gateway_standard_owner,
                stop_requested=stop_requested,
                router_action_timeout=2,
            )
            return {
                **base_result,
                "state": "ready",
                "profile": selected_profile,
                "model": selected_model,
                "router_reachable": True,
                "target_status": "loaded",
                "active_profiles": [selected_profile],
                "reason": "target_ready",
                "retryable": False,
                "safe_error": None,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "diagnostics": diagnostics,
            }
        except LlamaCppPrewarmDeferred:
            return {
                **base_result,
                "state": "unloaded",
                "profile": requested_profile,
                "model": selected_model,
                "reason": "active_profile_conflict",
                "retryable": True,
                "safe_error": "PrewarmDeferred",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "diagnostics": diagnostics,
            }
        except LlamaCppPrewarmStopped:
            return {
                **base_result,
                "state": "unknown",
                "reason": "shutdown",
                "retryable": False,
                "safe_error": "PrewarmStopped",
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "diagnostics": diagnostics,
            }
        except Exception as exc:
            reason = {
                "LlamaCppAvailabilityTimeout": "router_unavailable",
                "LlamaCppProviderUnavailable": "router_unavailable",
                "LlamaCppProfileSwitchTimeout": "profile_lock_busy",
                "LlamaCppProfileNotConfigured": (
                    "standard_profile_not_configured"
                    if gateway_standard_owner
                    else "target_unknown"
                ),
                "LlamaCppModelWarmingTimeout": "model_warming_timeout",
                "LlamaCppModelLoadTimeout": "model_load_timeout",
                "LlamaCppModelLoadRejected": "model_load_rejected",
                "LlamaCppModelStatusUnknown": "model_status_unknown",
            }.get(type(exc).__name__, "prewarm_failed")
            return {
                **base_result,
                "state": "failed",
                "profile": requested_profile,
                "model": selected_model,
                "reason": reason,
                "retryable": reason != "standard_profile_not_configured",
                "safe_error": type(exc).__name__,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "diagnostics": diagnostics,
            }

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
        deadline = min(
            float(opts.get("deadline_monotonic") or (started + timeout)),
            started + timeout,
        )
        availability_timeout = max(
            0.05,
            min(float(opts.get("availability_timeout_seconds") or 2), 2),
        )
        requested_profile = normalize_llama_cpp_profile(str(opts.get("llm_profile") or "standard"))
        selected_profile = requested_profile
        selected_model = str(opts.get("model") or self.config.model or "")
        diagnostics = self._new_diagnostics()
        caller_kind = str(opts.get("caller_kind") or "other_ai_task")
        if caller_kind not in {
            "assistant_primary",
            "assistant_prewarm",
            "other_ai_task",
        }:
            caller_kind = "other_ai_task"
        request_id_hash = str(opts.get("request_id_hash") or "")
        diagnostics.update(
            {
                "request_id_hash": (
                    request_id_hash
                    if re.fullmatch(r"[a-f0-9]{8,64}", request_id_hash)
                    else None
                ),
                "caller_kind": caller_kind,
                "task": feature,
                "requested_profile": requested_profile,
                "effective_profile": requested_profile,
            }
        )

        try:
            selected_profile, selected_model, degraded_from = self._resolve_and_prepare_model(
                requested_profile=requested_profile,
                deadline=deadline,
                availability_timeout=availability_timeout,
                diagnostics=diagnostics,
            )
            diagnostics["effective_profile"] = selected_profile
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
            chat_template_kwargs = opts.get("chat_template_kwargs")
            if isinstance(chat_template_kwargs, dict):
                payload["chat_template_kwargs"] = dict(chat_template_kwargs)
            thinking_disabled = bool(
                isinstance(chat_template_kwargs, dict)
                and chat_template_kwargs.get("enable_thinking") is False
            )
            diagnostics["thinking_disabled"] = thinking_disabled
            qwen_compatibility_required = bool(
                thinking_disabled
                and opts.get("qwen_no_think_compatibility", False)
                and llama_cpp_profile_model_family(selected_profile).startswith(
                    "qwen3"
                )
            )
            if (
                qwen_compatibility_required
                and payload.get("response_format") is not None
            ):
                payload["messages"] = _messages_with_no_think(chat_messages)

            generation_started = time.monotonic()
            try:
                def complete(request_payload: dict[str, Any]) -> tuple[dict[str, Any], str, bool]:
                    response = requests.post(
                        f"{self._api_base_url()}/chat/completions",
                        json=request_payload,
                        headers=self._headers(),
                        timeout=self._remaining_timeout(deadline=deadline),
                    )
                    try:
                        response.raise_for_status()
                    except requests.HTTPError as exc:
                        status_code = int(
                            getattr(getattr(exc, "response", None), "status_code", 0)
                            or 0
                        )
                        if (
                            request_payload.get("response_format") is not None
                            and 400 <= status_code < 500
                        ):
                            raise LlamaCppStructuredOutputRejected() from exc
                        raise
                    try:
                        response_data = response.json()
                    except Exception as exc:
                        raise LlamaCppInvalidResponse() from exc
                    choice = (response_data.get("choices") or [{}])[0] or {}
                    message = choice.get("message") or {}
                    visible_text = str(message.get("content") or "").strip()
                    reasoning_only = bool(
                        not visible_text
                        and str(message.get("reasoning_content") or "").strip()
                    )
                    return response_data, visible_text, reasoning_only

                data, text, reasoning_only = complete(payload)
                should_retry_reasoning = bool(
                    reasoning_only
                    and opts.get("reasoning_retry_allowed", False)
                    and (not thinking_disabled or qwen_compatibility_required)
                    and deadline - time.monotonic() >= 0.25
                )
                if should_retry_reasoning:
                    retry_payload = dict(payload)
                    retry_chat_kwargs = dict(
                        retry_payload.get("chat_template_kwargs") or {}
                    )
                    retry_chat_kwargs["enable_thinking"] = False
                    retry_payload["chat_template_kwargs"] = retry_chat_kwargs
                    if qwen_compatibility_required:
                        retry_payload["messages"] = _messages_with_no_think(
                            chat_messages
                        )
                    diagnostics["reasoning_retry_performed"] = True
                    diagnostics["thinking_disabled"] = True
                    data, text, reasoning_only = complete(retry_payload)
                    if text:
                        diagnostics["generation_result"] = (
                            "visible_content_after_retry"
                        )

                diagnostics.update(_llama_cpp_timing_diagnostics(data))
                if reasoning_only:
                    diagnostics["generation_result"] = "empty_visible_content"
                    raise LlamaCppEmptyVisibleContent()
                if not text:
                    raise LlamaCppInvalidResponse()
                final_choice = (data.get("choices") or [{}])[0] or {}
                if final_choice.get("finish_reason") == "length":
                    diagnostics["generation_result"] = "visible_content_truncated"
                elif diagnostics["generation_result"] is None:
                    diagnostics["generation_result"] = "visible_content"
            except requests.Timeout as exc:
                diagnostics["timeout_phase"] = "primary_generation"
                raise LlamaCppGenerationTimeout() from exc
            except requests.RequestException as exc:
                raise LlamaCppProviderUnavailable() from exc
            finally:
                diagnostics["generation_elapsed_ms"] = int(
                    (time.monotonic() - generation_started) * 1000
                )

            choice = (data.get("choices") or [{}])[0] or {}
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
                diagnostics=diagnostics,
            )
        except Exception as exc:
            if isinstance(exc, LlamaCppProfileSwitchTimeout):
                diagnostics["timeout_phase"] = "profile_switch_lock"
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
                diagnostics=diagnostics,
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
