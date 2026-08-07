from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import replace
from typing import Any

import requests

from ai_data_control_policy import enforce_ai_data_policy
from ai_model_config import DEFAULT_LLM_MODE, LlmProfile, get_profile
from ai_model_policy import AiTask, select_profile
from ai_provider_abstraction import build_provider_client
from ai_provider_policy import generate_with_provider, normalize_feature, select_provider_config
from ai_provider_registry import PROVIDER_LOCAL_LLAMA_CPP, PROVIDER_LOCAL_OLLAMA, load_provider_registry
from llama_cpp_profiles import get_llama_cpp_profile, select_llama_cpp_profile


logger = logging.getLogger(__name__)

PROVIDER_ERROR_CODES = {
    "provider_unavailable",
    "timeout",
    "policy_blocked",
    "authentication_error",
    "invalid_response",
    "empty_visible_content",
    "model_warming_timeout",
    "unknown_provider_error",
}
SOC_ASSISTANT_VISIBLE_MAX_TOKENS_DEFAULT = 384
SOC_ASSISTANT_QUALITY_VISIBLE_MAX_TOKENS_DEFAULT = 512
SOC_ASSISTANT_VISIBLE_MAX_TOKENS_MIN = 256
SOC_ASSISTANT_VISIBLE_MAX_TOKENS_MAX = 768
SOC_ASSISTANT_QUALITY_VISIBLE_MAX_TOKENS_MAX = 512


def normalize_provider_error(value: Any) -> str | None:
    """Map internal provider failures to stable, non-sensitive diagnostics."""

    raw = str(value or "").strip()
    if not raw:
        return None

    normalized = raw.lower().replace("-", "_").replace(" ", "_")
    if normalized in PROVIDER_ERROR_CODES:
        return normalized
    if "emptyvisiblecontent" in normalized or "empty_visible_content" in normalized:
        return "empty_visible_content"
    if "modelwarmingtimeout" in normalized or "model_warming_timeout" in normalized:
        return "model_warming_timeout"
    if "structuredoutputrejected" in normalized:
        return "invalid_response"
    if any(token in normalized for token in ("timeout", "timed_out", "readtimeout")):
        return "timeout"
    if any(
        token in normalized
        for token in (
            "policy",
            "denied",
            "forbidden",
            "not_allowed",
            "notallowlisted",
            "allowlist",
            "datapolicy",
            "redaction",
            "blockscall",
        )
    ):
        return "policy_blocked"
    if any(
        token in normalized
        for token in ("authentication", "unauthorized", "credential", "api_key", "401")
    ):
        return "authentication_error"
    if any(
        token in normalized
        for token in ("invalid", "decode", "malformed", "empty_response", "response_format")
    ):
        return "invalid_response"
    if any(
        token in normalized
        for token in (
            "connection",
            "connecterror",
            "unavailable",
            "disabled",
            "notloaded",
            "not_loaded",
            "router",
            "refused",
            "runtimeerror",
            "profilenotconfigured",
            "modelnotloaded",
        )
    ):
        return "provider_unavailable"
    if "invalidresponse" in normalized:
        return "invalid_response"
    return "unknown_provider_error"


def generate_ai_response(
    *,
    prompt: str | None = None,
    messages: list[dict[str, Any]] | None = None,
    task: AiTask | str,
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
    allow_provider_fallback: bool = True,
    force_local_llama_cpp: bool = False,
    temperature: float | None = None,
    response_format: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not prompt and not messages:
        raise ValueError("prompt or messages is required")

    profile_name = select_profile(
        task=task,
        severity=severity,
        requested_mode=requested_mode or DEFAULT_LLM_MODE,
        user_triggered=user_triggered,
    )
    feature = normalize_feature(task)
    registry = load_provider_registry()
    provider = (
        registry.providers["local_llama_cpp"]
        if force_local_llama_cpp
        else select_provider_config(feature=feature, registry=registry)
    )

    if provider.provider_type == PROVIDER_LOCAL_LLAMA_CPP:
        assistant_reasoning_disabled = (
            feature == AiTask.SOC_ASSISTANT.value
            or bool((context or {}).get("disable_reasoning"))
        )
        llama_profile_name = select_llama_cpp_profile(
            task=task,
            severity=severity,
            requested_mode=requested_mode,
            user_triggered=user_triggered,
        )
        profile = get_llama_cpp_profile(llama_profile_name)
        response = generate_with_provider(
            feature=feature,
            prompt=prompt,
            messages=messages,
            context=context,
            options=_profile_options(
                profile=profile,
                timeout_seconds=timeout_seconds,
                deadline_monotonic=deadline_monotonic,
                availability_timeout_seconds=availability_timeout_seconds,
                max_tokens=(
                    _soc_assistant_visible_max_tokens(
                        requested_mode=requested_mode,
                        override=max_visible_tokens,
                    )
                    if assistant_reasoning_disabled
                    else None
                ),
                chat_template_kwargs=(
                    {"enable_thinking": False}
                    if assistant_reasoning_disabled
                    else None
                ),
                reasoning_retry_allowed=(
                    assistant_reasoning_disabled and response_format is None
                ),
                qwen_no_think_compatibility=assistant_reasoning_disabled,
                caller_kind=(
                    str((context or {}).get("caller_kind") or "")
                    if assistant_reasoning_disabled
                    else "other_ai_task"
                ),
                request_id_hash=(
                    str((context or {}).get("request_id_hash") or "")
                    if assistant_reasoning_disabled
                    else None
                ),
                temperature=temperature,
                response_format=response_format,
            ),
            current_user=current_user,
            registry=registry,
            provider_config=provider,
        )
        primary_result = _provider_result(
            response=response,
            profile=profile,
            fallback_used=False,
            error_type=response.safe_error,
        )
        primary_result["primary_elapsed_ms"] = response.latency_ms or 0
        primary_result["selected_profile"] = (
            getattr(response, "profile", None) or profile.name
        )
        primary_result["timeout_reason"] = _timeout_reason(
            error=response.safe_error,
            diagnostics=primary_result.get("provider_diagnostics"),
            deadline_monotonic=deadline_monotonic,
            phase="primary",
        )

        if response.safe_error == "LlamaCppEmptyVisibleContent":
            primary_result["fallback_skipped_reason"] = "empty_visible_content"
            return _with_generation_diagnostics(
                primary_result,
                primary_provider=provider.key,
                fallback_attempted=False,
                requested_mode=requested_mode,
            )

        if (
            allow_provider_fallback
            and response.safe_error
            and _logical_provider_key(
                os.getenv("AI_LLM_FALLBACK_PROVIDER", "ollama")
            )
            == "local_ollama"
        ):
            logger.warning(
                "AI provider fallback primary=%s fallback=%s task=%s reason=%s",
                provider.key,
                "local_ollama",
                feature,
                response.safe_error,
            )
            primary_result["fallback_provider"] = "local_ollama"
            remaining = _remaining_budget(deadline_monotonic)
            fallback_budget = min(
                float(fallback_timeout_seconds or timeout_seconds or profile.timeout_seconds),
                remaining,
            )
            fallback_phase_deadline = time.monotonic() + fallback_budget
            if fallback_budget < 0.25:
                primary_result["fallback_skipped_reason"] = "total_budget_exhausted"
                primary_result["timeout_reason"] = "total_budget_exhausted"
                return _with_generation_diagnostics(
                    primary_result,
                    primary_provider=provider.key,
                    fallback_provider="local_ollama",
                    fallback_attempted=False,
                    requested_mode=requested_mode,
                )

            fallback_available = True
            availability_elapsed_ms = 0
            availability_status = "not_checked"
            if deadline_monotonic is not None or fallback_timeout_seconds is not None:
                fallback_available, availability_elapsed_ms, availability_status = (
                    _ollama_fallback_available(
                        profile_name=getattr(response, "profile", None) or profile.name,
                        timeout_seconds=min(
                            float(availability_timeout_seconds or 2),
                            fallback_budget,
                            2,
                        ),
                    )
                )
            primary_result["fallback_availability_elapsed_ms"] = availability_elapsed_ms
            primary_result["fallback_availability_status"] = availability_status
            if not fallback_available:
                primary_result["fallback_skipped_reason"] = "provider_unavailable"
                return _with_generation_diagnostics(
                    primary_result,
                    primary_provider=provider.key,
                    fallback_provider="local_ollama",
                    fallback_attempted=False,
                    requested_mode=requested_mode,
                )

            remaining = _remaining_budget(deadline_monotonic)
            fallback_budget = min(
                max(0.0, fallback_phase_deadline - time.monotonic()),
                remaining,
            )
            if fallback_budget < 0.25:
                primary_result["fallback_skipped_reason"] = "total_budget_exhausted"
                primary_result["timeout_reason"] = "total_budget_exhausted"
                return _with_generation_diagnostics(
                    primary_result,
                    primary_provider=provider.key,
                    fallback_provider="local_ollama",
                    fallback_attempted=False,
                    requested_mode=requested_mode,
                )

            fallback_deadline = fallback_phase_deadline
            if deadline_monotonic is not None:
                fallback_deadline = min(fallback_deadline, deadline_monotonic)
            fallback = _call_ollama_with_fallback(
                feature=feature,
                prompt=prompt,
                messages=messages,
                profile_name=getattr(response, "profile", None) or profile.name,
                timeout_seconds=fallback_budget,
                deadline_monotonic=fallback_deadline,
                allow_profile_fallback=False,
                context=context,
                current_user=current_user,
            )
            fallback["fallback_used"] = True
            fallback["primary_elapsed_ms"] = response.latency_ms or 0
            fallback["fallback_elapsed_ms"] = fallback.get("latency_ms") or 0
            fallback["fallback_availability_elapsed_ms"] = availability_elapsed_ms
            fallback["fallback_availability_status"] = availability_status
            fallback["provider_diagnostics"] = primary_result.get("provider_diagnostics")
            fallback["selected_profile"] = primary_result.get("selected_profile")
            fallback["timeout_reason"] = _timeout_reason(
                error=fallback.get("safe_error") or fallback.get("error_type"),
                diagnostics=primary_result.get("provider_diagnostics"),
                deadline_monotonic=deadline_monotonic,
                phase="fallback",
            )
            fallback = _with_generation_diagnostics(
                fallback,
                primary_provider=provider.key,
                fallback_provider="local_ollama",
                fallback_attempted=True,
                requested_mode=requested_mode,
            )
            _log_provider_selected(
                provider_key="local_ollama",
                provider_type=PROVIDER_LOCAL_OLLAMA,
                task=feature,
                profile=str(fallback.get("profile") or "unknown"),
                model=str(fallback.get("model") or "unknown"),
                external=False,
                fallback=True,
                redaction_mode=str(fallback.get("redaction_mode") or "LOCAL_ONLY"),
            )
            return fallback
        result = _with_generation_diagnostics(
            primary_result,
            primary_provider=provider.key,
            requested_mode=requested_mode,
        )
        _log_provider_selected(
            provider_key=response.provider_key,
            provider_type=response.provider_type,
            task=feature,
            profile=str(result.get("profile") or profile.name),
            model=str(result.get("model") or profile.model),
            external=response.used_external_provider,
            fallback=bool(result.get("fallback_used")),
            redaction_mode=response.redaction_mode,
        )
        return result

    if provider.provider_type != PROVIDER_LOCAL_OLLAMA:
        profile = get_profile(profile_name)
        response = generate_with_provider(
            feature=feature,
            prompt=prompt,
            messages=messages,
            context=context,
            options=_profile_options(
                profile=profile,
                timeout_seconds=timeout_seconds,
                deadline_monotonic=deadline_monotonic,
                availability_timeout_seconds=availability_timeout_seconds,
                response_format=response_format,
            ),
            current_user=current_user,
            registry=registry,
            provider_config=provider,
        )
        result = _provider_result(
            response=response,
            profile=profile,
            fallback_used=False,
            error_type=response.safe_error,
        )
        result["primary_elapsed_ms"] = response.latency_ms or 0
        result["selected_profile"] = profile.name
        result["timeout_reason"] = _timeout_reason(
            error=response.safe_error,
            diagnostics=result.get("provider_diagnostics"),
            deadline_monotonic=deadline_monotonic,
            phase="primary",
        )
        result = _with_generation_diagnostics(
            result,
            primary_provider=provider.key,
            requested_mode=requested_mode,
        )
        _log_provider_selected(
            provider_key=response.provider_key,
            provider_type=response.provider_type,
            task=feature,
            profile=str(result.get("profile") or profile.name),
            model=str(result.get("model") or profile.model),
            external=response.used_external_provider,
            fallback=bool(result.get("fallback_used")),
            redaction_mode=response.redaction_mode,
        )
        return result

    result = _call_ollama_with_fallback(
        feature=feature,
        prompt=prompt,
        messages=messages,
        profile_name=profile_name,
        timeout_seconds=timeout_seconds,
        deadline_monotonic=deadline_monotonic,
        context=context,
        current_user=current_user,
    )
    result.setdefault("primary_elapsed_ms", result.get("latency_ms") or 0)
    result.setdefault("selected_profile", profile_name)
    result["timeout_reason"] = _timeout_reason(
        error=result.get("safe_error") or result.get("error_type"),
        diagnostics=None,
        deadline_monotonic=deadline_monotonic,
        phase="primary",
    )
    result = _with_generation_diagnostics(
        result,
        primary_provider=provider.key,
        fallback_provider="local_ollama" if result.get("fallback_used") else None,
        fallback_attempted=bool(result.get("fallback_used")),
        requested_mode=requested_mode,
    )
    _log_provider_selected(
        provider_key="local_ollama",
        provider_type=PROVIDER_LOCAL_OLLAMA,
        task=feature,
        profile=str(result.get("profile") or profile_name),
        model=str(result.get("model") or "unknown"),
        external=False,
        fallback=bool(result.get("fallback_used")),
        redaction_mode=str(result.get("redaction_mode") or "LOCAL_ONLY"),
    )
    return result


def _call_ollama_with_fallback(
    *,
    feature: str,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    profile_name: str,
    timeout_seconds: float | None,
    deadline_monotonic: float | None = None,
    allow_profile_fallback: bool = True,
    context: dict[str, Any] | None = None,
    current_user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    profile = get_profile(profile_name)
    local_deadline = started + float(timeout_seconds or profile.timeout_seconds)
    if deadline_monotonic is not None:
        local_deadline = min(local_deadline, deadline_monotonic)
    call_kwargs = {
        "feature": feature,
        "prompt": prompt,
        "messages": messages,
    }
    if context is not None:
        call_kwargs["context"] = context
    if current_user is not None:
        call_kwargs["current_user"] = current_user

    primary_started = time.monotonic()
    try:
        attempt_timeout = _remaining_budget(local_deadline)
        if attempt_timeout < 0.05:
            raise requests.exceptions.Timeout("AssistantTotalBudgetExceeded")
        text = _call_ollama(
            **call_kwargs,
            profile=profile,
            timeout_seconds=attempt_timeout,
        )
        result = _result(
            text=text,
            profile=profile,
            fallback_used=False,
            error_type=None,
            started=started,
        )
        result["primary_elapsed_ms"] = int(
            (time.monotonic() - primary_started) * 1000
        )
        result["fallback_elapsed_ms"] = 0
        return result
    except Exception as exc:
        primary_elapsed_ms = int((time.monotonic() - primary_started) * 1000)
        if profile.name == "fast" or not allow_profile_fallback:
            result = _result(
                text="",
                profile=profile,
                fallback_used=False,
                error_type=type(exc).__name__,
                started=started,
            )
            result["primary_elapsed_ms"] = primary_elapsed_ms
            result["fallback_elapsed_ms"] = 0
            return result

        if _remaining_budget(local_deadline) < 0.25:
            result = _result(
                text="",
                profile=profile,
                fallback_used=False,
                error_type="AssistantTotalBudgetExceeded",
                started=started,
            )
            result["primary_elapsed_ms"] = primary_elapsed_ms
            result["fallback_elapsed_ms"] = 0
            return result

        fallback = get_profile("fast")
        logger.warning(
            "AI provider fallback primary=%s fallback=%s task=%s reason=%s",
            "local_ollama",
            "local_ollama",
            feature,
            type(exc).__name__,
        )

        fallback_started = time.monotonic()
        try:
            attempt_timeout = _remaining_budget(local_deadline)
            if attempt_timeout < 0.05:
                raise requests.exceptions.Timeout("AssistantTotalBudgetExceeded")
            text = _call_ollama(
                **call_kwargs,
                profile=fallback,
                timeout_seconds=attempt_timeout,
            )
            result = _result(
                text=text,
                profile=fallback,
                fallback_used=True,
                error_type=type(exc).__name__,
                started=started,
            )
            result["primary_elapsed_ms"] = primary_elapsed_ms
            result["fallback_elapsed_ms"] = int(
                (time.monotonic() - fallback_started) * 1000
            )
            return result
        except Exception as fallback_exc:
            result = _result(
                text="",
                profile=fallback,
                fallback_used=True,
                error_type=type(fallback_exc).__name__,
                started=started,
            )
            result["primary_elapsed_ms"] = primary_elapsed_ms
            result["fallback_elapsed_ms"] = int(
                (time.monotonic() - fallback_started) * 1000
            )
            return result


def _call_ollama(
    *,
    feature: str,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    profile: LlmProfile,
    timeout_seconds: float | None,
    context: dict[str, Any] | None = None,
    current_user: dict[str, Any] | None = None,
) -> str:
    registry = load_provider_registry()
    config = registry.get("local_ollama")
    if config is None:
        raise RuntimeError("Local Ollama provider configuration is missing.")

    policy_decision = enforce_ai_data_policy(
        feature_key=feature,
        provider_config=config,
        registry=registry,
        prompt=prompt,
        messages=messages,
        context=context,
        current_user=current_user,
    )
    if not policy_decision.allowed:
        raise RuntimeError(policy_decision.reason or "AIDataPolicyDenied")

    client = build_provider_client(config)
    response = client.generate(
        feature=feature,
        prompt=policy_decision.transformed_prompt,
        messages=policy_decision.transformed_messages,
        context=policy_decision.transformed_context,
        options=_profile_options(profile=profile, timeout_seconds=timeout_seconds),
        data_control={
            "redaction_mode": policy_decision.mode,
            "policy_preprocessed": True,
            "policy_decision_id": policy_decision.decision_id,
            "policy_redaction_applied": policy_decision.redaction_applied,
            "policy_output_character_count": policy_decision.output_character_count,
            "policy_replacements": dict(policy_decision.replacements),
        },
    )

    if response.safe_error:
        if response.safe_error in {
            "ReadTimeout",
            "Timeout",
            "TimeoutError",
            "TimeoutException",
        }:
            raise requests.exceptions.Timeout(response.safe_error)
        raise RuntimeError(response.safe_error)

    return response.text


def _result(
    *,
    text: str,
    profile: LlmProfile,
    fallback_used: bool,
    error_type: str | None,
    started: float,
) -> dict[str, Any]:
    return {
        "text": text,
        "profile": profile.name,
        "model": profile.model,
        "fallback_used": fallback_used,
        "error_type": error_type,
        "latency_ms": int((time.monotonic() - started) * 1000),
        "provider_key": "local_ollama",
        "provider_type": PROVIDER_LOCAL_OLLAMA,
        "used_external_provider": False,
        "redaction_applied": False,
        "redaction_mode": "LOCAL_ONLY",
        "safe_error": error_type,
    }


def _remaining_budget(deadline_monotonic: float | None) -> float:
    if deadline_monotonic is None:
        return float("inf")
    return max(0.0, deadline_monotonic - time.monotonic())


def _ollama_fallback_available(
    *,
    profile_name: str,
    timeout_seconds: float,
) -> tuple[bool, int, str]:
    started = time.monotonic()
    registry = load_provider_registry()
    config = registry.get("local_ollama")
    if config is None or not config.enabled:
        return False, int((time.monotonic() - started) * 1000), "provider_unavailable"

    profile = get_profile(profile_name)
    bounded_config = replace(
        config,
        model=profile.model,
        timeout_seconds=max(0.05, min(float(timeout_seconds), 2)),
    )
    health = build_provider_client(bounded_config).health_check()
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if health.reachable is not True:
        return False, elapsed_ms, "provider_unavailable"
    if health.model_available is not True:
        return False, elapsed_ms, "model_unavailable"
    return True, elapsed_ms, "available"


def _timeout_reason(
    *,
    error: Any,
    diagnostics: Any,
    deadline_monotonic: float | None,
    phase: str,
) -> str | None:
    if not error:
        return None
    if str(error) == "AssistantTotalBudgetExceeded":
        return "total_budget_exhausted"
    details = diagnostics if isinstance(diagnostics, dict) else {}
    timeout_phase = str(details.get("timeout_phase") or "")
    if (
        timeout_phase == "model_warmup"
        or "ModelWarmingTimeout" in str(error)
    ):
        return "model_warming_timeout"
    if deadline_monotonic is not None and _remaining_budget(deadline_monotonic) <= 0:
        return "total_budget_exhausted"

    if timeout_phase == "model_load" or "ModelLoadTimeout" in str(error):
        return "model_load_timeout"
    if timeout_phase == "profile_switch_lock":
        return "primary_timeout"
    if normalize_provider_error(error) == "timeout":
        return "fallback_timeout" if phase == "fallback" else "primary_timeout"
    return None


def _profile_options(
    *,
    profile: LlmProfile,
    timeout_seconds: float | None,
    deadline_monotonic: float | None = None,
    availability_timeout_seconds: float | None = None,
    max_tokens: int | None = None,
    chat_template_kwargs: dict[str, Any] | None = None,
    reasoning_retry_allowed: bool = False,
    qwen_no_think_compatibility: bool = False,
    caller_kind: str | None = None,
    request_id_hash: str | None = None,
    temperature: float | None = None,
    response_format: dict[str, Any] | None = None,
) -> dict[str, Any]:
    options = {
        "model": profile.model,
        "llm_profile": profile.name,
        "num_ctx": profile.num_ctx,
        "temperature": (
            profile.temperature if temperature is None else temperature
        ),
        "timeout_seconds": timeout_seconds or profile.timeout_seconds,
        "keep_alive": profile.keep_alive,
    }
    if deadline_monotonic is not None:
        options["deadline_monotonic"] = deadline_monotonic
    if availability_timeout_seconds is not None:
        options["availability_timeout_seconds"] = availability_timeout_seconds
    if max_tokens is not None:
        options["max_tokens"] = max_tokens
    if chat_template_kwargs is not None:
        options["chat_template_kwargs"] = dict(chat_template_kwargs)
    if reasoning_retry_allowed:
        options["reasoning_retry_allowed"] = True
    if qwen_no_think_compatibility:
        options["qwen_no_think_compatibility"] = True
    if caller_kind in {
        "assistant_primary",
        "assistant_prewarm",
        "other_ai_task",
    }:
        options["caller_kind"] = caller_kind
    if request_id_hash and re.fullmatch(r"[a-f0-9]{8,64}", request_id_hash):
        options["request_id_hash"] = request_id_hash
    if response_format is not None:
        options["response_format"] = dict(response_format)
    return options


def _soc_assistant_visible_max_tokens(
    *,
    requested_mode: str | None = None,
    override: int | None = None,
) -> int:
    quality = str(requested_mode or "").strip().lower() == "quality"
    default = (
        SOC_ASSISTANT_QUALITY_VISIBLE_MAX_TOKENS_DEFAULT
        if quality
        else SOC_ASSISTANT_VISIBLE_MAX_TOKENS_DEFAULT
    )
    maximum = (
        SOC_ASSISTANT_QUALITY_VISIBLE_MAX_TOKENS_MAX
        if quality
        else SOC_ASSISTANT_VISIBLE_MAX_TOKENS_MAX
    )
    try:
        configured = (
            int(override)
            if override is not None
            else int(
                os.getenv(
                    (
                        "AI_SOC_ASSISTANT_QUALITY_MAX_VISIBLE_TOKENS"
                        if quality
                        else "AI_SOC_ASSISTANT_MAX_VISIBLE_TOKENS"
                    ),
                    os.getenv(
                        "AI_SOC_ASSISTANT_VISIBLE_MAX_TOKENS",
                        str(default),
                    ),
                )
            )
        )
    except (TypeError, ValueError):
        configured = default
    return min(
        max(configured, SOC_ASSISTANT_VISIBLE_MAX_TOKENS_MIN),
        maximum,
    )


def _log_provider_selected(
    *,
    provider_key: str,
    provider_type: str,
    task: str,
    profile: str,
    model: str,
    external: bool,
    fallback: bool,
    redaction_mode: str,
) -> None:
    logger.info(
        "AI provider selected provider=%s type=%s task=%s profile=%s resolved_model=%s external=%s fallback=%s redaction_mode=%s",
        provider_key,
        provider_type,
        task,
        profile,
        model,
        str(external).lower(),
        str(fallback).lower(),
        redaction_mode,
    )


def _logical_provider_key(value: str | None) -> str | None:
    normalized = str(value or "").lower().strip()
    mapping = {
        "ollama": "local_ollama",
        "local_ollama": "local_ollama",
        "llama_cpp": "local_llama_cpp",
        "llama.cpp": "local_llama_cpp",
        "local_llama_cpp": "local_llama_cpp",
    }
    return mapping.get(normalized, normalized or None)


def _with_generation_diagnostics(
    result: dict[str, Any],
    *,
    primary_provider: str,
    fallback_provider: str | None = None,
    fallback_attempted: bool = False,
    requested_mode: str | None = None,
) -> dict[str, Any]:
    text = str(result.get("text") or "").strip()
    used_fallback = fallback_attempted or bool(result.get("fallback_used"))
    effective_provider = str(result.get("provider_key") or "").strip() or None
    effective_profile = str(result.get("profile") or "").strip() or None

    result.update(
        {
            "generation_kind": (
                "model_fallback"
                if text and used_fallback
                else "model_success"
                if text
                else "unavailable"
            ),
            "primary_provider": primary_provider,
            "attempted_provider": primary_provider,
            "attempted_profile": (
                result.get("selected_profile") or result.get("profile")
            ),
            "effective_provider": effective_provider if text else None,
            "effective_profile": effective_profile if text else None,
            "effective_model": result.get("model") if text else None,
            "fallback_provider": fallback_provider,
            "fallback_attempted": used_fallback,
            "provider_status": (
                "ok"
                if text
                else normalize_provider_error(
                    result.get("safe_error") or result.get("error_type")
                )
                or "invalid_response"
            ),
            "requested_mode": requested_mode or DEFAULT_LLM_MODE,
        }
    )
    return result


def _provider_result(
    *,
    response,
    profile: LlmProfile,
    fallback_used: bool,
    error_type: str | None,
) -> dict[str, Any]:
    return {
        "text": response.text,
        "profile": getattr(response, "profile", None) or profile.name,
        "model": response.model or profile.model,
        "finish_reason": response.finish_reason,
        "fallback_used": fallback_used or response.fallback_used,
        "error_type": error_type,
        "latency_ms": response.latency_ms or 0,
        "provider_key": response.provider_key,
        "provider_type": response.provider_type,
        "used_external_provider": response.used_external_provider,
        "redaction_applied": response.redaction_applied,
        "redaction_mode": response.redaction_mode,
        "safe_error": response.safe_error,
        "usage": response.usage,
        "provider_diagnostics": response.diagnostics,
    }
