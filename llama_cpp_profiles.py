from __future__ import annotations

import os
from dataclasses import dataclass

from ai_model_config import LlmProfile
from ai_model_policy import AiTask


LLAMA_CPP_PROVIDER_KEY = "local_llama_cpp"
LLAMA_CPP_DEFAULT_ROUTER_BASE_URL = "http://127.0.0.1:8081"
LLAMA_CPP_DEFAULT_API_BASE_URL = "http://127.0.0.1:8081/v1"
LLAMA_CPP_DEFAULT_LOCK_PATH = "/tmp/ai-soc-llama-cpp-profile.lock"
LLAMA_CPP_PROFILE_NAMES = ("fast", "standard", "quality")


@dataclass(frozen=True)
class ResolvedLlamaCppProfile:
    profile: str
    model: str
    degraded_from: str | None = None


def _env_str(name: str, default: str) -> str:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip()
    return normalized or default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env_str(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env_str(name, str(default)))
    except ValueError:
        return default


def normalize_llama_cpp_profile(value: str | None, default: str = "standard") -> str:
    normalized = str(value or default).lower().strip()
    if normalized == "auto":
        normalized = default
    return normalized if normalized in LLAMA_CPP_PROFILE_NAMES else default


def llama_cpp_profile_models() -> dict[str, str]:
    return {
        "fast": _env_str("LLAMA_CPP_FAST_MODEL", "ai-soc-fast"),
        "standard": _env_str("LLAMA_CPP_STANDARD_MODEL", "ai-soc-standard"),
        "quality": _env_str("LLAMA_CPP_QUALITY_MODEL", "ai-soc-quality"),
    }


def llama_cpp_profile_timeout(profile: str) -> int:
    normalized = normalize_llama_cpp_profile(profile)
    env_names = {
        "fast": "LLAMA_CPP_FAST_TIMEOUT_SECONDS",
        "standard": "LLAMA_CPP_STANDARD_TIMEOUT_SECONDS",
        "quality": "LLAMA_CPP_QUALITY_TIMEOUT_SECONDS",
    }
    defaults = {
        "fast": 15,
        "standard": 30,
        "quality": 60,
    }
    return _env_int(env_names[normalized], defaults[normalized])


def get_llama_cpp_profile(profile: str | None) -> LlmProfile:
    normalized = normalize_llama_cpp_profile(profile)
    models = llama_cpp_profile_models()
    return LlmProfile(
        name=normalized,
        model=models[normalized],
        num_ctx=_env_int("LLAMA_CPP_NUM_CTX", 4096),
        temperature=_env_float("LLAMA_CPP_TEMPERATURE", 0.2),
        timeout_seconds=llama_cpp_profile_timeout(normalized),
        keep_alive="",
    )


def _task_value(task: AiTask | str | None) -> str:
    if isinstance(task, AiTask):
        return task.value
    return str(task or "").lower().strip()


def default_llama_cpp_profile() -> str:
    return normalize_llama_cpp_profile(_env_str("LLM_DEFAULT_PROFILE", "standard"))


def select_llama_cpp_profile(
    *,
    task: AiTask | str | None,
    requested_mode: str | None = None,
    severity: str | None = None,
    user_triggered: bool = False,
) -> str:
    requested = str(requested_mode or "").lower().strip()
    if requested in LLAMA_CPP_PROFILE_NAMES:
        return requested

    task_name = _task_value(task)
    if not task_name:
        return default_llama_cpp_profile()

    fast_tasks = {
        AiTask.CLASSIFICATION.value,
        AiTask.ROUTING.value,
        AiTask.INCIDENT_TRIAGE.value,
        "fallback",
        "provider_test",
        "smoke",
        "worker_triage",
    }
    standard_tasks = {
        AiTask.ACTION_HOW_TO.value,
        AiTask.CASE_ANALYSIS.value,
        AiTask.COMMAND_ROOM.value,
        AiTask.DETECTION_QUALITY.value,
        AiTask.INCIDENT_ANALYSIS.value,
        "case_ai_analysis",
        "detection_quality_how_to_execute",
        "incident_ai_analysis",
        "incident_command_brief",
        "recommended_playbooks",
        "similar_incidents",
    }
    quality_tasks = {
        AiTask.EXECUTIVE_SUMMARY.value,
        AiTask.REMEDIATION.value,
        AiTask.REPORT.value,
        "detailed_remediation",
        "executive_insights",
        "remediation_explanation",
        "report_polish",
        "report_support",
    }

    if task_name in fast_tasks:
        return "fast"
    if task_name in standard_tasks:
        return "standard"
    if task_name in quality_tasks:
        return "quality"

    severity_upper = str(severity or "").upper().strip()
    if user_triggered and severity_upper in {"HIGH", "CRITICAL"}:
        return "quality"

    return default_llama_cpp_profile()


def resolve_llama_cpp_profile(
    preferred_profile: str | None,
    available_model_ids: set[str] | list[str] | tuple[str, ...],
) -> ResolvedLlamaCppProfile:
    preferred = normalize_llama_cpp_profile(preferred_profile)
    models = llama_cpp_profile_models()
    available = {str(model).strip() for model in available_model_ids if str(model).strip()}

    if preferred == "quality":
        candidates = ("quality", "standard", "fast")
    elif preferred == "standard":
        candidates = ("standard", "fast")
    else:
        candidates = ("fast",)

    for profile in candidates:
        model = models[profile]
        if model in available:
            return ResolvedLlamaCppProfile(
                profile=profile,
                model=model,
                degraded_from=preferred if profile != preferred else None,
            )

    fallback_model = models["fast"]
    return ResolvedLlamaCppProfile(
        profile="fast",
        model=fallback_model,
        degraded_from=preferred if preferred != "fast" else None,
    )
