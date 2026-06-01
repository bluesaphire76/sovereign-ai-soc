from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*args, **kwargs):
        return False


load_dotenv()


@dataclass(frozen=True)
class LlmProfile:
    name: str
    model: str
    num_ctx: int
    temperature: float
    timeout_seconds: int
    keep_alive: str


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


OLLAMA_BASE_URL = _env_str("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
LEGACY_OLLAMA_MODEL = _env_str("OLLAMA_MODEL", "")
DEFAULT_LLM_MODE = _env_str("AI_SOC_LLM_MODE", "auto").lower()

FAST_PROFILE = LlmProfile(
    name="fast",
    model=_env_str("AI_SOC_LLM_FAST", "llama3.2:3b"),
    num_ctx=_env_int("AI_SOC_LLM_FAST_NUM_CTX", 2048),
    temperature=_env_float("AI_SOC_LLM_FAST_TEMPERATURE", 0.1),
    timeout_seconds=_env_int("AI_SOC_LLM_FAST_TIMEOUT", 20),
    keep_alive=_env_str("AI_SOC_LLM_FAST_KEEP_ALIVE", "30s"),
)

STANDARD_PROFILE = LlmProfile(
    name="standard",
    model=_env_str("AI_SOC_LLM_STANDARD", LEGACY_OLLAMA_MODEL or "qwen3.5:4b"),
    num_ctx=_env_int("AI_SOC_LLM_STANDARD_NUM_CTX", 4096),
    temperature=_env_float("AI_SOC_LLM_STANDARD_TEMPERATURE", 0.2),
    timeout_seconds=_env_int("AI_SOC_LLM_STANDARD_TIMEOUT", 45),
    keep_alive=_env_str("AI_SOC_LLM_STANDARD_KEEP_ALIVE", "2m"),
)

QUALITY_PROFILE = LlmProfile(
    name="quality",
    model=_env_str("AI_SOC_LLM_QUALITY", "llama3.1:8b-instruct-q4_K_M"),
    num_ctx=_env_int("AI_SOC_LLM_QUALITY_NUM_CTX", 4096),
    temperature=_env_float("AI_SOC_LLM_QUALITY_TEMPERATURE", 0.2),
    timeout_seconds=_env_int("AI_SOC_LLM_QUALITY_TIMEOUT", 90),
    keep_alive=_env_str("AI_SOC_LLM_QUALITY_KEEP_ALIVE", "0s"),
)

PROFILES = {
    "fast": FAST_PROFILE,
    "standard": STANDARD_PROFILE,
    "quality": QUALITY_PROFILE,
}


def get_profile(profile_name: str | None) -> LlmProfile:
    normalized = (profile_name or "standard").lower().strip()

    if normalized == "auto":
        normalized = "standard"

    return PROFILES.get(normalized, STANDARD_PROFILE)
