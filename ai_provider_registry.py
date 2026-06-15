from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ai_model_config import OLLAMA_BASE_URL as LEGACY_OLLAMA_BASE_URL, get_profile
from ai_provider_redaction import (
    REDACTION_BLOCK_EXTERNAL,
    REDACTION_LOCAL_ONLY,
    REDACTION_MODES,
)


PROVIDER_LOCAL_OLLAMA = "LOCAL_OLLAMA"
PROVIDER_OPENAI_COMPATIBLE = "OPENAI_COMPATIBLE"
PROVIDER_AZURE_OPENAI_COMPATIBLE = "AZURE_OPENAI_COMPATIBLE"
PROVIDER_ANTHROPIC_COMPATIBLE = "ANTHROPIC_COMPATIBLE"
PROVIDER_CUSTOM_HTTP_COMPATIBLE = "CUSTOM_HTTP_COMPATIBLE"
PROVIDER_DISABLED = "DISABLED"

PROVIDER_TYPES = {
    PROVIDER_LOCAL_OLLAMA,
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_AZURE_OPENAI_COMPATIBLE,
    PROVIDER_ANTHROPIC_COMPATIBLE,
    PROVIDER_CUSTOM_HTTP_COMPATIBLE,
    PROVIDER_DISABLED,
}

LOCAL_FEATURE_ALLOWLIST = [
    "incident_triage",
    "incident_analysis",
    "incident_ai_analysis",
    "incident_command_brief",
    "command_room",
    "case_ai_analysis",
    "detection_quality",
    "detection_quality_how_to_execute",
    "action_how_to",
    "executive_insights",
    "executive_summary",
    "report",
    "report_support",
    "remediation",
    "remediation_explanation",
    "classification",
    "routing",
    "provider_test",
]


@dataclass(frozen=True)
class ProviderConfig:
    key: str
    provider_type: str
    display_name: str
    enabled: bool
    external: bool
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    timeout_seconds: float = 30
    max_tokens: int | None = None
    feature_allowlist: list[str] = field(default_factory=list)
    redaction_mode: str = REDACTION_BLOCK_EXTERNAL
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        if self.provider_type == PROVIDER_LOCAL_OLLAMA:
            return bool(self.base_url and self.model)

        if self.provider_type == PROVIDER_DISABLED:
            return False

        return bool(self.base_url and self.model and self.api_key)

    @property
    def base_url_configured(self) -> bool:
        return bool(self.base_url)

    @property
    def api_key_configured(self) -> bool:
        return bool(self.api_key)


@dataclass(frozen=True)
class ProviderRegistry:
    default_provider: str
    external_providers_enabled: bool
    providers: dict[str, ProviderConfig]
    feature_overrides: dict[str, str] = field(default_factory=dict)

    def get(self, provider_key: str | None) -> ProviderConfig | None:
        return self.providers.get((provider_key or "").strip())


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_str(name: str, default: str | None = None) -> str | None:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip()
    return value if value else default


def _env_float(name: str, default: float) -> float:
    raw = _env_str(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int | None = None) -> int | None:
    raw = _env_str(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _redaction_mode(value: str | None, default: str) -> str:
    normalized = (value or default).upper().strip()
    return normalized if normalized in REDACTION_MODES else default


def _feature_overrides_from_env() -> dict[str, str]:
    raw = _env_str("AI_PROVIDER_FEATURE_OVERRIDES", "")
    overrides: dict[str, str] = {}

    for item in _csv(raw):
        if ":" not in item:
            continue
        feature, provider_key = item.split(":", 1)
        feature = feature.strip()
        provider_key = provider_key.strip()
        if feature and provider_key:
            overrides[feature] = provider_key

    return overrides


def _external_provider_from_env(
    *,
    key: str,
    provider_type: str,
    display_name: str,
    prefix: str,
) -> ProviderConfig:
    return ProviderConfig(
        key=key,
        provider_type=provider_type,
        display_name=display_name,
        enabled=_env_bool(f"{prefix}_ENABLED", False),
        external=True,
        base_url=_env_str(f"{prefix}_BASE_URL"),
        model=_env_str(f"{prefix}_MODEL"),
        api_key=_env_str(f"{prefix}_API_KEY"),
        timeout_seconds=_env_float(f"{prefix}_TIMEOUT_SECONDS", 30),
        max_tokens=_env_int(f"{prefix}_MAX_TOKENS", 800),
        feature_allowlist=_csv(_env_str(f"{prefix}_FEATURE_ALLOWLIST", "")),
        redaction_mode=_redaction_mode(_env_str(f"{prefix}_REDACTION_MODE"), REDACTION_BLOCK_EXTERNAL),
    )


def _providers_from_env() -> dict[str, ProviderConfig]:
    local_profile = get_profile("standard")
    local = ProviderConfig(
        key="local_ollama",
        provider_type=PROVIDER_LOCAL_OLLAMA,
        display_name="Local Ollama",
        enabled=_env_bool("AI_OLLAMA_ENABLED", True),
        external=False,
        base_url=_env_str("AI_OLLAMA_BASE_URL", LEGACY_OLLAMA_BASE_URL),
        model=_env_str("AI_OLLAMA_MODEL", local_profile.model),
        timeout_seconds=_env_float("AI_OLLAMA_TIMEOUT_SECONDS", float(local_profile.timeout_seconds)),
        feature_allowlist=_csv(_env_str("AI_OLLAMA_FEATURE_ALLOWLIST")) or LOCAL_FEATURE_ALLOWLIST,
        redaction_mode=REDACTION_LOCAL_ONLY,
    )

    providers = {
        local.key: local,
        "openai_compatible": _external_provider_from_env(
            key="openai_compatible",
            provider_type=PROVIDER_OPENAI_COMPATIBLE,
            display_name="OpenAI-compatible provider",
            prefix="AI_OPENAI_COMPATIBLE",
        ),
        "azure_openai_compatible": _external_provider_from_env(
            key="azure_openai_compatible",
            provider_type=PROVIDER_AZURE_OPENAI_COMPATIBLE,
            display_name="Azure OpenAI-compatible provider",
            prefix="AI_AZURE_OPENAI_COMPATIBLE",
        ),
        "anthropic_compatible": _external_provider_from_env(
            key="anthropic_compatible",
            provider_type=PROVIDER_ANTHROPIC_COMPATIBLE,
            display_name="Anthropic-compatible provider",
            prefix="AI_ANTHROPIC_COMPATIBLE",
        ),
        "custom_http_compatible": _external_provider_from_env(
            key="custom_http_compatible",
            provider_type=PROVIDER_CUSTOM_HTTP_COMPATIBLE,
            display_name="Custom HTTP-compatible provider",
            prefix="AI_CUSTOM_HTTP_COMPATIBLE",
        ),
    }
    return providers


def _load_config_file(path: str | None) -> dict[str, Any]:
    if not path:
        return {}

    config_path = Path(path)
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path

    if not config_path.exists():
        return {}

    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _apply_file_config(
    providers: dict[str, ProviderConfig],
    file_config: dict[str, Any],
) -> dict[str, ProviderConfig]:
    configured = dict(providers)
    raw_providers = file_config.get("providers") if isinstance(file_config, dict) else None
    if not isinstance(raw_providers, list):
        return configured

    for item in raw_providers:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        if not key:
            continue

        existing = configured.get(key)
        provider_type = str(item.get("type") or (existing.provider_type if existing else PROVIDER_DISABLED)).upper()
        if provider_type not in PROVIDER_TYPES:
            provider_type = PROVIDER_DISABLED

        configured[key] = replace(
            existing
            or ProviderConfig(
                key=key,
                provider_type=provider_type,
                display_name=key.replace("_", " ").title(),
                enabled=False,
                external=provider_type != PROVIDER_LOCAL_OLLAMA,
            ),
            provider_type=provider_type,
            display_name=str(item.get("display_name") or (existing.display_name if existing else key)),
            enabled=bool(item.get("enabled", existing.enabled if existing else False)),
            external=bool(item.get("external", provider_type != PROVIDER_LOCAL_OLLAMA)),
            base_url=_env_str(str(item.get("base_url_env") or "")) or item.get("base_url") or (existing.base_url if existing else None),
            model=_env_str(str(item.get("model_env") or "")) or item.get("model") or (existing.model if existing else None),
            api_key=_env_str(str(item.get("api_key_env") or "")) or (existing.api_key if existing else None),
            timeout_seconds=float(item.get("timeout_seconds", existing.timeout_seconds if existing else 30)),
            max_tokens=item.get("max_tokens", existing.max_tokens if existing else 800),
            feature_allowlist=list(item.get("feature_allowlist") or (existing.feature_allowlist if existing else [])),
            redaction_mode=_redaction_mode(
                str(item.get("redaction_mode") or ""),
                existing.redaction_mode if existing else REDACTION_BLOCK_EXTERNAL,
            ),
            metadata=dict(item.get("metadata") or {}),
        )

    return configured


def load_provider_registry() -> ProviderRegistry:
    providers = _providers_from_env()
    config_path = _env_str("AI_PROVIDER_CONFIG_PATH", "storage/config/ai_providers.json")
    file_config = _load_config_file(config_path)
    providers = _apply_file_config(providers, file_config)
    default_provider = _env_str(
        "AI_PROVIDER_DEFAULT",
        str(file_config.get("default_provider") or "local_ollama") if isinstance(file_config, dict) else "local_ollama",
    )
    if default_provider not in providers:
        default_provider = "local_ollama"

    external_enabled = _env_bool(
        "AI_EXTERNAL_PROVIDERS_ENABLED",
        bool(file_config.get("external_providers_enabled", False)) if isinstance(file_config, dict) else False,
    )

    overrides = _feature_overrides_from_env()
    if isinstance(file_config, dict) and isinstance(file_config.get("feature_overrides"), dict):
        overrides.update(
            {
                str(feature): str(provider_key)
                for feature, provider_key in file_config["feature_overrides"].items()
            }
        )

    return ProviderRegistry(
        default_provider=default_provider,
        external_providers_enabled=external_enabled,
        providers=providers,
        feature_overrides=overrides,
    )


def provider_public_dict(config: ProviderConfig, *, include_api_key_presence: bool) -> dict[str, Any]:
    return {
        "key": config.key,
        "type": config.provider_type,
        "display_name": config.display_name,
        "enabled": config.enabled,
        "external": config.external,
        "configured": config.configured,
        "model": config.model,
        "base_url_configured": config.base_url_configured,
        "api_key_configured": config.api_key_configured if include_api_key_presence else None,
        "timeout_seconds": config.timeout_seconds,
        "max_tokens": config.max_tokens,
        "feature_allowlist": list(config.feature_allowlist),
        "redaction_mode": config.redaction_mode,
    }
