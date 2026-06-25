from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ai_model_config import OLLAMA_BASE_URL as LEGACY_OLLAMA_BASE_URL, get_profile
from llama_cpp_profiles import (
    LLAMA_CPP_DEFAULT_API_BASE_URL,
    LLAMA_CPP_DEFAULT_LOCK_PATH,
    LLAMA_CPP_DEFAULT_ROUTER_BASE_URL,
    llama_cpp_profile_models,
)
from ai_provider_redaction import (
    REDACTION_BLOCK_EXTERNAL,
    REDACTION_LOCAL_ONLY,
    REDACTION_MODES,
)


PROVIDER_LOCAL_OLLAMA = "LOCAL_OLLAMA"
PROVIDER_LOCAL_LLAMA_CPP = "LOCAL_LLAMA_CPP"
PROVIDER_OPENAI_COMPATIBLE = "OPENAI_COMPATIBLE"
PROVIDER_AZURE_OPENAI_COMPATIBLE = "AZURE_OPENAI_COMPATIBLE"
PROVIDER_ANTHROPIC_COMPATIBLE = "ANTHROPIC_COMPATIBLE"
PROVIDER_CUSTOM_HTTP_COMPATIBLE = "CUSTOM_HTTP_COMPATIBLE"
PROVIDER_DISABLED = "DISABLED"

PROVIDER_TYPES = {
    PROVIDER_LOCAL_OLLAMA,
    PROVIDER_LOCAL_LLAMA_CPP,
    PROVIDER_OPENAI_COMPATIBLE,
    PROVIDER_AZURE_OPENAI_COMPATIBLE,
    PROVIDER_ANTHROPIC_COMPATIBLE,
    PROVIDER_CUSTOM_HTTP_COMPATIBLE,
    PROVIDER_DISABLED,
}

PROVIDER_DISPLAY_NAMES = {
    "local_ollama": "Ollama",
    "local_llama_cpp": "llama.cpp",
    "openrouter": "Openrouter",
    "openai_compatible": "OpenAI",
    "azure_openai_compatible": "MS Azure",
    "anthropic_compatible": "Anthropic",
    "custom_http_compatible": "Custom HTTP",
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


LOCAL_PROVIDER_TYPES = {
    PROVIDER_LOCAL_OLLAMA,
    PROVIDER_LOCAL_LLAMA_CPP,
}


def is_local_provider_type(provider_type: str | None) -> bool:
    return str(provider_type or "").upper().strip() in LOCAL_PROVIDER_TYPES


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
        if is_local_provider_type(self.provider_type):
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


def _optional_api_key_value(value: str | None) -> str | None:
    if not value:
        return None
    if str(value).strip().lower() in {"no-key", "none", "null", "local-only"}:
        return None
    return str(value).strip()


def _env_optional_api_key(name: str) -> str | None:
    value = _env_str(name)
    if not value:
        return None
    if value.lower() in {"no-key", "none", "null", "local-only"}:
        return None
    return value


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


def _logical_provider_key(value: str | None) -> str | None:
    normalized = str(value or "").lower().strip()
    if not normalized:
        return None
    mapping = {
        "ollama": "local_ollama",
        "local_ollama": "local_ollama",
        "llama_cpp": "local_llama_cpp",
        "llama.cpp": "local_llama_cpp",
        "local_llama_cpp": "local_llama_cpp",
    }
    return mapping.get(normalized, normalized)


def _external_provider_from_env(
    *,
    key: str,
    provider_type: str,
    display_name: str,
    prefix: str,
    default_base_url: str | None = None,
) -> ProviderConfig:
    return ProviderConfig(
        key=key,
        provider_type=provider_type,
        display_name=display_name,
        enabled=_env_bool(f"{prefix}_ENABLED", False),
        external=True,
        base_url=_env_str(f"{prefix}_BASE_URL", default_base_url),
        model=_env_str(f"{prefix}_MODEL"),
        api_key=_env_str(f"{prefix}_API_KEY"),
        timeout_seconds=_env_float(f"{prefix}_TIMEOUT_SECONDS", 30),
        max_tokens=_env_int(f"{prefix}_MAX_TOKENS", 800),
        feature_allowlist=_csv(_env_str(f"{prefix}_FEATURE_ALLOWLIST", "")),
        redaction_mode=_redaction_mode(_env_str(f"{prefix}_REDACTION_MODE"), REDACTION_BLOCK_EXTERNAL),
        metadata={
            "enabled_env": f"{prefix}_ENABLED",
            "base_url_env": f"{prefix}_BASE_URL",
            "model_env": f"{prefix}_MODEL",
            "api_key_env": f"{prefix}_API_KEY",
            "timeout_seconds_env": f"{prefix}_TIMEOUT_SECONDS",
            "max_tokens_env": f"{prefix}_MAX_TOKENS",
            "feature_allowlist_env": f"{prefix}_FEATURE_ALLOWLIST",
            "redaction_mode_env": f"{prefix}_REDACTION_MODE",
        },
    )


def _providers_from_env() -> dict[str, ProviderConfig]:
    local_profile = get_profile("standard")
    local = ProviderConfig(
        key="local_ollama",
        provider_type=PROVIDER_LOCAL_OLLAMA,
        display_name=PROVIDER_DISPLAY_NAMES["local_ollama"],
        enabled=_env_bool("AI_OLLAMA_ENABLED", True),
        external=False,
        base_url=_env_str("AI_OLLAMA_BASE_URL", LEGACY_OLLAMA_BASE_URL),
        model=_env_str("AI_OLLAMA_MODEL", local_profile.model),
        timeout_seconds=_env_float("AI_OLLAMA_TIMEOUT_SECONDS", float(local_profile.timeout_seconds)),
        feature_allowlist=_csv(_env_str("AI_OLLAMA_FEATURE_ALLOWLIST")) or LOCAL_FEATURE_ALLOWLIST,
        redaction_mode=REDACTION_LOCAL_ONLY,
        metadata={
            "enabled_env": "AI_OLLAMA_ENABLED",
            "base_url_env": "AI_OLLAMA_BASE_URL",
            "model_env": "AI_OLLAMA_MODEL",
            "timeout_seconds_env": "AI_OLLAMA_TIMEOUT_SECONDS",
            "feature_allowlist_env": "AI_OLLAMA_FEATURE_ALLOWLIST",
        },
    )
    llama_cpp_models = llama_cpp_profile_models()
    llama_cpp_router_base_url = _env_str("LLAMA_CPP_BASE_URL", LLAMA_CPP_DEFAULT_ROUTER_BASE_URL)
    llama_cpp_api_base_url = _env_str("LLAMA_CPP_API_BASE_URL", LLAMA_CPP_DEFAULT_API_BASE_URL)
    local_llama_cpp = ProviderConfig(
        key="local_llama_cpp",
        provider_type=PROVIDER_LOCAL_LLAMA_CPP,
        display_name=PROVIDER_DISPLAY_NAMES["local_llama_cpp"],
        enabled=_env_bool("LLAMA_CPP_ENABLED", False),
        external=False,
        base_url=llama_cpp_api_base_url,
        model=llama_cpp_models["fast"],
        api_key=_env_optional_api_key("LLAMA_CPP_API_KEY"),
        timeout_seconds=_env_float("LLAMA_CPP_TIMEOUT_SECONDS", 30),
        feature_allowlist=LOCAL_FEATURE_ALLOWLIST,
        redaction_mode=REDACTION_LOCAL_ONLY,
        metadata={
            "enabled_env": "LLAMA_CPP_ENABLED",
            "router_enabled_env": "LLAMA_CPP_ROUTER_ENABLED",
            "base_url_env": "LLAMA_CPP_BASE_URL",
            "api_base_url_env": "LLAMA_CPP_API_BASE_URL",
            "api_key_env": "LLAMA_CPP_API_KEY",
            "timeout_seconds_env": "LLAMA_CPP_TIMEOUT_SECONDS",
            "fast_model_env": "LLAMA_CPP_FAST_MODEL",
            "standard_model_env": "LLAMA_CPP_STANDARD_MODEL",
            "quality_model_env": "LLAMA_CPP_QUALITY_MODEL",
            "auto_profile_switch_env": "LLAMA_CPP_AUTO_PROFILE_SWITCH",
            "exclusive_model_env": "LLAMA_CPP_EXCLUSIVE_MODEL",
            "profile_switch_lock_env": "LLAMA_CPP_PROFILE_SWITCH_LOCK",
            "router_base_url": llama_cpp_router_base_url,
            "native_ui_url": llama_cpp_router_base_url,
            "profile_switch_lock": _env_str("LLAMA_CPP_PROFILE_SWITCH_LOCK", LLAMA_CPP_DEFAULT_LOCK_PATH),
        },
    )

    providers = {
        local.key: local,
        local_llama_cpp.key: local_llama_cpp,
        "openrouter": _external_provider_from_env(
            key="openrouter",
            provider_type=PROVIDER_OPENAI_COMPATIBLE,
            display_name=PROVIDER_DISPLAY_NAMES["openrouter"],
            prefix="AI_OPENROUTER",
            default_base_url="https://openrouter.ai/api/v1",
        ),
        "openai_compatible": _external_provider_from_env(
            key="openai_compatible",
            provider_type=PROVIDER_OPENAI_COMPATIBLE,
            display_name=PROVIDER_DISPLAY_NAMES["openai_compatible"],
            prefix="AI_OPENAI_COMPATIBLE",
        ),
        "azure_openai_compatible": _external_provider_from_env(
            key="azure_openai_compatible",
            provider_type=PROVIDER_AZURE_OPENAI_COMPATIBLE,
            display_name=PROVIDER_DISPLAY_NAMES["azure_openai_compatible"],
            prefix="AI_AZURE_OPENAI_COMPATIBLE",
        ),
        "anthropic_compatible": _external_provider_from_env(
            key="anthropic_compatible",
            provider_type=PROVIDER_ANTHROPIC_COMPATIBLE,
            display_name=PROVIDER_DISPLAY_NAMES["anthropic_compatible"],
            prefix="AI_ANTHROPIC_COMPATIBLE",
        ),
        "custom_http_compatible": _external_provider_from_env(
            key="custom_http_compatible",
            provider_type=PROVIDER_CUSTOM_HTTP_COMPATIBLE,
            display_name=PROVIDER_DISPLAY_NAMES["custom_http_compatible"],
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
        local_provider = is_local_provider_type(provider_type)
        api_key_env = str(item.get("api_key_env") or "")
        api_key_value = _env_str(api_key_env) or (existing.api_key if existing else None)
        if local_provider:
            api_key_value = _optional_api_key_value(api_key_value)

        configured[key] = replace(
            existing
            or ProviderConfig(
                key=key,
                provider_type=provider_type,
                display_name=key.replace("_", " ").title(),
                enabled=False,
                external=not local_provider,
            ),
            provider_type=provider_type,
            display_name=PROVIDER_DISPLAY_NAMES.get(
                key,
                str(item.get("display_name") or (existing.display_name if existing else key)),
            ),
            enabled=bool(item.get("enabled", existing.enabled if existing else False)),
            external=False if local_provider else bool(item.get("external", True)),
            base_url=_env_str(str(item.get("base_url_env") or "")) or item.get("base_url") or (existing.base_url if existing else None),
            model=_env_str(str(item.get("model_env") or "")) or item.get("model") or (existing.model if existing else None),
            api_key=api_key_value,
            timeout_seconds=float(item.get("timeout_seconds", existing.timeout_seconds if existing else 30)),
            max_tokens=item.get("max_tokens", existing.max_tokens if existing else 800),
            feature_allowlist=list(item.get("feature_allowlist") or (existing.feature_allowlist if existing else [])),
            redaction_mode=_redaction_mode(
                str(item.get("redaction_mode") or ""),
                existing.redaction_mode if existing else REDACTION_BLOCK_EXTERNAL,
            ),
            metadata={**(existing.metadata if existing else {}), **dict(item.get("metadata") or {})},
        )

    return configured


def load_provider_registry() -> ProviderRegistry:
    providers = _providers_from_env()
    config_path = _env_str("AI_PROVIDER_CONFIG_PATH", "storage/config/ai_providers.json")
    file_config = _load_config_file(config_path)
    providers = _apply_file_config(providers, file_config)
    default_provider = (
        str(file_config.get("default_provider") or "").strip()
        if isinstance(file_config, dict)
        else ""
    ) or _logical_provider_key(_env_str("AI_PROVIDER_DEFAULT")) or _logical_provider_key(
        _env_str("AI_LLM_PROVIDER", "ollama")
    ) or "local_ollama"
    if default_provider not in providers:
        default_provider = "local_ollama"

    if isinstance(file_config, dict) and "external_providers_enabled" in file_config:
        external_enabled = bool(file_config.get("external_providers_enabled"))
    else:
        external_enabled = _env_bool("AI_EXTERNAL_PROVIDERS_ENABLED", False)

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
        "base_url": config.base_url if include_api_key_presence else None,
        "base_url_configured": config.base_url_configured,
        "api_key_configured": config.api_key_configured if include_api_key_presence else None,
        "timeout_seconds": config.timeout_seconds,
        "max_tokens": config.max_tokens,
        "feature_allowlist": list(config.feature_allowlist),
        "redaction_mode": config.redaction_mode,
    }


def resolve_provider_config_path(path: str | None = None) -> Path:
    configured = path or _env_str("AI_PROVIDER_CONFIG_PATH", "storage/config/ai_providers.json")
    config_path = Path(configured)
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path
    return config_path


def _provider_file_item(config: ProviderConfig) -> dict[str, Any]:
    item: dict[str, Any] = {
        "key": config.key,
        "type": config.provider_type,
        "display_name": config.display_name,
        "enabled": config.enabled,
        "external": config.external,
        "base_url": config.base_url,
        "model": config.model,
        "timeout_seconds": config.timeout_seconds,
        "max_tokens": config.max_tokens,
        "feature_allowlist": list(config.feature_allowlist),
        "redaction_mode": config.redaction_mode,
        "metadata": dict(config.metadata),
    }
    api_key_env = config.metadata.get("api_key_env")
    if api_key_env:
        item["api_key_env"] = api_key_env
    return item


def _write_registry_config(registry: ProviderRegistry) -> None:
    path = resolve_provider_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "default_provider": registry.default_provider,
        "external_providers_enabled": registry.external_providers_enabled,
        "feature_overrides": dict(registry.feature_overrides),
        "providers": [_provider_file_item(config) for config in registry.providers.values()],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def save_registry_settings(
    *,
    default_provider: str | None = None,
    external_providers_enabled: bool | None = None,
    feature_overrides: dict[str, str] | None = None,
) -> ProviderRegistry:
    current = load_provider_registry()
    updated = ProviderRegistry(
        default_provider=default_provider if default_provider in current.providers else current.default_provider,
        external_providers_enabled=(
            current.external_providers_enabled
            if external_providers_enabled is None
            else bool(external_providers_enabled)
        ),
        providers=current.providers,
        feature_overrides=dict(current.feature_overrides if feature_overrides is None else feature_overrides),
    )
    _write_registry_config(updated)
    return load_provider_registry()


def save_provider_settings(
    provider_key: str,
    updates: dict[str, Any],
) -> ProviderRegistry:
    current = load_provider_registry()
    existing = current.get(provider_key)
    if existing is None:
        raise KeyError(provider_key)

    redaction_mode = _redaction_mode(
        str(updates.get("redaction_mode") or existing.redaction_mode),
        existing.redaction_mode,
    )
    provider = replace(
        existing,
        enabled=bool(updates.get("enabled", existing.enabled)),
        base_url=(str(updates.get("base_url")).strip() if updates.get("base_url") is not None else existing.base_url),
        model=(str(updates.get("model")).strip() if updates.get("model") is not None else existing.model),
        timeout_seconds=float(updates.get("timeout_seconds", existing.timeout_seconds)),
        max_tokens=(
            int(updates.get("max_tokens"))
            if updates.get("max_tokens") not in {None, ""}
            else existing.max_tokens
        ),
        feature_allowlist=[
            str(value).strip()
            for value in updates.get("feature_allowlist", existing.feature_allowlist)
            if str(value).strip()
        ],
        redaction_mode=redaction_mode,
    )
    providers = dict(current.providers)
    providers[provider_key] = provider
    updated = ProviderRegistry(
        default_provider=current.default_provider,
        external_providers_enabled=current.external_providers_enabled,
        providers=providers,
        feature_overrides=dict(current.feature_overrides),
    )
    _write_registry_config(updated)
    return load_provider_registry()
