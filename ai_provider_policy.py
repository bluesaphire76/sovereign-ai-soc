from __future__ import annotations

from dataclasses import asdict
from typing import Any

from ai_model_policy import AiTask
from ai_provider_abstraction import AIProviderResponse, build_provider_client
from ai_provider_audit import record_ai_provider_audit
from ai_provider_redaction import REDACTION_BLOCK_EXTERNAL, REDACTION_LOCAL_ONLY
from ai_provider_registry import (
    PROVIDER_LOCAL_OLLAMA,
    ProviderConfig,
    ProviderRegistry,
    load_provider_registry,
)


TASK_FEATURE_MAP = {
    AiTask.INCIDENT_TRIAGE.value: "incident_triage",
    AiTask.INCIDENT_ANALYSIS.value: "incident_ai_analysis",
    AiTask.COMMAND_ROOM.value: "incident_command_brief",
    AiTask.CASE_ANALYSIS.value: "case_ai_analysis",
    AiTask.DETECTION_QUALITY.value: "detection_quality_how_to_execute",
    AiTask.ACTION_HOW_TO.value: "detection_quality_how_to_execute",
    AiTask.EXECUTIVE_SUMMARY.value: "executive_insights",
    AiTask.REPORT.value: "report_support",
    AiTask.REMEDIATION.value: "remediation_explanation",
    AiTask.CLASSIFICATION.value: "classification",
    AiTask.ROUTING.value: "routing",
}


def normalize_feature(task_or_feature: AiTask | str) -> str:
    value = task_or_feature.value if isinstance(task_or_feature, AiTask) else str(task_or_feature or "")
    normalized = value.strip().lower()
    return TASK_FEATURE_MAP.get(normalized, normalized)


def select_provider_config(
    *,
    feature: str,
    registry: ProviderRegistry | None = None,
) -> ProviderConfig:
    current_registry = registry or load_provider_registry()
    provider_key = current_registry.feature_overrides.get(feature) or current_registry.default_provider
    selected = current_registry.get(provider_key) or current_registry.get("local_ollama")
    if selected is None:
        raise RuntimeError("Local Ollama provider configuration is missing.")
    return selected


def _blocked_response(
    *,
    config: ProviderConfig,
    feature: str,
    safe_error: str,
) -> AIProviderResponse:
    return AIProviderResponse(
        provider_key=config.key,
        provider_type=config.provider_type,
        model=config.model,
        text="",
        finish_reason=None,
        latency_ms=0,
        used_external_provider=config.external,
        redaction_applied=False,
        fallback_used=False,
        safe_error=safe_error,
        usage=None,
        redaction_mode=config.redaction_mode,
        input_character_count_after_redaction=0,
        output_character_count=0,
    )


def external_block_reason(
    *,
    config: ProviderConfig,
    feature: str,
    registry: ProviderRegistry,
) -> str | None:
    if not config.external:
        return None

    if not registry.external_providers_enabled:
        return "ExternalProvidersGloballyDisabled"

    if not config.enabled:
        return "ProviderDisabled"

    if not config.configured:
        return "ProviderNotConfigured"

    if feature not in set(config.feature_allowlist):
        return "FeatureNotAllowlisted"

    if config.redaction_mode in {REDACTION_BLOCK_EXTERNAL, REDACTION_LOCAL_ONLY}:
        return "ExternalRedactionModeBlocksCall"

    return None


def generate_with_provider(
    *,
    feature: AiTask | str,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    context: dict[str, Any] | None = None,
    options: dict[str, Any] | None = None,
    data_control: dict[str, Any] | None = None,
    current_user: dict[str, Any] | None = None,
) -> AIProviderResponse:
    feature_key = normalize_feature(feature)
    registry = load_provider_registry()
    config = select_provider_config(feature=feature_key, registry=registry)

    if config.provider_type == PROVIDER_LOCAL_OLLAMA:
        client = build_provider_client(config)
        return client.generate(
            feature=feature_key,
            prompt=prompt,
            messages=messages,
            context=context,
            options=options,
            data_control={"redaction_mode": REDACTION_LOCAL_ONLY},
        )

    block_reason = external_block_reason(config=config, feature=feature_key, registry=registry)
    if block_reason:
        response = _blocked_response(config=config, feature=feature_key, safe_error=block_reason)
        record_ai_provider_audit(
            event_type="AI_PROVIDER_EXTERNAL_CALL_BLOCKED",
            outcome="DENIED",
            provider_key=config.key,
            provider_type=config.provider_type,
            feature=feature_key,
            model=config.model,
            external=True,
            redaction_mode=config.redaction_mode,
            redaction_applied=False,
            input_character_count_after_redaction=0,
            output_character_count=0,
            latency_ms=0,
            fallback_used=False,
            safe_error=block_reason,
            current_user=current_user,
            incident_id=(context or {}).get("incident_id"),
            case_id=(context or {}).get("case_id"),
        )
        return response

    client = build_provider_client(config)
    response = client.generate(
        feature=feature_key,
        prompt=prompt,
        messages=messages,
        context=context,
        options=options,
        data_control={**(data_control or {}), "redaction_mode": config.redaction_mode},
    )
    record_ai_provider_audit(
        event_type="AI_PROVIDER_EXTERNAL_CALL",
        outcome="SUCCESS" if response.text and not response.safe_error else "FAILURE",
        provider_key=response.provider_key,
        provider_type=response.provider_type,
        feature=feature_key,
        model=response.model,
        external=response.used_external_provider,
        redaction_mode=response.redaction_mode,
        redaction_applied=response.redaction_applied,
        input_character_count_after_redaction=response.input_character_count_after_redaction,
        output_character_count=response.output_character_count,
        latency_ms=response.latency_ms,
        fallback_used=response.fallback_used,
        safe_error=response.safe_error,
        current_user=current_user,
        incident_id=(context or {}).get("incident_id"),
        case_id=(context or {}).get("case_id"),
        request_metadata={"usage": response.usage or {}},
    )
    return response


def provider_capabilities() -> dict[str, Any]:
    return {
        "provider_types": [
            "LOCAL_OLLAMA",
            "OPENAI_COMPATIBLE",
            "AZURE_OPENAI_COMPATIBLE",
            "ANTHROPIC_COMPATIBLE",
            "CUSTOM_HTTP_COMPATIBLE",
            "DISABLED",
        ],
        "redaction_modes": [
            "LOCAL_ONLY",
            "METADATA_ONLY",
            "REDACTED_CONTEXT",
            "BLOCK_EXTERNAL",
        ],
        "feature_keys": sorted(set(TASK_FEATURE_MAP.values())),
        "external_provider_adapter_status": {
            "OPENAI_COMPATIBLE": "implemented",
            "AZURE_OPENAI_COMPATIBLE": "configuration_visible",
            "ANTHROPIC_COMPATIBLE": "configuration_visible",
            "CUSTOM_HTTP_COMPATIBLE": "configuration_visible",
        },
    }


def health_to_dict(value: Any) -> dict[str, Any]:
    return asdict(value)
