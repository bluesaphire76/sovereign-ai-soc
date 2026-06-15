from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ai_provider_registry import ProviderConfig, ProviderRegistry
from database import SessionLocal
from models import SecurityAuditEvent


POLICY_EXTERNAL_AI_DISABLED = "EXTERNAL_AI_DISABLED"
POLICY_LOCAL_ONLY = "LOCAL_ONLY"
POLICY_METADATA_ONLY = "METADATA_ONLY"
POLICY_REDACTED_CONTEXT = "REDACTED_CONTEXT"
POLICY_FULL_CONTEXT_ADMIN_ONLY = "FULL_CONTEXT_ADMIN_ONLY"
POLICY_CUSTOM_ALLOWLIST = "CUSTOM_ALLOWLIST"
POLICY_FEATURE_DISABLED = "FEATURE_DISABLED"

POLICY_MODES = {
    POLICY_EXTERNAL_AI_DISABLED,
    POLICY_LOCAL_ONLY,
    POLICY_METADATA_ONLY,
    POLICY_REDACTED_CONTEXT,
    POLICY_FULL_CONTEXT_ADMIN_ONLY,
    POLICY_CUSTOM_ALLOWLIST,
    POLICY_FEATURE_DISABLED,
}

DATA_CLASSES = [
    "PUBLIC",
    "INTERNAL",
    "SENSITIVE_SOC",
    "SECRET",
    "CREDENTIAL",
    "PERSONAL_DATA",
    "RAW_SECURITY_TELEMETRY",
]

FEATURE_ALIASES = {
    "action_how_to": "how_to_execute",
    "case_analysis": "case_ai_analysis",
    "command_room": "incident_command_brief",
    "detection_quality": "detection_quality_assistance",
    "detection_quality_how_to_execute": "how_to_execute",
    "executive_summary": "executive_insights",
    "incident_analysis": "incident_ai_analysis",
    "remediation": "remediation_planning",
    "remediation_explanation": "remediation_planning",
    "report": "report_generation",
    "report_support": "report_generation",
}

FEATURE_DEFINITIONS: list[dict[str, str]] = [
    {
        "feature_key": "incident_triage",
        "display_name": "Incident triage",
        "description": "Initial alert enrichment and triage reasoning.",
    },
    {
        "feature_key": "incident_ai_analysis",
        "display_name": "Incident AI analysis",
        "description": "Analyst-facing incident analysis and summaries.",
    },
    {
        "feature_key": "incident_command_brief",
        "display_name": "Incident command brief",
        "description": "Command-room and stakeholder incident brief generation.",
    },
    {
        "feature_key": "case_ai_analysis",
        "display_name": "Case AI analysis",
        "description": "Case-level AI summaries and closure support.",
    },
    {
        "feature_key": "recommended_actions",
        "display_name": "Recommended actions",
        "description": "Recommended analyst actions for cases and incidents.",
    },
    {
        "feature_key": "how_to_execute",
        "display_name": "How to execute",
        "description": "Action guidance and execution instructions.",
    },
    {
        "feature_key": "executive_insights",
        "display_name": "Executive insights",
        "description": "Executive SOC summaries and business-facing insights.",
    },
    {
        "feature_key": "report_generation",
        "display_name": "Report generation",
        "description": "Incident, case and evidence report generation.",
    },
    {
        "feature_key": "detection_quality_assistance",
        "display_name": "Detection quality assistance",
        "description": "Detection tuning and quality guidance.",
    },
    {
        "feature_key": "remediation_planning",
        "display_name": "Remediation planning",
        "description": "Remediation plan explanation and risk review.",
    },
    {
        "feature_key": "external_remediation_assistance",
        "display_name": "External remediation assistance",
        "description": "Reserved external remediation advisory workflow.",
    },
    {
        "feature_key": "classification",
        "display_name": "Classification",
        "description": "Fast local classification and routing support.",
    },
    {
        "feature_key": "routing",
        "display_name": "Routing",
        "description": "Fast local routing and workflow selection support.",
    },
    {
        "feature_key": "provider_test",
        "display_name": "Provider test",
        "description": "Harmless provider connectivity validation.",
    },
]

SECRET_FIELD_MARKERS = {
    "access_token",
    "apikey",
    "api_key",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "connectionstring",
    "connection_string",
    "databaseurl",
    "database_url",
    "env",
    "jwttoken",
    "jwt",
    "ntfytoken",
    "ntfytopic",
    "ntfy_token",
    "ntfy_topic",
    "openaikey",
    "openaiapikey",
    "openai_api_key",
    "azureopenaiapikey",
    "azure_openai_api_key",
    "anthropicapikey",
    "anthropic_api_key",
    "ollamahost",
    "ollama_host",
    "passwd",
    "password",
    "privatekey",
    "private_key",
    "secret",
    "smtppassword",
    "smtp_password",
    "token",
}

CREDENTIAL_FIELD_MARKERS = {
    "credential",
    "authorization",
    "bearer",
    "cookie",
    "jwt",
    "token",
}

PERSONAL_FIELD_MARKERS = {
    "email",
    "user",
    "username",
}

IP_FIELD_MARKERS = {
    "destinationip",
    "destination_ip",
    "ip",
    "sourceip",
    "source_ip",
}

HOST_FIELD_MARKERS = {
    "agentname",
    "agent_name",
    "host",
    "hostname",
}

RAW_TELEMETRY_FIELD_MARKERS = {
    "dnsquery",
    "dns_query",
    "headers",
    "payload",
    "rawalert",
    "raw_alert",
    "rawevent",
    "raw_event",
    "request",
    "requestbody",
    "request_body",
    "response",
    "responsebody",
    "response_body",
    "suricataevent",
    "suricata_event",
    "wazuhevent",
    "wazuh_event",
}

FIELD_MARKERS = {
    "filepath",
    "file_path",
    "processcommandline",
    "process_command_line",
}

PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
TOKEN_RE = re.compile(
    r"(?i)\b(bearer\s+[a-z0-9._\-+/=]+|api[_-]?key\s*[:=]\s*[^\s,;]+|token\s*[:=]\s*[^\s,;]+)"
)
PASSWORD_RE = re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*[^\s,;]+")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
URL_CREDENTIAL_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@", re.IGNORECASE)
FILE_PATH_RE = re.compile(r"(?<![\w.-])(?:/[A-Za-z0-9._@%+\-]+){2,}")
HOSTNAME_RE = re.compile(
    r"\b(?=.{1,253}\b)(?![0-9.]+\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}\b"
)

POLICY_EVENT_TYPES = {
    "AI_DATA_POLICY_EVALUATED",
    "AI_DATA_POLICY_DENIED",
    "AI_DATA_POLICY_ALLOWED_LOCAL",
    "AI_DATA_POLICY_ALLOWED_EXTERNAL",
    "AI_DATA_POLICY_REDACTION_APPLIED",
    "AI_DATA_POLICY_CHANGED",
    "AI_DATA_POLICY_PREVIEW_RUN",
    "AI_DATA_POLICY_DECISION_VIEWED",
}


@dataclass(frozen=True)
class AiDataGlobalDefaults:
    default_mode: str = POLICY_LOCAL_ONLY
    external_default_policy: str = POLICY_EXTERNAL_AI_DISABLED
    audit_enabled: bool = True
    payload_preview_enabled: bool = True
    store_payload_hash: bool = True
    store_redacted_preview: bool = False


@dataclass(frozen=True)
class FeaturePolicy:
    feature_key: str
    display_name: str
    description: str
    mode: str = POLICY_LOCAL_ONLY
    allowed_provider_keys: list[str] = field(default_factory=list)
    allowed_roles: list[str] = field(default_factory=lambda: ["ADMIN", "ANALYST"])
    require_confirmation: bool = False
    payload_preview_enabled: bool = True
    store_payload_hash: bool = True
    store_redacted_preview: bool = False
    allow_raw_telemetry: bool = False
    allow_personal_data: bool = False
    audit_level: str = "decision"
    updated_at: str | None = None
    updated_by: str | None = None
    update_reason: str | None = None


@dataclass(frozen=True)
class RedactionSummary:
    transformed_value: Any
    applied: bool
    replacements: dict[str, int]
    input_character_count: int
    output_character_count: int


@dataclass(frozen=True)
class AiPolicyDecision:
    decision_id: str
    feature_key: str
    requested_feature_key: str
    provider_key: str
    provider_type: str
    model: str | None
    external: bool
    mode: str
    allowed: bool
    action: str
    reason: str | None
    actor_role: str | None
    redaction_applied: bool
    replacements: dict[str, int]
    input_character_count: int
    output_character_count: int
    payload_hash: str | None
    redacted_preview: Any | None
    transformed_prompt: str | None
    transformed_messages: list[dict[str, Any]] | None
    transformed_context: dict[str, Any] | None


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    value = raw.strip()
    return value or default


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def normalize_feature_key(feature_key: str | None) -> str:
    normalized = str(feature_key or "").strip().lower()
    return FEATURE_ALIASES.get(normalized, normalized)


def _normalize_field_name(name: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name or "").lower())


def _is_field_match(normalized: str, markers: set[str]) -> bool:
    collapsed_markers = {_normalize_field_name(marker) for marker in markers}
    return normalized in collapsed_markers or any(
        marker in normalized
        for marker in collapsed_markers
        if len(marker) > 3
    )


def _count(replacements: dict[str, int], key: str, amount: int = 1) -> None:
    replacements[key] = replacements.get(key, 0) + amount


def _json_dumps(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)


def payload_hash(value: Any) -> str:
    return hashlib.sha256(_json_dumps(value).encode("utf-8")).hexdigest()


def resolve_policy_config_path(path: str | None = None) -> Path:
    configured = path or _env_str("AI_DATA_POLICY_CONFIG_PATH", "storage/config/ai_data_control_policy.json")
    config_path = Path(configured)
    if not config_path.is_absolute():
        config_path = Path.cwd() / config_path
    return config_path


def _global_defaults_from_env() -> AiDataGlobalDefaults:
    mode = _env_str("AI_DATA_POLICY_DEFAULT_MODE", POLICY_LOCAL_ONLY).upper()
    external_mode = _env_str("AI_EXTERNAL_DEFAULT_POLICY", POLICY_EXTERNAL_AI_DISABLED).upper()
    return AiDataGlobalDefaults(
        default_mode=mode if mode in POLICY_MODES else POLICY_LOCAL_ONLY,
        external_default_policy=external_mode if external_mode in POLICY_MODES else POLICY_EXTERNAL_AI_DISABLED,
        audit_enabled=_env_bool("AI_POLICY_AUDIT_ENABLED", True),
        payload_preview_enabled=_env_bool("AI_POLICY_PAYLOAD_PREVIEW_ENABLED", True),
        store_payload_hash=_env_bool("AI_POLICY_STORE_PAYLOAD_HASH", True),
        store_redacted_preview=_env_bool("AI_POLICY_STORE_REDACTED_PREVIEW", False),
    )


def default_feature_policies() -> dict[str, FeaturePolicy]:
    defaults = _global_defaults_from_env()
    policies: dict[str, FeaturePolicy] = {}
    for item in FEATURE_DEFINITIONS:
        feature_key = item["feature_key"]
        mode = POLICY_METADATA_ONLY if feature_key == "provider_test" else defaults.default_mode
        policies[feature_key] = FeaturePolicy(
            feature_key=feature_key,
            display_name=item["display_name"],
            description=item["description"],
            mode=mode,
            payload_preview_enabled=defaults.payload_preview_enabled,
            store_payload_hash=defaults.store_payload_hash,
            store_redacted_preview=defaults.store_redacted_preview,
        )
    return policies


def _load_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _policy_from_dict(item: dict[str, Any], existing: FeaturePolicy) -> FeaturePolicy:
    mode = str(item.get("mode") or existing.mode).upper().strip()
    if mode not in POLICY_MODES:
        mode = existing.mode

    allowed_roles = [
        str(role).upper().strip()
        for role in item.get("allowed_roles", existing.allowed_roles)
        if str(role).strip()
    ]
    allowed_roles = [role for role in allowed_roles if role in {"ADMIN", "ANALYST", "VIEWER"}]
    if not allowed_roles:
        allowed_roles = list(existing.allowed_roles)

    return replace(
        existing,
        mode=mode,
        allowed_provider_keys=[
            str(value).strip()
            for value in item.get("allowed_provider_keys", existing.allowed_provider_keys)
            if str(value).strip()
        ],
        allowed_roles=allowed_roles,
        require_confirmation=bool(item.get("require_confirmation", existing.require_confirmation)),
        payload_preview_enabled=bool(item.get("payload_preview_enabled", existing.payload_preview_enabled)),
        store_payload_hash=bool(item.get("store_payload_hash", existing.store_payload_hash)),
        store_redacted_preview=bool(item.get("store_redacted_preview", existing.store_redacted_preview)),
        allow_raw_telemetry=bool(item.get("allow_raw_telemetry", existing.allow_raw_telemetry)),
        allow_personal_data=bool(item.get("allow_personal_data", existing.allow_personal_data)),
        audit_level=str(item.get("audit_level") or existing.audit_level),
        updated_at=item.get("updated_at") or existing.updated_at,
        updated_by=item.get("updated_by") or existing.updated_by,
        update_reason=item.get("update_reason") or existing.update_reason,
    )


def load_policy_config() -> tuple[AiDataGlobalDefaults, dict[str, FeaturePolicy]]:
    global_defaults = _global_defaults_from_env()
    policies = default_feature_policies()
    file_config = _load_json_file(resolve_policy_config_path())

    raw_defaults = file_config.get("global_defaults") if isinstance(file_config, dict) else None
    if isinstance(raw_defaults, dict):
        global_defaults = replace(
            global_defaults,
            default_mode=str(raw_defaults.get("default_mode") or global_defaults.default_mode).upper(),
            external_default_policy=str(
                raw_defaults.get("external_default_policy") or global_defaults.external_default_policy
            ).upper(),
            audit_enabled=bool(raw_defaults.get("audit_enabled", global_defaults.audit_enabled)),
            payload_preview_enabled=bool(
                raw_defaults.get("payload_preview_enabled", global_defaults.payload_preview_enabled)
            ),
            store_payload_hash=bool(raw_defaults.get("store_payload_hash", global_defaults.store_payload_hash)),
            store_redacted_preview=bool(
                raw_defaults.get("store_redacted_preview", global_defaults.store_redacted_preview)
            ),
        )

    raw_policies = file_config.get("feature_policies") if isinstance(file_config, dict) else None
    if isinstance(raw_policies, list):
        for item in raw_policies:
            if not isinstance(item, dict):
                continue
            feature_key = normalize_feature_key(str(item.get("feature_key") or ""))
            existing = policies.get(feature_key)
            if existing is None:
                existing = FeaturePolicy(
                    feature_key=feature_key,
                    display_name=str(item.get("display_name") or feature_key.replace("_", " ").title()),
                    description=str(item.get("description") or ""),
                    mode=global_defaults.default_mode,
                )
            policies[feature_key] = _policy_from_dict(item, existing)

    return global_defaults, policies


def save_policy_config(global_defaults: AiDataGlobalDefaults, policies: dict[str, FeaturePolicy]) -> None:
    path = resolve_policy_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": "v0.7.0-step12",
        "global_defaults": asdict(global_defaults),
        "data_classes": DATA_CLASSES,
        "feature_policies": [asdict(policy) for policy in sorted(policies.values(), key=lambda item: item.feature_key)],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def get_feature_policy(feature_key: str) -> FeaturePolicy:
    _, policies = load_policy_config()
    canonical = normalize_feature_key(feature_key)
    if canonical in policies:
        return policies[canonical]
    defaults = _global_defaults_from_env()
    return FeaturePolicy(
        feature_key=canonical,
        display_name=canonical.replace("_", " ").title(),
        description="Dynamically discovered AI feature.",
        mode=defaults.default_mode,
        payload_preview_enabled=defaults.payload_preview_enabled,
        store_payload_hash=defaults.store_payload_hash,
        store_redacted_preview=defaults.store_redacted_preview,
    )


def _replacement_for_field(key: str, *, external_sensitive: bool) -> str | None:
    normalized = _normalize_field_name(key)
    if _is_field_match(normalized, SECRET_FIELD_MARKERS):
        if _is_field_match(normalized, CREDENTIAL_FIELD_MARKERS):
            return "[REDACTED_CREDENTIAL]"
        return "[REDACTED_SECRET]"

    if not external_sensitive:
        return None

    if _is_field_match(normalized, IP_FIELD_MARKERS):
        return "[REDACTED_IP]"
    if _is_field_match(normalized, PERSONAL_FIELD_MARKERS):
        return "[REDACTED_PERSONAL_DATA]"
    if _is_field_match(normalized, HOST_FIELD_MARKERS):
        return "[REDACTED_HOST]"
    if _is_field_match(normalized, RAW_TELEMETRY_FIELD_MARKERS):
        return "[REDACTED_RAW_TELEMETRY]"
    if _is_field_match(normalized, FIELD_MARKERS):
        return "[REDACTED_FIELD]"
    return None


def redact_text(
    text: str,
    *,
    external_sensitive: bool,
    allow_personal_data: bool = False,
) -> RedactionSummary:
    original = text or ""
    updated = original
    replacements: dict[str, int] = {}

    for name, pattern, marker in [
        ("secret", PRIVATE_KEY_RE, "[REDACTED_SECRET]"),
        ("credential", URL_CREDENTIAL_RE, r"\1[REDACTED_CREDENTIAL]:[REDACTED_CREDENTIAL]@"),
        ("credential", TOKEN_RE, "[REDACTED_CREDENTIAL]"),
        ("secret", PASSWORD_RE, "[REDACTED_SECRET]"),
    ]:
        updated, count = pattern.subn(marker, updated)
        if count:
            _count(replacements, name, count)

    if external_sensitive:
        if not allow_personal_data:
            updated, count = EMAIL_RE.subn("[REDACTED_PERSONAL_DATA]", updated)
            if count:
                _count(replacements, "personal_data", count)

        for name, pattern, marker in [
            ("ip", IPV4_RE, "[REDACTED_IP]"),
            ("ip", IPV6_RE, "[REDACTED_IP]"),
            ("host", HOSTNAME_RE, "[REDACTED_HOST]"),
            ("field", FILE_PATH_RE, "[REDACTED_FIELD]"),
        ]:
            updated, count = pattern.subn(marker, updated)
            if count:
                _count(replacements, name, count)

    return RedactionSummary(
        transformed_value=updated,
        applied=updated != original,
        replacements=replacements,
        input_character_count=len(original),
        output_character_count=len(updated),
    )


def redact_value(
    value: Any,
    *,
    external_sensitive: bool,
    allow_raw_telemetry: bool = False,
    allow_personal_data: bool = False,
) -> RedactionSummary:
    replacements: dict[str, int] = {}

    def walk(item: Any, key: str | None = None) -> Any:
        replacement = _replacement_for_field(key or "", external_sensitive=external_sensitive)
        if replacement:
            if replacement == "[REDACTED_RAW_TELEMETRY]" and allow_raw_telemetry:
                return item
            if replacement == "[REDACTED_PERSONAL_DATA]" and allow_personal_data:
                return item
            _count(replacements, replacement.strip("[]").lower())
            return replacement

        if isinstance(item, dict):
            return {str(child_key): walk(child_value, str(child_key)) for child_key, child_value in item.items()}

        if isinstance(item, list):
            return [walk(child) for child in item]

        if isinstance(item, tuple):
            return [walk(child) for child in item]

        if isinstance(item, str):
            result = redact_text(
                item,
                external_sensitive=external_sensitive,
                allow_personal_data=allow_personal_data,
            )
            for name, count in result.replacements.items():
                _count(replacements, name, count)
            return result.transformed_value

        return item

    before = _json_dumps(value)
    redacted = walk(value)
    after = _json_dumps(redacted)
    return RedactionSummary(
        transformed_value=redacted,
        applied=before != after,
        replacements=replacements,
        input_character_count=len(before),
        output_character_count=len(after),
    )


def _merge_replacements(*items: dict[str, int]) -> dict[str, int]:
    merged: dict[str, int] = {}
    for item in items:
        for key, count in item.items():
            _count(merged, key, count)
    return merged


def metadata_only_payload(
    *,
    feature_key: str,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    context: dict[str, Any] | None,
) -> RedactionSummary:
    payload = {
        "feature_key": feature_key,
        "prompt_character_count": len(prompt or ""),
        "message_count": len(messages or []),
        "message_roles": [
            str(message.get("role") or "unknown")
            for message in (messages or [])
            if isinstance(message, dict)
        ],
        "context_keys": sorted(str(key) for key in (context or {}).keys()),
        "notice": "Metadata-only AI request. No raw SOC telemetry, credentials, personal data or evidence body included.",
    }
    text = _json_dumps(payload)
    return RedactionSummary(
        transformed_value={"prompt": text, "messages": None, "context": payload},
        applied=True,
        replacements={"metadata_only": 1},
        input_character_count=len(_json_dumps({"prompt": prompt, "messages": messages, "context": context})),
        output_character_count=len(text),
    )


def transform_payload_for_policy(
    *,
    feature_policy: FeaturePolicy,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    context: dict[str, Any] | None,
    external: bool,
) -> RedactionSummary:
    if external and feature_policy.mode == POLICY_METADATA_ONLY:
        return metadata_only_payload(
            feature_key=feature_policy.feature_key,
            prompt=prompt,
            messages=messages,
            context=context,
        )

    external_sensitive = external and feature_policy.mode != POLICY_FULL_CONTEXT_ADMIN_ONLY
    payload = {
        "prompt": prompt,
        "messages": messages,
        "context": context,
    }
    return redact_value(
        payload,
        external_sensitive=external_sensitive,
        allow_raw_telemetry=feature_policy.allow_raw_telemetry,
        allow_personal_data=feature_policy.allow_personal_data,
    )


def _actor_role(current_user: dict[str, Any] | None) -> str | None:
    role = str((current_user or {}).get("role") or "").upper().strip()
    return role or None


def _actor_name(current_user: dict[str, Any] | None) -> str | None:
    return str((current_user or {}).get("username") or (current_user or {}).get("id") or "").strip() or None


def _decision_dict(decision: AiPolicyDecision) -> dict[str, Any]:
    data = asdict(decision)
    data.pop("transformed_prompt", None)
    data.pop("transformed_messages", None)
    data.pop("transformed_context", None)
    return data


def record_policy_event(
    *,
    event_type: str,
    outcome: str,
    decision: AiPolicyDecision | None = None,
    details: dict[str, Any] | None = None,
    current_user: dict[str, Any] | None = None,
    target_id: str | None = None,
) -> None:
    global_defaults, _ = load_policy_config()
    if not global_defaults.audit_enabled:
        return

    safe_details = dict(details or {})
    if decision is not None:
        safe_details.update(_decision_dict(decision))

    db = SessionLocal()
    try:
        db.add(
            SecurityAuditEvent(
                event_type=event_type,
                outcome=outcome,
                actor_user_id=(current_user or {}).get("id"),
                actor_username=(current_user or {}).get("username"),
                actor_role=(current_user or {}).get("role"),
                target_type="AI_DATA_POLICY",
                target_id=target_id or (decision.feature_key if decision else None),
                details_json=json.dumps(safe_details, default=str, sort_keys=True),
            )
        )
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def enforce_ai_data_policy(
    *,
    feature_key: str,
    provider_config: ProviderConfig,
    registry: ProviderRegistry | None,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    context: dict[str, Any] | None,
    current_user: dict[str, Any] | None = None,
    confirmed: bool = False,
    audit: bool = True,
) -> AiPolicyDecision:
    global_defaults, policies = load_policy_config()
    requested_feature = str(feature_key or "").strip().lower()
    canonical_feature = normalize_feature_key(requested_feature)
    feature_policy = policies.get(canonical_feature) or get_feature_policy(canonical_feature)
    role = _actor_role(current_user)
    external = bool(provider_config.external)
    raw_payload = {"prompt": prompt, "messages": messages, "context": context}
    raw_hash = payload_hash(raw_payload) if feature_policy.store_payload_hash else None
    reason: str | None = None
    allowed = True
    action = "allow_local" if not external else "allow_external"

    if feature_policy.mode == POLICY_FEATURE_DISABLED:
        allowed = False
        action = "deny"
        reason = "FeatureDisabled"
    elif not external:
        allowed = True
        action = "allow_local"
    elif not (registry and registry.external_providers_enabled):
        allowed = False
        action = "deny_external_use_local"
        reason = "ExternalProvidersGloballyDisabled"
    elif global_defaults.external_default_policy == POLICY_EXTERNAL_AI_DISABLED and feature_policy.mode in {
        POLICY_EXTERNAL_AI_DISABLED,
        POLICY_LOCAL_ONLY,
    }:
        allowed = False
        action = "deny_external_use_local"
        reason = "ExternalAiDisabledByPolicy"
    elif feature_policy.mode in {POLICY_EXTERNAL_AI_DISABLED, POLICY_LOCAL_ONLY}:
        allowed = False
        action = "deny_external_use_local"
        reason = "ExternalAiDisabledByFeaturePolicy"
    elif feature_policy.allowed_provider_keys and provider_config.key not in set(feature_policy.allowed_provider_keys):
        allowed = False
        action = "deny_external_use_local"
        reason = "ProviderNotAllowedByPolicy"
    elif role and role not in set(feature_policy.allowed_roles):
        allowed = False
        action = "deny_external_use_local"
        reason = "RoleNotAllowedByPolicy"
    elif not role and "SYSTEM" not in set(feature_policy.allowed_roles):
        allowed = False
        action = "deny_external_use_local"
        reason = "SystemActorNotAllowedByPolicy"
    elif feature_policy.mode == POLICY_FULL_CONTEXT_ADMIN_ONLY and role != "ADMIN":
        allowed = False
        action = "deny_external_use_local"
        reason = "FullContextRequiresAdmin"
    elif feature_policy.require_confirmation and not confirmed:
        allowed = False
        action = "deny_external_requires_confirmation"
        reason = "ConfirmationRequired"

    if allowed:
        transformed = transform_payload_for_policy(
            feature_policy=feature_policy,
            prompt=prompt,
            messages=messages,
            context=context,
            external=external,
        )
        transformed_payload = transformed.transformed_value
    else:
        transformed = redact_value(raw_payload, external_sensitive=True)
        transformed_payload = transformed.transformed_value

    if isinstance(transformed_payload, dict):
        transformed_prompt = transformed_payload.get("prompt")
        transformed_messages = transformed_payload.get("messages")
        transformed_context = transformed_payload.get("context")
    else:
        transformed_prompt = str(transformed_payload)
        transformed_messages = None
        transformed_context = None

    preview = transformed_payload if feature_policy.store_redacted_preview else None
    decision = AiPolicyDecision(
        decision_id=str(uuid.uuid4()),
        feature_key=canonical_feature,
        requested_feature_key=requested_feature,
        provider_key=provider_config.key,
        provider_type=provider_config.provider_type,
        model=provider_config.model,
        external=external,
        mode=feature_policy.mode,
        allowed=allowed,
        action=action,
        reason=reason,
        actor_role=role,
        redaction_applied=transformed.applied,
        replacements=transformed.replacements,
        input_character_count=transformed.input_character_count,
        output_character_count=transformed.output_character_count,
        payload_hash=raw_hash,
        redacted_preview=preview,
        transformed_prompt=str(transformed_prompt) if transformed_prompt is not None else None,
        transformed_messages=transformed_messages if isinstance(transformed_messages, list) else None,
        transformed_context=transformed_context if isinstance(transformed_context, dict) else None,
    )

    if audit:
        record_policy_event(
            event_type="AI_DATA_POLICY_EVALUATED",
            outcome="ALLOWED" if allowed else "DENIED",
            decision=decision,
            current_user=current_user,
        )

        if not allowed:
            record_policy_event(
                event_type="AI_DATA_POLICY_DENIED",
                outcome="DENIED",
                decision=decision,
                current_user=current_user,
            )
        elif external:
            record_policy_event(
                event_type="AI_DATA_POLICY_ALLOWED_EXTERNAL",
                outcome="ALLOWED",
                decision=decision,
                current_user=current_user,
            )
        else:
            record_policy_event(
                event_type="AI_DATA_POLICY_ALLOWED_LOCAL",
                outcome="ALLOWED",
                decision=decision,
                current_user=current_user,
            )

        if decision.redaction_applied:
            record_policy_event(
                event_type="AI_DATA_POLICY_REDACTION_APPLIED",
                outcome="APPLIED",
                decision=decision,
                current_user=current_user,
            )

    return decision


def update_feature_policy(
    *,
    feature_key: str,
    updates: dict[str, Any],
    reason: str,
    current_user: dict[str, Any] | None,
) -> FeaturePolicy:
    if not reason.strip():
        raise ValueError("A change reason is required.")

    global_defaults, policies = load_policy_config()
    canonical = normalize_feature_key(feature_key)
    current = policies.get(canonical) or get_feature_policy(canonical)
    mutable = asdict(current)
    allowed_keys = {
        "mode",
        "allowed_provider_keys",
        "allowed_roles",
        "require_confirmation",
        "payload_preview_enabled",
        "store_payload_hash",
        "store_redacted_preview",
        "allow_raw_telemetry",
        "allow_personal_data",
        "audit_level",
    }
    for key, value in updates.items():
        if key in allowed_keys:
            mutable[key] = value

    mode = str(mutable.get("mode") or current.mode).upper().strip()
    if mode not in POLICY_MODES:
        raise ValueError("Invalid policy mode.")
    if mode == POLICY_FULL_CONTEXT_ADMIN_ONLY and "ADMIN" not in {
        str(role).upper().strip() for role in mutable.get("allowed_roles", [])
    }:
        raise ValueError("FULL_CONTEXT_ADMIN_ONLY requires ADMIN in allowed_roles.")
    if mode == POLICY_FULL_CONTEXT_ADMIN_ONLY and bool(mutable.get("store_redacted_preview")):
        raise ValueError("FULL_CONTEXT_ADMIN_ONLY cannot persist redacted previews.")

    mutable["mode"] = mode
    mutable["allowed_provider_keys"] = [
        str(provider_key).strip()
        for provider_key in mutable.get("allowed_provider_keys", [])
        if str(provider_key).strip()
    ]
    mutable["allowed_roles"] = [
        str(role).upper().strip()
        for role in mutable.get("allowed_roles", [])
        if str(role).upper().strip() in {"ADMIN", "ANALYST", "VIEWER", "SYSTEM"}
    ]
    if not mutable["allowed_roles"]:
        mutable["allowed_roles"] = ["ADMIN", "ANALYST"]

    mutable["updated_at"] = _utc_now()
    mutable["updated_by"] = _actor_name(current_user)
    mutable["update_reason"] = reason.strip()

    updated = FeaturePolicy(**mutable)
    policies[canonical] = updated
    save_policy_config(global_defaults, policies)
    record_policy_event(
        event_type="AI_DATA_POLICY_CHANGED",
        outcome="SUCCESS",
        current_user=current_user,
        target_id=canonical,
        details={
            "feature_key": canonical,
            "mode": updated.mode,
            "allowed_provider_keys": updated.allowed_provider_keys,
            "allowed_roles": updated.allowed_roles,
            "reason": reason.strip(),
        },
    )
    return updated


def policies_payload() -> dict[str, Any]:
    global_defaults, policies = load_policy_config()
    return {
        "global_defaults": asdict(global_defaults),
        "data_classes": DATA_CLASSES,
        "policy_modes": sorted(POLICY_MODES),
        "features": [asdict(policy) for policy in sorted(policies.values(), key=lambda item: item.feature_key)],
    }


def decisions_payload(*, limit: int = 50) -> list[dict[str, Any]]:
    db = SessionLocal()
    try:
        events = (
            db.query(SecurityAuditEvent)
            .filter(SecurityAuditEvent.event_type.in_(sorted(POLICY_EVENT_TYPES)))
            .order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.desc())
            .limit(max(1, min(limit, 200)))
            .all()
        )
        rows = []
        for event in events:
            try:
                details = json.loads(event.details_json or "{}")
            except Exception:
                details = {}
            rows.append(
                {
                    "id": event.id,
                    "event_type": event.event_type,
                    "outcome": event.outcome,
                    "actor_username": event.actor_username,
                    "actor_role": event.actor_role,
                    "target_id": event.target_id,
                    "created_at": event.created_at.isoformat() if event.created_at else None,
                    "details": details,
                }
            )
        return rows
    except Exception:
        return []
    finally:
        db.close()


def policy_capabilities() -> dict[str, Any]:
    return {
        "policy_modes": sorted(POLICY_MODES),
        "data_classes": DATA_CLASSES,
        "features": FEATURE_DEFINITIONS,
        "redaction_tokens": [
            "[REDACTED_SECRET]",
            "[REDACTED_CREDENTIAL]",
            "[REDACTED_PERSONAL_DATA]",
            "[REDACTED_IP]",
            "[REDACTED_HOST]",
            "[REDACTED_RAW_TELEMETRY]",
            "[REDACTED_FIELD]",
        ],
        "audit_event_types": sorted(POLICY_EVENT_TYPES),
    }
