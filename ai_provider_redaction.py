from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


REDACTION_LOCAL_ONLY = "LOCAL_ONLY"
REDACTION_METADATA_ONLY = "METADATA_ONLY"
REDACTION_REDACTED_CONTEXT = "REDACTED_CONTEXT"
REDACTION_BLOCK_EXTERNAL = "BLOCK_EXTERNAL"

REDACTION_MODES = {
    REDACTION_LOCAL_ONLY,
    REDACTION_METADATA_ONLY,
    REDACTION_REDACTED_CONTEXT,
    REDACTION_BLOCK_EXTERNAL,
}

TOKEN_RE = re.compile(
    r"(?i)\b(bearer\s+[a-z0-9._\-+/=]+|api[_-]?key\s*[:=]\s*[^\s,;]+|token\s*[:=]\s*[^\s,;]+)"
)
PASSWORD_RE = re.compile(r"(?i)\b(password|passwd|pwd|secret)\s*[:=]\s*[^\s,;]+")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
URL_CREDENTIAL_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^@\s/]+)@", re.IGNORECASE)
FILE_PATH_RE = re.compile(r"(?<![\w.-])(?:/[A-Za-z0-9._@%+\-]+){2,}")
HOSTNAME_RE = re.compile(
    r"\b(?=.{1,253}\b)(?![0-9.]+\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,}\b"
)
USERNAME_KEY_RE = re.compile(r"(?i)\b(user|username|account|login)\s*[:=]\s*[A-Za-z0-9._@%+\-\\]+")

SENSITIVE_KEYS = {
    "authorization",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "password",
    "passwd",
    "secret",
    "token",
}


@dataclass(frozen=True)
class RedactionOptions:
    redact_ips: bool = True
    redact_usernames: bool = True
    redact_hostnames: bool = True
    redact_file_paths: bool = True
    sensitive_context_keys: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class RedactionResult:
    value: Any
    applied: bool
    replacements: dict[str, int]
    input_character_count: int
    output_character_count: int


def _counted_sub(pattern: re.Pattern[str], replacement: str, text: str) -> tuple[str, int]:
    updated, count = pattern.subn(replacement, text)
    return updated, count


def redact_text(text: str, options: RedactionOptions | None = None) -> RedactionResult:
    opts = options or RedactionOptions()
    original = text or ""
    updated = original
    replacements: dict[str, int] = {}

    patterns: list[tuple[str, re.Pattern[str], str]] = [
        ("private_keys", PRIVATE_KEY_RE, "<REDACTED_SECRET>"),
        ("tokens", TOKEN_RE, "<REDACTED_TOKEN>"),
        ("passwords", PASSWORD_RE, "<REDACTED_SECRET>"),
        ("url_credentials", URL_CREDENTIAL_RE, r"\1<REDACTED_USER>:<REDACTED_SECRET>@"),
        ("emails", EMAIL_RE, "<REDACTED_EMAIL>"),
    ]
    if opts.redact_ips:
        patterns.extend(
            [
                ("ipv4", IPV4_RE, "<REDACTED_IP>"),
                ("ipv6", IPV6_RE, "<REDACTED_IP>"),
            ]
        )
    if opts.redact_usernames:
        patterns.append(("usernames", USERNAME_KEY_RE, r"\1=<REDACTED_USER>"))
    if opts.redact_hostnames:
        patterns.append(("hostnames", HOSTNAME_RE, "<REDACTED_HOST>"))
    if opts.redact_file_paths:
        patterns.append(("file_paths", FILE_PATH_RE, "<REDACTED_PATH>"))

    for name, pattern, replacement in patterns:
        updated, count = _counted_sub(pattern, replacement, updated)
        if count:
            replacements[name] = count

    return RedactionResult(
        value=updated,
        applied=updated != original,
        replacements=replacements,
        input_character_count=len(original),
        output_character_count=len(updated),
    )


def redact_value(value: Any, options: RedactionOptions | None = None) -> RedactionResult:
    opts = options or RedactionOptions()
    replacements: dict[str, int] = {}

    def walk(item: Any, key: str | None = None) -> Any:
        key_normalized = (key or "").lower()
        if key_normalized in SENSITIVE_KEYS or key_normalized in opts.sensitive_context_keys:
            replacements["sensitive_keys"] = replacements.get("sensitive_keys", 0) + 1
            return "<REDACTED_SECRET>"

        if isinstance(item, dict):
            return {str(child_key): walk(child_value, str(child_key)) for child_key, child_value in item.items()}

        if isinstance(item, list):
            return [walk(child) for child in item]

        if isinstance(item, tuple):
            return [walk(child) for child in item]

        if isinstance(item, str):
            result = redact_text(item, opts)
            for name, count in result.replacements.items():
                replacements[name] = replacements.get(name, 0) + count
            return result.value

        return item

    before = json.dumps(value, default=str, sort_keys=True)
    redacted = walk(value)
    after = json.dumps(redacted, default=str, sort_keys=True)

    return RedactionResult(
        value=redacted,
        applied=before != after,
        replacements=replacements,
        input_character_count=len(before),
        output_character_count=len(after),
    )


def metadata_only_payload(
    *,
    feature: str,
    prompt: str | None = None,
    messages: list[dict[str, Any]] | None = None,
    context: dict[str, Any] | None = None,
) -> RedactionResult:
    payload = {
        "feature": feature,
        "prompt_character_count": len(prompt or ""),
        "message_count": len(messages or []),
        "message_roles": [
            str(message.get("role") or "unknown")
            for message in (messages or [])
            if isinstance(message, dict)
        ],
        "context_keys": sorted(str(key) for key in (context or {}).keys()),
    }
    text = (
        "AI SOC metadata-only external prompt.\n"
        "No raw incident, case, alert, command output or evidence payload is included.\n"
        f"{json.dumps(payload, sort_keys=True)}"
    )

    return RedactionResult(
        value=text,
        applied=True,
        replacements={"metadata_only": 1},
        input_character_count=len(prompt or "") + len(json.dumps(messages or [], default=str)),
        output_character_count=len(text),
    )


def prepare_external_prompt(
    *,
    feature: str,
    prompt: str | None,
    messages: list[dict[str, Any]] | None,
    context: dict[str, Any] | None,
    redaction_mode: str,
    options: RedactionOptions | None = None,
) -> tuple[str | None, list[dict[str, Any]] | None, RedactionResult]:
    normalized = (redaction_mode or REDACTION_BLOCK_EXTERNAL).upper().strip()

    if normalized == REDACTION_METADATA_ONLY:
        result = metadata_only_payload(feature=feature, prompt=prompt, messages=messages, context=context)
        return str(result.value), None, result

    if normalized == REDACTION_REDACTED_CONTEXT:
        if messages:
            redacted_messages: list[dict[str, Any]] = []
            applied = False
            replacements: dict[str, int] = {}
            input_chars = 0
            output_chars = 0

            for message in messages:
                content = str(message.get("content") or "")
                result = redact_text(content, options)
                redacted_messages.append({**message, "content": result.value})
                applied = applied or result.applied
                input_chars += result.input_character_count
                output_chars += result.output_character_count
                for name, count in result.replacements.items():
                    replacements[name] = replacements.get(name, 0) + count

            return (
                None,
                redacted_messages,
                RedactionResult(
                    value=redacted_messages,
                    applied=applied,
                    replacements=replacements,
                    input_character_count=input_chars,
                    output_character_count=output_chars,
                ),
            )

        result = redact_text(prompt or "", options)
        return str(result.value), None, result

    raise ValueError("External provider call is blocked by redaction policy.")
