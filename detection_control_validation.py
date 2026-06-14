from __future__ import annotations

import json
import re
from typing import Any, Mapping

from pydantic import BaseModel, Field


ALLOWED_RULE_TYPES = {
    "NOISE_SUPPRESSION",
    "EXCEPTION",
    "DETECTION_RULE",
    "SOURCE_POLICY",
    "TELEMETRY_SOURCE",
    "SERVICE_CONTROL",
}

ALLOWED_STATUSES = {
    "ACTIVE",
    "DISABLED",
    "DRAFT",
    "FAILED_VALIDATION",
}

ALLOWED_MATCHER_KINDS = {
    "CONTAINS",
    "EXACT",
    "REGEX",
    "JSON",
    "YAML",
}

DANGEROUS_MATCHERS = {
    "",
    "*",
    ".*",
    "^.*$",
    "(?s).*",
}


class DetectionControlValidationResult(BaseModel):
    valid: bool
    severity: str
    messages: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def _text(value: Any) -> str:
    return str(value or "").strip()


def normalize_detection_control_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    enabled = payload.get("enabled")

    if enabled is None:
        enabled = True

    status = _text(payload.get("status")).upper()

    if not status:
        status = "ACTIVE" if bool(enabled) else "DISABLED"

    return {
        "name": _text(payload.get("name")),
        "type": _text(payload.get("type") or payload.get("rule_type")).upper(),
        "status": status,
        "scope": _text(payload.get("scope")),
        "matcher_kind": _text(payload.get("matcher_kind")).upper(),
        "matcher_value": _text(payload.get("matcher_value") or payload.get("pattern")),
        "reason": _text(payload.get("reason")),
        "owner": _text(payload.get("owner")),
        "enabled": bool(enabled),
        "description": _text(payload.get("description")) or None,
        "metadata": payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    }


def _validate_json(value: str, messages: list[str]) -> None:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        messages.append(f"Matcher JSON is malformed: {exc.msg}")
        return

    if parsed in (None, "", [], {}):
        messages.append("Matcher JSON cannot be empty.")


def _validate_yaml(value: str, messages: list[str]) -> None:
    try:
        import yaml  # type: ignore
    except Exception:
        messages.append("YAML matcher validation requires PyYAML to be installed.")
        return

    try:
        parsed = yaml.safe_load(value)
    except Exception as exc:
        messages.append(f"Matcher YAML is malformed: {exc}")
        return

    if parsed in (None, "", [], {}):
        messages.append("Matcher YAML cannot be empty.")


def validate_detection_control_payload(
    payload: Mapping[str, Any],
) -> DetectionControlValidationResult:
    normalized = normalize_detection_control_payload(payload)
    messages: list[str] = []
    warnings: list[str] = []

    if not normalized["name"]:
        messages.append("Rule name is required.")

    if normalized["type"] not in ALLOWED_RULE_TYPES:
        messages.append(
            f"Type must be one of: {', '.join(sorted(ALLOWED_RULE_TYPES))}."
        )

    if normalized["status"] not in ALLOWED_STATUSES:
        messages.append(
            f"Status must be one of: {', '.join(sorted(ALLOWED_STATUSES))}."
        )

    if not normalized["scope"]:
        messages.append("Scope is required.")

    if not normalized["matcher_kind"]:
        messages.append("Matcher kind is required.")
    elif normalized["matcher_kind"] not in ALLOWED_MATCHER_KINDS:
        messages.append(
            f"Matcher kind must be one of: {', '.join(sorted(ALLOWED_MATCHER_KINDS))}."
        )

    matcher = normalized["matcher_value"]

    if matcher in DANGEROUS_MATCHERS:
        messages.append("Matcher is too broad for a governed detection-control entry.")

    if not matcher:
        messages.append("Matcher cannot be empty.")

    if not normalized["reason"]:
        messages.append("Reason is required.")

    if not normalized["owner"]:
        messages.append("Owner is required.")

    scope = normalized["scope"].lower()

    if scope in {"*", "all"}:
        messages.append("Scope cannot be a global wildcard.")
    elif scope == "global" and normalized["type"] in {"NOISE_SUPPRESSION", "EXCEPTION"}:
        warnings.append("Global scope should be used only for narrow, reviewed matchers.")

    if normalized["matcher_kind"] == "REGEX" and matcher:
        try:
            re.compile(matcher)
        except re.error as exc:
            messages.append(f"Regex matcher does not compile: {exc}")

    if normalized["matcher_kind"] == "JSON" and matcher:
        _validate_json(matcher, messages)

    if normalized["matcher_kind"] == "YAML" and matcher:
        _validate_yaml(matcher, messages)

    if messages:
        return DetectionControlValidationResult(
            valid=False,
            severity="ERROR",
            messages=messages,
            warnings=warnings,
        )

    return DetectionControlValidationResult(
        valid=True,
        severity="WARNING" if warnings else "OK",
        messages=[],
        warnings=warnings,
    )
