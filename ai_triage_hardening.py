import json
import os
from threading import Lock
from typing import Any

import requests
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(*args, **kwargs):
        return False

from ai_model_config import get_profile
from ai_model_policy import AiTask
from llm_client import generate_ai_response

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = get_profile("standard").model
_LAST_LLM_CALL_METADATA: dict[str, Any] = {}
_LAST_LLM_CALL_LOCK = Lock()


def _bool_env(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


AI_TRIAGE_ENABLED = _bool_env("AI_TRIAGE_ENABLED", "true")
AI_TRIAGE_RETRY_ON_INVALID_OUTPUT = _bool_env(
    "AI_TRIAGE_RETRY_ON_INVALID_OUTPUT",
    "true",
)
AI_TRIAGE_FALLBACK_ON_ERROR = _bool_env("AI_TRIAGE_FALLBACK_ON_ERROR", "true")
AI_TRIAGE_TIMEOUT_SECONDS = float(os.getenv("AI_TRIAGE_TIMEOUT_SECONDS", "30"))
AI_TRIAGE_RETRY_ON_TIMEOUT = _bool_env("AI_TRIAGE_RETRY_ON_TIMEOUT", "true")
AI_TRIAGE_RETRY_TIMEOUT_SECONDS = float(os.getenv("AI_TRIAGE_RETRY_TIMEOUT_SECONDS", "15"))
AI_TRIAGE_COMPACT_RETRY_MAX_CHARS = int(
    os.getenv("AI_TRIAGE_COMPACT_RETRY_MAX_CHARS", "3000")
)


def _get(data: dict, *path):
    current = data

    for key in path:
        if not isinstance(current, dict):
            return None

        current = current.get(key)

        if current is None:
            return None

    return current


def _safe_text(value) -> str:
    if value is None:
        return "-"

    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, ensure_ascii=False)

    return str(value)


def _error_type(exc: Exception | None) -> str | None:
    if exc is None:
        return None

    return type(exc).__name__


def is_timeout_exception(exc: Exception | None) -> bool:
    if exc is None:
        return False

    if isinstance(exc, requests.exceptions.Timeout):
        return True

    return type(exc).__name__ in {
        "ReadTimeout",
        "Timeout",
        "TimeoutError",
        "TimeoutException",
    }


def _raise_for_empty_llm_result(result: dict[str, Any]) -> None:
    error_type = str(result.get("error_type") or "EmptyLlmResponse")

    if error_type in {
        "ReadTimeout",
        "Timeout",
        "TimeoutError",
        "TimeoutException",
    }:
        raise requests.exceptions.Timeout(error_type)

    raise RuntimeError(error_type)


def _record_llm_call_metadata(result: dict[str, Any]) -> None:
    with _LAST_LLM_CALL_LOCK:
        _LAST_LLM_CALL_METADATA.clear()
        _LAST_LLM_CALL_METADATA.update(
            {
                "profile": result.get("profile"),
                "model": result.get("model"),
                "fallback_used": result.get("fallback_used"),
                "error_type": result.get("error_type"),
                "latency_ms": result.get("latency_ms"),
                "provider_key": result.get("provider_key"),
                "provider_type": result.get("provider_type"),
                "used_external_provider": result.get("used_external_provider"),
                "redaction_applied": result.get("redaction_applied"),
                "redaction_mode": result.get("redaction_mode"),
            }
        )


def get_last_llm_call_metadata() -> dict[str, Any]:
    with _LAST_LLM_CALL_LOCK:
        return dict(_LAST_LLM_CALL_METADATA)


def compact_triage_prompt(prompt: str) -> str:
    max_chars = max(AI_TRIAGE_COMPACT_RETRY_MAX_CHARS, 1000)

    if len(prompt) <= max_chars:
        return prompt

    head_size = max_chars // 2
    tail_size = max_chars - head_size

    return (
        prompt[:head_size]
        + "\n\n[... prompt compacted for timeout retry ...]\n\n"
        + prompt[-tail_size:]
    )


def build_ai_triage_failure_reason(
    exc: Exception,
    retry_attempted: bool = False,
    retry_error: Exception | None = None,
) -> str:
    if is_timeout_exception(exc):
        if retry_attempted and retry_error is not None:
            if is_timeout_exception(retry_error):
                return (
                    "Local AI triage timed out after "
                    f"{AI_TRIAGE_TIMEOUT_SECONDS:.0f}s; compact retry also timed out "
                    f"after {AI_TRIAGE_RETRY_TIMEOUT_SECONDS:.0f}s."
                )

            return (
                "Local AI triage timed out after "
                f"{AI_TRIAGE_TIMEOUT_SECONDS:.0f}s; compact retry failed with "
                f"{type(retry_error).__name__}."
            )

        return (
            "Local AI triage timed out after "
            f"{AI_TRIAGE_TIMEOUT_SECONDS:.0f}s before a successful LLM response was available."
        )

    if retry_attempted and retry_error is not None:
        return (
            "AI triage failed or returned invalid output; retry also failed with "
            f"{type(retry_error).__name__}."
        )

    return "AI triage failed or returned invalid output."


def call_ollama_chat(
    messages: list[dict],
    timeout_seconds: float | None = None,
    task: AiTask | str = AiTask.INCIDENT_TRIAGE,
    severity: str | None = None,
    requested_mode: str | None = "auto",
    user_triggered: bool = False,
) -> str:
    timeout = timeout_seconds or AI_TRIAGE_TIMEOUT_SECONDS
    result = generate_ai_response(
        messages=messages,
        task=task,
        severity=severity,
        requested_mode=requested_mode,
        user_triggered=user_triggered,
        timeout_seconds=timeout,
    )
    _record_llm_call_metadata(result)
    text = str(result.get("text") or "")

    if not text:
        _raise_for_empty_llm_result(result)

    return text


def build_fallback_analysis(
    alert: dict,
    reason: str,
    error_type: str | None = None,
    retry_attempted: bool = False,
    context_note: str | None = None,
) -> str:
    rule = _safe_text(_get(alert, "rule", "description"))
    rule_id = _safe_text(_get(alert, "rule", "id"))
    level = _safe_text(_get(alert, "rule", "level"))
    agent = _safe_text(_get(alert, "agent", "name"))
    timestamp = _safe_text(alert.get("@timestamp"))
    mitre = _safe_text(_get(alert, "rule", "mitre"))
    full_log = _safe_text(alert.get("full_log"))

    error_line = f"- Error type: {error_type}" if error_type else "- Error type: not applicable"
    context_line = (
        f"- Context note: {context_note}"
        if context_note
        else "- Context note: no additional context issue reported"
    )

    return f"""AI triage mode: deterministic fallback
AI triage status: fallback
Fallback reason: {reason}
Model configured: {OLLAMA_MODEL}
Retry attempted: {"yes" if retry_attempted else "no"}
{error_line}
{context_line}

1. Event type
Security alert selected by deterministic correlation precheck.

2. Actual severity
Wazuh level: {level}. The event requires analyst validation because deterministic correlation selected it for incident creation.

3. Likely MITRE ATT&CK mapping
Configured alert mapping: {mitre}

4. Business risk
Potential security-relevant activity on agent {agent}. Business impact depends on whether the activity is expected, authorized and correlated with other events.

5. Recommended checks
- Review the raw Wazuh alert and confirm whether the activity is expected.
- Validate timestamp, agent, user, command, source IP and destination context where available.
- Check related raw events, security alerts and event aggregates.
- Confirm whether similar alerts occurred in the same correlation window.
- Review host logs and authentication history around the event time.

6. Suggested remediation
No automatic remediation was performed. Human analyst validation is required before taking action. If the activity is confirmed suspicious, contain the affected account or host according to the local incident response procedure.

7. Short executive summary
The LLM triage path was unavailable, disabled, timed out or returned invalid output. The incident was still created because deterministic correlation considered the signal relevant.

Operational evidence
- Timestamp: {timestamp}
- Agent: {agent}
- Rule ID: {rule_id}
- Rule: {rule}
- Level: {level}
- Full log: {full_log}
"""
