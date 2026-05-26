import json
import os

import requests
from dotenv import load_dotenv

load_dotenv()

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:8b")


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
) -> str:
    timeout = timeout_seconds or AI_TRIAGE_TIMEOUT_SECONDS

    payload = {
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
    }

    response = requests.post(
        f"{OLLAMA_BASE_URL}/api/chat",
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()

    data = response.json()
    message = data.get("message") or {}

    return str(message.get("content") or "")


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
