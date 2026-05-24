import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any

from ai_triage_hardening import OLLAMA_MODEL, call_ollama_chat
from llm_output import is_invalid_llm_output, sanitize_llm_output


GUIDANCE_TIMEOUT_SECONDS = float(
    os.getenv("DETECTION_QUALITY_GUIDANCE_TIMEOUT_SECONDS", "20")
)
GUIDANCE_CACHE_TTL_SECONDS = int(
    os.getenv("DETECTION_QUALITY_GUIDANCE_CACHE_TTL_SECONDS", "900")
)
_GUIDANCE_CACHE: dict[str, dict[str, Any]] = {}
_GUIDANCE_CACHE_LOCK = Lock()
_GUIDANCE_INFLIGHT_LOCKS: dict[str, Lock] = {}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _guidance_cache_key(payload: dict[str, Any]) -> str:
    weakest = payload.get("weakest_scenario")
    weakest_scenario_name = None

    if isinstance(weakest, dict):
        weakest_scenario_name = weakest.get("scenario")

    source = {
        "scenario_name": payload.get("scenario_name") or weakest_scenario_name,
        "recommended_action": payload.get("recommended_action"),
    }
    normalized = json.dumps(source, sort_keys=True, ensure_ascii=False)

    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _is_cache_valid(entry: dict[str, Any]) -> bool:
    cached_at = entry.get("cached_at")
    if not cached_at:
        return False

    try:
        cached_dt = datetime.fromisoformat(str(cached_at))
    except ValueError:
        return False

    return datetime.now(timezone.utc) - cached_dt < timedelta(
        seconds=GUIDANCE_CACHE_TTL_SECONDS
    )


def _get_inflight_lock(cache_key: str) -> Lock:
    with _GUIDANCE_CACHE_LOCK:
        lock = _GUIDANCE_INFLIGHT_LOCKS.get(cache_key)

        if lock is None:
            lock = Lock()
            _GUIDANCE_INFLIGHT_LOCKS[cache_key] = lock

        return lock


def _cached_guidance(cache_key: str) -> dict[str, Any] | None:
    with _GUIDANCE_CACHE_LOCK:
        cached = _GUIDANCE_CACHE.get(cache_key)

        if not cached or not _is_cache_valid(cached):
            return None

        result = dict(cached)
        result["cache_hit"] = True
        result["cache_key"] = cache_key

        return result


def extract_json_object(text: str) -> dict[str, Any]:
    cleaned = sanitize_llm_output(text)
    cleaned = cleaned.replace("```json", "").replace("```", "").strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError("LLM output does not contain a JSON object")

    return json.loads(cleaned[start:end + 1])


def fallback_guidance(payload: dict[str, Any], reason: str) -> dict[str, Any]:
    action = str(payload.get("recommended_action") or "").strip()

    if not action:
        action = "Review synthetic detection quality signals and validate gaps."

    return {
        "source": "deterministic_fallback",
        "model": OLLAMA_MODEL,
        "generated_at": _utc_now_iso(),
        "error_type": reason,
        "how_to_execute": [
            "Open the synthetic scenario breakdown and identify the weakest coverage signal.",
            "Review the latest synthetic incidents linked to the affected scenario.",
            "Validate correlation, priority and MITRE fields against the expected synthetic scenario metadata.",
            "Tune detection, mapping or correlation logic only after analyst validation.",
            "Re-run the synthetic scenario and confirm the coverage score improves.",
        ],
        "validation_notes": (
            "Fallback guidance was generated because local LLM guidance was unavailable. "
            "Human validation is still required before any detection tuning or release decision."
        ),
        "recommended_action": action,
    }


def build_guidance_prompt(payload: dict[str, Any]) -> str:
    return f"""
/no_think

You are a senior defensive SOC detection engineer.

Generate concise execution guidance for the recommended detection-quality action.
Use only the data in the payload. Do not invent scenario counts or evidence.

PAYLOAD:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Output constraints:
- English only.
- Return JSON only.
- Do not include Markdown.
- Do not include chain-of-thought, hidden reasoning, internal deliberation or <think> tags.
- Do not suggest offensive activity.
- Do not suggest automatic production changes without human validation.
- Keep steps concrete for a SOC manager, detection engineer or analyst.

Return exactly this JSON structure:
{{
  "how_to_execute": [
    "Concrete step 1",
    "Concrete step 2",
    "Concrete step 3"
  ],
  "validation_notes": "Short note describing human validation and expected evidence."
}}
"""


def normalize_guidance(raw_payload: dict[str, Any], source_payload: dict[str, Any]) -> dict[str, Any]:
    raw_steps = raw_payload.get("how_to_execute")
    steps: list[str] = []

    if isinstance(raw_steps, list):
        for item in raw_steps[:6]:
            text = str(item or "").strip()
            if text:
                steps.append(text[:280])

    if len(steps) < 3:
        raise ValueError("LLM guidance did not contain at least 3 execution steps")

    validation_notes = str(raw_payload.get("validation_notes") or "").strip()
    if not validation_notes:
        validation_notes = "Human analyst validation is required before detection tuning or release decisions."

    return {
        "source": "local_ai",
        "model": OLLAMA_MODEL,
        "generated_at": _utc_now_iso(),
        "error_type": None,
        "how_to_execute": steps,
        "validation_notes": validation_notes[:360],
        "recommended_action": source_payload.get("recommended_action"),
    }


def _generate_detection_quality_guidance_uncached(payload: dict[str, Any]) -> dict[str, Any]:
    prompt = build_guidance_prompt(payload)

    try:
        raw_output = call_ollama_chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a defensive AI SOC Assistant. Return valid JSON only. "
                        "Answer in English only. Do not include chain-of-thought, hidden reasoning, "
                        "markdown, or <think> tags."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            timeout_seconds=GUIDANCE_TIMEOUT_SECONDS,
        )

        cleaned = sanitize_llm_output(raw_output)
        parsed = extract_json_object(cleaned)

        if is_invalid_llm_output(raw_output) or is_invalid_llm_output(cleaned):
            raw_output = call_ollama_chat(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "The previous output was invalid. Return valid JSON only. "
                            "English only. No markdown. No chain-of-thought. No <think> tags."
                        ),
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                timeout_seconds=GUIDANCE_TIMEOUT_SECONDS,
            )
            cleaned = sanitize_llm_output(raw_output)
            parsed = extract_json_object(cleaned)

        return normalize_guidance(parsed, payload)

    except Exception as exc:
        return fallback_guidance(payload, type(exc).__name__)


def generate_detection_quality_guidance(payload: dict[str, Any]) -> dict[str, Any]:
    force_refresh = bool(payload.get("force_refresh"))
    cache_key = _guidance_cache_key(payload)

    if not force_refresh:
        cached = _cached_guidance(cache_key)

        if cached:
            return cached

    with _get_inflight_lock(cache_key):
        if not force_refresh:
            cached = _cached_guidance(cache_key)

            if cached:
                return cached

        result = dict(_generate_detection_quality_guidance_uncached(payload))
        result["cache_hit"] = False
        result["cache_key"] = cache_key
        result["cached_at"] = _utc_now_iso()

        with _GUIDANCE_CACHE_LOCK:
            _GUIDANCE_CACHE[cache_key] = dict(result)

    return result
