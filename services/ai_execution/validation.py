from __future__ import annotations

import json
from typing import Any

from llm_output import is_invalid_llm_output, sanitize_llm_output


def normalize_gateway_output(
    text: str,
    *,
    output_schema: str,
) -> tuple[dict[str, Any] | list[Any] | str | None, str | None]:
    raw = str(text or "")
    if not raw.strip() or is_invalid_llm_output(raw):
        return None, "invalid_visible_output"
    cleaned = sanitize_llm_output(raw).strip()
    if not cleaned:
        return None, "invalid_visible_output"
    if output_schema == "text_v1":
        return cleaned, None
    try:
        payload = json.loads(cleaned)
    except (TypeError, ValueError):
        return None, "invalid_json"
    if not isinstance(payload, (dict, list)):
        return None, "invalid_json_type"
    return payload, None
