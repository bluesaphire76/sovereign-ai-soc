from __future__ import annotations

import ast
import json
from typing import Any


def _structured_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value


def _items(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def normalize_mitre_facts(value: Any) -> list[dict[str, str]]:
    parsed = _structured_value(value)
    records = parsed if isinstance(parsed, list) else [parsed]
    normalized: list[dict[str, str]] = []
    for record in records:
        if not isinstance(record, dict):
            text = " ".join(str(record or "").split())[:240]
            if text:
                normalized.append({"id": text})
            continue
        identifiers = _items(record.get("id") or record.get("technique_id"))
        names = _items(record.get("name") or record.get("technique"))
        for index in range(max(len(identifiers), len(names))):
            fact = {
                key: " ".join(str(selected).split())[:240]
                for key, selected in (
                    ("id", identifiers[index] if index < len(identifiers) else None),
                    ("name", names[index] if index < len(names) else None),
                )
                if selected is not None and str(selected).strip()
            }
            if fact and fact not in normalized:
                normalized.append(fact)
    return normalized[:12]
