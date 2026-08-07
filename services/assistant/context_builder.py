from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from services.assistant.sources import SourceRecord


@dataclass(frozen=True)
class ContextBuildResult:
    context: str
    limitations: list[str] = field(default_factory=list)


def _bounded_text(value: Any, *, max_chars: int) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _bounded_facts(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _bounded_facts(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_bounded_facts(item) for item in value[:10]]
    if isinstance(value, str):
        return _bounded_text(value, max_chars=1000)
    return value


def build_assistant_context(
    *,
    message: str,
    fact_inventory: dict[str, Any],
    sources: list[SourceRecord],
    max_context_chars: int,
) -> ContextBuildResult:
    limit = max(1000, min(int(max_context_chars), 24000))
    limitations: list[str] = []
    authoritative_facts = _bounded_facts(fact_inventory)
    advisory = [
        {
            "source_id": source.source_id,
            "source_type": source.source_type,
            "label": _bounded_text(source.label, max_chars=160),
            "section": _bounded_text(source.section, max_chars=160)
            if source.section
            else None,
            "text": _bounded_text(source.excerpt, max_chars=500),
        }
        for source in sources
        if source.authority == "advisory"
    ]
    allowed_sources = [
        {
            "source_id": source.source_id,
            "source_type": source.source_type,
            "authority": source.authority,
            "label": _bounded_text(source.label, max_chars=160),
        }
        for source in sources
        if source.source_id
    ]
    payload = {
        "authoritative_facts": authoritative_facts,
        "advisory_context": advisory,
        "allowed_sources": allowed_sources,
        "analyst_question": _bounded_text(message, max_chars=2000),
    }

    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    while advisory and len(encoded) > limit:
        removed = advisory.pop()
        allowed_sources[:] = [
            source
            for source in allowed_sources
            if source["source_id"] != removed["source_id"]
        ]
        limitations.append(
            "Advisory semantic context was abbreviated to preserve authoritative facts."
        )
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)

    if len(encoded) > limit:
        for key in (
            "latest_stored_analysis",
            "closure",
            "linked_incidents",
            "latest_actions",
            "attack_chain",
            "escalation_reason",
            "correlation_summary",
            "summary",
        ):
            if key not in authoritative_facts:
                continue
            authoritative_facts[key] = None
            limitations.append(
                "Some long-form authoritative context was omitted from the model prompt."
            )
            encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
            if len(encoded) <= limit:
                break

    if len(encoded) > limit:
        raise ValueError("authoritative fact inventory exceeds context budget")
    return ContextBuildResult(context=encoded, limitations=list(dict.fromkeys(limitations)))
