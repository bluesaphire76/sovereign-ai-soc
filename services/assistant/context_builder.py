from __future__ import annotations

from dataclasses import dataclass, field

from services.assistant.sources import SourceRecord


@dataclass(frozen=True)
class ContextBuildResult:
    context: str
    limitations: list[str] = field(default_factory=list)


def _bounded(value: str, *, max_chars: int) -> tuple[str, bool]:
    text = str(value or "").strip()
    if len(text) <= max_chars:
        return text, False
    return f"{text[: max_chars - 3].rstrip()}...", True


def _format_source(record: SourceRecord, *, max_excerpt_chars: int) -> tuple[str, bool]:
    excerpt, truncated = _bounded(record.excerpt, max_chars=max_excerpt_chars)
    score = f", semantic_score={record.score:.3f}" if isinstance(record.score, (int, float)) else ""
    section = f", section={record.section}" if record.section else ""
    header = (
        f"[{record.source_id}] {record.source_type}; "
        f"authority={record.authority}; label={record.label}{score}{section}"
    )
    return f"{header}\n{excerpt}", truncated


def build_assistant_context(
    *,
    message: str,
    sources: list[SourceRecord],
    max_context_chars: int,
    max_excerpt_chars: int = 1200,
) -> ContextBuildResult:
    limitations: list[str] = []
    authoritative = [source for source in sources if source.authority == "authoritative"]
    advisory = [source for source in sources if source.authority == "advisory"]

    lines = [
        "AUTHORITATIVE OPERATIONAL FACTS",
    ]
    if not authoritative:
        lines.append("No exact operational records were retrieved.")

    for source in authoritative:
        block, truncated = _format_source(source, max_excerpt_chars=max_excerpt_chars)
        lines.extend(["", block])
        if truncated:
            limitations.append(f"{source.source_id} was truncated to fit the per-source context budget.")

    lines.extend(["", "ADVISORY SEMANTIC MEMORY"])
    if not advisory:
        lines.append("No advisory semantic memory was retrieved.")

    for source in advisory:
        block, truncated = _format_source(source, max_excerpt_chars=max_excerpt_chars)
        lines.extend(["", block])
        if truncated:
            limitations.append(f"{source.source_id} was truncated to fit the per-source context budget.")

    lines.extend(
        [
            "",
            "USER QUESTION",
            message,
        ]
    )

    context = "\n".join(lines)
    bounded_context, truncated_context = _bounded(
        context,
        max_chars=max(1000, min(max_context_chars, 24000)),
    )
    if truncated_context:
        limitations.append("Assistant context was truncated to fit the configured context budget.")

    return ContextBuildResult(context=bounded_context, limitations=limitations)
