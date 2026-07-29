from __future__ import annotations

from dataclasses import dataclass, replace

from schemas.assistant import AssistantSource


@dataclass(frozen=True)
class SourceRecord:
    source_type: str
    authority: str
    label: str
    excerpt: str
    record_id: str | None = None
    url: str | None = None
    score: float | None = None
    section: str | None = None
    source_id: str | None = None

    def with_source_id(self, source_id: str) -> "SourceRecord":
        return replace(self, source_id=source_id)

    def to_response_source(self) -> AssistantSource:
        return AssistantSource(
            source_id=self.source_id or "",
            source_type=self.source_type,
            authority=self.authority,  # type: ignore[arg-type]
            record_id=self.record_id,
            label=self.label,
            url=self.url,
            score=self.score,
            section=self.section,
        )


def assign_source_ids(records: list[SourceRecord], *, max_sources: int) -> list[SourceRecord]:
    """Return deterministic backend-created source IDs.

    Authoritative records are always assigned before advisory records. Within
    each authority tier, the retrieval order is preserved.
    """

    tier = {"authoritative": 0, "advisory": 1}
    deduped: list[SourceRecord] = []
    seen: set[tuple[str, str, str | None, str]] = set()

    for record in records:
        key = (
            record.authority,
            record.source_type,
            record.record_id,
            record.label,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)

    ordered = sorted(
        enumerate(deduped),
        key=lambda item: (tier.get(item[1].authority, 99), item[0]),
    )
    bounded = [record for _, record in ordered[: max(1, min(max_sources, 12))]]

    return [
        record.with_source_id(f"S{index}")
        for index, record in enumerate(bounded, start=1)
    ]
