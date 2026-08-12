from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from services.assistant.sources import SourceRecord, assign_source_ids
from services.assistant.v3.contracts import V3AnalyticalContextPackage
from services.assistant.v3.discourse import RenderedV3Answer


@dataclass(frozen=True)
class V3Attribution:
    sources: tuple[SourceRecord, ...]
    source_ids_by_ref: dict[str, tuple[str, ...]]


def _source_key(source_type: str, record_id: str | None) -> tuple[str, str]:
    return source_type, str(record_id or "")


def _synthetic_source(
    *,
    source_type: str,
    record_id: str,
    label: str | None = None,
    authority: str = "authoritative",
    provenance_class: str | None = None,
) -> SourceRecord:
    url = None
    if source_type == "incident" and record_id.isdigit():
        url = f"/incidents/{record_id}"
    elif source_type == "case" and record_id.isdigit():
        url = f"/cases/{record_id}"
    return SourceRecord(
        source_type=source_type,
        authority=authority,
        record_id=record_id,
        label=label or f"{source_type.replace('_', ' ').title()} {record_id}",
        excerpt="Typed source referenced by the validated V3 analytical plan.",
        url=url,
        provenance_class=provenance_class,
    )


def build_v3_attribution(
    *,
    package: V3AnalyticalContextPackage,
    rendered: RenderedV3Answer,
    existing_sources: Iterable[SourceRecord],
    max_sources: int,
) -> V3Attribution:
    atoms = {item.atom_id: item for item in package.operational_atoms}
    references = {item.knowledge_id: item for item in package.reference_atoms}
    advisories = {item.knowledge_id: item for item in package.advisory_atoms}
    candidates = {
        item.candidate_id: item for item in package.cross_incident_candidates
    }
    existing = list(existing_sources)
    existing_by_key = {
        _source_key(item.source_type, item.record_id): item for item in existing
    }
    keys_by_ref: dict[str, list[tuple[str, str]]] = {}
    provenance_by_key: dict[tuple[str, str], str] = {}

    def add_key(
        ref: str,
        source_type: str,
        record_id: str,
        provenance_class: str = "operational_source",
    ) -> None:
        key = _source_key(source_type, record_id)
        provenance_by_key.setdefault(key, provenance_class)
        keys_by_ref.setdefault(ref, [])
        if key not in keys_by_ref[ref]:
            keys_by_ref[ref].append(key)

    def resolve_ref(ref: str) -> None:
        if ref in atoms:
            provenance = atoms[ref].provenance
            add_key(ref, provenance.source_type, provenance.source_record_id)
            return
        relationship = package.relationship_registry.resolve(ref)
        if relationship is not None:
            for evidence_ref in relationship.evidence_atom_refs:
                resolve_ref(evidence_ref)
                for key in keys_by_ref.get(evidence_ref, []):
                    add_key(ref, *key)
            return
        if ref in candidates:
            add_key(ref, "incident", str(candidates[ref].candidate_incident_id))
            return
        if ref in references:
            provenance = references[ref].provenance
            add_key(
                ref,
                provenance.source_type,
                provenance.source_record_id,
                "reference_knowledge",
            )
            return
        if ref in advisories:
            provenance = advisories[ref].provenance
            add_key(
                ref,
                provenance.source_type,
                provenance.source_record_id,
                "advisory_playbook",
            )

    ordered_refs = list(
        dict.fromkeys(ref for block in rendered.blocks for ref in block.source_refs)
    )
    for ref in ordered_refs:
        resolve_ref(ref)
    required_keys = list(
        dict.fromkeys(key for ref in ordered_refs for key in keys_by_ref.get(ref, []))
    )
    records: list[SourceRecord] = []
    for source_type, record_id in required_keys:
        current = existing_by_key.get((source_type, record_id))
        if current is not None:
            records.append(
                current
                if current.provenance_class is not None
                else replace(
                    current,
                    provenance_class=provenance_by_key[(source_type, record_id)],
                )
            )
            continue
        authority = (
            "authoritative" if source_type in {"incident", "case"} else "advisory"
        )
        records.append(
            _synthetic_source(
                source_type=source_type,
                record_id=record_id,
                authority=authority,
                provenance_class=provenance_by_key[(source_type, record_id)],
            )
        )
    assigned = assign_source_ids(records, max_sources=max_sources)
    source_id_by_key = {
        _source_key(item.source_type, item.record_id): item.source_id
        for item in assigned
        if item.source_id
    }
    missing_keys = [key for key in required_keys if key not in source_id_by_key]
    if missing_keys:
        raise ValueError("V3 plan exceeds response source attribution budget")
    source_ids_by_ref = {
        ref: tuple(source_id_by_key[key] for key in keys if key in source_id_by_key)
        for ref, keys in keys_by_ref.items()
    }
    return V3Attribution(tuple(assigned), source_ids_by_ref)
