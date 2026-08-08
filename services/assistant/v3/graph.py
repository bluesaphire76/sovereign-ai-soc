from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable

from services.assistant.v3.contracts import (
    AnalyticalRelationship,
    AuthorityClass,
    CaseRelationshipAtom,
    CrossIncidentEvidenceGraph,
    DetectionAtom,
    DiscoverySignal,
    EvidenceAtom,
    HostAtom,
    IncidentCandidate,
    IncidentIdentityAtom,
    MitreTechniqueAtom,
    Provenance,
    RecordedCorrelationAtom,
    RelationshipClass,
    RelationshipType,
    UserAtom,
)


_RELATIONSHIP_TYPES = {
    DiscoverySignal.SHARED_HOST: RelationshipType.SHARED_HOST,
    DiscoverySignal.SHARED_AGENT: RelationshipType.SHARED_AGENT,
    DiscoverySignal.SHARED_USER: RelationshipType.SHARED_USER,
    DiscoverySignal.SHARED_RULE: RelationshipType.SHARED_RULE,
    DiscoverySignal.SHARED_DETECTION_FAMILY: RelationshipType.SHARED_DETECTION_FAMILY,
    DiscoverySignal.SHARED_MITRE: RelationshipType.SHARED_MITRE,
    DiscoverySignal.SHARED_OBSERVABLE: RelationshipType.SHARED_OBSERVABLE,
    DiscoverySignal.SHARED_EVENT_FAMILY: RelationshipType.SHARED_EVENT_FAMILY,
    DiscoverySignal.SHARED_CORRELATION_TYPE: RelationshipType.SHARED_CORRELATION_TYPE,
    DiscoverySignal.SAME_CASE: RelationshipType.SAME_CASE,
    DiscoverySignal.TEMPORAL_PROXIMITY: RelationshipType.TEMPORAL_PROXIMITY,
    DiscoverySignal.SEMANTIC_SIMILARITY: RelationshipType.SEMANTIC_SIMILARITY,
}


@dataclass(frozen=True)
class RecordedCorrelationLink:
    left_incident_id: int
    right_incident_id: int
    evidence_atom_refs: tuple[str, ...]
    source_record_id: str


def _relationship_id(*parts: object) -> str:
    value = "\x1f".join(str(part) for part in parts)
    return f"relationship:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:20]}"


def _refs_for_signal(
    signal: DiscoverySignal,
    *,
    left_id: int,
    right_id: int,
    atoms: list[EvidenceAtom],
    candidate_id: str,
) -> list[str]:
    left = [atom for atom in atoms if atom.incident_id == left_id]
    right = [atom for atom in atoms if atom.incident_id == right_id]
    if signal is DiscoverySignal.EXPLICIT_SELECTION:
        return []
    if signal is DiscoverySignal.SEMANTIC_SIMILARITY:
        return [candidate_id]
    if signal is DiscoverySignal.TEMPORAL_PROXIMITY:
        refs = [
            atom.atom_id
            for atom in [*left, *right]
            if isinstance(atom, IncidentIdentityAtom) and atom.timestamp
        ]
        return refs
    type_for_signal = {
        DiscoverySignal.SHARED_HOST: HostAtom,
        DiscoverySignal.SHARED_AGENT: HostAtom,
        DiscoverySignal.SHARED_USER: UserAtom,
        DiscoverySignal.SHARED_RULE: DetectionAtom,
        DiscoverySignal.SHARED_MITRE: MitreTechniqueAtom,
        DiscoverySignal.SHARED_CORRELATION_TYPE: RecordedCorrelationAtom,
        DiscoverySignal.SAME_CASE: CaseRelationshipAtom,
    }.get(signal)
    if type_for_signal is None:
        return []
    left_atoms = [atom for atom in left if isinstance(atom, type_for_signal)]
    right_atoms = [atom for atom in right if isinstance(atom, type_for_signal)]
    for left_atom in left_atoms:
        for right_atom in right_atoms:
            if _comparable_value(left_atom, signal) == _comparable_value(right_atom, signal):
                return [left_atom.atom_id, right_atom.atom_id]
    return []


def _comparable_value(atom: EvidenceAtom, signal: DiscoverySignal) -> object:
    if isinstance(atom, HostAtom):
        return atom.host
    if isinstance(atom, UserAtom):
        return atom.user
    if isinstance(atom, DetectionAtom):
        return atom.rule
    if isinstance(atom, MitreTechniqueAtom):
        return atom.technique_id or atom.technique_name
    if isinstance(atom, RecordedCorrelationAtom):
        return atom.correlation_type
    if isinstance(atom, CaseRelationshipAtom):
        return atom.case_id
    return (signal, atom.atom_id)


class CrossIncidentGraphBuilder:
    def build(
        self,
        *,
        anchor_incident_id: int | None,
        candidates: Iterable[IncidentCandidate],
        operational_atoms: Iterable[EvidenceAtom],
        recorded_links: Iterable[RecordedCorrelationLink] = (),
        max_incidents: int = 8,
    ) -> CrossIncidentEvidenceGraph:
        atoms = list(operational_atoms)
        available = {atom.atom_id for atom in atoms}
        relationships: list[AnalyticalRelationship] = []
        selected_candidates = list(candidates)[: max(0, max_incidents - 1)]
        available.update(candidate.candidate_id for candidate in selected_candidates)
        incident_ids = [anchor_incident_id] if anchor_incident_id is not None else []
        incident_ids.extend(candidate.candidate_incident_id for candidate in selected_candidates)

        if anchor_incident_id is not None:
            for candidate in selected_candidates:
                for signal in candidate.discovery_signals:
                    refs = _refs_for_signal(
                        signal,
                        left_id=anchor_incident_id,
                        right_id=candidate.candidate_incident_id,
                        atoms=atoms,
                        candidate_id=candidate.candidate_id,
                    )
                    if not refs:
                        continue
                    relationship_class = (
                        RelationshipClass.SEMANTIC_SIMILARITY
                        if signal is DiscoverySignal.SEMANTIC_SIMILARITY
                        else RelationshipClass.ANALYTICAL_RELATIONSHIP
                    )
                    authority = (
                        AuthorityClass.SEMANTIC_CANDIDATE
                        if relationship_class is RelationshipClass.SEMANTIC_SIMILARITY
                        else AuthorityClass.ANALYTICAL_DERIVATION
                    )
                    relationships.append(
                        AnalyticalRelationship(
                            relationship_id=_relationship_id(
                                anchor_incident_id,
                                candidate.candidate_incident_id,
                                signal.value,
                            ),
                            relationship_class=relationship_class,
                            relationship_type=_RELATIONSHIP_TYPES[signal],
                            authority_class=authority,
                            left_incident_id=anchor_incident_id,
                            right_incident_id=candidate.candidate_incident_id,
                            evidence_atom_refs=refs,
                            provenance=Provenance(
                                authority_class=authority,
                                source_type="cross_incident_discovery",
                                source_record_id=candidate.candidate_id,
                                retrieval_method=(
                                    "semantic_retrieval"
                                    if authority is AuthorityClass.SEMANTIC_CANDIDATE
                                    else "deterministic_derivation"
                                ),
                            ),
                            strength=(
                                max(0.0, candidate.semantic_score)
                                if signal is DiscoverySignal.SEMANTIC_SIMILARITY
                                and candidate.semantic_score is not None
                                else None
                            ),
                        )
                    )

        for link in recorded_links:
            refs = list(link.evidence_atom_refs)
            if not refs or not set(refs).issubset(available):
                continue
            relationships.append(
                AnalyticalRelationship(
                    relationship_id=_relationship_id(
                        link.left_incident_id,
                        link.right_incident_id,
                        "recorded",
                    ),
                    relationship_class=RelationshipClass.RECORDED_CORRELATION,
                    relationship_type=RelationshipType.PLATFORM_RECORDED_CORRELATION,
                    authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
                    left_incident_id=link.left_incident_id,
                    right_incident_id=link.right_incident_id,
                    evidence_atom_refs=refs,
                    provenance=Provenance(
                        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
                        source_type="platform_correlation",
                        source_record_id=link.source_record_id,
                        retrieval_method="operational_query",
                    ),
                )
            )
            incident_ids.extend([link.left_incident_id, link.right_incident_id])
        relationships.sort(key=lambda item: item.relationship_id)
        return CrossIncidentEvidenceGraph(
            incident_ids=list(dict.fromkeys(incident_ids))[:max_incidents],
            relationships=relationships,
            available_evidence_refs=sorted(available),
        )
