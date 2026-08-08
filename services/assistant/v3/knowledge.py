from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from services.assistant.v3.contracts import (
    AdvisoryKnowledgeAtom,
    AuthorityClass,
    ContextPlan,
    ContextRequirement,
    EvidenceAtom,
    MitreTechniqueAtom,
    Provenance,
    ReferenceKnowledgeAtom,
)


@dataclass(frozen=True)
class ReferenceCatalogEntry:
    knowledge_id: str
    knowledge_type: str
    subject: str
    bounded_content: str
    source_path: str
    requirements: tuple[ContextRequirement, ...]


REFERENCE_CATALOG = (
    ReferenceCatalogEntry(
        knowledge_id="reference:correlation:recorded",
        knowledge_type="correlation_semantics",
        subject="recorded correlation",
        bounded_content=(
            "A recorded correlation is explicit platform state. It remains distinct "
            "from an Assistant-derived analytical relationship and does not by itself "
            "establish causality or compromise."
        ),
        source_path="docs/architecture/v0.9-ai-assistant-v3-milestone-a.md",
        requirements=(ContextRequirement.CORRELATION,),
    ),
    ReferenceCatalogEntry(
        knowledge_id="reference:correlation:analytical",
        knowledge_type="correlation_semantics",
        subject="analytical relationship",
        bounded_content=(
            "An analytical relationship records shared, traceable evidence between "
            "incidents. It is neither platform-recorded correlation nor proof of a "
            "shared cause, attacker, campaign, or compromised asset."
        ),
        source_path="docs/architecture/v0.9-ai-assistant-v3-milestone-a.md",
        requirements=(ContextRequirement.CROSS_INCIDENT,),
    ),
    ReferenceCatalogEntry(
        knowledge_id="reference:correlation:semantic",
        knowledge_type="correlation_semantics",
        subject="semantic similarity",
        bounded_content=(
            "Semantic similarity is a retrieval signal only. Any historical incident "
            "used for operational comparison must be rehydrated from authoritative "
            "storage, and similarity must not be represented as correlation."
        ),
        source_path="docs/architecture/v0.9-ai-assistant-v3-milestone-a.md",
        requirements=(ContextRequirement.CROSS_INCIDENT,),
    ),
    ReferenceCatalogEntry(
        knowledge_id="reference:risk:separation",
        knowledge_type="risk_methodology",
        subject="severity, risk, and priority",
        bounded_content=(
            "Canonical severity, risk-normalization severity, numeric risk, and "
            "recommended priority are separate recorded concepts and cannot replace "
            "one another."
        ),
        source_path="docs/architecture/v0.8-ai-assistant-foundation.md",
        requirements=(ContextRequirement.RISK, ContextRequirement.PRIORITY),
    ),
)

MITRE_REFERENCE_CATALOG = {
    "T1112": (
        "Modify Registry",
        "services/assistant/v3/knowledge.py",
    ),
    "T1110": (
        "Brute Force",
        "docs/architecture/v0.7.0-qdrant-playbook-metadata-indexing.md",
    ),
}


class ReferenceKnowledgeProvider:
    def __init__(
        self,
        catalog: tuple[ReferenceCatalogEntry, ...] = REFERENCE_CATALOG,
    ) -> None:
        self._catalog = catalog

    def retrieve(
        self,
        *,
        plan: ContextPlan,
        operational_atoms: Iterable[EvidenceAtom],
    ) -> list[ReferenceKnowledgeAtom]:
        if not plan.include_reference:
            return []
        requested = set(plan.requirements)
        result: list[ReferenceKnowledgeAtom] = []
        seen: set[str] = set()
        for atom in operational_atoms:
            if not isinstance(atom, MitreTechniqueAtom) or not atom.technique_id:
                continue
            catalog_item = MITRE_REFERENCE_CATALOG.get(atom.technique_id)
            if catalog_item is None:
                continue
            name, source_path = catalog_item
            knowledge_id = f"reference:mitre:{atom.technique_id}"
            if knowledge_id in seen:
                continue
            seen.add(knowledge_id)
            result.append(
                ReferenceKnowledgeAtom(
                    knowledge_id=knowledge_id,
                    knowledge_type="mitre_definition",
                    subject=atom.technique_id,
                    bounded_content=f"{atom.technique_id} = {name}.",
                    provenance=Provenance(
                        authority_class=AuthorityClass.REFERENCE_KNOWLEDGE,
                        source_type="project_mitre_catalog",
                        source_record_id=source_path,
                        retrieval_method="project_catalog",
                    ),
                )
            )
            if len(result) >= plan.limits.max_reference_atoms:
                return result
        for entry in self._catalog:
            if not requested.intersection(entry.requirements):
                continue
            result.append(
                ReferenceKnowledgeAtom(
                    knowledge_id=entry.knowledge_id,
                    knowledge_type=entry.knowledge_type,
                    subject=entry.subject,
                    bounded_content=entry.bounded_content,
                    provenance=Provenance(
                        authority_class=AuthorityClass.REFERENCE_KNOWLEDGE,
                        source_type="project_documentation",
                        source_record_id=entry.source_path,
                        retrieval_method="project_catalog",
                    ),
                )
            )
            if len(result) >= plan.limits.max_reference_atoms:
                break
        return result


_ADVISORY_TYPES = {
    "historical_incident": "historical_incident_advisory",
    "detection_control": "investigation_guidance",
    "case_closure": "investigation_guidance",
    "knowledge_base": "playbook_guidance",
}


def _knowledge_id(source_type: str, record_id: str, section: str) -> str:
    material = "\x1f".join((source_type, record_id, section))
    return f"advisory:{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def normalize_advisory_sources(
    sources: Iterable[Any],
    *,
    plan: ContextPlan,
) -> list[AdvisoryKnowledgeAtom]:
    if not plan.include_advisory:
        return []
    atoms: list[AdvisoryKnowledgeAtom] = []
    seen: set[str] = set()
    for source in sources:
        if getattr(source, "authority", None) != "advisory":
            continue
        source_type = str(getattr(source, "source_type", "") or "")
        knowledge_type = _ADVISORY_TYPES.get(source_type)
        if knowledge_type is None:
            continue
        record_id = str(getattr(source, "record_id", None) or "unidentified")[:128]
        section = str(getattr(source, "section", None) or "")[:128]
        knowledge_id = _knowledge_id(source_type, record_id, section)
        if knowledge_id in seen:
            continue
        seen.add(knowledge_id)
        content = " ".join(str(getattr(source, "excerpt", "") or "").split())[:900]
        subject = " ".join(str(getattr(source, "label", "") or "").split())[:240]
        if not content or not subject:
            continue
        atoms.append(
            AdvisoryKnowledgeAtom(
                knowledge_id=knowledge_id,
                knowledge_type=knowledge_type,
                subject=subject,
                guidance_code=f"review_{source_type}"[:80],
                bounded_content=content,
                provenance=Provenance(
                    authority_class=AuthorityClass.ADVISORY_KNOWLEDGE,
                    source_type=source_type,
                    source_record_id=record_id,
                    source_id=getattr(source, "source_id", None),
                    retrieval_method="semantic_retrieval",
                ),
            )
        )
        if len(atoms) >= plan.limits.max_advisory_atoms:
            break
    return atoms
