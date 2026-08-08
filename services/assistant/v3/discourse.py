from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from services.assistant.v3.contracts import (
    CaseIdentityAtom,
    CaseRelationshipAtom,
    CompromiseStateAtom,
    DetectionAtom,
    DiscoverySignal,
    EscalationReasonAtom,
    EscalationStateAtom,
    EvidenceAtom,
    HostAtom,
    IncidentIdentityAtom,
    MitreTechniqueAtom,
    PriorityAtom,
    RecordedCorrelationAtom,
    RelationshipType,
    RiskAtom,
    StatusAtom,
    TimelineEventAtom,
    UserAtom,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_contracts import (
    AnalyticalUnit,
    AnalyticalUnitType,
    AnswerSectionType,
    GroundedAnswerPlanV3,
    NonImplicationCode,
    PlanLimitationCode,
)


@dataclass(frozen=True)
class RenderedV3Block:
    section_type: AnswerSectionType
    text: str
    source_refs: tuple[str, ...]


@dataclass(frozen=True)
class RenderedV3Answer:
    blocks: tuple[RenderedV3Block, ...]
    render_ms: float

    @property
    def used_advisory_context(self) -> bool:
        return any(
            ref.startswith("advisory:")
            for block in self.blocks
            for ref in block.source_refs
        )


def _record_subject(
    atom: EvidenceAtom,
    *,
    language: str,
) -> str:
    if atom.incident_id is not None:
        return f"L'incidente {atom.incident_id}" if language == "it" else f"Incident {atom.incident_id}"
    if atom.case_id is not None:
        return f"Il caso {atom.case_id}" if language == "it" else f"Case {atom.case_id}"
    return "Il record" if language == "it" else "The record"


def _join_clauses(values: list[str], *, language: str) -> str:
    values = [value for value in values if value]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    conjunction = " e " if language == "it" else " and "
    if len(values) == 2:
        return conjunction.join(values)
    return f"{', '.join(values[:-1])}{conjunction}{values[-1]}"


def _atom_clauses(atom: EvidenceAtom, *, language: str) -> list[str]:
    if isinstance(atom, IncidentIdentityAtom):
        if atom.timestamp:
            return [
                f"ha timestamp registrato {atom.timestamp}"
                if language == "it"
                else f"has recorded timestamp {atom.timestamp}"
            ]
        return []
    if isinstance(atom, CaseIdentityAtom):
        return ([f"è denominato {atom.title}"] if language == "it" else [f"is titled {atom.title}"]) if atom.title else []
    if isinstance(atom, StatusAtom):
        result = [f"risulta {atom.status}" if language == "it" else f"is {atom.status}"]
        if atom.canonical_severity:
            result.append(
                f"ha severità canonica {atom.canonical_severity}"
                if language == "it"
                else f"has canonical severity {atom.canonical_severity}"
            )
        return result
    if isinstance(atom, RiskAtom):
        result = []
        if atom.risk_score is not None:
            result.append(
                f"mantiene un risk score di {atom.risk_score:g}"
                if language == "it"
                else f"has a recorded risk score of {atom.risk_score:g}"
            )
        if atom.risk_normalization_severity:
            result.append(
                f"la normalizzazione del rischio registra {atom.risk_normalization_severity}"
                if language == "it"
                else f"risk normalization records {atom.risk_normalization_severity}"
            )
        return result
    if isinstance(atom, PriorityAtom):
        return [
            f"ha priorità raccomandata {atom.recommended_priority}"
            if language == "it"
            else f"has recorded recommended priority {atom.recommended_priority}"
        ]
    if isinstance(atom, HostAtom):
        noun = "host" if atom.representation == "host" else "agente"
        if language == "en":
            noun = "host" if atom.representation == "host" else "agent"
        return [
            f"è associato al {noun} {atom.host}"
            if language == "it"
            else f"is associated with {noun} {atom.host}"
        ]
    if isinstance(atom, UserAtom):
        return [
            f"coinvolge l'utente registrato {atom.user}"
            if language == "it"
            else f"involves recorded user {atom.user}"
        ]
    if isinstance(atom, DetectionAtom):
        level = f" (livello {atom.level})" if language == "it" else f" (level {atom.level})"
        if atom.level is None:
            level = ""
        return [
            f"deriva dalla regola di detection {atom.rule}{level}"
            if language == "it"
            else f"was raised by detection rule {atom.rule}{level}"
        ]
    if isinstance(atom, MitreTechniqueAtom):
        value = atom.technique_id or atom.technique_name or ""
        if atom.technique_id and atom.technique_name:
            value = f"{atom.technique_id} ({atom.technique_name})"
        return [
            f"è associato alla tecnica MITRE {value}"
            if language == "it"
            else f"is associated with MITRE technique {value}"
        ]
    if isinstance(atom, TimelineEventAtom):
        timestamp = f" alle {atom.timestamp}" if language == "it" else f" at {atom.timestamp}"
        if not atom.timestamp:
            timestamp = ""
        return [
            f"la timeline registra {atom.event_type}{timestamp}"
            if language == "it"
            else f"the timeline records {atom.event_type}{timestamp}"
        ]
    if isinstance(atom, RecordedCorrelationAtom):
        values = []
        if isinstance(atom.correlated, bool):
            values.append(
                "ha una correlazione registrata"
                if atom.correlated and language == "it"
                else "non ha correlazione registrata"
                if language == "it"
                else "has recorded correlation"
                if atom.correlated
                else "has recorded no correlation"
            )
        if atom.correlation_type:
            values.append(
                f"il tipo registrato è {atom.correlation_type}"
                if language == "it"
                else f"the recorded type is {atom.correlation_type}"
            )
        if atom.correlation_score is not None:
            values.append(
                f"il correlation score è {atom.correlation_score:g}"
                if language == "it"
                else f"the correlation score is {atom.correlation_score:g}"
            )
        return values
    if isinstance(atom, EscalationStateAtom):
        value = "vero" if atom.escalated else "falso"
        if language == "en":
            value = "true" if atom.escalated else "false"
        return [
            f"registra esplicitamente escalated={value}"
            if language == "it"
            else f"explicitly records escalated={value}"
        ]
    if isinstance(atom, EscalationReasonAtom):
        return [
            f"registra come motivo di escalation: {atom.reason}"
            if language == "it"
            else f"records this escalation reason: {atom.reason}"
        ]
    if isinstance(atom, CompromiseStateAtom):
        if atom.compromise_confirmed is None:
            return []
        value = "confermata" if atom.compromise_confirmed else "non confermata"
        if language == "en":
            value = "confirmed" if atom.compromise_confirmed else "not confirmed"
        return [
            f"registra la compromissione come {value}"
            if language == "it"
            else f"records compromise as {value}"
        ]
    if isinstance(atom, CaseRelationshipAtom):
        return [
            f"è collegato al caso {atom.case_id}"
            if language == "it"
            else f"is linked to case {atom.case_id}"
        ]
    return []


def _render_recorded_facts(
    unit: AnalyticalUnit,
    *,
    atoms: dict[str, EvidenceAtom],
    language: str,
) -> str:
    grouped: dict[tuple[int | None, int | None], list[EvidenceAtom]] = {}
    for ref in unit.fact_refs:
        atom = atoms[ref]
        grouped.setdefault((atom.incident_id, atom.case_id), []).append(atom)
    sentences = []
    for selected in grouped.values():
        clauses = [
            clause
            for atom in selected
            for clause in _atom_clauses(atom, language=language)
        ]
        if clauses:
            sentences.append(
                f"{_record_subject(selected[0], language=language)} "
                f"{_join_clauses(clauses, language=language)}."
            )
    return " ".join(sentences)


_RELATION_LABELS = {
    RelationshipType.SHARED_HOST: ("lo stesso host", "the same host"),
    RelationshipType.SHARED_AGENT: ("lo stesso agente", "the same agent"),
    RelationshipType.SHARED_USER: ("lo stesso utente", "the same user"),
    RelationshipType.SHARED_RULE: ("la stessa regola di detection", "the same detection rule"),
    RelationshipType.SHARED_DETECTION_FAMILY: ("la stessa famiglia di detection", "the same detection family"),
    RelationshipType.SHARED_MITRE: ("la stessa tecnica MITRE", "the same MITRE technique"),
    RelationshipType.SHARED_OBSERVABLE: ("lo stesso osservabile", "the same observable"),
    RelationshipType.SHARED_EVENT_FAMILY: ("la stessa famiglia di eventi", "the same event family"),
    RelationshipType.SHARED_CORRELATION_TYPE: ("lo stesso tipo di correlazione", "the same correlation type"),
    RelationshipType.SAME_CASE: ("l'appartenenza allo stesso caso", "membership in the same case"),
    RelationshipType.TEMPORAL_PROXIMITY: ("prossimità temporale entro 24 ore", "temporal proximity within 24 hours"),
    RelationshipType.SEMANTIC_SIMILARITY: ("similarità semantica", "semantic similarity"),
    RelationshipType.PLATFORM_RECORDED_CORRELATION: ("una correlazione registrata dalla piattaforma", "a platform-recorded correlation"),
}


def _render_relationship(unit: AnalyticalUnit, package: V3AnalyticalContextPackage) -> str:
    language = package.response_language
    sentences = []
    for ref in unit.relationship_refs:
        relationship = package.relationship_registry.resolve(ref)
        if relationship is None:
            continue
        label = _RELATION_LABELS[relationship.relationship_type][0 if language == "it" else 1]
        if relationship.relationship_type is RelationshipType.PLATFORM_RECORDED_CORRELATION:
            sentences.append(
                f"La piattaforma registra {label} tra gli incidenti {relationship.left_incident_id} e {relationship.right_incident_id}."
                if language == "it"
                else f"The platform records {label} between incidents {relationship.left_incident_id} and {relationship.right_incident_id}."
            )
        elif relationship.relationship_type is RelationshipType.SEMANTIC_SIMILARITY:
            sentences.append(
                f"L'incidente {relationship.right_incident_id} è un candidato di confronto per {label} con il {relationship.left_incident_id}."
                if language == "it"
                else f"Incident {relationship.right_incident_id} is a comparison candidate based on {label} with incident {relationship.left_incident_id}."
            )
        else:
            sentences.append(
                f"Gli incidenti {relationship.left_incident_id} e {relationship.right_incident_id} condividono {label}; questa è una relazione analitica derivata dai record."
                if language == "it"
                else f"Incidents {relationship.left_incident_id} and {relationship.right_incident_id} share {label}; this is an analytical relationship derived from records."
            )
    return " ".join(sentences)


def _render_candidate(unit: AnalyticalUnit, package: V3AnalyticalContextPackage) -> str:
    candidates = {item.candidate_id: item for item in package.cross_incident_candidates}
    selected = [candidates[ref] for ref in unit.candidate_refs]
    values = [item.candidate_incident_id for item in selected]
    joined = ", ".join(str(value) for value in values)
    explicit = any(
        DiscoverySignal.EXPLICIT_SELECTION in item.discovery_signals
        for item in selected
    )
    if package.response_language == "it":
        subject = (
            "La selezione esplicita include"
            if explicit
            else "La policy di retrieval identifica"
        )
        return f"{subject} gli incidenti {joined} come confronti rilevanti; il ranking indica utilità comparativa, non rischio o compromissione."
    subject = (
        "The explicit record set includes"
        if explicit
        else "The retrieval policy identifies"
    )
    return f"{subject} incidents {joined} as relevant comparisons; ranking indicates comparison utility, not risk or compromise."


def _render_comparison(
    unit: AnalyticalUnit,
    *,
    atoms: dict[str, EvidenceAtom],
    language: str,
) -> str:
    selected = [atoms[ref] for ref in unit.fact_refs]
    descriptions = []
    for atom in selected:
        clauses = _atom_clauses(atom, language=language)
        if clauses:
            descriptions.append(
                f"{_record_subject(atom, language=language)} {_join_clauses(clauses, language=language)}"
            )
    if not descriptions:
        return ""
    prefix = "Nel confronto, " if language == "it" else "In comparison, "
    separator = "; " if unit.unit_type is AnalyticalUnitType.DIFFERENCE else ", "
    return f"{prefix}{separator.join(descriptions)}."


def _render_pattern(unit: AnalyticalUnit, package: V3AnalyticalContextPackage) -> str:
    relationships = [
        package.relationship_registry.resolve(ref) for ref in unit.relationship_refs
    ]
    relationships = [item for item in relationships if item is not None]
    incident_ids = sorted(
        {
            value
            for item in relationships
            for value in (item.left_incident_id, item.right_incident_id)
        }
    )
    label = _RELATION_LABELS[relationships[0].relationship_type][
        0 if package.response_language == "it" else 1
    ]
    joined = ", ".join(str(value) for value in incident_ids)
    if package.response_language == "it":
        return f"Il pattern supportato riguarda {len(incident_ids)} incidenti ({joined}) che condividono {label}."
    return f"The supported pattern covers {len(incident_ids)} incidents ({joined}) sharing {label}."


_NON_IMPLICATION_TEXT = {
    NonImplicationCode.CORRELATION_NOT_COMPROMISE: (
        "La correlazione non dimostra di per sé una compromissione.",
        "Correlation does not by itself establish compromise.",
    ),
    NonImplicationCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY: (
        "Una relazione analitica non dimostra causalità, causa comune, attaccante o campagna condivisi.",
        "An analytical relationship does not establish causality, a common cause, attacker, or campaign.",
    ),
    NonImplicationCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION: (
        "La similarità semantica non equivale a una correlazione registrata.",
        "Semantic similarity is not a recorded correlation.",
    ),
    NonImplicationCode.SHARED_MITRE_NOT_SAME_ATTACKER: (
        "Una tecnica MITRE condivisa non dimostra lo stesso attaccante o la stessa campagna.",
        "A shared MITRE technique does not establish the same attacker or campaign.",
    ),
    NonImplicationCode.SHARED_HOST_NOT_COMMON_ROOT_CAUSE: (
        "Un host condiviso non dimostra una causa radice comune.",
        "A shared host does not establish a common root cause.",
    ),
    NonImplicationCode.SAME_CASE_NOT_CAUSALITY: (
        "L'appartenenza allo stesso caso non dimostra causalità.",
        "Membership in the same case does not establish causality.",
    ),
    NonImplicationCode.CANDIDATE_RANK_NOT_RISK: (
        "Il ranking dei candidati indica rilevanza per il confronto, non rischio, severità o compromissione.",
        "Candidate ranking indicates comparison relevance, not risk, severity, or compromise.",
    ),
}


_LIMITATION_TEXT = {
    PlanLimitationCode.REQUESTED_DATA_NOT_RECORDED: (
        "Il dato richiesto non è registrato nel contesto autorevole disponibile.",
        "The requested data is not recorded in the available authoritative context.",
    ),
    PlanLimitationCode.CANONICAL_SEVERITY_NOT_RECORDED: (
        "La severità canonica non è registrata e non viene sostituita dal risk score o dalla priorità.",
        "Canonical severity is not recorded and is not replaced by risk score or priority.",
    ),
    PlanLimitationCode.NO_AUTHORITATIVE_ESCALATION_BOOLEAN: (
        "Non è disponibile un booleano autorevole di escalation; il motivo non prova lo stato.",
        "No authoritative escalation boolean is available; a reason does not prove state.",
    ),
    PlanLimitationCode.NO_RELATED_INCIDENT_CANDIDATES: (
        "La ricerca non ha prodotto candidati cross-incident supportati.",
        "The search produced no supported cross-incident candidates.",
    ),
    PlanLimitationCode.SEMANTIC_INDEX_DEGRADED: (
        "L'indice semantico era degradato; l'analisi resta basata sui record autorevoli disponibili.",
        "The semantic index was degraded; analysis remains based on available authoritative records.",
    ),
    PlanLimitationCode.REFERENCE_KNOWLEDGE_UNAVAILABLE: (
        "Non è disponibile conoscenza di riferimento pertinente.",
        "No relevant reference knowledge is available.",
    ),
    PlanLimitationCode.ADVISORY_KNOWLEDGE_UNAVAILABLE: (
        "Non è disponibile guida consultiva pertinente.",
        "No relevant advisory guidance is available.",
    ),
    PlanLimitationCode.EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY: (
        "Le evidenze disponibili non stabiliscono causalità.",
        "The available evidence does not establish causality.",
    ),
}


def _render_unit(
    unit: AnalyticalUnit,
    *,
    package: V3AnalyticalContextPackage,
    atoms: dict[str, EvidenceAtom],
) -> str:
    language = package.response_language
    if unit.unit_type in {
        AnalyticalUnitType.RECORDED_FACT,
        AnalyticalUnitType.RECORDED_CORRELATION,
    } and unit.fact_refs:
        return _render_recorded_facts(unit, atoms=atoms, language=language)
    if unit.unit_type in {
        AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
        AnalyticalUnitType.SEMANTIC_SIMILARITY,
    } or (
        unit.unit_type is AnalyticalUnitType.RECORDED_CORRELATION
        and unit.relationship_refs
    ):
        return _render_relationship(unit, package)
    if unit.unit_type in {AnalyticalUnitType.COMPARISON, AnalyticalUnitType.DIFFERENCE}:
        return _render_comparison(unit, atoms=atoms, language=language)
    if unit.unit_type is AnalyticalUnitType.SHARED_PATTERN:
        return _render_pattern(unit, package)
    if unit.unit_type is AnalyticalUnitType.CANDIDATE_RELEVANCE:
        return _render_candidate(unit, package)
    if unit.unit_type is AnalyticalUnitType.TEMPORAL_SEQUENCE:
        return _render_relationship(unit, package)
    if unit.unit_type is AnalyticalUnitType.REFERENCE_EXPLANATION:
        references = {item.knowledge_id: item for item in package.reference_atoms}
        return " ".join(references[ref].bounded_content for ref in unit.reference_refs)
    if unit.unit_type in {
        AnalyticalUnitType.ADVISORY_GUIDANCE,
        AnalyticalUnitType.NEXT_CHECK,
    }:
        advisories = {item.knowledge_id: item for item in package.advisory_atoms}
        content = " ".join(advisories[ref].bounded_content for ref in unit.advisory_refs)
        prefix = (
            "Come guida investigativa, "
            if language == "it"
            else "As investigative guidance, "
        )
        return f"{prefix}{content}"
    if unit.unit_type is AnalyticalUnitType.NON_IMPLICATION:
        assert unit.non_implication is not None
        return _NON_IMPLICATION_TEXT[unit.non_implication][0 if language == "it" else 1]
    if unit.unit_type is AnalyticalUnitType.LIMITATION:
        assert unit.limitation is not None
        return _LIMITATION_TEXT[unit.limitation][0 if language == "it" else 1]
    if unit.unit_type is AnalyticalUnitType.ABSENCE:
        if unit.absence_field and unit.absence_field.value == "severity":
            return _LIMITATION_TEXT[PlanLimitationCode.CANONICAL_SEVERITY_NOT_RECORDED][0 if language == "it" else 1]
        if unit.absence_field and unit.absence_field.value == "escalated":
            return _LIMITATION_TEXT[PlanLimitationCode.NO_AUTHORITATIVE_ESCALATION_BOOLEAN][0 if language == "it" else 1]
    return ""


class RichGroundedDiscourseRenderer:
    def render(
        self,
        plan: GroundedAnswerPlanV3,
        *,
        package: V3AnalyticalContextPackage,
        clock: Callable[[], float] = time.monotonic,
    ) -> RenderedV3Answer:
        started = clock()
        atoms = {item.atom_id: item for item in package.operational_atoms}
        blocks: list[RenderedV3Block] = []
        rendered_texts: set[str] = set()
        for section in plan.sections:
            paragraphs: list[str] = []
            source_refs: list[str] = []
            for unit in section.units:
                text = " ".join(_render_unit(unit, package=package, atoms=atoms).split())
                normalized = text.casefold()
                if not text or normalized in rendered_texts:
                    continue
                rendered_texts.add(normalized)
                paragraphs.append(text)
                source_refs.extend(
                    [
                        *unit.fact_refs,
                        *unit.relationship_refs,
                        *unit.candidate_refs,
                        *unit.reference_refs,
                        *unit.advisory_refs,
                    ]
                )
            if paragraphs:
                blocks.append(
                    RenderedV3Block(
                        section_type=section.section_type,
                        text="\n\n".join(paragraphs),
                        source_refs=tuple(dict.fromkeys(source_refs)),
                    )
                )
        if not blocks:
            raise ValueError("validated V3 plan rendered no visible blocks")
        return RenderedV3Answer(
            blocks=tuple(blocks),
            render_ms=max(0.0, (clock() - started) * 1000),
        )
