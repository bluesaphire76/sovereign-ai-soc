from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from services.assistant.v3.contracts import (
    AdvisoryActionCode,
    AdvisoryContextCode,
    AdvisoryKnowledgeAtom,
    AdvisoryReasonCode,
    AdvisoryTargetType,
    CaseIdentityAtom,
    CaseRelationshipAtom,
    CompromiseStateAtom,
    DetectionAtom,
    DiscoverySignal,
    EscalationReasonAtom,
    EscalationStateAtom,
    EvidenceAtom,
    FactField,
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
    conjunction = (
        " ed "
        if language == "it" and values[-1].casefold().startswith(("e", "è"))
        else " e "
        if language == "it"
        else " and "
    )
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
        if language == "it":
            association = (
                f"è associato al host {atom.host}"
                if atom.representation == "host"
                else f"è associato all'agente {atom.host}"
            )
        else:
            noun = "host" if atom.representation == "host" else "agent"
            association = f"is associated with {noun} {atom.host}"
        return [
            association
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
        rule = atom.rule.rstrip(".") if level else atom.rule
        return [
            f"deriva dalla regola di detection {rule}{level}"
            if language == "it"
            else f"was raised by detection rule {rule}{level}"
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
    sentences: list[str] = []
    for selected in grouped.values():
        primary_atoms = [
            atom
            for atom in selected
            if isinstance(atom, (StatusAtom, DetectionAtom, HostAtom, UserAtom))
        ]
        handling_atoms = [
            atom
            for atom in selected
            if isinstance(
                atom,
                (
                    RiskAtom,
                    PriorityAtom,
                    EscalationStateAtom,
                    EscalationReasonAtom,
                    CompromiseStateAtom,
                    CaseRelationshipAtom,
                ),
            )
        ]
        technical_atoms = [
            atom for atom in selected if isinstance(atom, MitreTechniqueAtom)
        ]
        correlation_atoms = [
            atom for atom in selected if isinstance(atom, RecordedCorrelationAtom)
        ]
        timeline_atoms = [
            atom for atom in selected if isinstance(atom, TimelineEventAtom)
        ]
        identity_atoms = [
            atom
            for atom in selected
            if isinstance(atom, (IncidentIdentityAtom, CaseIdentityAtom))
        ]
        categorized = {
            id(atom)
            for atom in (
                *primary_atoms,
                *handling_atoms,
                *technical_atoms,
                *correlation_atoms,
                *timeline_atoms,
                *identity_atoms,
            )
        }
        primary_clauses = [
            clause
            for atom in primary_atoms
            for clause in _atom_clauses(atom, language=language)
        ]
        if primary_clauses:
            sentences.append(
                f"{_record_subject(selected[0], language=language)} "
                f"{_join_clauses(primary_clauses, language=language)}."
            )
        handling_clauses = [
            clause
            for atom in handling_atoms
            for clause in _atom_clauses(atom, language=language)
        ]
        if handling_clauses:
            record_subject = _record_subject(selected[0], language=language)
            if language == "it":
                record_subject = record_subject.replace("L'", "l'", 1).replace(
                    "Il ", "il ", 1
                )
            subject = (
                f"Nel contesto operativo corrente, {record_subject}"
                if language == "it"
                else f"In the current handling context, {record_subject.lower()}"
            )
            sentences.append(
                f"{subject} {_join_clauses(handling_clauses, language=language)}."
            )
        for atom in correlation_atoms:
            values: list[str] = []
            if isinstance(atom.correlated, bool):
                if language == "it":
                    values.append(
                        "una correlazione registrata"
                        if atom.correlated
                        else "l'assenza di correlazione registrata"
                    )
                else:
                    values.append(
                        "a recorded correlation"
                        if atom.correlated
                        else "recorded absence of correlation"
                    )
            if atom.correlation_type:
                values.append(
                    f"il tipo {atom.correlation_type}"
                    if language == "it"
                    else f"type {atom.correlation_type}"
                )
            if atom.correlation_score is not None:
                values.append(
                    f"il punteggio {atom.correlation_score:g}"
                    if language == "it"
                    else f"score {atom.correlation_score:g}"
                )
            if values:
                joined = _join_clauses(values, language=language)
                record_subject = _record_subject(atom, language=language)
                if language == "it":
                    record_subject = record_subject.replace(
                        "L'", "l'", 1
                    ).replace("Il ", "il ", 1)
                sentences.append(
                    f"Separatamente, lo stato di piattaforma per {record_subject} registra {joined}."
                    if language == "it"
                    else f"Separately, platform state for {record_subject.lower()} records {joined}."
                )
        technical_clauses = [
            clause
            for atom in technical_atoms
            for clause in _atom_clauses(atom, language=language)
        ]
        if technical_clauses:
            record_subject = _record_subject(selected[0], language=language)
            if language == "it":
                record_subject = record_subject.replace("L'", "l'", 1).replace(
                    "Il ", "il ", 1
                )
            subject = (
                f"Come contesto tecnico di supporto, {record_subject}"
                if language == "it"
                else f"As supporting technical context, {record_subject.lower()}"
            )
            sentences.append(
                f"{subject} {_join_clauses(technical_clauses, language=language)}."
            )
        for atom in timeline_atoms:
            timestamp = f" alle {atom.timestamp}" if language == "it" else f" at {atom.timestamp}"
            if not atom.timestamp:
                timestamp = ""
            sentences.append(
                f"La timeline aggiunge l'evento {atom.event_type}{timestamp}."
                if language == "it"
                else f"The timeline adds event {atom.event_type}{timestamp}."
            )
        identity_clauses = [
            clause
            for atom in identity_atoms
            for clause in _atom_clauses(atom, language=language)
        ]
        if identity_clauses:
            subject = (
                "Per collocarlo nel tempo, il record"
                if language == "it"
                else "To place it in time, the record"
            )
            sentences.append(
                f"{subject} {_join_clauses(identity_clauses, language=language)}."
            )
        other_clauses = [
            clause
            for atom in selected
            if id(atom) not in categorized
            for clause in _atom_clauses(atom, language=language)
        ]
        if other_clauses:
            sentences.append(
                f"{_record_subject(selected[0], language=language)} "
                f"{_join_clauses(other_clauses, language=language)}."
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

_PATTERN_LABELS = {
    RelationshipType.SHARED_HOST: ("host", "host"),
    RelationshipType.SHARED_AGENT: ("agente", "agent"),
    RelationshipType.SHARED_USER: ("utente", "user"),
    RelationshipType.SHARED_RULE: ("regola di detection", "detection rule"),
    RelationshipType.SHARED_DETECTION_FAMILY: ("famiglia di detection", "detection family"),
    RelationshipType.SHARED_MITRE: ("tecnica MITRE", "MITRE technique"),
    RelationshipType.SHARED_OBSERVABLE: ("osservabile", "observable"),
    RelationshipType.SHARED_EVENT_FAMILY: ("famiglia di eventi", "event family"),
    RelationshipType.SHARED_CORRELATION_TYPE: ("tipo di correlazione", "correlation type"),
    RelationshipType.SAME_CASE: ("caso", "case membership"),
    RelationshipType.TEMPORAL_PROXIMITY: ("finestra temporale", "24-hour time window"),
    RelationshipType.SEMANTIC_SIMILARITY: ("segnale semantico", "semantic signal"),
    RelationshipType.PLATFORM_RECORDED_CORRELATION: ("correlazione registrata", "platform-recorded correlation"),
}


def _render_relationship(unit: AnalyticalUnit, package: V3AnalyticalContextPackage) -> str:
    language = package.response_language
    relationships = []
    for ref in unit.relationship_refs:
        relationship = package.relationship_registry.resolve(ref)
        if relationship is not None:
            relationships.append(relationship)
    if not relationships:
        return ""
    relationships.sort(
        key=lambda item: (
            -(item.strength if item.strength is not None else 0.0),
            item.right_incident_id,
            item.relationship_type.value,
        )
    )

    def comparison_clause(relationship) -> str:
        label = _RELATION_LABELS[relationship.relationship_type][
            0 if language == "it" else 1
        ]
        if language == "it":
            return (
                f"gli incidenti {relationship.left_incident_id} e "
                f"{relationship.right_incident_id} condividono {label}"
            )
        return (
            f"incidents {relationship.left_incident_id} and "
            f"{relationship.right_incident_id} share {label}"
        )

    clauses = [comparison_clause(item) for item in relationships]
    if unit.unit_type is AnalyticalUnitType.RECORDED_CORRELATION:
        joined = _join_clauses(clauses, language=language)
        return (
            f"La piattaforma registra i seguenti collegamenti: {joined}."
            if language == "it"
            else f"The platform records the following links: {joined}."
        )
    if unit.unit_type is AnalyticalUnitType.SEMANTIC_SIMILARITY:
        joined = _join_clauses(clauses, language=language)
        return (
            f"Come segnale di retrieval, {joined}; sono candidati di confronto basati sulla similarità semantica."
            if language == "it"
            else f"As a retrieval signal, {joined}; these are comparison candidates based on semantic similarity."
        )
    if len(clauses) == 1:
        return (
            f"{clauses[0].capitalize()}; è una relazione analitica derivata dai record."
            if language == "it"
            else f"{clauses[0].capitalize()}; this is an analytical relationship derived from records."
        )
    leading, *supporting = clauses
    support_text = _join_clauses(supporting, language=language)
    return (
        f"Il confronto principale è che {leading}; il contesto aggiuntivo indica che {support_text}. Sono relazioni analitiche derivate dai record."
        if language == "it"
        else f"The leading comparison is that {leading}; additional context indicates that {support_text}. They are analytical relationships derived from records."
    )


def _render_candidate(unit: AnalyticalUnit, package: V3AnalyticalContextPackage) -> str:
    candidates = {item.candidate_id: item for item in package.cross_incident_candidates}
    selected = sorted(
        (candidates[ref] for ref in unit.candidate_refs),
        key=lambda item: (-item.ranking_score, item.candidate_incident_id),
    )
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
        if len(selected) > 1 and not explicit:
            return (
                f"La policy di retrieval classifica l'incidente {values[0]} come confronto principale e include {', '.join(str(value) for value in values[1:])} come contesto secondario. Il ranking indica utilità comparativa, non rischio, severità o compromissione."
            )
        return f"{subject} gli incidenti {joined} come confronti rilevanti; il ranking indica utilità comparativa, non rischio, severità o compromissione."
    subject = (
        "The explicit record set includes"
        if explicit
        else "The retrieval policy identifies"
    )
    if len(selected) > 1 and not explicit:
        return (
            f"The retrieval policy ranks incident {values[0]} as the leading comparison and includes {', '.join(str(value) for value in values[1:])} as secondary context. Ranking indicates comparison utility, not risk, severity, or compromise."
        )
    return f"{subject} incidents {joined} as relevant comparisons; ranking indicates comparison utility, not risk, severity, or compromise."


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
            subject = _record_subject(atom, language=language)
            if language == "it":
                subject = subject.replace("L'", "l'", 1).replace("Il ", "il ", 1)
            descriptions.append(
                f"{subject} {_join_clauses(clauses, language=language)}"
            )
    if not descriptions:
        return ""
    incident_ids = [atom.incident_id for atom in selected if atom.incident_id is not None]
    if unit.unit_type is AnalyticalUnitType.COMPARISON:
        clauses = _atom_clauses(selected[0], language=language)
        if not clauses:
            return ""
        pluralized: list[str] = []
        replacements = (
            (
                ("è associato ", "sono associati "),
                ("risulta ", "risultano "),
                ("è ", "sono "),
                ("ha ", "hanno "),
                ("deriva ", "derivano "),
                ("mantiene ", "mantengono "),
            )
            if language == "it"
            else (("is ", "are "), ("was ", "were "), ("has ", "have "))
        )
        for clause in clauses:
            for singular, plural in replacements:
                if clause.startswith(singular):
                    clause = f"{plural}{clause[len(singular):]}"
                    break
            pluralized.append(clause)
        joined_ids = _join_clauses(
            [str(incident_id) for incident_id in incident_ids],
            language=language,
        )
        return (
            f"Gli incidenti {joined_ids} {_join_clauses(pluralized, language=language)}."
            if language == "it"
            else f"Incidents {joined_ids} {_join_clauses(pluralized, language=language)}."
        )
    separator = "; mentre " if language == "it" else "; whereas "
    prefix = "Nel confronto diretto, " if language == "it" else "In the direct comparison, "
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
    label = _PATTERN_LABELS[relationships[0].relationship_type][
        0 if package.response_language == "it" else 1
    ]
    joined = ", ".join(str(value) for value in incident_ids)
    if package.response_language == "it":
        return f"Il pattern supportato riguarda {len(incident_ids)} incidenti ({joined}) ed è definito dalla condivisione dello stesso {label} nei record autorevoli."
    return f"The supported pattern covers {len(incident_ids)} incidents ({joined}) and is defined by a shared {label} in authoritative records."


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
    NonImplicationCode.NO_RECORDED_DIFFERENCE_IN_COMPARED_FIELDS: (
        "Nei campi confrontabili disponibili non risultano valori differenti registrati.",
        "No differing values are recorded in the available comparable fields.",
    ),
}


_ABSENCE_FIELD_TEXT = {
    FactField.RECOMMENDED_PRIORITY: (
        "La priorita raccomandata non e registrata nel contesto autorevole disponibile.",
        "Recommended priority is not recorded in the available authoritative context.",
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
        "Non è disponibile guida consultiva pertinente, quindi non posso "
        "attribuire verifiche specifiche a un playbook recuperato.",
        "No relevant advisory guidance is available, so I cannot attribute "
        "specific checks to a retrieved playbook.",
    ),
    PlanLimitationCode.EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY: (
        "Le evidenze disponibili non stabiliscono causalità.",
        "The available evidence does not establish causality.",
    ),
}


def closed_safety_sentences() -> frozenset[str]:
    translations = (
        *_NON_IMPLICATION_TEXT.values(),
        *_LIMITATION_TEXT.values(),
    )
    return frozenset(
        text
        for localized_values in translations
        for text in localized_values
    )


def _scope_prefix(
    package: V3AnalyticalContextPackage,
    *,
    purpose: str,
) -> str:
    language = package.response_language
    incident_ids = package.resolved_scope.active_incident_ids
    case_ids = package.resolved_scope.active_case_ids
    if len(incident_ids) == 1:
        if language == "it":
            return f"Per l'incidente {incident_ids[0]}, {purpose}"
        return f"For incident {incident_ids[0]}, {purpose}"
    if case_ids:
        if language == "it":
            return f"Per il caso {case_ids[0]}, {purpose}"
        return f"For case {case_ids[0]}, {purpose}"
    if language == "it":
        return f"Per i record selezionati, {purpose}"
    return f"For the selected records, {purpose}"


_ADVISORY_ACTION_TEXT = {
    AdvisoryActionCode.COMPARE_RELATED_EVIDENCE: (
        "confronta le evidenze autorevoli di detection e timeline con il precedente storico recuperato",
        "compare authoritative detection and timeline evidence with the retrieved historical precedent",
    ),
    AdvisoryActionCode.VERIFY_DETECTION_CONTROL: (
        "verifica il controllo di detection pertinente rispetto alle evidenze correnti",
        "verify the relevant detection control against current evidence",
    ),
    AdvisoryActionCode.VERIFY_CASE_HANDLING: (
        "riesamina la gestione del caso rispetto alle evidenze registrate",
        "review case handling against the recorded evidence",
    ),
    AdvisoryActionCode.FOLLOW_PLAYBOOK_CHECKS: (
        "applica alle evidenze correnti i controlli del playbook recuperato",
        "apply the retrieved playbook checks to current evidence",
    ),
}

_ADVISORY_REASON_TEXT = {
    AdvisoryReasonCode.HISTORICAL_SIMILARITY_RETRIEVED: (
        "È stato recuperato un incidente storico come lead di similarità, non come prova che gli eventi coincidano",
        "A historical incident was retrieved as a similarity lead, not as evidence that the events are the same",
    ),
    AdvisoryReasonCode.CONTROL_GUIDANCE_RETRIEVED: (
        "La guida del controllo recuperata motiva questa verifica",
        "Retrieved control guidance motivates this verification",
    ),
    AdvisoryReasonCode.CASE_GUIDANCE_RETRIEVED: (
        "La guida di gestione del caso recuperata motiva questa verifica",
        "Retrieved case-handling guidance motivates this verification",
    ),
    AdvisoryReasonCode.PLAYBOOK_GUIDANCE_RETRIEVED: (
        "Il playbook recuperato fornisce il percorso di verifica",
        "The retrieved playbook provides the verification path",
    ),
}

_ADVISORY_TARGET_TEXT = {
    AdvisoryTargetType.DETECTION_AND_TIMELINE: (
        "Cerca corrispondenze o divergenze nei campi di detection e negli eventi adiacenti della timeline",
        "Look for matching or diverging detection fields and adjacent timeline events",
    ),
    AdvisoryTargetType.DETECTION_CONTROL: (
        "Controlla configurazione, copertura e detection prodotte dal controllo",
        "Inspect the control configuration, coverage, and resulting detections",
    ),
    AdvisoryTargetType.CASE_EVIDENCE: (
        "Controlla le evidenze del caso e lo stato di gestione registrato",
        "Inspect case evidence and the recorded handling state",
    ),
    AdvisoryTargetType.SOURCE_DEFINED_ARTIFACTS: (
        "Cerca gli artefatti e i risultati definiti dalla fonte consultiva nelle evidenze disponibili",
        "Look for the advisory source-defined artifacts and outcomes in the available evidence",
    ),
}

_ADVISORY_CONTEXT_TEXT = {
    AdvisoryContextCode.HISTORICAL_INCIDENT: (
        "precedente storico recuperato",
        "retrieved historical precedent",
    ),
    AdvisoryContextCode.DETECTION_CONTROL: (
        "guida del controllo di detection",
        "detection-control guidance",
    ),
    AdvisoryContextCode.CASE_CLOSURE: (
        "guida di gestione del caso",
        "case-handling guidance",
    ),
    AdvisoryContextCode.KNOWLEDGE_BASE: (
        "playbook della knowledge base",
        "knowledge-base playbook",
    ),
}

_REFERENCE_TEXT = {
    "reference:correlation:recorded": (
        "Una correlazione registrata è uno stato esplicito della piattaforma. Resta distinta da una relazione analitica derivata dall'Assistant e non dimostra da sola causalità o compromissione.",
        "A recorded correlation is explicit platform state. It remains distinct from an Assistant-derived analytical relationship and does not by itself establish causality or compromise.",
    ),
    "reference:correlation:analytical": (
        "Una relazione analitica registra evidenze condivise e tracciabili tra incidenti. Non è una correlazione registrata dalla piattaforma né una prova di causa, attaccante, campagna o asset compromesso condivisi.",
        "An analytical relationship records shared, traceable evidence between incidents. It is neither platform-recorded correlation nor proof of a shared cause, attacker, campaign, or compromised asset.",
    ),
    "reference:correlation:semantic": (
        "La similarità semantica è soltanto un segnale di retrieval. Un incidente storico usato nel confronto operativo deve essere reidratato dallo storage autorevole e la similarità non può essere presentata come correlazione.",
        "Semantic similarity is a retrieval signal only. Any historical incident used for operational comparison must be rehydrated from authoritative storage, and similarity must not be represented as correlation.",
    ),
    "reference:risk:separation": (
        "Severità canonica, severità di normalizzazione, rischio numerico e priorità raccomandata sono concetti registrati distinti e non si sostituiscono a vicenda.",
        "Canonical severity, risk-normalization severity, numeric risk, and recommended priority are separate recorded concepts and cannot replace one another.",
    ),
}


def _render_advisory(
    unit: AnalyticalUnit,
    *,
    package: V3AnalyticalContextPackage,
) -> str:
    advisories = {item.knowledge_id: item for item in package.advisory_atoms}
    selected: list[AdvisoryKnowledgeAtom] = [
        advisories[ref] for ref in unit.advisory_refs
    ]
    language_index = 0 if package.response_language == "it" else 1
    sentences: list[str] = []
    seen: set[tuple[object, ...]] = set()
    for advisory in selected:
        semantic_key = (
            advisory.action_code,
            advisory.reason_code,
            advisory.target_type,
            advisory.context_code,
        )
        if semantic_key in seen:
            continue
        seen.add(semantic_key)
        action = _ADVISORY_ACTION_TEXT[advisory.action_code][language_index]
        reason = _ADVISORY_REASON_TEXT[advisory.reason_code][language_index]
        target = _ADVISORY_TARGET_TEXT[advisory.target_type][language_index]
        context = _ADVISORY_CONTEXT_TEXT[advisory.context_code][language_index]
        if package.response_language == "it":
            sentences.append(
                f"{_scope_prefix(package, purpose='come prossimo controllo, ')}{action}. "
                f"{reason}. Usa il {context} solo come guida, non come fatto operativo. "
                f"{target}."
            )
        else:
            sentences.append(
                f"{_scope_prefix(package, purpose='as the next check, ')}{action}. "
                f"{reason}. Use the {context} only as guidance, not as an operational fact. "
                f"{target}."
            )
    return " ".join(sentences)


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
        language_index = 0 if language == "it" else 1
        content = " ".join(
            _REFERENCE_TEXT.get(
                ref,
                (
                    references[ref].bounded_content,
                    references[ref].bounded_content,
                ),
            )[language_index]
            for ref in unit.reference_refs
        )
        purpose = (
            "la conoscenza di riferimento indica: "
            if language == "it"
            else "reference knowledge explains: "
        )
        return f"{_scope_prefix(package, purpose=purpose)}{content}"
    if unit.unit_type in {
        AnalyticalUnitType.ADVISORY_GUIDANCE,
        AnalyticalUnitType.NEXT_CHECK,
    }:
        return _render_advisory(unit, package=package)
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
        if unit.absence_field in _ABSENCE_FIELD_TEXT:
            return _ABSENCE_FIELD_TEXT[unit.absence_field][
                0 if language == "it" else 1
            ]
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
            fact_units = [
                unit
                for unit in section.units
                if unit.fact_refs
                and unit.unit_type
                in {
                    AnalyticalUnitType.RECORDED_FACT,
                    AnalyticalUnitType.RECORDED_CORRELATION,
                }
            ]
            aggregate_fact_refs = list(
                dict.fromkeys(
                    ref for unit in fact_units for ref in unit.fact_refs
                )
            )
            facts_rendered = False
            aggregate_types = {
                AnalyticalUnitType.ANALYTICAL_RELATIONSHIP,
                AnalyticalUnitType.SEMANTIC_SIMILARITY,
                AnalyticalUnitType.CANDIDATE_RELEVANCE,
                AnalyticalUnitType.ADVISORY_GUIDANCE,
                AnalyticalUnitType.NEXT_CHECK,
            }
            aggregated_types: set[AnalyticalUnitType] = set()
            for unit in section.units:
                render_unit = unit
                if unit in fact_units:
                    if facts_rendered:
                        continue
                    facts_rendered = True
                    render_unit = unit.model_copy(
                        update={"fact_refs": aggregate_fact_refs}
                    )
                elif unit.unit_type in aggregate_types:
                    if unit.unit_type in aggregated_types:
                        continue
                    aggregated_types.add(unit.unit_type)
                    peers = [
                        item
                        for item in section.units
                        if item.unit_type is unit.unit_type
                    ]
                    render_unit = unit.model_copy(
                        update={
                            "relationship_refs": list(
                                dict.fromkeys(
                                    ref
                                    for item in peers
                                    for ref in item.relationship_refs
                                )
                            ),
                            "candidate_refs": list(
                                dict.fromkeys(
                                    ref
                                    for item in peers
                                    for ref in item.candidate_refs
                                )
                            ),
                            "advisory_refs": list(
                                dict.fromkeys(
                                    ref
                                    for item in peers
                                    for ref in item.advisory_refs
                                )
                            ),
                        }
                    )
                text = " ".join(
                    _render_unit(
                        render_unit,
                        package=package,
                        atoms=atoms,
                    ).split()
                )
                if not text:
                    continue
                if section.section_type is AnswerSectionType.EVIDENCE:
                    text = (
                        f"Evidenze operative di supporto: {text}"
                        if package.response_language == "it"
                        else f"Supporting operational evidence: {text}"
                    )
                elif section.section_type is AnswerSectionType.KEY_FINDINGS:
                    text = (
                        f"Il contesto operativo rilevante aggiunge: {text}"
                        if package.response_language == "it"
                        else f"The relevant handling context adds: {text}"
                    )
                normalized = text.casefold()
                if normalized in rendered_texts:
                    continue
                rendered_texts.add(normalized)
                paragraphs.append(text)
                source_refs.extend(
                    [
                        *render_unit.fact_refs,
                        *render_unit.relationship_refs,
                        *render_unit.candidate_refs,
                        *render_unit.reference_refs,
                        *render_unit.advisory_refs,
                    ]
                )
            if paragraphs:
                blocks.append(
                    RenderedV3Block(
                        section_type=section.section_type,
                        text=" ".join(paragraphs),
                        source_refs=tuple(dict.fromkeys(source_refs)),
                    )
                )
        if not blocks:
            raise ValueError("validated V3 plan rendered no visible blocks")
        return RenderedV3Answer(
            blocks=tuple(blocks),
            render_ms=max(0.0, (clock() - started) * 1000),
        )
