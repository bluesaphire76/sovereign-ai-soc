from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from typing import Any

from services.assistant.v3.contracts import (
    AdvisoryKnowledgeAtom,
    AnalyticalRelationship,
    AuthorityClass,
    CaseIdentityAtom,
    CaseRelationshipAtom,
    CompromiseStateAtom,
    DetectionAtom,
    EscalationReasonAtom,
    EscalationStateAtom,
    EvidenceDetailAtom,
    HostAtom,
    IncidentCandidate,
    IncidentIdentityAtom,
    MitreTechniqueAtom,
    ObservableAtom,
    PriorityAtom,
    ProcessAtom,
    Provenance,
    RecordedCorrelationAtom,
    ReferenceKnowledgeAtom,
    RelationshipClass,
    RiskAtom,
    StatusAtom,
    TimelineEventAtom,
    UserAtom,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.semantic_proof.contracts import (
    AllowedSemanticRole,
    EvidenceKind,
    EvidenceProofUnit,
    PremiseLanguage,
    ProofLanguage,
    ProofScope,
    ProofScopeKind,
)


def _proof_id(source_ref: str, field: str, language: PremiseLanguage) -> str:
    material = f"{source_ref}\x1f{field}\x1f{language}"
    suffix = hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]
    return f"proof:{language}:{field}:{suffix}"


def _number(value: float | int) -> str:
    numeric = float(value)
    return str(int(numeric)) if numeric.is_integer() else format(numeric, ".12g")


def _boolean(value: bool, language: ProofLanguage) -> str:
    if language == "it":
        return "vero" if value else "falso"
    return "true" if value else "false"


def _atom_scope(atom: Any) -> ProofScope:
    if atom.incident_id is not None:
        return ProofScope(
            scope_kind=ProofScopeKind.INCIDENT,
            incident_ids=[atom.incident_id],
            case_ids=[atom.case_id] if atom.case_id is not None else [],
        )
    if atom.case_id is not None:
        return ProofScope(scope_kind=ProofScopeKind.CASE, case_ids=[atom.case_id])
    return ProofScope(scope_kind=ProofScopeKind.GLOBAL)


def _relationship_scope(relationship: AnalyticalRelationship) -> ProofScope:
    return ProofScope(
        scope_kind=ProofScopeKind.INCIDENT_PAIR,
        incident_ids=[relationship.left_incident_id, relationship.right_incident_id],
    )


def _kind_and_role_for_relationship(
    relationship: AnalyticalRelationship,
) -> tuple[EvidenceKind, AllowedSemanticRole]:
    if relationship.relationship_class is RelationshipClass.RECORDED_CORRELATION:
        return EvidenceKind.RECORDED_CORRELATION, AllowedSemanticRole.RECORDED_RELATIONSHIP
    if relationship.relationship_class is RelationshipClass.ANALYTICAL_RELATIONSHIP:
        return EvidenceKind.ANALYTICAL_RELATIONSHIP, AllowedSemanticRole.ANALYTICAL_COMPARISON
    return EvidenceKind.SEMANTIC_CANDIDATE, AllowedSemanticRole.CANDIDATE_DISCOVERY


class EvidenceProofUnitCompiler:
    """Compile package-local evidence into literal, non-interpretive premises."""

    def compile(
        self,
        package: V3AnalyticalContextPackage,
        *,
        premise_languages: Sequence[ProofLanguage] = ("en", "it"),
    ) -> tuple[EvidenceProofUnit, ...]:
        languages = tuple(dict.fromkeys(premise_languages))
        if not languages or any(language not in {"en", "it"} for language in languages):
            raise ValueError("proof compiler supports only en and it premises")

        registry = {entry.source_ref: entry for entry in package.source_registry}
        allowed_incident_ids = {
            *package.resolved_scope.active_incident_ids,
            *package.resolved_scope.explicit_compare_incident_ids,
            *package.cross_incident_graph.incident_ids,
            *(item.candidate_incident_id for item in package.cross_incident_candidates),
        }
        allowed_case_ids = set(package.resolved_scope.active_case_ids)
        units: list[EvidenceProofUnit] = []

        for atom in package.operational_atoms:
            entry = registry.get(atom.atom_id)
            if (
                entry is None
                or entry.authority_class is not atom.authority_class
                or not self._atom_is_in_scope(
                    atom,
                    allowed_incident_ids=allowed_incident_ids,
                    allowed_case_ids=allowed_case_ids,
                )
            ):
                continue
            units.extend(self._compile_atom(atom, languages=languages))

        for relationship in package.relationship_registry.relationships:
            if not {
                relationship.left_incident_id,
                relationship.right_incident_id,
            }.issubset(allowed_incident_ids):
                continue
            units.extend(self._compile_relationship(relationship, languages=languages))

        for candidate in package.cross_incident_candidates:
            entry = registry.get(candidate.candidate_id)
            if (
                entry is None
                or entry.authority_class is not AuthorityClass.SEMANTIC_CANDIDATE
                or candidate.candidate_incident_id not in allowed_incident_ids
            ):
                continue
            units.extend(
                self._compile_candidate(
                    candidate,
                    package=package,
                    source_type=entry.source_type,
                    source_record_id=entry.source_record_id,
                    languages=languages,
                )
            )

        for atom in package.reference_atoms:
            entry = registry.get(atom.knowledge_id)
            if entry is None or entry.authority_class is not atom.authority_class:
                continue
            units.extend(self._compile_reference(atom, languages=languages))

        for atom in package.advisory_atoms:
            entry = registry.get(atom.knowledge_id)
            if entry is None or entry.authority_class is not atom.authority_class:
                continue
            units.extend(self._compile_advisory(atom, languages=languages))

        unit_ids = [unit.proof_unit_id for unit in units]
        if len(unit_ids) != len(set(unit_ids)):
            raise ValueError("proof compiler produced duplicate unit IDs")
        return tuple(units)

    @staticmethod
    def _atom_is_in_scope(
        atom: Any,
        *,
        allowed_incident_ids: set[int],
        allowed_case_ids: set[int],
    ) -> bool:
        if atom.incident_id is not None:
            return atom.incident_id in allowed_incident_ids
        if atom.case_id is not None:
            return atom.case_id in allowed_case_ids
        return not allowed_incident_ids and not allowed_case_ids

    @staticmethod
    def _unit(
        *,
        source_ref: str,
        field: str,
        language: PremiseLanguage,
        authority_class: AuthorityClass,
        evidence_kind: EvidenceKind,
        scope: ProofScope,
        premise: str,
        source_refs: list[str],
        provenance: Provenance,
        role: AllowedSemanticRole,
    ) -> EvidenceProofUnit:
        return EvidenceProofUnit(
            proof_unit_id=_proof_id(source_ref, field, language),
            authority_class=authority_class,
            evidence_kind=evidence_kind,
            scope=scope,
            canonical_premise=premise,
            source_refs=list(dict.fromkeys(source_refs)),
            provenance=provenance,
            premise_language=language,
            allowed_semantic_role=role,
        )

    def _literal_units(
        self,
        *,
        source_ref: str,
        field: str,
        authority_class: AuthorityClass,
        evidence_kind: EvidenceKind,
        scope: ProofScope,
        source_refs: list[str],
        provenance: Provenance,
        role: AllowedSemanticRole,
        languages: Sequence[ProofLanguage],
        premise: Callable[[ProofLanguage], str],
    ) -> list[EvidenceProofUnit]:
        return [
            self._unit(
                source_ref=source_ref,
                field=field,
                language=language,
                authority_class=authority_class,
                evidence_kind=evidence_kind,
                scope=scope,
                premise=premise(language),
                source_refs=source_refs,
                provenance=provenance,
                role=role,
            )
            for language in languages
        ]

    def _compile_atom(
        self,
        atom: Any,
        *,
        languages: Sequence[ProofLanguage],
    ) -> list[EvidenceProofUnit]:
        scope = _atom_scope(atom)
        kind = (
            EvidenceKind.RECORDED_CORRELATION
            if isinstance(atom, RecordedCorrelationAtom)
            else EvidenceKind.OPERATIONAL_FACT
        )
        role = (
            AllowedSemanticRole.RECORDED_RELATIONSHIP
            if kind is EvidenceKind.RECORDED_CORRELATION
            else AllowedSemanticRole.RECORDED_VALUE
        )
        common = {
            "source_ref": atom.atom_id,
            "authority_class": atom.authority_class,
            "evidence_kind": kind,
            "scope": scope,
            "source_refs": [atom.atom_id],
            "provenance": atom.provenance,
            "role": role,
            "languages": languages,
        }
        units: list[EvidenceProofUnit] = []

        def add(field: str, premise: Callable[[ProofLanguage], str]) -> None:
            units.extend(self._literal_units(field=field, premise=premise, **common))

        subject_en = f"Incident {atom.incident_id}" if atom.incident_id else f"Case {atom.case_id}"
        subject_it = f"Incidente {atom.incident_id}" if atom.incident_id else f"Caso {atom.case_id}"

        if isinstance(atom, IncidentIdentityAtom):
            add(
                "incident_id",
                lambda language: (
                    f"Incident identifier: {atom.incident_id}."
                    if language == "en"
                    else f"Identificativo incidente: {atom.incident_id}."
                ),
            )
            if atom.timestamp:
                add(
                    "timestamp",
                    lambda language: (
                        f"{subject_en} recorded timestamp: {atom.timestamp}."
                        if language == "en"
                        else f"Timestamp registrato per {subject_it}: {atom.timestamp}."
                    ),
                )
        elif isinstance(atom, CaseIdentityAtom):
            add(
                "case_id",
                lambda language: (
                    f"Case identifier: {atom.case_id}."
                    if language == "en"
                    else f"Identificativo caso: {atom.case_id}."
                ),
            )
            if atom.title:
                add(
                    "case_title",
                    lambda language: (
                        f"{subject_en} recorded title: {atom.title}."
                        if language == "en"
                        else f"Titolo registrato per {subject_it}: {atom.title}."
                    ),
                )
        elif isinstance(atom, StatusAtom):
            add(
                "status",
                lambda language: (
                    f"{subject_en} status recorded as {atom.status}."
                    if language == "en"
                    else f"Stato registrato per {subject_it}: {atom.status}."
                ),
            )
            if atom.canonical_severity:
                add(
                    "canonical_severity",
                    lambda language: (
                        f"{subject_en} canonical severity recorded as {atom.canonical_severity}."
                        if language == "en"
                        else f"Severita canonica registrata per {subject_it}: {atom.canonical_severity}."
                    ),
                )
        elif isinstance(atom, RiskAtom):
            if atom.risk_score is not None:
                add(
                    "risk_score",
                    lambda language: (
                        f"{subject_en} recorded risk score: {_number(atom.risk_score)}."
                        if language == "en"
                        else f"Punteggio di rischio registrato per {subject_it}: {_number(atom.risk_score)}."
                    ),
                )
            if atom.risk_normalization_severity:
                add(
                    "risk_normalization",
                    lambda language: (
                        f"{subject_en} recorded risk normalization: {atom.risk_normalization_severity}."
                        if language == "en"
                        else f"Normalizzazione del rischio registrata per {subject_it}: {atom.risk_normalization_severity}."
                    ),
                )
        elif isinstance(atom, PriorityAtom):
            add(
                "recommended_priority",
                lambda language: (
                    f"{subject_en} recorded recommended priority: {atom.recommended_priority}."
                    if language == "en"
                    else f"Priorita raccomandata registrata per {subject_it}: {atom.recommended_priority}."
                ),
            )
        elif isinstance(atom, HostAtom):
            label_en = "host" if atom.representation == "host" else "agent"
            label_it = "host" if atom.representation == "host" else "agente"
            add(
                atom.representation,
                lambda language: (
                    f"{subject_en} recorded {label_en}: {atom.host}."
                    if language == "en"
                    else f"{label_it.capitalize()} registrato per {subject_it}: {atom.host}."
                ),
            )
        elif isinstance(atom, UserAtom):
            add(
                "user",
                lambda language: (
                    f"{subject_en} recorded user: {atom.user}."
                    if language == "en"
                    else f"Utente registrato per {subject_it}: {atom.user}."
                ),
            )
        elif isinstance(atom, DetectionAtom):
            add(
                "detection_rule",
                lambda language: (
                    f"{subject_en} recorded detection rule: {atom.rule}."
                    if language == "en"
                    else f"Regola di detection registrata per {subject_it}: {atom.rule}."
                ),
            )
            if atom.level is not None:
                add(
                    "detection_level",
                    lambda language: (
                        f"{subject_en} recorded detection rule level: {atom.level}."
                        if language == "en"
                        else f"Livello della regola di detection registrato per {subject_it}: {atom.level}."
                    ),
                )
        elif isinstance(atom, MitreTechniqueAtom):
            value = ": ".join(
                item for item in (atom.technique_id, atom.technique_name) if item
            )
            add(
                "mitre_technique",
                lambda language: (
                    f"{subject_en} recorded MITRE technique: {value}."
                    if language == "en"
                    else f"Tecnica MITRE registrata per {subject_it}: {value}."
                ),
            )
        elif isinstance(atom, TimelineEventAtom):
            timestamp = f" at {atom.timestamp}" if atom.timestamp else ""
            timestamp_it = f" alle {atom.timestamp}" if atom.timestamp else ""
            add(
                "timeline_event",
                lambda language: (
                    f"{subject_en} timeline records event {atom.event_type}{timestamp}."
                    if language == "en"
                    else f"La timeline di {subject_it} registra l'evento {atom.event_type}{timestamp_it}."
                ),
            )
        elif isinstance(atom, ObservableAtom):
            add(
                "observable",
                lambda language: (
                    f"{subject_en} recorded {atom.observable_type} observable: {atom.value}."
                    if language == "en"
                    else f"Osservabile {atom.observable_type} registrato per {subject_it}: {atom.value}."
                ),
            )
        elif isinstance(atom, ProcessAtom):
            add(
                "process_name",
                lambda language: (
                    f"{subject_en} recorded process name: {atom.process_name}."
                    if language == "en"
                    else f"Nome processo registrato per {subject_it}: {atom.process_name}."
                ),
            )
            if atom.process_id:
                add(
                    "process_id",
                    lambda language: (
                        f"{subject_en} recorded process ID: {atom.process_id}."
                        if language == "en"
                        else f"ID processo registrato per {subject_it}: {atom.process_id}."
                    ),
                )
            if atom.parent_process_name:
                add(
                    "parent_process",
                    lambda language: (
                        f"{subject_en} recorded parent process: {atom.parent_process_name}."
                        if language == "en"
                        else f"Processo padre registrato per {subject_it}: {atom.parent_process_name}."
                    ),
                )
        elif isinstance(atom, EvidenceDetailAtom):
            add(
                "evidence_detail",
                lambda language: (
                    f"{subject_en} recorded evidence of type {atom.evidence_type}: {atom.summary}."
                    if language == "en"
                    else f"Evidenza registrata per {subject_it}, tipo {atom.evidence_type}: {atom.summary}."
                ),
            )
        elif isinstance(atom, RecordedCorrelationAtom):
            if atom.correlated is not None:
                add(
                    "correlated",
                    lambda language: (
                        f"{subject_en} recorded correlation flag: {_boolean(atom.correlated, language)}."
                        if language == "en"
                        else f"Flag di correlazione registrato per {subject_it}: {_boolean(atom.correlated, language)}."
                    ),
                )
            if atom.correlation_type:
                add(
                    "correlation_type",
                    lambda language: (
                        f"{subject_en} recorded correlation type: {atom.correlation_type}."
                        if language == "en"
                        else f"Tipo di correlazione registrato per {subject_it}: {atom.correlation_type}."
                    ),
                )
            if atom.correlation_score is not None:
                add(
                    "correlation_score",
                    lambda language: (
                        f"{subject_en} recorded correlation score: {_number(atom.correlation_score)}."
                        if language == "en"
                        else f"Punteggio di correlazione registrato per {subject_it}: {_number(atom.correlation_score)}."
                    ),
                )
        elif isinstance(atom, EscalationStateAtom):
            add(
                "escalated",
                lambda language: (
                    f"{subject_en} recorded escalation flag: {_boolean(atom.escalated, language)}."
                    if language == "en"
                    else f"Flag di escalation registrato per {subject_it}: {_boolean(atom.escalated, language)}."
                ),
            )
        elif isinstance(atom, EscalationReasonAtom):
            add(
                "escalation_reason",
                lambda language: (
                    f"{subject_en} recorded escalation reason: {atom.reason}."
                    if language == "en"
                    else f"Motivo di escalation registrato per {subject_it}: {atom.reason}."
                ),
            )
        elif isinstance(atom, CompromiseStateAtom):
            if atom.compromise_confirmed is not None:
                add(
                    "compromise_confirmed",
                    lambda language: (
                        f"{subject_en} recorded compromise confirmation: {_boolean(atom.compromise_confirmed, language)}."
                        if language == "en"
                        else f"Conferma di compromissione registrata per {subject_it}: {_boolean(atom.compromise_confirmed, language)}."
                    ),
                )
        elif isinstance(atom, CaseRelationshipAtom):
            add(
                "case_relationship",
                lambda language: (
                    f"Incident {atom.incident_id} has recorded case relationship {atom.relationship_type} with Case {atom.case_id}."
                    if language == "en"
                    else f"L'Incidente {atom.incident_id} ha la relazione registrata {atom.relationship_type} con il Caso {atom.case_id}."
                ),
            )
        return units

    def _compile_relationship(
        self,
        relationship: AnalyticalRelationship,
        *,
        languages: Sequence[ProofLanguage],
    ) -> list[EvidenceProofUnit]:
        kind, role = _kind_and_role_for_relationship(relationship)

        def premise(language: ProofLanguage) -> str:
            if kind is EvidenceKind.RECORDED_CORRELATION:
                if language == "en":
                    return (
                        f"The platform records relationship type {relationship.relationship_type.value} "
                        f"between Incidents {relationship.left_incident_id} and {relationship.right_incident_id}."
                    )
                return (
                    f"La piattaforma registra la relazione di tipo {relationship.relationship_type.value} "
                    f"tra gli Incidenti {relationship.left_incident_id} e {relationship.right_incident_id}."
                )
            if kind is EvidenceKind.ANALYTICAL_RELATIONSHIP:
                if language == "en":
                    return (
                        f"A deterministic analytical relationship of type {relationship.relationship_type.value} "
                        f"was derived between Incidents {relationship.left_incident_id} and {relationship.right_incident_id}."
                    )
                return (
                    f"E stata derivata una relazione analitica deterministica di tipo {relationship.relationship_type.value} "
                    f"tra gli Incidenti {relationship.left_incident_id} e {relationship.right_incident_id}."
                )
            if language == "en":
                return (
                    f"Semantic similarity relationship type {relationship.relationship_type.value} selected "
                    f"Incident {relationship.right_incident_id} as a candidate for Incident {relationship.left_incident_id}."
                )
            return (
                f"La relazione di similarita semantica di tipo {relationship.relationship_type.value} ha selezionato "
                f"l'Incidente {relationship.right_incident_id} come candidato per l'Incidente {relationship.left_incident_id}."
            )

        return self._literal_units(
            source_ref=relationship.relationship_id,
            field=f"relationship_{relationship.relationship_type.value.lower()}",
            authority_class=relationship.authority_class,
            evidence_kind=kind,
            scope=_relationship_scope(relationship),
            source_refs=[relationship.relationship_id, *relationship.evidence_atom_refs],
            provenance=relationship.provenance,
            role=role,
            languages=languages,
            premise=premise,
        )

    def _compile_candidate(
        self,
        candidate: IncidentCandidate,
        *,
        package: V3AnalyticalContextPackage,
        source_type: str,
        source_record_id: str,
        languages: Sequence[ProofLanguage],
    ) -> list[EvidenceProofUnit]:
        anchor_id = package.resolved_scope.active_incident_ids[:1]
        scope = (
            ProofScope(
                scope_kind=ProofScopeKind.INCIDENT_PAIR,
                incident_ids=[anchor_id[0], candidate.candidate_incident_id],
            )
            if anchor_id and anchor_id[0] != candidate.candidate_incident_id
            else ProofScope(
                scope_kind=ProofScopeKind.INCIDENT,
                incident_ids=[candidate.candidate_incident_id],
            )
        )
        signals = ", ".join(item.value for item in candidate.discovery_signals)
        provenance = Provenance(
            authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
            source_type=source_type,
            source_record_id=source_record_id,
            retrieval_method=(
                "semantic_retrieval"
                if candidate.discovery_source in {"semantic", "hybrid"}
                else "deterministic_derivation"
            ),
        )
        return self._literal_units(
            source_ref=candidate.candidate_id,
            field="candidate_discovery",
            authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
            evidence_kind=EvidenceKind.SEMANTIC_CANDIDATE,
            scope=scope,
            source_refs=[candidate.candidate_id],
            provenance=provenance,
            role=AllowedSemanticRole.CANDIDATE_DISCOVERY,
            languages=languages,
            premise=lambda language: (
                f"Incident {candidate.candidate_incident_id} is a cross-incident candidate with discovery signals: {signals}."
                if language == "en"
                else f"L'Incidente {candidate.candidate_incident_id} e un candidato cross-incident con segnali di discovery: {signals}."
            ),
        )

    def _compile_reference(
        self,
        atom: ReferenceKnowledgeAtom,
        *,
        languages: Sequence[ProofLanguage],
    ) -> list[EvidenceProofUnit]:
        del languages
        return [
            self._unit(
                source_ref=atom.knowledge_id,
                field="reference_knowledge",
                language="und",
                authority_class=atom.authority_class,
                evidence_kind=EvidenceKind.REFERENCE_KNOWLEDGE,
                scope=ProofScope(scope_kind=ProofScopeKind.GLOBAL),
                source_refs=[atom.knowledge_id],
                provenance=atom.provenance,
                role=AllowedSemanticRole.TECHNICAL_EXPLANATION,
                premise=(
                    f"Reference subject: {atom.subject}. "
                    f"Content: {atom.bounded_content}"
                ),
            )
        ]

    def _compile_advisory(
        self,
        atom: AdvisoryKnowledgeAtom,
        *,
        languages: Sequence[ProofLanguage],
    ) -> list[EvidenceProofUnit]:
        del languages
        return [
            self._unit(
                source_ref=atom.knowledge_id,
                field="advisory_knowledge",
                language="und",
                authority_class=atom.authority_class,
                evidence_kind=EvidenceKind.ADVISORY_KNOWLEDGE,
                scope=ProofScope(scope_kind=ProofScopeKind.GLOBAL),
                source_refs=[atom.knowledge_id],
                provenance=atom.provenance,
                role=AllowedSemanticRole.INVESTIGATION_GUIDANCE,
                premise=(
                    f"Advisory subject: {atom.subject}. "
                    f"Guidance: {atom.bounded_content}"
                ),
            )
        ]
