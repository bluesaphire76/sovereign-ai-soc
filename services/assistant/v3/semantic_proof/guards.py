from __future__ import annotations

import unicodedata
from enum import Enum

from pydantic import Field

from services.assistant.v3.contracts import ClosedModel
from services.assistant.v3.semantic_proof.contracts import (
    EvidenceKind,
    EvidenceProofUnit,
    ProofPredicate,
)


class SemanticConcept(str, Enum):
    STATUS = "STATUS"
    INVESTIGATION_STATE = "INVESTIGATION_STATE"
    HOST_IDENTITY = "HOST_IDENTITY"
    USER_IDENTITY = "USER_IDENTITY"
    DETECTION = "DETECTION"
    MITRE_CLASSIFICATION = "MITRE_CLASSIFICATION"
    RISK_SCORE = "RISK_SCORE"
    RISK_NORMALIZATION = "RISK_NORMALIZATION"
    SEVERITY = "SEVERITY"
    PRIORITY = "PRIORITY"
    RECORDED_CORRELATION = "RECORDED_CORRELATION"
    ANALYTICAL_RELATIONSHIP = "ANALYTICAL_RELATIONSHIP"
    SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY"
    THREAT_ASSESSMENT = "THREAT_ASSESSMENT"
    COMPROMISE = "COMPROMISE"
    MALICIOUSNESS = "MALICIOUSNESS"
    ATTACKER_ATTRIBUTION = "ATTACKER_ATTRIBUTION"
    CAMPAIGN_ATTRIBUTION = "CAMPAIGN_ATTRIBUTION"
    PERSISTENCE = "PERSISTENCE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    CAUSALITY = "CAUSALITY"
    BUSINESS_IMPACT = "BUSINESS_IMPACT"
    URGENCY = "URGENCY"
    RECOMMENDATION = "RECOMMENDATION"
    REFERENCE_EXPLANATION = "REFERENCE_EXPLANATION"
    CURRENT_OPERATIONAL_STATE = "CURRENT_OPERATIONAL_STATE"


class TypedGuardReason(str, Enum):
    ACCEPTED = "ACCEPTED"
    EMPTY_PROPOSITION = "EMPTY_PROPOSITION"
    MISSING_REQUIRED_ANCHOR = "MISSING_REQUIRED_ANCHOR"
    CONFLICTING_NUMERIC_VALUE = "CONFLICTING_NUMERIC_VALUE"
    POLARITY_MISMATCH = "POLARITY_MISMATCH"
    INCOMPATIBLE_SEMANTIC_CONCEPT = "INCOMPATIBLE_SEMANTIC_CONCEPT"
    REFERENCE_USED_AS_OPERATIONAL_STATE = "REFERENCE_USED_AS_OPERATIONAL_STATE"
    ADVISORY_USED_AS_OPERATIONAL_STATE = "ADVISORY_USED_AS_OPERATIONAL_STATE"


class TypedGuardDecision(ClosedModel):
    accepted: bool
    proof_unit_id: str = Field(min_length=1, max_length=220)
    reason: TypedGuardReason
    detected_concepts: list[SemanticConcept] = Field(default_factory=list)
    missing_anchors: list[str] = Field(default_factory=list, max_length=8)
    conflicting_numbers: list[str] = Field(default_factory=list, max_length=8)


_CONCEPT_PHRASES: dict[SemanticConcept, tuple[str, ...]] = {
    SemanticConcept.STATUS: (
        "status",
        "stato",
    ),
    SemanticConcept.INVESTIGATION_STATE: (
        "investigated",
        "investigation completed",
        "evaluated",
        "assessed",
        "resolved",
        "investigato",
        "indagato",
        "valutato",
        "analizzato",
        "risolto",
    ),
    SemanticConcept.HOST_IDENTITY: (
        "host",
        "endpoint",
        "agent",
        "agente",
    ),
    SemanticConcept.USER_IDENTITY: (
        "recorded user",
        "utente registrato",
    ),
    SemanticConcept.DETECTION: (
        "detection",
        "detection rule",
        "regola di detection",
        "regola di rilevamento",
    ),
    SemanticConcept.MITRE_CLASSIFICATION: (
        "mitre",
        "technique",
        "tecnica",
    ),
    SemanticConcept.RISK_SCORE: (
        "risk score",
        "punteggio di rischio",
    ),
    SemanticConcept.RISK_NORMALIZATION: (
        "risk normalization",
        "risk band",
        "normalizzazione del rischio",
        "fascia di rischio",
    ),
    SemanticConcept.SEVERITY: (
        "severity",
        "severita",
        "gravita",
    ),
    SemanticConcept.PRIORITY: (
        "priority",
        "priorita",
    ),
    SemanticConcept.RECORDED_CORRELATION: (
        "recorded correlation",
        "platform correlation",
        "platform recorded correlation",
        "correlazione registrata",
        "correlazione di piattaforma",
        "correlati dalla piattaforma",
    ),
    SemanticConcept.ANALYTICAL_RELATIONSHIP: (
        "analytical relationship",
        "derived relationship",
        "relazione analitica",
        "relazione derivata",
    ),
    SemanticConcept.SEMANTIC_SIMILARITY: (
        "semantic similarity",
        "semantic candidate",
        "similarita semantica",
        "candidato semantico",
    ),
    SemanticConcept.THREAT_ASSESSMENT: (
        "threat",
        "threat level",
        "minaccia",
        "livello di minaccia",
    ),
    SemanticConcept.COMPROMISE: (
        "compromise",
        "compromised",
        "compromissione",
        "compromesso",
        "compromessa",
    ),
    SemanticConcept.MALICIOUSNESS: (
        "malicious",
        "benign",
        "harmful",
        "malevolo",
        "malevola",
        "benigno",
        "benigna",
        "dannoso",
        "dannosa",
        "attivita anomala",
        "anomalous activity",
    ),
    SemanticConcept.ATTACKER_ATTRIBUTION: (
        "attacker",
        "threat actor",
        "same actor",
        "attaccante",
        "attore della minaccia",
        "stesso attore",
    ),
    SemanticConcept.CAMPAIGN_ATTRIBUTION: (
        "campaign",
        "campagna",
    ),
    SemanticConcept.PERSISTENCE: (
        "persistence",
        "persistenza",
    ),
    SemanticConcept.LATERAL_MOVEMENT: (
        "lateral movement",
        "movimento laterale",
    ),
    SemanticConcept.CAUSALITY: (
        "cause",
        "caused",
        "causality",
        "because",
        "same cause",
        "causa",
        "causato",
        "causalita",
        "perche",
        "stessa causa",
    ),
    SemanticConcept.BUSINESS_IMPACT: (
        "business impact",
        "operational impact",
        "impatto sul business",
        "impatto operativo",
        "impatto aziendale",
    ),
    SemanticConcept.URGENCY: (
        "urgent",
        "urgency",
        "needs attention",
        "significant security event",
        "urgente",
        "urgenza",
        "richiede attenzione",
        "evento di sicurezza significativo",
    ),
    SemanticConcept.RECOMMENDATION: (
        "should review",
        "should check",
        "recommend",
        "recommended action",
        "dovrebbe esaminare",
        "dovrebbe verificare",
        "raccomanda",
        "si consiglia",
        "azione raccomandata",
    ),
    SemanticConcept.REFERENCE_EXPLANATION: (
        "defines",
        "means",
        "reference knowledge",
        "definisce",
        "significa",
        "conoscenza di riferimento",
    ),
    SemanticConcept.CURRENT_OPERATIONAL_STATE: (
        "current incident",
        "current case",
        "incident currently",
        "incidente corrente",
        "caso corrente",
        "attualmente l incidente",
    ),
}


_ALLOWED_PREDICATES: dict[SemanticConcept, frozenset[ProofPredicate]] = {
    SemanticConcept.STATUS: frozenset({ProofPredicate.STATUS}),
    SemanticConcept.INVESTIGATION_STATE: frozenset(),
    SemanticConcept.HOST_IDENTITY: frozenset(
        {ProofPredicate.HOST, ProofPredicate.AGENT}
    ),
    SemanticConcept.USER_IDENTITY: frozenset({ProofPredicate.USER}),
    SemanticConcept.DETECTION: frozenset(
        {ProofPredicate.DETECTION_RULE, ProofPredicate.DETECTION_LEVEL}
    ),
    SemanticConcept.MITRE_CLASSIFICATION: frozenset(
        {ProofPredicate.MITRE_TECHNIQUE, ProofPredicate.REFERENCE_EXPLANATION}
    ),
    SemanticConcept.RISK_SCORE: frozenset({ProofPredicate.RISK_SCORE}),
    SemanticConcept.RISK_NORMALIZATION: frozenset(
        {ProofPredicate.RISK_NORMALIZATION}
    ),
    SemanticConcept.SEVERITY: frozenset({ProofPredicate.CANONICAL_SEVERITY}),
    SemanticConcept.PRIORITY: frozenset({ProofPredicate.RECOMMENDED_PRIORITY}),
    SemanticConcept.RECORDED_CORRELATION: frozenset(
        {
            ProofPredicate.CORRELATION_FLAG,
            ProofPredicate.CORRELATION_TYPE,
            ProofPredicate.CORRELATION_SCORE,
            ProofPredicate.RECORDED_RELATIONSHIP,
        }
    ),
    SemanticConcept.ANALYTICAL_RELATIONSHIP: frozenset(
        {ProofPredicate.ANALYTICAL_RELATIONSHIP}
    ),
    SemanticConcept.SEMANTIC_SIMILARITY: frozenset(
        {ProofPredicate.SEMANTIC_SIMILARITY, ProofPredicate.CANDIDATE_DISCOVERY}
    ),
    SemanticConcept.THREAT_ASSESSMENT: frozenset(),
    SemanticConcept.COMPROMISE: frozenset({ProofPredicate.COMPROMISE_CONFIRMED}),
    SemanticConcept.MALICIOUSNESS: frozenset(),
    SemanticConcept.ATTACKER_ATTRIBUTION: frozenset(),
    SemanticConcept.CAMPAIGN_ATTRIBUTION: frozenset(),
    SemanticConcept.PERSISTENCE: frozenset(),
    SemanticConcept.LATERAL_MOVEMENT: frozenset(),
    SemanticConcept.CAUSALITY: frozenset(),
    SemanticConcept.BUSINESS_IMPACT: frozenset(),
    SemanticConcept.URGENCY: frozenset(),
    SemanticConcept.RECOMMENDATION: frozenset({ProofPredicate.ADVISORY_GUIDANCE}),
    SemanticConcept.REFERENCE_EXPLANATION: frozenset(
        {ProofPredicate.REFERENCE_EXPLANATION}
    ),
    SemanticConcept.CURRENT_OPERATIONAL_STATE: frozenset(
        predicate
        for predicate in ProofPredicate
        if predicate
        not in {
            ProofPredicate.REFERENCE_EXPLANATION,
            ProofPredicate.ADVISORY_GUIDANCE,
            ProofPredicate.SEMANTIC_SIMILARITY,
            ProofPredicate.CANDIDATE_DISCOVERY,
        }
    ),
}


_NEGATION_TOKENS = frozenset(
    {
        "no",
        "not",
        "never",
        "without",
        "cannot",
        "non",
        "mai",
        "senza",
        "nessun",
        "nessuna",
    }
)

_FUNCTION_WORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "as",
        "at",
        "between",
        "by",
        "for",
        "from",
        "has",
        "have",
        "in",
        "is",
        "its",
        "of",
        "on",
        "the",
        "this",
        "to",
        "was",
        "were",
        "with",
        "al",
        "alla",
        "come",
        "con",
        "da",
        "dal",
        "dalla",
        "del",
        "dell",
        "della",
        "di",
        "e",
        "gli",
        "ha",
        "hanno",
        "i",
        "il",
        "in",
        "l",
        "la",
        "le",
        "lo",
        "nel",
        "nella",
        "per",
        "stata",
        "su",
        "tra",
        "un",
        "una",
    }
)

_GENERIC_PROOF_WORDS = frozenset(
    {
        "canonical",
        "confirmation",
        "derived",
        "identifies",
        "identified",
        "links",
        "named",
        "platform",
        "platform-recorded",
        "record",
        "recorded",
        "records",
        "selected",
        "true",
        "false",
        "canonica",
        "collega",
        "conferma",
        "denominata",
        "derivata",
        "derivato",
        "falsa",
        "falso",
        "identifica",
        "identificato",
        "identificata",
        "indicato",
        "piattaforma",
        "registrata",
        "registrato",
        "registra",
        "selezionato",
        "selezionata",
        "vera",
        "vero",
    }
)

_PREDICATE_WORDS: dict[ProofPredicate, frozenset[str]] = {
    ProofPredicate.INCIDENT_ID: frozenset({"incident", "incidente", "identifier", "identificativo"}),
    ProofPredicate.INCIDENT_TIMESTAMP: frozenset({"incident", "incidente", "timestamp"}),
    ProofPredicate.CASE_ID: frozenset({"case", "caso", "identifier", "identificativo"}),
    ProofPredicate.CASE_TITLE: frozenset({"case", "caso", "title", "titolo"}),
    ProofPredicate.STATUS: frozenset({"incident", "incidente", "status", "stato"}),
    ProofPredicate.CANONICAL_SEVERITY: frozenset(
        {"incident", "incidente", "canonical", "canonica", "severity", "severita"}
    ),
    ProofPredicate.RISK_SCORE: frozenset(
        {"incident", "incidente", "risk", "rischio", "score", "punteggio", "pari"}
    ),
    ProofPredicate.RISK_NORMALIZATION: frozenset(
        {"incident", "incidente", "risk", "rischio", "normalization", "normalizzazione"}
    ),
    ProofPredicate.RECOMMENDED_PRIORITY: frozenset(
        {"incident", "incidente", "recommended", "raccomandata", "priority", "priorita"}
    ),
    ProofPredicate.HOST: frozenset({"incident", "incidente", "host"}),
    ProofPredicate.AGENT: frozenset({"incident", "incidente", "agent", "agente"}),
    ProofPredicate.USER: frozenset({"incident", "incidente", "user", "utente"}),
    ProofPredicate.DETECTION_RULE: frozenset(
        {"incident", "incidente", "detection", "rule", "regola", "rilevamento"}
    ),
    ProofPredicate.DETECTION_LEVEL: frozenset(
        {"incident", "incidente", "detection", "rule", "regola", "level", "livello"}
    ),
    ProofPredicate.MITRE_TECHNIQUE: frozenset(
        {
            "incident",
            "incidente",
            "event",
            "evento",
            "mitre",
            "technique",
            "tecnica",
            "classification",
            "classificazione",
            "classified",
            "classificato",
        }
    ),
    ProofPredicate.TIMELINE_EVENT: frozenset(
        {"incident", "incidente", "timeline", "event", "evento"}
    ),
    ProofPredicate.OBSERVABLE: frozenset(
        {"incident", "incidente", "observable", "osservabile", "ip"}
    ),
    ProofPredicate.PROCESS_NAME: frozenset(
        {"incident", "incidente", "process", "processo", "name", "nome"}
    ),
    ProofPredicate.PROCESS_ID: frozenset(
        {"incident", "incidente", "process", "processo", "id"}
    ),
    ProofPredicate.PARENT_PROCESS: frozenset(
        {"incident", "incidente", "process", "processo", "parent", "padre"}
    ),
    ProofPredicate.EVIDENCE_DETAIL: frozenset(
        {"incident", "incidente", "evidence", "evidenza", "type", "tipo"}
    ),
    ProofPredicate.CORRELATION_FLAG: frozenset(
        {"incident", "incidente", "correlation", "correlazione", "flag"}
    ),
    ProofPredicate.CORRELATION_TYPE: frozenset(
        {"incident", "incidente", "correlation", "correlazione", "type", "tipo"}
    ),
    ProofPredicate.CORRELATION_SCORE: frozenset(
        {"incident", "incidente", "correlation", "correlazione", "score", "punteggio"}
    ),
    ProofPredicate.ESCALATED: frozenset(
        {"incident", "incidente", "escalation", "escalated", "flag"}
    ),
    ProofPredicate.ESCALATION_REASON: frozenset(
        {"incident", "incidente", "escalation", "reason", "motivo"}
    ),
    ProofPredicate.COMPROMISE_CONFIRMED: frozenset(
        {"incident", "incidente", "compromise", "compromissione", "confirmation", "conferma"}
    ),
    ProofPredicate.CASE_RELATIONSHIP: frozenset(
        {"incident", "incidente", "case", "caso", "relationship", "relazione"}
    ),
    ProofPredicate.RECORDED_RELATIONSHIP: frozenset(
        {"incident", "incidents", "incidente", "incidenti", "correlation", "correlazione", "relationship", "relazione"}
    ),
    ProofPredicate.ANALYTICAL_RELATIONSHIP: frozenset(
        {"incident", "incidents", "incidente", "incidenti", "analytical", "analitica", "relationship", "relazione"}
    ),
    ProofPredicate.SEMANTIC_SIMILARITY: frozenset(
        {
            "incident",
            "incidents",
            "incidente",
            "incidenti",
            "semantic",
            "semantica",
            "semantico",
            "similarity",
            "similarita",
            "candidate",
            "candidato",
        }
    ),
    ProofPredicate.CANDIDATE_DISCOVERY: frozenset(
        {"incident", "incidente", "candidate", "candidato", "cross-incident", "discovery", "signals", "segnali"}
    ),
    ProofPredicate.REFERENCE_EXPLANATION: frozenset(
        {"reference", "riferimento", "knowledge", "conoscenza", "defines", "definisce", "means", "significa", "mitre"}
    ),
    ProofPredicate.ADVISORY_GUIDANCE: frozenset(
        {"advisory", "guidance", "guida", "recommends", "raccomanda"}
    ),
}

_OPEN_TEXT_PREDICATES = frozenset(
    {
        ProofPredicate.CASE_TITLE,
        ProofPredicate.EVIDENCE_DETAIL,
        ProofPredicate.ESCALATION_REASON,
        ProofPredicate.REFERENCE_EXPLANATION,
        ProofPredicate.ADVISORY_GUIDANCE,
    }
)


def _normalized_tokens(value: str) -> tuple[str, ...]:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    without_accents = "".join(
        character for character in decomposed if not unicodedata.combining(character)
    )
    normalized_characters: list[str] = []
    for index, character in enumerate(without_accents):
        decimal_point = (
            character == "."
            and index > 0
            and index + 1 < len(without_accents)
            and without_accents[index - 1].isdigit()
            and without_accents[index + 1].isdigit()
        )
        normalized_characters.append(
            character
            if character.isalnum() or character in {"_", "-"} or decimal_point
            else " "
        )
    normalized = "".join(normalized_characters)
    return tuple(
        token for token in normalized.split() if any(character.isalnum() for character in token)
    )


def _contains_tokens(tokens: tuple[str, ...], candidate: tuple[str, ...]) -> bool:
    if not candidate or len(candidate) > len(tokens):
        return False
    return any(
        tokens[offset : offset + len(candidate)] == candidate
        for offset in range(len(tokens) - len(candidate) + 1)
    )


def detect_semantic_concepts(value: str) -> tuple[SemanticConcept, ...]:
    tokens = _normalized_tokens(value)
    return tuple(
        concept
        for concept, phrases in _CONCEPT_PHRASES.items()
        if any(_contains_tokens(tokens, _normalized_tokens(phrase)) for phrase in phrases)
    )


def _anchor_present(anchor: str, text_tokens: tuple[str, ...]) -> bool:
    normalized_anchor = _normalized_tokens(anchor)
    if normalized_anchor == ("true",):
        return any(item in text_tokens for item in ("true", "vero", "vera"))
    if normalized_anchor == ("false",):
        return any(item in text_tokens for item in ("false", "falso", "falsa"))
    return _contains_tokens(text_tokens, normalized_anchor)


def _numeric_tokens(tokens: tuple[str, ...]) -> set[str]:
    result: set[str] = set()
    for token in tokens:
        try:
            numeric = float(token)
        except ValueError:
            continue
        result.add(str(int(numeric)) if numeric.is_integer() else format(numeric, ".12g"))
    return result


def uncovered_material_tokens(
    proof_unit: EvidenceProofUnit,
    proposition: str,
) -> tuple[str, ...]:
    canonical_tokens = {
        *_normalized_tokens(proof_unit.canonical_premise),
        *(
            token
            for value in proof_unit.value.canonical_values
            for token in _normalized_tokens(value)
        ),
    }
    scope_tokens = {
        str(item)
        for item in [*proof_unit.scope.incident_ids, *proof_unit.scope.case_ids]
    }
    allowed = (
        canonical_tokens
        | scope_tokens
        | _FUNCTION_WORDS
        | _GENERIC_PROOF_WORDS
        | set(_PREDICATE_WORDS[proof_unit.predicate])
    )
    return tuple(
        dict.fromkeys(
            token
            for token in _normalized_tokens(proposition)
            if token not in allowed
        )
    )


def eligible_for_deterministic_proof(
    proof_unit: EvidenceProofUnit,
    proposition: str,
) -> bool:
    return (
        proof_unit.predicate not in _OPEN_TEXT_PREDICATES
        and not uncovered_material_tokens(proof_unit, proposition)
    )


class TypedSemanticGuard:
    """Fail-closed semantic compatibility checks over typed proof obligations."""

    def evaluate(
        self,
        proof_unit: EvidenceProofUnit,
        proposition: str,
    ) -> TypedGuardDecision:
        text = proposition.strip()
        if not text:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.EMPTY_PROPOSITION,
            )

        text_tokens = _normalized_tokens(text)
        missing = [
            anchor
            for anchor in proof_unit.value.required_anchors
            if not _anchor_present(anchor, text_tokens)
        ]
        if missing:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.MISSING_REQUIRED_ANCHOR,
                missing_anchors=missing,
            )

        allowed_numbers = _numeric_tokens(
            tuple(
                token
                for value in proof_unit.value.canonical_values
                for token in _normalized_tokens(value)
            )
        ) | {
            str(item)
            for item in [*proof_unit.scope.incident_ids, *proof_unit.scope.case_ids]
        }
        conflicting_numbers = sorted(_numeric_tokens(text_tokens) - allowed_numbers)
        if conflicting_numbers:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.CONFLICTING_NUMERIC_VALUE,
                conflicting_numbers=conflicting_numbers,
            )

        canonical_tokens = _normalized_tokens(
            " ".join(
                [proof_unit.canonical_premise, *proof_unit.value.canonical_values]
            )
        )
        if (
            _NEGATION_TOKENS.intersection(text_tokens)
            and not _NEGATION_TOKENS.intersection(canonical_tokens)
        ):
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.POLARITY_MISMATCH,
            )

        concepts = detect_semantic_concepts(text)
        canonical_concepts = {
            concept
            for value in proof_unit.value.canonical_values
            for concept in detect_semantic_concepts(value)
        }
        incompatible = [
            concept
            for concept in concepts
            if proof_unit.predicate not in _ALLOWED_PREDICATES[concept]
            and concept not in canonical_concepts
        ]
        if incompatible:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.INCOMPATIBLE_SEMANTIC_CONCEPT,
                detected_concepts=list(concepts),
            )

        if (
            proof_unit.evidence_kind is EvidenceKind.REFERENCE_KNOWLEDGE
            and SemanticConcept.CURRENT_OPERATIONAL_STATE in concepts
        ):
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.REFERENCE_USED_AS_OPERATIONAL_STATE,
                detected_concepts=list(concepts),
            )
        if (
            proof_unit.evidence_kind is EvidenceKind.ADVISORY_KNOWLEDGE
            and SemanticConcept.CURRENT_OPERATIONAL_STATE in concepts
        ):
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.ADVISORY_USED_AS_OPERATIONAL_STATE,
                detected_concepts=list(concepts),
            )

        return TypedGuardDecision(
            accepted=True,
            proof_unit_id=proof_unit.proof_unit_id,
            reason=TypedGuardReason.ACCEPTED,
            detected_concepts=list(concepts),
        )
