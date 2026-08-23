from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Sequence
from enum import Enum

from pydantic import Field

from services.assistant.v3.contracts import AuthorityClass, ClosedModel
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
    OBSERVED_BEHAVIOR = "OBSERVED_BEHAVIOR"


class TypedGuardReason(str, Enum):
    ACCEPTED = "ACCEPTED"
    EMPTY_PROPOSITION = "EMPTY_PROPOSITION"
    MISSING_REQUIRED_ANCHOR = "MISSING_REQUIRED_ANCHOR"
    CONFLICTING_NUMERIC_VALUE = "CONFLICTING_NUMERIC_VALUE"
    CONFLICTING_TEMPORAL_VALUE = "CONFLICTING_TEMPORAL_VALUE"
    POLARITY_MISMATCH = "POLARITY_MISMATCH"
    INCOMPATIBLE_SEMANTIC_CONCEPT = "INCOMPATIBLE_SEMANTIC_CONCEPT"
    REFERENCE_USED_AS_OPERATIONAL_STATE = "REFERENCE_USED_AS_OPERATIONAL_STATE"
    ADVISORY_USED_AS_OPERATIONAL_STATE = "ADVISORY_USED_AS_OPERATIONAL_STATE"
    INCOMPATIBLE_AUTHORITY_COMBINATION = "INCOMPATIBLE_AUTHORITY_COMBINATION"
    INCOMPATIBLE_SCOPE = "INCOMPATIBLE_SCOPE"
    MISSING_COMPONENT_SUPPORT = "MISSING_COMPONENT_SUPPORT"


class TypedGuardDecision(ClosedModel):
    accepted: bool
    proof_unit_id: str = Field(min_length=1, max_length=220)
    reason: TypedGuardReason
    detected_concepts: list[SemanticConcept] = Field(default_factory=list)
    missing_anchors: list[str] = Field(default_factory=list, max_length=8)
    conflicting_numbers: list[str] = Field(default_factory=list, max_length=8)
    conflicting_temporal_values: list[str] = Field(default_factory=list, max_length=8)


_CONCEPT_PHRASES: dict[SemanticConcept, tuple[str, ...]] = {
    SemanticConcept.STATUS: (
        "status",
        "stato operativo",
        "stato dell incidente",
        "stato del caso",
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
        "incidente analizzato",
        "incidenti analizzati",
        "caso analizzato",
        "casi analizzati",
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
        "stato di correlazione",
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
        "cannot recommend",
        "non posso raccomandare",
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
    SemanticConcept.OBSERVED_BEHAVIOR: (
        "observed behavior",
        "observed activity",
        "comportamento osservato",
        "attivita osservata",
    ),
}


_ALLOWED_PREDICATES: dict[SemanticConcept, frozenset[ProofPredicate]] = {
    SemanticConcept.STATUS: frozenset(
        {
            ProofPredicate.STATUS,
            ProofPredicate.ANALYTICAL_COUNT,
            ProofPredicate.ANALYTICAL_DISTRIBUTION,
            ProofPredicate.ANALYTICAL_TREND,
            ProofPredicate.ANALYTICAL_PERIOD_COMPARISON,
            ProofPredicate.ANALYTICAL_TOP_K,
            ProofPredicate.ANALYTICAL_RESULT_SET,
        }
    ),
    SemanticConcept.INVESTIGATION_STATE: frozenset(),
    SemanticConcept.HOST_IDENTITY: frozenset(
        {
            ProofPredicate.HOST,
            ProofPredicate.AGENT,
            ProofPredicate.ANALYTICAL_COUNT,
            ProofPredicate.ANALYTICAL_DISTRIBUTION,
            ProofPredicate.ANALYTICAL_TREND,
            ProofPredicate.ANALYTICAL_PERIOD_COMPARISON,
            ProofPredicate.ANALYTICAL_TOP_K,
            ProofPredicate.ANALYTICAL_RESULT_SET,
        }
    ),
    SemanticConcept.USER_IDENTITY: frozenset({ProofPredicate.USER}),
    SemanticConcept.DETECTION: frozenset(
        {
            ProofPredicate.DETECTION_RULE,
            ProofPredicate.DETECTION_LEVEL,
            ProofPredicate.ANALYTICAL_COUNT,
            ProofPredicate.ANALYTICAL_DISTRIBUTION,
            ProofPredicate.ANALYTICAL_TREND,
            ProofPredicate.ANALYTICAL_PERIOD_COMPARISON,
            ProofPredicate.ANALYTICAL_TOP_K,
            ProofPredicate.ANALYTICAL_RESULT_SET,
        }
    ),
    SemanticConcept.MITRE_CLASSIFICATION: frozenset(
        {
            ProofPredicate.MITRE_TECHNIQUE,
            ProofPredicate.MITRE_CONTEXT,
            ProofPredicate.REFERENCE_EXPLANATION,
            ProofPredicate.NON_IMPLICATION,
            ProofPredicate.ANALYTICAL_COUNT,
            ProofPredicate.ANALYTICAL_DISTRIBUTION,
            ProofPredicate.ANALYTICAL_TREND,
            ProofPredicate.ANALYTICAL_PERIOD_COMPARISON,
            ProofPredicate.ANALYTICAL_TOP_K,
            ProofPredicate.ANALYTICAL_RESULT_SET,
        }
    ),
    SemanticConcept.RISK_SCORE: frozenset(
        {
            ProofPredicate.RISK_SCORE,
            ProofPredicate.RISK_RECORD,
            ProofPredicate.NON_IMPLICATION,
            ProofPredicate.ANALYTICAL_COUNT,
            ProofPredicate.ANALYTICAL_DISTRIBUTION,
            ProofPredicate.ANALYTICAL_TREND,
            ProofPredicate.ANALYTICAL_PERIOD_COMPARISON,
            ProofPredicate.ANALYTICAL_TOP_K,
            ProofPredicate.ANALYTICAL_RESULT_SET,
        }
    ),
    SemanticConcept.RISK_NORMALIZATION: frozenset(
        {
            ProofPredicate.RISK_NORMALIZATION,
            ProofPredicate.RISK_RECORD,
            ProofPredicate.NON_IMPLICATION,
            ProofPredicate.ANALYTICAL_COUNT,
            ProofPredicate.ANALYTICAL_DISTRIBUTION,
            ProofPredicate.ANALYTICAL_TREND,
            ProofPredicate.ANALYTICAL_PERIOD_COMPARISON,
            ProofPredicate.ANALYTICAL_TOP_K,
            ProofPredicate.ANALYTICAL_RESULT_SET,
        }
    ),
    SemanticConcept.SEVERITY: frozenset(
        {
            ProofPredicate.CANONICAL_SEVERITY,
            ProofPredicate.NON_IMPLICATION,
            ProofPredicate.ANALYTICAL_COUNT,
            ProofPredicate.ANALYTICAL_DISTRIBUTION,
            ProofPredicate.ANALYTICAL_TREND,
            ProofPredicate.ANALYTICAL_PERIOD_COMPARISON,
            ProofPredicate.ANALYTICAL_TOP_K,
            ProofPredicate.ANALYTICAL_RESULT_SET,
        }
    ),
    SemanticConcept.PRIORITY: frozenset(
        {
            ProofPredicate.RECOMMENDED_PRIORITY,
            ProofPredicate.ANALYTICAL_COUNT,
            ProofPredicate.ANALYTICAL_DISTRIBUTION,
            ProofPredicate.ANALYTICAL_TREND,
            ProofPredicate.ANALYTICAL_PERIOD_COMPARISON,
            ProofPredicate.ANALYTICAL_TOP_K,
            ProofPredicate.ANALYTICAL_RESULT_SET,
        }
    ),
    SemanticConcept.RECORDED_CORRELATION: frozenset(
        {
            ProofPredicate.CORRELATION_FLAG,
            ProofPredicate.CORRELATION_TYPE,
            ProofPredicate.CORRELATION_SCORE,
            ProofPredicate.RECORDED_CORRELATION_STATE,
            ProofPredicate.RECORDED_RELATIONSHIP,
            ProofPredicate.NON_IMPLICATION,
        }
    ),
    SemanticConcept.ANALYTICAL_RELATIONSHIP: frozenset(
        {ProofPredicate.ANALYTICAL_RELATIONSHIP, ProofPredicate.NON_IMPLICATION}
    ),
    SemanticConcept.SEMANTIC_SIMILARITY: frozenset(
        {
            ProofPredicate.SEMANTIC_SIMILARITY,
            ProofPredicate.CANDIDATE_DISCOVERY,
            ProofPredicate.NON_IMPLICATION,
        }
    ),
    SemanticConcept.THREAT_ASSESSMENT: frozenset({ProofPredicate.NON_IMPLICATION}),
    SemanticConcept.COMPROMISE: frozenset(
        {ProofPredicate.COMPROMISE_CONFIRMED, ProofPredicate.NON_IMPLICATION}
    ),
    SemanticConcept.MALICIOUSNESS: frozenset({ProofPredicate.NON_IMPLICATION}),
    SemanticConcept.ATTACKER_ATTRIBUTION: frozenset(
        {ProofPredicate.NON_IMPLICATION}
    ),
    SemanticConcept.CAMPAIGN_ATTRIBUTION: frozenset(
        {ProofPredicate.NON_IMPLICATION}
    ),
    SemanticConcept.PERSISTENCE: frozenset({ProofPredicate.NON_IMPLICATION}),
    SemanticConcept.LATERAL_MOVEMENT: frozenset({ProofPredicate.NON_IMPLICATION}),
    SemanticConcept.CAUSALITY: frozenset({ProofPredicate.NON_IMPLICATION}),
    SemanticConcept.BUSINESS_IMPACT: frozenset({ProofPredicate.NON_IMPLICATION}),
    SemanticConcept.URGENCY: frozenset({ProofPredicate.NON_IMPLICATION}),
    SemanticConcept.RECOMMENDATION: frozenset(
        {ProofPredicate.ADVISORY_GUIDANCE, ProofPredicate.CONTEXT_LIMITATION}
    ),
    SemanticConcept.REFERENCE_EXPLANATION: frozenset(
        {ProofPredicate.REFERENCE_EXPLANATION, ProofPredicate.MITRE_CONTEXT}
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
    SemanticConcept.OBSERVED_BEHAVIOR: frozenset({ProofPredicate.NON_IMPLICATION}),
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
        "che",
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
        "stato",
        "sono",
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
        "corresponds",
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
        "corrisponde",
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
    ProofPredicate.RISK_RECORD: frozenset(
        {
            "incident",
            "incidente",
            "risk",
            "rischio",
            "score",
            "punteggio",
            "normalization",
            "normalizzazione",
            "pari",
        }
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
    ProofPredicate.MITRE_CONTEXT: frozenset(
        {
            "classification",
            "classificazione",
            "classified",
            "classificato",
            "context",
            "contesto",
            "defines",
            "definisce",
            "incident",
            "incidente",
            "knowledge",
            "conoscenza",
            "means",
            "significa",
            "mitre",
            "reference",
            "riferimento",
            "states",
            "indica",
            "technique",
            "tecnica",
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
    ProofPredicate.RECORDED_CORRELATION_STATE: frozenset(
        {
            "active",
            "attivo",
            "correlation",
            "correlazione",
            "correlated",
            "correlato",
            "flag",
            "host",
            "incident",
            "incidente",
            "score",
            "punteggio",
            "pattern",
            "single",
            "singolo",
            "state",
            "stato",
            "type",
            "tipo",
        }
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
        {
            "analytical",
            "analitica",
            "agent",
            "agente",
            "close",
            "condivide",
            "condividono",
            "condivisa",
            "condiviso",
            "incident",
            "incidents",
            "incidente",
            "incidenti",
            "proximity",
            "regola",
            "relationship",
            "relazione",
            "rilevamento",
            "rule",
            "same",
            "share",
            "shared",
            "stessa",
            "stesso",
            "tempo",
            "temporally",
            "temporale",
            "temporaneamente",
            "vicinanza",
            "vicini",
            "mostra",
            "utilizzano",
        }
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
    ProofPredicate.NON_IMPLICATION: frozenset(
        {
            "alone",
            "analytical",
            "analitica",
            "association",
            "associazione",
            "correlation",
            "correlazione",
            "does",
            "establish",
            "evidence",
            "evidenza",
            "incident",
            "incidente",
            "non",
            "not",
            "relationship",
            "relazione",
            "stabilisce",
        }
    ),
    ProofPredicate.CONTEXT_LIMITATION: frozenset(
        {
            "advisory",
            "available",
            "context",
            "contesto",
            "guidance",
            "guida",
            "pertinente",
            "playbook",
            "presente",
            "relevant",
            "retrieved",
            "recuperata",
        }
    ),
    ProofPredicate.ANALYTICAL_COUNT: frozenset(
        {
            "authorized",
            "autorizzata",
            "count",
            "conteggio",
            "incident",
            "incidente",
            "incidents",
            "incidenti",
            "case",
            "cases",
            "caso",
            "casi",
            "record",
            "records",
            "risultato",
            "totale",
        }
    ),
    ProofPredicate.ANALYTICAL_DISTRIBUTION: frozenset(
        {
            "authorized",
            "autorizzata",
            "distribution",
            "distribuzione",
            "group",
            "gruppo",
            "incident",
            "incidente",
            "incidents",
            "incidenti",
            "records",
            "risultato",
        }
    ),
    ProofPredicate.ANALYTICAL_TREND: frozenset(
        {
            "authorized",
            "autorizzata",
            "daily",
            "giornaliero",
            "giorno",
            "incident",
            "incidente",
            "incidents",
            "incidenti",
            "trend",
            "records",
            "risultato",
        }
    ),
    ProofPredicate.ANALYTICAL_PERIOD_COMPARISON: frozenset(
        {
            "authorized",
            "autorizzata",
            "compare",
            "comparison",
            "confronto",
            "current",
            "corrente",
            "difference",
            "differenza",
            "incident",
            "incidente",
            "incidents",
            "incidenti",
            "period",
            "periodo",
            "previous",
            "precedente",
            "records",
            "risultato",
        }
    ),
    ProofPredicate.ANALYTICAL_TOP_K: frozenset(
        {
            "agent",
            "agente",
            "authorized",
            "autorizzata",
            "detection",
            "incident",
            "incidente",
            "incidents",
            "incidenti",
            "ranking",
            "records",
            "regola",
            "risultato",
            "top",
        }
    ),
    ProofPredicate.ANALYTICAL_RESULT_SET: frozenset(
        {
            "authorized",
            "autorizzata",
            "case",
            "cases",
            "caso",
            "casi",
            "incident",
            "incidente",
            "incidents",
            "incidenti",
            "record",
            "records",
            "result",
            "risultato",
            "set",
        }
    ),
}

_OPEN_TEXT_PREDICATES = frozenset(
    {
        ProofPredicate.CASE_TITLE,
        ProofPredicate.EVIDENCE_DETAIL,
        ProofPredicate.ESCALATION_REASON,
        ProofPredicate.REFERENCE_EXPLANATION,
        ProofPredicate.ADVISORY_GUIDANCE,
        ProofPredicate.NON_IMPLICATION,
        ProofPredicate.CONTEXT_LIMITATION,
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


def _typed_value_concepts(proof_unit: EvidenceProofUnit) -> set[SemanticConcept]:
    if proof_unit.predicate not in {
        ProofPredicate.ANALYTICAL_RELATIONSHIP,
        ProofPredicate.RECORDED_RELATIONSHIP,
        ProofPredicate.SEMANTIC_SIMILARITY,
        ProofPredicate.NON_IMPLICATION,
    }:
        return set()
    tokens = {
        token
        for value in proof_unit.value.canonical_values
        for token in _normalized_tokens(value.replace("_", " "))
    }
    concepts: set[SemanticConcept] = set()
    if tokens.intersection({"agent", "host"}):
        concepts.add(SemanticConcept.HOST_IDENTITY)
    if "user" in tokens:
        concepts.add(SemanticConcept.USER_IDENTITY)
    if tokens.intersection({"rule", "detection"}):
        concepts.add(SemanticConcept.DETECTION)
    if "mitre" in tokens:
        concepts.add(SemanticConcept.MITRE_CLASSIFICATION)
    if "correlation" in tokens:
        concepts.add(SemanticConcept.RECORDED_CORRELATION)
    if "semantic" in tokens:
        concepts.add(SemanticConcept.SEMANTIC_SIMILARITY)
    return concepts


_TYPED_VALUE_ALIASES: dict[ProofPredicate, dict[str, tuple[str, ...]]] = {
    ProofPredicate.STATUS: {
        "NEW": ("new", "nuovo", "nuova"),
        "OPEN": ("open", "aperto", "aperta"),
        "CLOSED": ("closed", "chiuso", "chiusa"),
        "RESOLVED": ("resolved", "risolto", "risolta"),
    },
    ProofPredicate.RISK_NORMALIZATION: {
        "LOW": ("low", "basso", "bassa"),
        "MEDIUM": ("medium", "medio", "media"),
        "HIGH": ("high", "alto", "alta"),
        "CRITICAL": ("critical", "critico", "critica"),
    },
    ProofPredicate.RECOMMENDED_PRIORITY: {
        "LOW": ("low", "bassa"),
        "MEDIUM": ("medium", "media"),
        "HIGH": ("high", "alta"),
        "CRITICAL": ("critical", "critica"),
    },
    ProofPredicate.ANALYTICAL_COUNT: {
        "0": (
            "no records",
            "no incidents",
            "no cases",
            "nessun record",
            "nessun incidente",
            "nessun caso",
            "non ci sono",
            "non risultano",
            "non sono stati registrati",
        ),
    },
    ProofPredicate.ANALYTICAL_RESULT_SET: {
        "0": (
            "empty result set",
            "no records",
            "no incidents",
            "no cases",
            "result set vuoto",
            "nessun record",
            "nessun incidente",
            "nessun caso",
            "non risultano",
        ),
    },
}


def _anchor_present(
    anchor: str,
    text_tokens: tuple[str, ...],
    *,
    predicate: ProofPredicate,
) -> bool:
    normalized_anchor = _normalized_tokens(anchor)
    if normalized_anchor == ("true",):
        return any(item in text_tokens for item in ("true", "vero", "vera"))
    if normalized_anchor == ("false",):
        return any(item in text_tokens for item in ("false", "falso", "falsa"))
    aliases = _TYPED_VALUE_ALIASES.get(predicate, {}).get(anchor.upper(), ())
    if any(_contains_tokens(text_tokens, _normalized_tokens(alias)) for alias in aliases):
        return True
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


_ISO_TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b",
    re.IGNORECASE,
)


def _temporal_resolution_mentions(value: str) -> set[str]:
    tokens = _normalized_tokens(value)
    mentions: set[str] = set()
    phrases = {
        ("today",): "TODAY",
        ("oggi",): "TODAY",
        ("this", "week"): "THIS_WEEK",
        ("questa", "settimana"): "THIS_WEEK",
        ("this", "month"): "THIS_MONTH",
        ("questo", "mese"): "THIS_MONTH",
        ("previous", "month"): "PREVIOUS_MONTH",
        ("previous", "calendar", "month"): "PREVIOUS_MONTH",
        ("mese", "scorso"): "PREVIOUS_MONTH",
        ("scorso", "mese"): "PREVIOUS_MONTH",
        ("last", "month"): "AMBIGUOUS_LAST_MONTH",
        ("ultimo", "mese"): "AMBIGUOUS_LAST_MONTH",
    }
    for phrase, resolution in phrases.items():
        if _contains_tokens(tokens, phrase):
            mentions.add(resolution)
    for index, token in enumerate(tokens):
        if not token.isdigit():
            continue
        previous = tokens[index - 1] if index > 0 else ""
        following = tokens[index + 1] if index + 1 < len(tokens) else ""
        after_following = tokens[index + 2] if index + 2 < len(tokens) else ""
        if token == "24" and following in {"hour", "hours", "ora", "ore"}:
            if previous in {"last", "past", "ultime", "ultimi"}:
                mentions.add("LAST_24_HOURS")
            continue
        if following not in {"day", "days", "giorno", "giorni"}:
            continue
        if previous in {"last", "past", "ultime", "ultimi"}:
            mentions.add(f"LAST_{token}_DAYS")
        if after_following in {"previous", "precedenti"}:
            mentions.add(f"PREVIOUS_LAST_{token}_DAYS")
    return mentions


def _temporal_conflicts(
    proof_unit: EvidenceProofUnit,
    proposition: str,
) -> list[str]:
    constraints = proof_unit.value.temporal_constraints
    if not constraints:
        return []
    expected_resolutions = {item.resolution for item in constraints}
    mentioned_resolutions = _temporal_resolution_mentions(proposition)
    conflicts = sorted(mentioned_resolutions - expected_resolutions)
    expected_timestamps = {
        value
        for item in constraints
        for value in (item.start_utc, item.end_utc)
    }
    mentioned_timestamps = set(_ISO_TIMESTAMP_PATTERN.findall(proposition))
    conflicts.extend(sorted(mentioned_timestamps - expected_timestamps))
    return list(dict.fromkeys(conflicts))


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
            if not _anchor_present(
                anchor,
                text_tokens,
                predicate=proof_unit.predicate,
            )
        ]
        if missing:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.MISSING_REQUIRED_ANCHOR,
                missing_anchors=missing,
            )

        temporal_conflicts = _temporal_conflicts(proof_unit, text)
        if temporal_conflicts:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=proof_unit.proof_unit_id,
                reason=TypedGuardReason.CONFLICTING_TEMPORAL_VALUE,
                conflicting_temporal_values=temporal_conflicts,
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
        if (
            proof_unit.predicate
            in {ProofPredicate.NON_IMPLICATION, ProofPredicate.CONTEXT_LIMITATION}
            and _NEGATION_TOKENS.intersection(canonical_tokens)
            and not _NEGATION_TOKENS.intersection(text_tokens)
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
            for concept in detect_semantic_concepts(value.replace("_", " "))
        } | _typed_value_concepts(proof_unit)
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

    def evaluate_combined(
        self,
        proof_units: Sequence[EvidenceProofUnit],
        proposition: str,
    ) -> TypedGuardDecision:
        if len(proof_units) == 1:
            return self.evaluate(proof_units[0], proposition)
        material = "\x1f".join(item.proof_unit_id for item in proof_units)
        combined_id = f"combined:{hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]}"
        text = proposition.strip()
        if not text:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.EMPTY_PROPOSITION,
            )

        authorities = {item.authority_class for item in proof_units}
        allowed_authority_sets = {
            frozenset({AuthorityClass.OPERATIONAL_AUTHORITATIVE}),
            frozenset({AuthorityClass.REFERENCE_KNOWLEDGE}),
            frozenset({AuthorityClass.ANALYTICAL_DERIVATION}),
            frozenset(
                {
                    AuthorityClass.OPERATIONAL_AUTHORITATIVE,
                    AuthorityClass.ANALYTICAL_DERIVATION,
                }
            ),
            frozenset(
                {
                    AuthorityClass.OPERATIONAL_AUTHORITATIVE,
                    AuthorityClass.REFERENCE_KNOWLEDGE,
                }
            ),
        }
        if frozenset(authorities) not in allowed_authority_sets:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.INCOMPATIBLE_AUTHORITY_COMBINATION,
            )
        operational_boundary_bundle = authorities == {
            AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            AuthorityClass.ANALYTICAL_DERIVATION,
        }
        if operational_boundary_bundle:
            operational_refs = {
                ref
                for unit in proof_units
                if unit.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
                for ref in unit.source_refs
            }
            analytical_units = [
                unit
                for unit in proof_units
                if unit.authority_class is AuthorityClass.ANALYTICAL_DERIVATION
            ]
            if (
                not operational_refs
                or any(
                    unit.evidence_kind is not EvidenceKind.ANALYTICAL_BOUNDARY
                    or not operational_refs.intersection(unit.source_refs)
                    for unit in analytical_units
                )
            ):
                return TypedGuardDecision(
                    accepted=False,
                    proof_unit_id=combined_id,
                    reason=TypedGuardReason.INCOMPATIBLE_AUTHORITY_COMBINATION,
                )
        if authorities == {
            AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            AuthorityClass.REFERENCE_KNOWLEDGE,
        }:
            operational_tokens = {
                token
                for unit in proof_units
                if unit.authority_class is AuthorityClass.OPERATIONAL_AUTHORITATIVE
                for value in unit.value.canonical_values
                for token in _normalized_tokens(value)
            }
            reference_tokens = {
                token
                for unit in proof_units
                if unit.authority_class is AuthorityClass.REFERENCE_KNOWLEDGE
                for value in unit.value.canonical_values
                for token in _normalized_tokens(value)
            }
            if not operational_tokens.intersection(reference_tokens):
                return TypedGuardDecision(
                    accepted=False,
                    proof_unit_id=combined_id,
                    reason=TypedGuardReason.INCOMPATIBLE_AUTHORITY_COMBINATION,
                )

        incident_scopes = {
            tuple(unit.scope.incident_ids)
            for unit in proof_units
            if unit.scope.incident_ids
        }
        case_scopes = {
            tuple(unit.scope.case_ids)
            for unit in proof_units
            if unit.scope.case_ids
        }
        if len(incident_scopes) > 1 or len(case_scopes) > 1:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.INCOMPATIBLE_SCOPE,
            )

        text_tokens = _normalized_tokens(text)
        missing = [
            anchor
            for unit in proof_units
            for anchor in unit.value.required_anchors
            if not _anchor_present(
                anchor,
                text_tokens,
                predicate=unit.predicate,
            )
        ]
        if missing:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.MISSING_REQUIRED_ANCHOR,
                missing_anchors=list(dict.fromkeys(missing)),
            )

        temporal_conflicts = list(
            dict.fromkeys(
                conflict
                for unit in proof_units
                for conflict in _temporal_conflicts(unit, text)
            )
        )
        if temporal_conflicts:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.CONFLICTING_TEMPORAL_VALUE,
                conflicting_temporal_values=temporal_conflicts,
            )

        allowed_numbers = {
            number
            for unit in proof_units
            for number in _numeric_tokens(
                tuple(
                    token
                    for value in unit.value.canonical_values
                    for token in _normalized_tokens(value)
                )
            )
        } | {
            str(scope_id)
            for unit in proof_units
            for scope_id in [*unit.scope.incident_ids, *unit.scope.case_ids]
        }
        conflicting_numbers = sorted(_numeric_tokens(text_tokens) - allowed_numbers)
        if conflicting_numbers:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.CONFLICTING_NUMERIC_VALUE,
                conflicting_numbers=conflicting_numbers,
            )

        canonical_tokens = tuple(
            token
            for unit in proof_units
            for token in _normalized_tokens(
                " ".join(
                    [unit.canonical_premise, *unit.value.canonical_values]
                )
            )
        )
        if (
            _NEGATION_TOKENS.intersection(text_tokens)
            and not _NEGATION_TOKENS.intersection(canonical_tokens)
        ):
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.POLARITY_MISMATCH,
            )
        boundary_predicates = {
            unit.predicate
            for unit in proof_units
            if unit.predicate
            in {ProofPredicate.NON_IMPLICATION, ProofPredicate.CONTEXT_LIMITATION}
        }
        if (
            boundary_predicates
            and _NEGATION_TOKENS.intersection(canonical_tokens)
            and not _NEGATION_TOKENS.intersection(text_tokens)
        ):
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.POLARITY_MISMATCH,
            )

        concepts = detect_semantic_concepts(text)
        predicates = {unit.predicate for unit in proof_units}
        canonical_concepts = {
            concept
            for unit in proof_units
            for value in unit.value.canonical_values
            for concept in detect_semantic_concepts(value.replace("_", " "))
        } | {
            concept
            for unit in proof_units
            for concept in _typed_value_concepts(unit)
        }
        incompatible = [
            concept
            for concept in concepts
            if not predicates.intersection(_ALLOWED_PREDICATES[concept])
            and concept not in canonical_concepts
        ]
        if incompatible:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.INCOMPATIBLE_SEMANTIC_CONCEPT,
                detected_concepts=list(concepts),
            )

        if SemanticConcept.CURRENT_OPERATIONAL_STATE in concepts and authorities <= {
            AuthorityClass.REFERENCE_KNOWLEDGE,
            AuthorityClass.ADVISORY_KNOWLEDGE,
        }:
            return TypedGuardDecision(
                accepted=False,
                proof_unit_id=combined_id,
                reason=TypedGuardReason.REFERENCE_USED_AS_OPERATIONAL_STATE,
                detected_concepts=list(concepts),
            )

        for unit in proof_units:
            if operational_boundary_bundle:
                continue
            if unit.value.required_anchors:
                continue
            has_value = any(
                _contains_tokens(text_tokens, _normalized_tokens(value))
                for value in unit.value.canonical_values
            )
            has_unique_concept = any(
                unit.predicate in _ALLOWED_PREDICATES[concept]
                and sum(
                    predicate in _ALLOWED_PREDICATES[concept]
                    for predicate in predicates
                )
                == 1
                for concept in concepts
            )
            if not (has_value or has_unique_concept):
                return TypedGuardDecision(
                    accepted=False,
                    proof_unit_id=combined_id,
                    reason=TypedGuardReason.MISSING_COMPONENT_SUPPORT,
                )

        return TypedGuardDecision(
            accepted=True,
            proof_unit_id=combined_id,
            reason=TypedGuardReason.ACCEPTED,
            detected_concepts=list(concepts),
        )
