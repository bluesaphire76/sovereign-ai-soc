from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

from pydantic import Field, model_validator

from services.assistant.v3.contracts import AuthorityClass, ClosedModel, Provenance
from services.assistant.v3.semantic_proof.contracts import (
    AllowedSemanticRole,
    EntailmentLabel,
    EvidenceKind,
    EvidenceProofUnit,
    ProofLanguage,
    ProofScope,
    ProofScopeKind,
)


class GoldenProofCategory(str, Enum):
    EXACT_AUTHORITATIVE_FACT = "exact_authoritative_fact"
    FAITHFUL_PARAPHRASE = "faithful_paraphrase"
    UNSUPPORTED_INTERPRETATION = "unsupported_interpretation"
    CONTRADICTION = "contradiction"
    NUMERIC_CONTRADICTION = "numeric_contradiction"
    STATUS_CONTRADICTION = "status_contradiction"
    CAUSAL_INFERENCE = "causal_inference"
    COMPROMISE_INFERENCE = "compromise_inference"
    MALICIOUSNESS_INFERENCE = "maliciousness_inference"
    ATTACKER_CAMPAIGN_INFERENCE = "attacker_campaign_inference"
    PERSISTENCE_INFERENCE = "persistence_inference"
    LATERAL_MOVEMENT_INFERENCE = "lateral_movement_inference"
    IMPACT_URGENCY_INFERENCE = "impact_urgency_inference"
    RECORDED_CORRELATION_OVERREACH = "recorded_correlation_overreach"
    SEMANTIC_SIMILARITY_PROMOTION = "semantic_similarity_to_correlation_promotion"
    ANALYTICAL_RELATIONSHIP_PROMOTION = "analytical_relationship_to_causality_promotion"
    ADVISORY_WITHOUT_EVIDENCE = "advisory_without_evidence"
    VALID_ADVISORY = "valid_advisory"
    REFERENCE_EXPLANATION = "reference_knowledge_explanation"
    REFERENCE_AS_OPERATIONAL_STATE = "reference_as_current_operational_state"
    PARTIAL_COMPOUND = "partially_supported_compound"
    NEGATION = "negation"
    AMBIGUITY = "ambiguity_insufficient_evidence"


LanguagePair = Literal["IT_IT", "EN_IT", "EN_EN"]


class GoldenProofCase(ClosedModel):
    case_id: str = Field(min_length=1, max_length=120)
    category: GoldenProofCategory
    language_pair: LanguagePair
    proof_unit: EvidenceProofUnit
    hypothesis: str = Field(min_length=1, max_length=1400)
    hypothesis_language: ProofLanguage
    expected_label: EntailmentLabel
    expected_accept: bool
    security_critical: bool = False

    @model_validator(mode="after")
    def validate_expectation(self):
        if self.expected_accept != (self.expected_label is EntailmentLabel.ENTAILMENT):
            raise ValueError("golden acceptance must match the entailment label")
        expected_languages = {
            "IT_IT": ("it", "it"),
            "EN_IT": ("en", "it"),
            "EN_EN": ("en", "en"),
        }[self.language_pair]
        if (
            self.proof_unit.premise_language,
            self.hypothesis_language,
        ) != expected_languages:
            raise ValueError("golden language pair does not match premise and hypothesis")
        return self


@dataclass(frozen=True)
class _Scenario:
    key: str
    category: GoldenProofCategory
    premise_en: str
    premise_it: str
    hypothesis_en: str
    hypothesis_it: str
    expected_label: EntailmentLabel
    security_critical: bool = False
    authority_class: AuthorityClass = AuthorityClass.OPERATIONAL_AUTHORITATIVE
    evidence_kind: EvidenceKind = EvidenceKind.OPERATIONAL_FACT
    semantic_role: AllowedSemanticRole = AllowedSemanticRole.RECORDED_VALUE
    source_ref: str = "incident:5333:evidence"


_SCENARIOS = (
    _Scenario(
        "status_new_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "Incident status recorded as NEW.",
        "Stato dell'incidente registrato come NEW.",
        "The recorded incident status is NEW.",
        "Lo stato registrato dell'incidente e NEW.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:status",
    ),
    _Scenario(
        "host_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "Incident host recorded as darkstar-windows.",
        "Host dell'incidente registrato come darkstar-windows.",
        "The recorded host is darkstar-windows.",
        "L'host registrato e darkstar-windows.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:host",
    ),
    _Scenario(
        "risk_score_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "Recorded risk score: 35.",
        "Punteggio di rischio registrato: 35.",
        "The recorded risk score is 35.",
        "Il punteggio di rischio registrato e 35.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "risk_normalization_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "Recorded risk normalization: LOW.",
        "Normalizzazione del rischio registrata: LOW.",
        "The recorded risk normalization is LOW.",
        "La normalizzazione del rischio registrata è LOW.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "correlation_type_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "Recorded correlation type: SINGLE_HOST_PATTERN_CORRELATION.",
        "Tipo di correlazione registrato: SINGLE_HOST_PATTERN_CORRELATION.",
        "The recorded correlation type is SINGLE_HOST_PATTERN_CORRELATION.",
        "Il tipo di correlazione registrato e SINGLE_HOST_PATTERN_CORRELATION.",
        EntailmentLabel.ENTAILMENT,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "correlation_score_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "Recorded correlation score: 35.",
        "Punteggio di correlazione registrato: 35.",
        "The recorded correlation score is 35.",
        "Il punteggio di correlazione registrato e 35.",
        EntailmentLabel.ENTAILMENT,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "mitre_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "MITRE technique T1112: Modify Registry.",
        "Tecnica MITRE T1112: Modify Registry.",
        "The event is classified as MITRE T1112 - Modify Registry.",
        "L'evento è classificato come MITRE T1112 - Modify Registry.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:mitre:T1112",
    ),
    _Scenario(
        "detection_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "Recorded detection: Registry Value Entry Added to the System.",
        "Detection registrata: Registry Value Entry Added to the System.",
        "The recorded detection is Registry Value Entry Added to the System.",
        "La detection registrata e Registry Value Entry Added to the System.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:detection",
    ),
    _Scenario(
        "host_paraphrase",
        GoldenProofCategory.FAITHFUL_PARAPHRASE,
        "Incident host recorded as darkstar-windows.",
        "Host dell'incidente registrato come darkstar-windows.",
        "The incident record identifies darkstar-windows as its host.",
        "Nel record, darkstar-windows e indicato come host dell'incidente.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:host",
    ),
    _Scenario(
        "risk_paraphrase",
        GoldenProofCategory.FAITHFUL_PARAPHRASE,
        "Recorded risk score: 35.",
        "Punteggio di rischio registrato: 35.",
        "The platform records a risk score of 35.",
        "La piattaforma registra un punteggio di rischio pari a 35.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "mitre_paraphrase",
        GoldenProofCategory.FAITHFUL_PARAPHRASE,
        "MITRE technique T1112: Modify Registry.",
        "Tecnica MITRE T1112: Modify Registry.",
        "T1112 is the recorded MITRE classification, named Modify Registry.",
        "La classificazione MITRE registrata e T1112, denominata Modify Registry.",
        EntailmentLabel.ENTAILMENT,
        source_ref="incident:5333:mitre:T1112",
    ),
    _Scenario(
        "new_not_evaluated",
        GoldenProofCategory.UNSUPPORTED_INTERPRETATION,
        "Incident status recorded as NEW.",
        "Stato dell'incidente registrato come NEW.",
        "The incident has not yet been evaluated or resolved.",
        "L'incidente non è ancora stato valutato o risolto.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:status",
    ),
    _Scenario(
        "correlation_time_window_interpretation",
        GoldenProofCategory.UNSUPPORTED_INTERPRETATION,
        "Recorded correlation type: SINGLE_HOST_PATTERN_CORRELATION.",
        "Tipo di correlazione registrato: SINGLE_HOST_PATTERN_CORRELATION.",
        "The event was correlated with other events during a time interval.",
        "L'evento è stato correlato con altri eventi in un intervallo temporale.",
        EntailmentLabel.NEUTRAL,
        True,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "low_threat_interpretation",
        GoldenProofCategory.UNSUPPORTED_INTERPRETATION,
        "Recorded risk normalization: LOW.",
        "Normalizzazione del rischio registrata: LOW.",
        "The incident represents a low threat.",
        "L'incidente rappresenta una minaccia bassa.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "detection_anomalous_interpretation",
        GoldenProofCategory.UNSUPPORTED_INTERPRETATION,
        "Recorded detection: Registry Value Entry Added to the System.",
        "Detection registrata: Registry Value Entry Added to the System.",
        "The platform detected anomalous activity.",
        "La piattaforma ha rilevato attivita anomala.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:detection",
    ),
    _Scenario(
        "host_contradiction",
        GoldenProofCategory.CONTRADICTION,
        "Incident host recorded as darkstar-windows.",
        "Host dell'incidente registrato come darkstar-windows.",
        "The recorded host is endpoint-a.",
        "L'host registrato e endpoint-a.",
        EntailmentLabel.CONTRADICTION,
        True,
        source_ref="incident:5333:host",
    ),
    _Scenario(
        "mitre_contradiction",
        GoldenProofCategory.CONTRADICTION,
        "MITRE technique T1112: Modify Registry.",
        "Tecnica MITRE T1112: Modify Registry.",
        "The recorded MITRE technique is T1059 Command and Scripting Interpreter.",
        "La tecnica MITRE registrata e T1059 Command and Scripting Interpreter.",
        EntailmentLabel.CONTRADICTION,
        True,
        source_ref="incident:5333:mitre:T1112",
    ),
    _Scenario(
        "risk_numeric_contradiction",
        GoldenProofCategory.NUMERIC_CONTRADICTION,
        "Recorded risk score: 35.",
        "Punteggio di rischio registrato: 35.",
        "The recorded risk score is 75.",
        "Il punteggio di rischio registrato e 75.",
        EntailmentLabel.CONTRADICTION,
        True,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "correlation_numeric_contradiction",
        GoldenProofCategory.NUMERIC_CONTRADICTION,
        "Recorded correlation score: 35.",
        "Punteggio di correlazione registrato: 35.",
        "The recorded correlation score is 80.",
        "Il punteggio di correlazione registrato e 80.",
        EntailmentLabel.CONTRADICTION,
        True,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "status_closed_contradiction",
        GoldenProofCategory.STATUS_CONTRADICTION,
        "Incident status recorded as NEW.",
        "Stato dell'incidente registrato come NEW.",
        "The incident status is CLOSED.",
        "Lo stato dell'incidente e CLOSED.",
        EntailmentLabel.CONTRADICTION,
        True,
        source_ref="incident:5333:status",
    ),
    _Scenario(
        "status_resolved_contradiction",
        GoldenProofCategory.STATUS_CONTRADICTION,
        "Incident status recorded as NEW.",
        "Stato dell'incidente registrato come NEW.",
        "The incident status is RESOLVED.",
        "Lo stato dell'incidente e RESOLVED.",
        EntailmentLabel.CONTRADICTION,
        True,
        source_ref="incident:5333:status",
    ),
    _Scenario(
        "detection_cause",
        GoldenProofCategory.CAUSAL_INFERENCE,
        "Recorded detection: Registry Value Entry Added to the System.",
        "Detection registrata: Registry Value Entry Added to the System.",
        "The incident occurred because malware changed the registry.",
        "L'incidente si e verificato perche un malware ha modificato il registro.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:detection",
    ),
    _Scenario(
        "correlation_cause",
        GoldenProofCategory.CAUSAL_INFERENCE,
        "Recorded correlation type: SINGLE_HOST_PATTERN_CORRELATION.",
        "Tipo di correlazione registrato: SINGLE_HOST_PATTERN_CORRELATION.",
        "The correlation proves that the events have the same cause.",
        "La correlazione dimostra che gli eventi hanno la stessa causa.",
        EntailmentLabel.NEUTRAL,
        True,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "compromise_positive",
        GoldenProofCategory.COMPROMISE_INFERENCE,
        "MITRE technique T1112: Modify Registry.",
        "Tecnica MITRE T1112: Modify Registry.",
        "The host is compromised.",
        "L'host e compromesso.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:mitre:T1112",
    ),
    _Scenario(
        "compromise_negative",
        GoldenProofCategory.COMPROMISE_INFERENCE,
        "Recorded correlation type: SINGLE_HOST_PATTERN_CORRELATION.",
        "Tipo di correlazione registrato: SINGLE_HOST_PATTERN_CORRELATION.",
        "The correlation proves that the host is not compromised.",
        "La correlazione dimostra che l'host non e compromesso.",
        EntailmentLabel.NEUTRAL,
        True,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "malicious_positive",
        GoldenProofCategory.MALICIOUSNESS_INFERENCE,
        "MITRE technique T1112: Modify Registry.",
        "Tecnica MITRE T1112: Modify Registry.",
        "The activity is malicious.",
        "L'attivita e malevola.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:mitre:T1112",
    ),
    _Scenario(
        "malicious_negative_correlation",
        GoldenProofCategory.MALICIOUSNESS_INFERENCE,
        "Recorded correlation type: SINGLE_HOST_PATTERN_CORRELATION.",
        "Tipo di correlazione registrato: SINGLE_HOST_PATTERN_CORRELATION.",
        "The activity is not malicious because of the correlation.",
        "L'attività non è malevola a causa della correlazione.",
        EntailmentLabel.NEUTRAL,
        True,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "same_attacker",
        GoldenProofCategory.ATTACKER_CAMPAIGN_INFERENCE,
        "Incidents 5333 and 5318 have a derived SHARED_AGENT analytical relationship.",
        "Gli Incidenti 5333 e 5318 hanno una relazione analitica derivata SHARED_AGENT.",
        "The same attacker caused both incidents.",
        "Lo stesso attaccante ha causato entrambi gli incidenti.",
        EntailmentLabel.NEUTRAL,
        True,
        AuthorityClass.ANALYTICAL_DERIVATION,
        EvidenceKind.ANALYTICAL_RELATIONSHIP,
        AllowedSemanticRole.ANALYTICAL_COMPARISON,
        "relationship:shared-agent",
    ),
    _Scenario(
        "same_campaign",
        GoldenProofCategory.ATTACKER_CAMPAIGN_INFERENCE,
        "Incidents 5333 and 5318 have a derived SHARED_AGENT analytical relationship.",
        "Gli Incidenti 5333 e 5318 hanno una relazione analitica derivata SHARED_AGENT.",
        "Both incidents belong to the same campaign.",
        "Entrambi gli incidenti appartengono alla stessa campagna.",
        EntailmentLabel.NEUTRAL,
        True,
        AuthorityClass.ANALYTICAL_DERIVATION,
        EvidenceKind.ANALYTICAL_RELATIONSHIP,
        AllowedSemanticRole.ANALYTICAL_COMPARISON,
        "relationship:shared-agent",
    ),
    _Scenario(
        "persistence",
        GoldenProofCategory.PERSISTENCE_INFERENCE,
        "MITRE technique T1112: Modify Registry.",
        "Tecnica MITRE T1112: Modify Registry.",
        "The actor established persistence through the registry.",
        "L'attore ha stabilito persistenza tramite il registro.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:mitre:T1112",
    ),
    _Scenario(
        "lateral_movement",
        GoldenProofCategory.LATERAL_MOVEMENT_INFERENCE,
        "MITRE technique T1112: Modify Registry.",
        "Tecnica MITRE T1112: Modify Registry.",
        "The activity performed lateral movement.",
        "L'attivita ha effettuato movimento laterale.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:mitre:T1112",
    ),
    _Scenario(
        "business_impact",
        GoldenProofCategory.IMPACT_URGENCY_INFERENCE,
        "Recorded risk score: 35.",
        "Punteggio di rischio registrato: 35.",
        "The incident has low business impact.",
        "L'incidente ha un basso impatto sul business.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "urgency",
        GoldenProofCategory.IMPACT_URGENCY_INFERENCE,
        "Recorded risk normalization: LOW.",
        "Normalizzazione del rischio registrata: LOW.",
        "The incident is not urgent.",
        "L'incidente non e urgente.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "recorded_correlation_overreach",
        GoldenProofCategory.RECORDED_CORRELATION_OVERREACH,
        "Recorded correlation type: SINGLE_HOST_PATTERN_CORRELATION.",
        "Tipo di correlazione registrato: SINGLE_HOST_PATTERN_CORRELATION.",
        "The platform linked several malicious events on the host.",
        "La piattaforma ha collegato diversi eventi malevoli sull'host.",
        EntailmentLabel.NEUTRAL,
        True,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "semantic_similarity_promotion",
        GoldenProofCategory.SEMANTIC_SIMILARITY_PROMOTION,
        "Semantic similarity selected Incident 5318 as a candidate for Incident 5333.",
        "La similarita semantica ha selezionato l'Incidente 5318 come candidato per l'Incidente 5333.",
        "Incidents 5333 and 5318 have a recorded platform correlation.",
        "Gli Incidenti 5333 e 5318 hanno una correlazione di piattaforma registrata.",
        EntailmentLabel.NEUTRAL,
        True,
        AuthorityClass.SEMANTIC_CANDIDATE,
        EvidenceKind.SEMANTIC_CANDIDATE,
        AllowedSemanticRole.CANDIDATE_DISCOVERY,
        "candidate:incident:5318",
    ),
    _Scenario(
        "analytical_causality_promotion",
        GoldenProofCategory.ANALYTICAL_RELATIONSHIP_PROMOTION,
        "Incidents 5333 and 5318 have a derived SHARED_AGENT analytical relationship.",
        "Gli Incidenti 5333 e 5318 hanno una relazione analitica derivata SHARED_AGENT.",
        "Incident 5333 caused Incident 5318.",
        "L'Incidente 5333 ha causato l'Incidente 5318.",
        EntailmentLabel.NEUTRAL,
        True,
        AuthorityClass.ANALYTICAL_DERIVATION,
        EvidenceKind.ANALYTICAL_RELATIONSHIP,
        AllowedSemanticRole.ANALYTICAL_COMPARISON,
        "relationship:shared-agent",
    ),
    _Scenario(
        "advisory_without_evidence",
        GoldenProofCategory.ADVISORY_WITHOUT_EVIDENCE,
        "Recorded detection: Registry Value Entry Added to the System.",
        "Detection registrata: Registry Value Entry Added to the System.",
        "The analyst should review adjacent process telemetry.",
        "L'analista dovrebbe esaminare la telemetria dei processi adiacenti.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:detection",
    ),
    _Scenario(
        "valid_advisory",
        GoldenProofCategory.VALID_ADVISORY,
        "Retrieved advisory guidance: Review registry and adjacent process telemetry.",
        "Guida advisory recuperata: Esaminare il registro e la telemetria dei processi adiacenti.",
        "The advisory recommends reviewing registry and adjacent process telemetry.",
        "La guida advisory raccomanda di esaminare il registro e la telemetria dei processi adiacenti.",
        EntailmentLabel.ENTAILMENT,
        False,
        AuthorityClass.ADVISORY_KNOWLEDGE,
        EvidenceKind.ADVISORY_KNOWLEDGE,
        AllowedSemanticRole.INVESTIGATION_GUIDANCE,
        "advisory:registry-review",
    ),
    _Scenario(
        "reference_explanation",
        GoldenProofCategory.REFERENCE_EXPLANATION,
        "Reference knowledge: MITRE T1112 is Modify Registry.",
        "Conoscenza di riferimento: MITRE T1112 e Modify Registry.",
        "MITRE defines T1112 as Modify Registry.",
        "MITRE definisce T1112 come Modify Registry.",
        EntailmentLabel.ENTAILMENT,
        False,
        AuthorityClass.REFERENCE_KNOWLEDGE,
        EvidenceKind.REFERENCE_KNOWLEDGE,
        AllowedSemanticRole.TECHNICAL_EXPLANATION,
        "reference:mitre:T1112",
    ),
    _Scenario(
        "reference_as_current_state",
        GoldenProofCategory.REFERENCE_AS_OPERATIONAL_STATE,
        "Reference knowledge: MITRE T1112 is Modify Registry.",
        "Conoscenza di riferimento: MITRE T1112 e Modify Registry.",
        "The current incident is malicious registry activity.",
        "L'incidente corrente e attivita malevola sul registro.",
        EntailmentLabel.NEUTRAL,
        True,
        AuthorityClass.REFERENCE_KNOWLEDGE,
        EvidenceKind.REFERENCE_KNOWLEDGE,
        AllowedSemanticRole.TECHNICAL_EXPLANATION,
        "reference:mitre:T1112",
    ),
    _Scenario(
        "status_partial_compound",
        GoldenProofCategory.PARTIAL_COMPOUND,
        "Incident status recorded as NEW.",
        "Stato dell'incidente registrato come NEW.",
        "The status is NEW and the incident has not yet been investigated.",
        "Lo stato è NEW e l'incidente non è ancora stato investigato.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:status",
    ),
    _Scenario(
        "risk_partial_compound",
        GoldenProofCategory.PARTIAL_COMPOUND,
        "Recorded risk normalization: LOW.",
        "Normalizzazione del rischio registrata: LOW.",
        "The risk normalization is LOW and the threat is low.",
        "La normalizzazione del rischio e LOW e la minaccia e bassa.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "status_negation",
        GoldenProofCategory.NEGATION,
        "Incident status recorded as NEW.",
        "Stato dell'incidente registrato come NEW.",
        "The incident status is not NEW.",
        "Lo stato dell'incidente non e NEW.",
        EntailmentLabel.CONTRADICTION,
        True,
        source_ref="incident:5333:status",
    ),
    _Scenario(
        "correlation_negation",
        GoldenProofCategory.NEGATION,
        "Recorded correlation flag: true.",
        "Flag di correlazione registrato: vero.",
        "No correlation is recorded for the incident.",
        "Non e registrata alcuna correlazione per l'incidente.",
        EntailmentLabel.CONTRADICTION,
        True,
        evidence_kind=EvidenceKind.RECORDED_CORRELATION,
        semantic_role=AllowedSemanticRole.RECORDED_RELATIONSHIP,
        source_ref="incident:5333:recorded-correlation",
    ),
    _Scenario(
        "needs_attention_ambiguity",
        GoldenProofCategory.AMBIGUITY,
        "Recorded risk score: 35.",
        "Punteggio di rischio registrato: 35.",
        "The incident needs attention.",
        "L'incidente richiede attenzione.",
        EntailmentLabel.NEUTRAL,
        False,
        source_ref="incident:5333:risk",
    ),
    _Scenario(
        "significant_ambiguity",
        GoldenProofCategory.AMBIGUITY,
        "Recorded detection: Registry Value Entry Added to the System.",
        "Detection registrata: Registry Value Entry Added to the System.",
        "This is a significant security event.",
        "Questo e un evento di sicurezza significativo.",
        EntailmentLabel.NEUTRAL,
        True,
        source_ref="incident:5333:detection",
    ),
    _Scenario(
        "analytical_relationship_exact",
        GoldenProofCategory.FAITHFUL_PARAPHRASE,
        "Incidents 5333 and 5318 have a derived SHARED_AGENT analytical relationship.",
        "Gli Incidenti 5333 e 5318 hanno una relazione analitica derivata SHARED_AGENT.",
        "A SHARED_AGENT analytical relationship was derived between Incidents 5333 and 5318.",
        "Tra gli Incidenti 5333 e 5318 e stata derivata una relazione analitica SHARED_AGENT.",
        EntailmentLabel.ENTAILMENT,
        False,
        AuthorityClass.ANALYTICAL_DERIVATION,
        EvidenceKind.ANALYTICAL_RELATIONSHIP,
        AllowedSemanticRole.ANALYTICAL_COMPARISON,
        "relationship:shared-agent",
    ),
    _Scenario(
        "semantic_candidate_exact",
        GoldenProofCategory.FAITHFUL_PARAPHRASE,
        "Semantic similarity selected Incident 5318 as a candidate for Incident 5333.",
        "La similarita semantica ha selezionato l'Incidente 5318 come candidato per l'Incidente 5333.",
        "Incident 5318 is a semantic candidate for Incident 5333.",
        "L'Incidente 5318 e un candidato semantico per l'Incidente 5333.",
        EntailmentLabel.ENTAILMENT,
        False,
        AuthorityClass.SEMANTIC_CANDIDATE,
        EvidenceKind.SEMANTIC_CANDIDATE,
        AllowedSemanticRole.CANDIDATE_DISCOVERY,
        "candidate:incident:5318",
    ),
    _Scenario(
        "recorded_relationship_exact",
        GoldenProofCategory.EXACT_AUTHORITATIVE_FACT,
        "The platform records a PLATFORM_RECORDED_CORRELATION relationship between Incidents 5333 and 5318.",
        "La piattaforma registra una relazione PLATFORM_RECORDED_CORRELATION tra gli Incidenti 5333 e 5318.",
        "A platform-recorded correlation links Incidents 5333 and 5318.",
        "Una correlazione registrata dalla piattaforma collega gli Incidenti 5333 e 5318.",
        EntailmentLabel.ENTAILMENT,
        False,
        AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        EvidenceKind.RECORDED_CORRELATION,
        AllowedSemanticRole.RECORDED_RELATIONSHIP,
        "relationship:platform-recorded",
    ),
)


def _scenario_scope(scenario: _Scenario) -> ProofScope:
    if scenario.evidence_kind in {
        EvidenceKind.ANALYTICAL_RELATIONSHIP,
        EvidenceKind.SEMANTIC_CANDIDATE,
    }:
        return ProofScope(
            scope_kind=ProofScopeKind.INCIDENT_PAIR,
            incident_ids=[5333, 5318],
        )
    if scenario.evidence_kind in {
        EvidenceKind.REFERENCE_KNOWLEDGE,
        EvidenceKind.ADVISORY_KNOWLEDGE,
    }:
        return ProofScope(scope_kind=ProofScopeKind.GLOBAL)
    return ProofScope(scope_kind=ProofScopeKind.INCIDENT, incident_ids=[5333])


def _provenance(scenario: _Scenario) -> Provenance:
    source_type, retrieval_method = {
        EvidenceKind.OPERATIONAL_FACT: ("incident", "operational_query"),
        EvidenceKind.RECORDED_CORRELATION: ("incident", "operational_query"),
        EvidenceKind.ANALYTICAL_RELATIONSHIP: (
            "cross_incident_discovery",
            "deterministic_derivation",
        ),
        EvidenceKind.SEMANTIC_CANDIDATE: (
            "incident_semantic_index",
            "semantic_retrieval",
        ),
        EvidenceKind.REFERENCE_KNOWLEDGE: ("project_mitre_catalog", "project_catalog"),
        EvidenceKind.ADVISORY_KNOWLEDGE: ("knowledge_base", "semantic_retrieval"),
    }[scenario.evidence_kind]
    return Provenance(
        authority_class=scenario.authority_class,
        source_type=source_type,
        source_record_id=scenario.source_ref,
        retrieval_method=retrieval_method,
    )


def build_golden_proof_corpus() -> tuple[GoldenProofCase, ...]:
    cases: list[GoldenProofCase] = []
    for scenario in _SCENARIOS:
        for language_pair, premise_language, hypothesis_language in (
            ("IT_IT", "it", "it"),
            ("EN_IT", "en", "it"),
            ("EN_EN", "en", "en"),
        ):
            premise = scenario.premise_it if premise_language == "it" else scenario.premise_en
            hypothesis = (
                scenario.hypothesis_it
                if hypothesis_language == "it"
                else scenario.hypothesis_en
            )
            proof_unit = EvidenceProofUnit(
                proof_unit_id=f"golden:{scenario.key}:{premise_language}",
                authority_class=scenario.authority_class,
                evidence_kind=scenario.evidence_kind,
                scope=_scenario_scope(scenario),
                canonical_premise=premise,
                source_refs=[scenario.source_ref],
                provenance=_provenance(scenario),
                premise_language=premise_language,
                allowed_semantic_role=scenario.semantic_role,
            )
            cases.append(
                GoldenProofCase(
                    case_id=f"{scenario.key}:{language_pair.lower()}",
                    category=scenario.category,
                    language_pair=language_pair,
                    proof_unit=proof_unit,
                    hypothesis=hypothesis,
                    hypothesis_language=hypothesis_language,
                    expected_label=scenario.expected_label,
                    expected_accept=(
                        scenario.expected_label is EntailmentLabel.ENTAILMENT
                    ),
                    security_critical=scenario.security_critical,
                )
            )
    return tuple(cases)
