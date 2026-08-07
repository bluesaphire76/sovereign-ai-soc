from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from schemas.assistant import AssistantResponseBlock, AssistantResponseLanguage
from services.assistant.claims import (
    AdvisoryGuidanceCode,
    ClaimType,
    FactField,
    GroundedClaim,
    GroundedClaimOutput,
    LimitationCode,
    RelationNode,
)
from services.assistant.sources import SourceRecord


@dataclass(frozen=True)
class RenderedAssistantOutput:
    direct_answer: str
    analysis: str | None = None
    next_check: str | None = None
    limitations: str | None = None
    used_advisory_context: bool = False
    direct_source_ids: list[str] = field(default_factory=list)
    analysis_source_ids: list[str] = field(default_factory=list)
    next_check_source_ids: list[str] = field(default_factory=list)
    limitation_source_ids: list[str] = field(default_factory=list)


_FIELD_LABELS = {
    "en": {
        FactField.SOURCE_TYPE: "source type",
        FactField.INCIDENT_ID: "incident ID",
        FactField.CASE_ID: "case ID",
        FactField.STATUS: "status",
        FactField.STATUS_DESCRIPTION: "status description",
        FactField.STATUS_MEANING: "status meaning",
        FactField.STATUS_CONTEXT: "status context",
        FactField.RISK_SCORE: "risk score",
        FactField.RISK_BAND: "risk band",
        FactField.RISK_LABEL: "risk label",
        FactField.RISK_DESCRIPTION: "risk description",
        FactField.RISK_METHOD: "risk method",
        FactField.RISK_SOURCE: "risk source",
        FactField.RISK_FORMULA: "risk formula",
        FactField.RISK_DERIVED_FROM: "risk derivation source",
        FactField.SEVERITY: "canonical incident severity",
        FactField.RISK_NORMALIZATION_SEVERITY: "risk-normalization severity",
        FactField.RECOMMENDED_PRIORITY: "recommended priority",
        FactField.CORRELATED: "correlation state",
        FactField.CORRELATION_TYPE: "correlation type",
        FactField.CORRELATION_SCORE: "correlation score",
        FactField.AGENT: "agent",
        FactField.HOST: "host",
        FactField.HOSTNAME: "hostname",
        FactField.USER: "user",
        FactField.USERNAME: "username",
        FactField.EVIDENCE: "evidence",
        FactField.LATEST_TIMELINE_EVENT: "latest timeline event",
        FactField.TIMELINE_EVENTS: "timeline events",
        FactField.EVENTS: "events",
        FactField.MITRE: "MITRE references",
        FactField.WAZUH_LEVEL: "Wazuh level",
        FactField.COMPROMISE_CONFIRMED: "compromise confirmation",
        FactField.THREAT_ASSESSMENT: "threat assessment",
        FactField.IMMEDIATE_THREAT: "immediate-threat assessment",
        FactField.URGENCY: "urgency",
        FactField.IMPACT: "impact",
        FactField.BUSINESS_IMPACT: "business impact",
        FactField.ESCALATED: "escalation state",
        FactField.ESCALATION_REASON: "escalation reason",
    },
    "it": {
        FactField.SOURCE_TYPE: "tipo di fonte",
        FactField.INCIDENT_ID: "ID incidente",
        FactField.CASE_ID: "ID caso",
        FactField.STATUS: "stato",
        FactField.STATUS_DESCRIPTION: "descrizione dello stato",
        FactField.STATUS_MEANING: "significato dello stato",
        FactField.STATUS_CONTEXT: "contesto dello stato",
        FactField.RISK_SCORE: "punteggio di rischio",
        FactField.RISK_BAND: "fascia di rischio",
        FactField.RISK_LABEL: "etichetta di rischio",
        FactField.RISK_DESCRIPTION: "descrizione del rischio",
        FactField.RISK_METHOD: "metodo di rischio",
        FactField.RISK_SOURCE: "fonte del rischio",
        FactField.RISK_FORMULA: "formula del rischio",
        FactField.RISK_DERIVED_FROM: "fonte della derivazione del rischio",
        FactField.SEVERITY: "severità canonica dell'incidente",
        FactField.RISK_NORMALIZATION_SEVERITY: "severità di normalizzazione del rischio",
        FactField.RECOMMENDED_PRIORITY: "priorità raccomandata",
        FactField.CORRELATED: "stato di correlazione",
        FactField.CORRELATION_TYPE: "tipo di correlazione",
        FactField.CORRELATION_SCORE: "punteggio di correlazione",
        FactField.AGENT: "agente",
        FactField.HOST: "host",
        FactField.HOSTNAME: "hostname",
        FactField.USER: "utente",
        FactField.USERNAME: "nome utente",
        FactField.EVIDENCE: "evidenza",
        FactField.LATEST_TIMELINE_EVENT: "ultimo evento della timeline",
        FactField.TIMELINE_EVENTS: "eventi della timeline",
        FactField.EVENTS: "eventi",
        FactField.MITRE: "riferimenti MITRE",
        FactField.WAZUH_LEVEL: "livello Wazuh",
        FactField.COMPROMISE_CONFIRMED: "conferma della compromissione",
        FactField.THREAT_ASSESSMENT: "valutazione della minaccia",
        FactField.IMMEDIATE_THREAT: "valutazione della minaccia immediata",
        FactField.URGENCY: "urgenza",
        FactField.IMPACT: "impatto",
        FactField.BUSINESS_IMPACT: "impatto sul business",
        FactField.ESCALATED: "stato di escalation",
        FactField.ESCALATION_REASON: "motivo dell'escalation",
    },
}


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _display_value(value: Any, *, language: AssistantResponseLanguage) -> str:
    if isinstance(value, bool):
        if language == "it":
            return "vero" if value else "falso"
        return "true" if value else "false"
    return str(value)


def _subject(
    facts: dict[str, Any],
    *,
    language: AssistantResponseLanguage,
) -> str:
    incident_id = facts.get("incident_id")
    if incident_id is not None:
        return f"L'incidente {incident_id}" if language == "it" else f"Incident {incident_id}"
    case_id = facts.get("case_id")
    if case_id is not None:
        return f"Il caso {case_id}" if language == "it" else f"Case {case_id}"
    return "Il record" if language == "it" else "The record"


def _render_fact(
    claim: GroundedClaim,
    *,
    facts: dict[str, Any],
    language: AssistantResponseLanguage,
) -> str:
    assert claim.field is not None
    label = _FIELD_LABELS[language][claim.field]
    value = _display_value(claim.value, language=language)
    subject = _subject(facts, language=language)
    if claim.field is FactField.SEVERITY:
        if language == "it":
            return f"{subject} ha severità canonica registrata {value}."
        return f"{subject} has recorded canonical severity {value}."
    if claim.field is FactField.RISK_NORMALIZATION_SEVERITY:
        if language == "it":
            return f"La normalizzazione del rischio registra severità {value}."
        return f"Risk normalization records severity {value}."
    if claim.field is FactField.RECOMMENDED_PRIORITY:
        if language == "it":
            return f"La priorità raccomandata registrata è {value}."
        return f"The recorded recommended priority is {value}."
    if claim.field is FactField.CORRELATED:
        if language == "it":
            return "La correlazione è registrata." if claim.value is True else "L'assenza di correlazione è registrata."
        return "Correlation is recorded." if claim.value is True else "No correlation is recorded."
    if language == "it":
        return f"{subject} ha {label} registrato: {value}."
    return f"{subject} has recorded {label}: {value}."


def _render_absence(
    claim: GroundedClaim,
    *,
    facts: dict[str, Any],
    language: AssistantResponseLanguage,
) -> str:
    assert claim.field is not None
    subject = _subject(facts, language=language)
    if claim.field is FactField.SEVERITY:
        if language == "it":
            return f"Per {subject.lower()} non è registrata alcuna severità canonica."
        return f"No canonical incident severity is recorded for {subject.lower()}."
    label = _FIELD_LABELS[language][claim.field]
    if language == "it":
        return f"Per {subject.lower()} non risulta registrato il campo {label}."
    return f"No {label} is recorded for {subject.lower()}."


def _render_non_implication(
    claim: GroundedClaim,
    *,
    language: AssistantResponseLanguage,
) -> str:
    if claim.subject is RelationNode.CORRELATION and claim.object is RelationNode.COMPROMISE:
        if language == "it":
            return "La correlazione non dimostra di per sé una compromissione."
        return "Correlation does not by itself establish compromise."
    if language == "it":
        return "La correlazione non dimostra di per sé un rapporto causale."
    return "Correlation does not by itself establish causality."


def _render_structured_reference(
    claim: GroundedClaim,
    *,
    language: AssistantResponseLanguage,
) -> str:
    assert claim.field is not None
    messages = {
        FactField.EVIDENCE: {
            "en": "Recorded evidence is available.",
            "it": "Sono disponibili evidenze registrate.",
        },
        FactField.LATEST_TIMELINE_EVENT: {
            "en": "A recorded latest timeline event is available.",
            "it": "È disponibile un ultimo evento di timeline registrato.",
        },
        FactField.TIMELINE_EVENTS: {
            "en": "Recorded timeline events are available.",
            "it": "Sono disponibili eventi di timeline registrati.",
        },
        FactField.EVENTS: {
            "en": "Recorded events are available.",
            "it": "Sono disponibili eventi registrati.",
        },
        FactField.MITRE: {
            "en": "Recorded MITRE information is available.",
            "it": "Sono disponibili informazioni MITRE registrate.",
        },
        FactField.RISK_DERIVED_FROM: {
            "en": "Recorded risk derivation provenance is available.",
            "it": "È disponibile la provenienza registrata della derivazione del rischio.",
        },
    }
    return messages[claim.field][language]


def _render_advisory(
    code: AdvisoryGuidanceCode,
    *,
    language: AssistantResponseLanguage,
) -> str:
    messages = {
        AdvisoryGuidanceCode.REVIEW_RELATED_TELEMETRY: {
            "en": "The advisory source recommends reviewing related telemetry.",
            "it": "La fonte consultiva raccomanda di esaminare la telemetria correlata.",
        },
        AdvisoryGuidanceCode.FOLLOW_RECORDED_PLAYBOOK: {
            "en": "The advisory source recommends following the recorded playbook.",
            "it": "La fonte consultiva raccomanda di seguire il playbook registrato.",
        },
    }
    return messages[code][language]


def _render_derivation(
    claim: GroundedClaim,
    *,
    language: AssistantResponseLanguage,
) -> str:
    assert claim.field is not None
    target = _FIELD_LABELS[language][claim.field]
    support = ", ".join(_FIELD_LABELS[language][field] for field in claim.derived_from)
    if language == "it":
        return f"La provenienza registrata per {target} usa: {support}."
    return f"The recorded provenance for {target} uses: {support}."


def _render_limitation(
    limitation: LimitationCode,
    *,
    language: AssistantResponseLanguage,
) -> str:
    messages = {
        LimitationCode.CANONICAL_SEVERITY_MISSING: {
            "en": "Canonical incident severity is not recorded.",
            "it": "La severità canonica dell'incidente non è registrata.",
        },
        LimitationCode.ADVISORY_CONTEXT_UNAVAILABLE: {
            "en": "Advisory context is unavailable.",
            "it": "Il contesto consultivo non è disponibile.",
        },
        LimitationCode.DATA_NOT_RECORDED: {
            "en": "The requested data is not recorded in the focused fact view.",
            "it": "I dati richiesti non sono registrati nella vista dei fatti selezionati.",
        },
    }
    return messages[limitation][language]


def render_claim_output(
    output: GroundedClaimOutput,
    *,
    fact_inventory: dict[str, Any],
    response_language: AssistantResponseLanguage,
) -> RenderedAssistantOutput:
    direct_parts: list[str] = []
    analysis_parts: list[str] = []
    direct_ids: list[str] = []
    analysis_ids: list[str] = []
    analysis_uses_authoritative_facts = False

    for claim in output.claims:
        if claim.claim_type in {ClaimType.RECORDED_FACT, ClaimType.DISTINCT_VALUE}:
            direct_parts.append(
                _render_fact(
                    claim,
                    facts=fact_inventory,
                    language=response_language,
                )
            )
            direct_ids.extend(claim.source_ids)
        elif claim.claim_type is ClaimType.ABSENCE:
            direct_parts.append(
                _render_absence(
                    claim,
                    facts=fact_inventory,
                    language=response_language,
                )
            )
            direct_ids.extend(claim.source_ids)
        elif claim.claim_type is ClaimType.STRUCTURED_REFERENCE:
            direct_parts.append(
                _render_structured_reference(
                    claim,
                    language=response_language,
                )
            )
            direct_ids.extend(claim.source_ids)
        elif claim.claim_type is ClaimType.NON_IMPLICATION:
            analysis_parts.append(
                _render_non_implication(claim, language=response_language)
            )
            analysis_ids.extend(claim.source_ids)
            if not claim.source_ids:
                analysis_uses_authoritative_facts = True
        elif claim.claim_type is ClaimType.ADVISORY_GUIDANCE:
            assert claim.guidance_code is not None
            analysis_parts.append(
                _render_advisory(claim.guidance_code, language=response_language)
            )
            analysis_ids.extend(claim.source_ids)
        elif claim.claim_type is ClaimType.DERIVATION:
            analysis_parts.append(
                _render_derivation(claim, language=response_language)
            )
            analysis_ids.extend(claim.source_ids)

    direct_ids = _unique(direct_ids)
    analysis_ids = _unique(analysis_ids)
    if analysis_uses_authoritative_facts:
        analysis_ids = _unique([*direct_ids, *analysis_ids])
    if not direct_parts:
        direct_parts.append(
            "Sono disponibili solo indicazioni consultive validate."
            if response_language == "it"
            else "Only validated advisory guidance is available."
        )
        direct_ids = list(analysis_ids)

    next_check = None
    next_check_ids: list[str] = []
    if output.next_check is not None:
        next_check = _render_advisory(
            output.next_check.guidance_code,
            language=response_language,
        )
        next_check_ids = list(output.next_check.source_ids)

    limitations = " ".join(
        _render_limitation(value, language=response_language)
        for value in output.limitations
    ) or None
    authoritative_ids = _unique(
        claim_source
        for claim in output.claims
        if claim.claim_type is not ClaimType.ADVISORY_GUIDANCE
        for claim_source in claim.source_ids
    )
    return RenderedAssistantOutput(
        direct_answer=" ".join(direct_parts),
        analysis=" ".join(analysis_parts) or None,
        next_check=next_check,
        limitations=limitations,
        used_advisory_context=output.used_advisory_context,
        direct_source_ids=direct_ids,
        analysis_source_ids=analysis_ids,
        next_check_source_ids=next_check_ids,
        limitation_source_ids=authoritative_ids,
    )


def response_blocks(
    output: RenderedAssistantOutput,
    *,
    sources: list[SourceRecord],
) -> list[AssistantResponseBlock]:
    known_ids = {source.source_id for source in sources if source.source_id}

    def known(values: list[str]) -> list[str]:
        return [value for value in values if value in known_ids]

    blocks = [
        AssistantResponseBlock(
            kind="direct_answer",
            text=output.direct_answer,
            source_ids=known(output.direct_source_ids),
        )
    ]
    if output.analysis:
        blocks.append(
            AssistantResponseBlock(
                kind="analysis",
                text=output.analysis,
                source_ids=known(output.analysis_source_ids),
            )
        )
    if output.next_check:
        blocks.append(
            AssistantResponseBlock(
                kind="next_check",
                text=output.next_check,
                source_ids=known(output.next_check_source_ids),
            )
        )
    if output.limitations:
        blocks.append(
            AssistantResponseBlock(
                kind="limitations",
                text=output.limitations,
                source_ids=known(output.limitation_source_ids),
            )
        )
    return blocks
