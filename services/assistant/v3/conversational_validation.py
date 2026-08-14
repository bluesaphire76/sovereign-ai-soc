from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from services.assistant.v3.conversational_contracts import (
    ConversationalClaim,
    ConversationalClaimType,
    ConversationalQualifierCode,
    ConversationalSegment,
    ConversationalSegmentKind,
    GroundedConversationalAnswerV31,
)
from services.assistant.v3.conversational_schema import (
    conversational_model_facing_evidence,
)
from services.assistant.v3.contracts import (
    AnswerIntent,
    AuthorityClass,
    CompromiseStateAtom,
    EscalationStateAtom,
    RecordedCorrelationAtom,
    RelationshipClass,
    RelationshipType,
    RiskAtom,
    StatusAtom,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_schema import (
    available_absence_fields,
    available_limitation_codes,
    available_non_implication_codes,
)


@dataclass(frozen=True)
class ConversationalValidationResult:
    accepted: bool
    reason: str | None = None


def parse_grounded_conversational_answer_v31(
    value: Any,
) -> GroundedConversationalAnswerV31 | None:
    if isinstance(value, GroundedConversationalAnswerV31):
        return value
    payload = value
    if isinstance(value, str):
        try:
            payload = json.loads(value)
        except (TypeError, ValueError):
            return None
    if not isinstance(payload, dict):
        return None
    try:
        return GroundedConversationalAnswerV31.model_validate(payload)
    except ValidationError:
        return None


def conversational_parse_diagnostic(value: Any) -> str:
    if not isinstance(value, dict):
        return "invalid_payload_type"
    try:
        GroundedConversationalAnswerV31.model_validate(value)
    except ValidationError as exc:
        diagnostics = []
        for error in exc.errors(include_input=False, include_context=False)[:6]:
            location = ".".join(str(item) for item in error.get("loc", ()))
            diagnostics.append(f"{location}:{error.get('type', 'validation_error')}")
        return ",".join(diagnostics) or "validation_error"
    return "none"


_ASSERTION_GUARDS: dict[str, tuple[str, ...]] = {
    "compromise": ("compromise", "compromis"),
    "actor_campaign": (
        "actor",
        "attore",
        "campaign",
        "campagna",
        "same attacker",
        "same actor",
        "same campaign",
        "stesso attaccante",
        "stesso attore",
        "stessa campagna",
    ),
    "causality": (
        "causality",
        "causal",
        "common cause",
        "causa comune",
        "causat",
    ),
    "maliciousness": (
        "malicious",
        "harmful",
        "dangerous",
        "malevol",
        "malintenz",
        "dannos",
        "pericolos",
        "nociv",
        "suspicious",
        "sospett",
        "anomalous",
        "anomal",
        "minaccia",
        " attack",
        "attacco",
    ),
    "lateral_movement": ("lateral movement", "movimento laterale"),
    "persistence": ("persistence", "persistenz"),
    "escalation": ("escalat",),
    "severity": ("severity", "severit", "gravità"),
    "risk_band": (
        "risk",
        "rischio",
        "risk band",
        "fascia di rischio",
        "rischio alto",
        "rischio medio",
        "rischio basso",
        "high risk",
        "medium risk",
        "low risk",
    ),
    "business_impact": (
        "business impact",
        "impatto business",
        "impatto aziendale",
        "urgent",
        "urgency",
        "urgente",
        "urgenza",
    ),
}

_NON_IMPLICATION_GUARDS = {
    "compromise": {
        ConversationalQualifierCode.CORRELATION_NOT_COMPROMISE,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "actor_campaign": {
        ConversationalQualifierCode.SHARED_MITRE_NOT_SAME_ATTACKER,
        ConversationalQualifierCode.UNSUPPORTED_ACTOR_OR_CAMPAIGN,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "causality": {
        ConversationalQualifierCode.ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY,
        ConversationalQualifierCode.SHARED_HOST_NOT_COMMON_ROOT_CAUSE,
        ConversationalQualifierCode.SAME_CASE_NOT_CAUSALITY,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "maliciousness": {
        ConversationalQualifierCode.EVIDENCE_NOT_MALICIOUSNESS,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "lateral_movement": {
        ConversationalQualifierCode.EVIDENCE_NOT_LATERAL_MOVEMENT,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "persistence": {
        ConversationalQualifierCode.EVIDENCE_NOT_PERSISTENCE,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "escalation": {
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "severity": {
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "risk_band": {
        ConversationalQualifierCode.RISK_BAND_NOT_RECORDED,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
    "business_impact": {
        ConversationalQualifierCode.BUSINESS_IMPACT_NOT_RECORDED,
        ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
    },
}

_ADVISORY_GUARDS = (
    " should ",
    "recommend that",
    "recommend reviewing",
    "recommend checking",
    "next step",
    "dovrebbe",
    "si consiglia",
    "consiglio di",
    "consigliamo",
    "prossima azione",
    "azioni successive",
)

_SPECULATION_GUARDS = (
    " potrebbe ",
    " potrebbero ",
    " può ",
    " possono ",
    " forse ",
    " might ",
    " could be ",
    " possibly ",
)

_UNCERTAINTY_NEGATION_MARKERS = (
    " does not ",
    " do not ",
    " is not ",
    " are not ",
    " cannot ",
    " can't ",
    " non ",
)

_SEMANTIC_CORRELATION_MARKERS = ("correlation", "correlazione")

_CURRENT_RECORD_ASSERTION_MARKERS = (
    "the incident is ",
    "the incident has ",
    "this incident is ",
    "this incident has ",
    "the case is ",
    "this case is ",
    "the record shows ",
    "the record records ",
    "l'incidente è ",
    "l'incidente ha ",
    "questo incidente è ",
    "questo incidente ha ",
    "il caso è ",
    "questo caso è ",
    "il record mostra ",
    "il record riporta ",
    "il record registra ",
)

_QUALITATIVE_LEVEL_MARKERS = {
    "CRITICAL": ("critical", "critico", "critica"),
    "HIGH": ("high", "alto", "alta", "elevato", "elevata"),
    "MEDIUM": ("medium", "moderate", "medio", "media", "moderato", "moderata"),
    "LOW": ("low", "basso", "bassa"),
}
_LEVEL_VALUE_ALIASES = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
}


def _mentioned_qualitative_levels(text: str) -> set[str]:
    normalized = text.casefold().translate(
        str.maketrans({character: " " for character in ".,;:!?()[]{}"})
    )
    padded = f" {normalized} "
    return {
        level
        for level, markers in _QUALITATIVE_LEVEL_MARKERS.items()
        if any(f" {marker} " in padded for marker in markers)
    }


def _recorded_qualitative_level_matches(
    text: str,
    recorded_values: list[str],
) -> bool:
    mentioned = _mentioned_qualitative_levels(text)
    if not mentioned:
        return True
    recorded = {
        normalized
        for value in recorded_values
        if (normalized := _LEVEL_VALUE_ALIASES.get(str(value).strip().upper()))
    }
    return bool(recorded) and mentioned.issubset(recorded)


def _package_has_recorded_guard_state(
    package: V3AnalyticalContextPackage,
    guard: str,
) -> bool:
    if guard == "compromise":
        return any(
            isinstance(item, CompromiseStateAtom)
            and item.compromise_confirmed is not None
            for item in package.operational_atoms
        )
    if guard == "escalation":
        return any(
            isinstance(item, EscalationStateAtom)
            for item in package.operational_atoms
        )
    if guard == "severity":
        return any(
            isinstance(item, StatusAtom) and item.canonical_severity is not None
            for item in package.operational_atoms
        )
    if guard == "risk_band":
        return any(
            isinstance(item, RiskAtom)
            and item.risk_normalization_severity is not None
            for item in package.operational_atoms
        )
    return False


def _guard_mentions_are_negated(text: str, markers: tuple[str, ...]) -> bool:
    sentences = [text]
    for delimiter in (".", "?", "!", ";", "\n"):
        sentences = [
            part
            for sentence in sentences
            for part in sentence.split(delimiter)
            if part.strip()
        ]
    matching = [
        f" {sentence.strip()} "
        for sentence in sentences
        if any(marker in sentence for marker in markers)
    ]
    return bool(matching) and all(
        any(negation in sentence for negation in _UNCERTAINTY_NEGATION_MARKERS)
        for sentence in matching
    )


class GroundedConversationalAnswerV31Validator:
    def validate(
        self,
        answer: GroundedConversationalAnswerV31,
        *,
        package: V3AnalyticalContextPackage,
    ) -> ConversationalValidationResult:
        if answer.response_language != package.response_language:
            return ConversationalValidationResult(False, "response_language_mismatch")
        segment_ids = [item.segment_id for item in answer.answer.segments]
        claim_ids = [item.claim_id for item in answer.claims]
        if len(segment_ids) != len(set(segment_ids)):
            return ConversationalValidationResult(False, "duplicate_segment_id")
        if len(claim_ids) != len(set(claim_ids)):
            return ConversationalValidationResult(False, "duplicate_claim_id")
        known_claims = set(claim_ids)
        referenced_claims = {
            claim_ref
            for segment in answer.answer.segments
            for claim_ref in segment.claim_refs
        }
        if not referenced_claims.issubset(known_claims):
            return ConversationalValidationResult(False, "unknown_claim_ref")
        first_kind = answer.answer.segments[0].kind
        valid_first_kinds = {ConversationalSegmentKind.DIRECT_ANSWER}
        if (
            package.intent_selection.primary_intent
            is AnswerIntent.EXECUTIVE_SUMMARY
        ):
            valid_first_kinds.add(ConversationalSegmentKind.EXECUTIVE_SUMMARY)
        if first_kind not in valid_first_kinds:
            return ConversationalValidationResult(False, "direct_answer_not_first")
        if any(
            segment.kind is ConversationalSegmentKind.DIRECT_ANSWER
            for segment in answer.answer.segments[1:]
        ):
            return ConversationalValidationResult(False, "direct_answer_repeated")

        view = conversational_model_facing_evidence(package)
        visible_refs = {
            *(item.atom_id for item in view.operational_atoms),
            *(item.relationship_id for item in view.relationships),
            *(item.candidate_id for item in view.candidates),
            *(item.knowledge_id for item in view.reference_atoms),
            *(item.knowledge_id for item in view.advisory_atoms),
        }
        for claim in answer.claims:
            if not set(claim.source_refs).issubset(visible_refs):
                return ConversationalValidationResult(False, "unknown_source_ref")
            result = self._validate_claim(claim, package=package)
            if not result.accepted:
                return result

        claims = {item.claim_id: item for item in answer.claims}
        for segment in answer.answer.segments:
            segment_claims = [claims[ref] for ref in segment.claim_refs]
            result = self._validate_segment(
                segment,
                claims=segment_claims,
                package=package,
            )
            if not result.accepted:
                return result

        return ConversationalValidationResult(True)

    @staticmethod
    def _validate_claim(
        claim: ConversationalClaim,
        *,
        package: V3AnalyticalContextPackage,
    ) -> ConversationalValidationResult:
        atoms = {item.atom_id: item for item in package.operational_atoms}
        candidates = {
            item.candidate_id: item for item in package.cross_incident_candidates
        }
        references = {item.knowledge_id: item for item in package.reference_atoms}
        advisories = {item.knowledge_id: item for item in package.advisory_atoms}
        relationships = {
            item.relationship_id: item
            for item in package.relationship_registry.relationships
        }
        refs = set(claim.source_refs)
        claim_type = claim.claim_type
        code_only = claim_type in {
            ConversationalClaimType.ABSENCE,
            ConversationalClaimType.NON_IMPLICATION,
            ConversationalClaimType.LIMITATION,
        }
        if code_only and claim.qualifier_code is ConversationalQualifierCode.NONE:
            return ConversationalValidationResult(False, "code_qualifier_missing")
        if code_only and refs:
            return ConversationalValidationResult(
                False,
                "code_qualifier_source_mismatch",
            )
        if not code_only and not refs:
            return ConversationalValidationResult(False, "evidence_source_ref_missing")
        if (
            not code_only
            and claim.qualifier_code is not ConversationalQualifierCode.NONE
        ):
            return ConversationalValidationResult(False, "evidence_qualifier_mismatch")

        if claim_type is ConversationalClaimType.OPERATIONAL_FACT:
            if not refs.issubset(atoms) or any(
                atoms[ref].authority_class is not AuthorityClass.OPERATIONAL_AUTHORITATIVE
                for ref in refs
            ):
                return ConversationalValidationResult(False, "operational_authority_mismatch")
        elif claim_type is ConversationalClaimType.RECORDED_CORRELATION:
            for ref in refs:
                if ref in atoms and isinstance(atoms[ref], RecordedCorrelationAtom):
                    continue
                relationship = relationships.get(ref)
                if (
                    relationship is None
                    or relationship.relationship_class
                    is not RelationshipClass.RECORDED_CORRELATION
                    or relationship.relationship_type
                    is not RelationshipType.PLATFORM_RECORDED_CORRELATION
                    or relationship.authority_class
                    is not AuthorityClass.OPERATIONAL_AUTHORITATIVE
                ):
                    return ConversationalValidationResult(
                        False,
                        "recorded_correlation_authority_mismatch",
                    )
        elif claim_type is ConversationalClaimType.ANALYTICAL_RELATIONSHIP:
            if any(
                ref not in relationships
                or relationships[ref].relationship_class
                is not RelationshipClass.ANALYTICAL_RELATIONSHIP
                or relationships[ref].authority_class
                is not AuthorityClass.ANALYTICAL_DERIVATION
                for ref in refs
            ):
                return ConversationalValidationResult(
                    False,
                    "analytical_relationship_authority_mismatch",
                )
        elif claim_type is ConversationalClaimType.SEMANTIC_CANDIDATE:
            if any(
                not (
                    ref in candidates
                    and candidates[ref].authority_class
                    is AuthorityClass.SEMANTIC_CANDIDATE
                )
                and not (
                    ref in relationships
                    and relationships[ref].relationship_class
                    is RelationshipClass.SEMANTIC_SIMILARITY
                    and relationships[ref].authority_class
                    is AuthorityClass.SEMANTIC_CANDIDATE
                )
                for ref in refs
            ):
                return ConversationalValidationResult(
                    False,
                    "semantic_candidate_authority_mismatch",
                )
        elif claim_type is ConversationalClaimType.REFERENCE_EXPLANATION:
            if not refs.issubset(references) or any(
                references[ref].authority_class is not AuthorityClass.REFERENCE_KNOWLEDGE
                for ref in refs
            ):
                return ConversationalValidationResult(False, "reference_authority_mismatch")
        elif claim_type is ConversationalClaimType.ADVISORY_GUIDANCE:
            if not refs.issubset(advisories) or any(
                advisories[ref].authority_class is not AuthorityClass.ADVISORY_KNOWLEDGE
                for ref in refs
            ):
                return ConversationalValidationResult(False, "advisory_authority_mismatch")
        elif claim_type is ConversationalClaimType.ABSENCE:
            available = {item.value for item in available_absence_fields(package)}
            if claim.qualifier_code.value not in available:
                return ConversationalValidationResult(False, "unsupported_absence")
        elif claim_type is ConversationalClaimType.NON_IMPLICATION:
            available = {
                item.value for item in available_non_implication_codes(package)
            }
            forward_compatible = {
                ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS,
                ConversationalQualifierCode.UNSUPPORTED_ACTOR_OR_CAMPAIGN,
                ConversationalQualifierCode.EVIDENCE_NOT_MALICIOUSNESS,
                ConversationalQualifierCode.EVIDENCE_NOT_LATERAL_MOVEMENT,
                ConversationalQualifierCode.EVIDENCE_NOT_PERSISTENCE,
                ConversationalQualifierCode.RISK_BAND_NOT_RECORDED,
                ConversationalQualifierCode.BUSINESS_IMPACT_NOT_RECORDED,
                ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY,
            }
            if (
                claim.qualifier_code.value not in available
                and claim.qualifier_code not in forward_compatible
            ):
                return ConversationalValidationResult(
                    False,
                    "unsupported_non_implication",
                )
        elif claim_type is ConversationalClaimType.LIMITATION:
            available = {item.value for item in available_limitation_codes(package)}
            if claim.qualifier_code.value not in available:
                return ConversationalValidationResult(False, "unsupported_limitation")

        explicit = set(package.resolved_scope.explicit_compare_incident_ids)
        if explicit:
            incident_ids: set[int] = set()
            for ref in refs:
                if ref in atoms and atoms[ref].incident_id is not None:
                    incident_ids.add(atoms[ref].incident_id)
                if ref in candidates:
                    incident_ids.add(candidates[ref].candidate_incident_id)
                if ref in relationships:
                    incident_ids.update(
                        {
                            relationships[ref].left_incident_id,
                            relationships[ref].right_incident_id,
                        }
                    )
            if incident_ids and not incident_ids.issubset(explicit):
                return ConversationalValidationResult(False, "explicit_compare_scope_drift")
        return ConversationalValidationResult(True)

    @staticmethod
    def _validate_segment(
        segment: ConversationalSegment,
        *,
        claims: list[ConversationalClaim],
        package: V3AnalyticalContextPackage,
    ) -> ConversationalValidationResult:
        text = segment.text.casefold()
        atom_by_ref = {item.atom_id: item for item in package.operational_atoms}
        referenced_atoms = [
            atom_by_ref[ref]
            for claim in claims
            for ref in claim.source_refs
            if ref in atom_by_ref
        ]
        qualifier_codes = {item.qualifier_code for item in claims}
        claim_types = {item.claim_type for item in claims}
        padded_text = f" {text} "
        if any(marker in padded_text for marker in _SPECULATION_GUARDS) and not any(
            item.claim_type
            in {
                ConversationalClaimType.ANALYTICAL_RELATIONSHIP,
                ConversationalClaimType.SEMANTIC_CANDIDATE,
                ConversationalClaimType.ADVISORY_GUIDANCE,
            }
            for item in claims
        ):
            return ConversationalValidationResult(
                False,
                "unsupported_speculation",
            )
        if any(marker in padded_text for marker in _ADVISORY_GUARDS) and not any(
            item.claim_type is ConversationalClaimType.ADVISORY_GUIDANCE
            for item in claims
        ):
            return ConversationalValidationResult(
                False,
                "unsupported_advisory_guidance",
            )
        if segment.kind is ConversationalSegmentKind.NEXT_STEP and not any(
            item.claim_type
            in {
                ConversationalClaimType.ADVISORY_GUIDANCE,
                ConversationalClaimType.LIMITATION,
            }
            for item in claims
        ):
            return ConversationalValidationResult(False, "next_step_without_advisory")
        if (
            ConversationalClaimType.SEMANTIC_CANDIDATE in claim_types
            and any(marker in text for marker in _SEMANTIC_CORRELATION_MARKERS)
            and not (
                _guard_mentions_are_negated(text, _SEMANTIC_CORRELATION_MARKERS)
                and ConversationalQualifierCode.SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION
                in qualifier_codes
            )
        ):
            return ConversationalValidationResult(
                False,
                "semantic_candidate_as_recorded_correlation",
            )
        if (
            ConversationalClaimType.REFERENCE_EXPLANATION in claim_types
            and not claim_types.intersection(
                {
                    ConversationalClaimType.OPERATIONAL_FACT,
                    ConversationalClaimType.RECORDED_CORRELATION,
                }
            )
            and any(marker in text for marker in _CURRENT_RECORD_ASSERTION_MARKERS)
        ):
            return ConversationalValidationResult(
                False,
                "reference_current_state_promotion",
            )
        for guard, markers in _ASSERTION_GUARDS.items():
            if not any(marker in text for marker in markers):
                continue
            negative_statement = _guard_mentions_are_negated(text, markers)
            if guard == "compromise":
                states = [
                    item.compromise_confirmed
                    for item in referenced_atoms
                    if isinstance(item, CompromiseStateAtom)
                    and item.compromise_confirmed is not None
                ]
                if states and (
                    (all(states) and not negative_statement)
                    or (not any(states) and negative_statement)
                ):
                    continue
            if guard == "escalation":
                states = [
                    item.escalated
                    for item in referenced_atoms
                    if isinstance(item, EscalationStateAtom)
                ]
                if states and (
                    (all(states) and not negative_statement)
                    or (not any(states) and negative_statement)
                ):
                    continue
            if guard == "severity":
                recorded_severity = [
                    item.canonical_severity
                    for item in referenced_atoms
                    if isinstance(item, StatusAtom)
                    and item.canonical_severity is not None
                ]
                if recorded_severity and _recorded_qualitative_level_matches(
                    text,
                    recorded_severity,
                ):
                    continue
            if guard == "risk_band":
                if (
                    not _mentioned_qualitative_levels(text)
                    and any(isinstance(item, RiskAtom) for item in referenced_atoms)
                ):
                    continue
                recorded_risk_band = [
                    item.risk_normalization_severity
                    for item in referenced_atoms
                    if isinstance(item, RiskAtom)
                    and item.risk_normalization_severity is not None
                ]
                if recorded_risk_band and _recorded_qualitative_level_matches(
                    text,
                    recorded_risk_band,
                ):
                    continue
            allowed_codes = _NON_IMPLICATION_GUARDS.get(guard, set())
            if _package_has_recorded_guard_state(package, guard):
                allowed_codes = allowed_codes - {
                    ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS
                }
            if (
                qualifier_codes.intersection(allowed_codes)
                and negative_statement
            ):
                continue
            return ConversationalValidationResult(
                False,
                f"unsupported_{guard}_assertion",
            )
        return ConversationalValidationResult(True)
