from __future__ import annotations

from typing import Any

from services.assistant.v3.conversational_contracts import (
    MAX_CONVERSATIONAL_CLAIMS,
    MAX_CONVERSATIONAL_SEGMENT_CHARS,
    MAX_CONVERSATIONAL_SEGMENTS,
    ConversationalClaimType,
    ConversationalQualifierCode,
    ConversationalSegmentKind,
)
from services.assistant.v3.contracts import (
    AnswerIntent,
    CompromiseStateAtom,
    RecordedCorrelationAtom,
    RelationshipClass,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.plan_schema import (
    ModelFacingEvidence,
    available_non_implication_codes,
    model_facing_evidence,
)


_MODEL_CLAIM_IDS = [f"c{index}" for index in range(1, MAX_CONVERSATIONAL_CLAIMS + 1)]


def conversational_model_facing_evidence(
    package: V3AnalyticalContextPackage,
) -> ModelFacingEvidence:
    view = model_facing_evidence(package)
    relationships = view.relationships[:3]
    required_atom_refs = {
        ref for item in relationships for ref in item.evidence_atom_refs
    }
    required_atoms = [
        item for item in view.operational_atoms if item.atom_id in required_atom_refs
    ]
    remaining_atoms = [
        item for item in view.operational_atoms if item.atom_id not in required_atom_refs
    ]
    operational_atoms = tuple((required_atoms + remaining_atoms)[:12])
    required_candidates = [
        item for item in view.candidates if item.candidate_id in required_atom_refs
    ]
    remaining_candidates = [
        item for item in view.candidates if item.candidate_id not in required_atom_refs
    ]
    return ModelFacingEvidence(
        operational_atoms=operational_atoms,
        relationships=relationships,
        candidates=tuple((required_candidates + remaining_candidates)[:2]),
        reference_atoms=view.reference_atoms[:1],
        advisory_atoms=view.advisory_atoms[:1],
    )


def _model_visible_refs(package: V3AnalyticalContextPackage) -> list[str]:
    view = conversational_model_facing_evidence(package)
    return list(
        dict.fromkeys(
            [item.atom_id for item in view.operational_atoms]
            + [item.relationship_id for item in view.relationships]
            + [item.candidate_id for item in view.candidates]
            + [item.knowledge_id for item in view.reference_atoms]
            + [item.knowledge_id for item in view.advisory_atoms]
        )
    )


def grounded_conversational_answer_v31_schema(
    package: V3AnalyticalContextPackage,
) -> dict[str, Any]:
    view = conversational_model_facing_evidence(package)
    if not _model_visible_refs(package):
        raise ValueError("V3.1 conversational schema requires typed evidence")
    compound_security_outcome_codes = []
    if not any(
        isinstance(item, CompromiseStateAtom) and item.compromise_confirmed is True
        for item in view.operational_atoms
    ):
        compound_security_outcome_codes.append(
            ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS.value
        )
    safety_codes = list(
        dict.fromkeys(
            compound_security_outcome_codes
            + [item.value for item in available_non_implication_codes(package)]
            + [
                ConversationalQualifierCode.UNSUPPORTED_ACTOR_OR_CAMPAIGN.value,
                ConversationalQualifierCode.EVIDENCE_NOT_MALICIOUSNESS.value,
                ConversationalQualifierCode.EVIDENCE_NOT_LATERAL_MOVEMENT.value,
                ConversationalQualifierCode.EVIDENCE_NOT_PERSISTENCE.value,
                ConversationalQualifierCode.RISK_BAND_NOT_RECORDED.value,
                ConversationalQualifierCode.BUSINESS_IMPACT_NOT_RECORDED.value,
                ConversationalQualifierCode.EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY.value,
            ]
        )
    )
    evidence_refs_by_type = {
        ConversationalClaimType.OPERATIONAL_FACT: [
            item.atom_id for item in view.operational_atoms
        ],
        ConversationalClaimType.RECORDED_CORRELATION: [
            item.atom_id
            for item in view.operational_atoms
            if isinstance(item, RecordedCorrelationAtom)
        ]
        + [
            item.relationship_id
            for item in view.relationships
            if item.relationship_class is RelationshipClass.RECORDED_CORRELATION
        ],
        ConversationalClaimType.ANALYTICAL_RELATIONSHIP: [
            item.relationship_id
            for item in view.relationships
            if item.relationship_class is RelationshipClass.ANALYTICAL_RELATIONSHIP
        ],
        ConversationalClaimType.SEMANTIC_CANDIDATE: [
            item.candidate_id for item in view.candidates
        ]
        + [
            item.relationship_id
            for item in view.relationships
            if item.relationship_class is RelationshipClass.SEMANTIC_SIMILARITY
        ],
        ConversationalClaimType.REFERENCE_EXPLANATION: [
            item.knowledge_id for item in view.reference_atoms
        ],
        ConversationalClaimType.ADVISORY_GUIDANCE: [
            item.knowledge_id for item in view.advisory_atoms
        ],
    }

    def first_available_type(
        preferred: tuple[ConversationalClaimType, ...],
    ) -> ConversationalClaimType:
        for claim_type in preferred:
            if evidence_refs_by_type[claim_type]:
                return claim_type
        raise ValueError("V3.1 conversational schema requires evidence claims")

    cross_intents = {
        AnswerIntent.COMPARE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.PATTERN_ANALYSIS,
    }
    c3_type = first_available_type(
        (
            ConversationalClaimType.ANALYTICAL_RELATIONSHIP,
            ConversationalClaimType.RECORDED_CORRELATION,
            ConversationalClaimType.SEMANTIC_CANDIDATE,
            ConversationalClaimType.OPERATIONAL_FACT,
        )
        if package.intent_selection.primary_intent in cross_intents
        else (
            ConversationalClaimType.RECORDED_CORRELATION,
            ConversationalClaimType.OPERATIONAL_FACT,
        )
    )
    c4_type = first_available_type(
        (
            ConversationalClaimType.ADVISORY_GUIDANCE,
            ConversationalClaimType.REFERENCE_EXPLANATION,
            ConversationalClaimType.OPERATIONAL_FACT,
        )
        if package.intent_selection.primary_intent is AnswerIntent.NEXT_ACTION
        else (
            ConversationalClaimType.SEMANTIC_CANDIDATE,
            ConversationalClaimType.REFERENCE_EXPLANATION,
            ConversationalClaimType.ADVISORY_GUIDANCE,
            ConversationalClaimType.OPERATIONAL_FACT,
        )
        if package.intent_selection.primary_intent in cross_intents
        else (
            ConversationalClaimType.REFERENCE_EXPLANATION,
            ConversationalClaimType.ADVISORY_GUIDANCE,
            ConversationalClaimType.OPERATIONAL_FACT,
        )
    )

    def evidence_claim_schema(
        claim_id: str,
        claim_type: ConversationalClaimType,
    ) -> dict[str, Any]:
        typed_refs = list(dict.fromkeys(evidence_refs_by_type[claim_type]))
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "claim_id": {"type": "string", "const": claim_id},
                "claim_type": {
                    "type": "string",
                    "const": claim_type.value,
                },
                "source_refs": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": min(
                        2
                        if claim_type is ConversationalClaimType.OPERATIONAL_FACT
                        else 1,
                        len(typed_refs),
                    ),
                    "uniqueItems": True,
                    "items": {"type": "string", "enum": typed_refs},
                },
                "qualifier_code": {
                    "type": "string",
                    "const": ConversationalQualifierCode.NONE.value,
                },
            },
            "required": [
                "claim_id",
                "claim_type",
                "source_refs",
                "qualifier_code",
            ],
        }

    def segment_schema(
        *,
        segment_id: str,
        kind: ConversationalSegmentKind,
        claim_refs: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "segment_id": {"type": "string", "const": segment_id},
                "kind": {"type": "string", "const": kind.value},
                "text": {
                    "type": "string",
                    "minLength": 40,
                    "maxLength": MAX_CONVERSATIONAL_SEGMENT_CHARS,
                },
                "claim_refs": claim_refs,
            },
            "required": ["segment_id", "kind", "text", "claim_refs"],
        }

    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "response_language": {
                "type": "string",
                "const": package.response_language,
            },
            "answer": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "segments": {
                        "type": "array",
                        "minItems": MAX_CONVERSATIONAL_SEGMENTS,
                        "maxItems": MAX_CONVERSATIONAL_SEGMENTS,
                        "prefixItems": [
                            segment_schema(
                                segment_id="s1",
                                kind=ConversationalSegmentKind.DIRECT_ANSWER,
                                claim_refs={
                                    "type": "array",
                                    "minItems": 4,
                                    "maxItems": 4,
                                    "prefixItems": [
                                        {"type": "string", "const": claim_id}
                                        for claim_id in _MODEL_CLAIM_IDS
                                    ],
                                },
                            ),
                            segment_schema(
                                segment_id="s2",
                                kind=ConversationalSegmentKind.UNCERTAINTY,
                                claim_refs={
                                    "type": "array",
                                    "minItems": 4,
                                    "maxItems": 4,
                                    "prefixItems": [
                                        {"type": "string", "const": claim_id}
                                        for claim_id in _MODEL_CLAIM_IDS
                                    ],
                                },
                            ),
                        ],
                    },
                },
                "required": ["segments"],
            },
            "claims": {
                "type": "array",
                "minItems": MAX_CONVERSATIONAL_CLAIMS,
                "maxItems": MAX_CONVERSATIONAL_CLAIMS,
                "prefixItems": [
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "claim_id": {"type": "string", "const": "c1"},
                            "claim_type": {
                                "type": "string",
                                "const": ConversationalClaimType.NON_IMPLICATION.value,
                            },
                            "source_refs": {
                                "type": "array",
                                "maxItems": 0,
                            },
                            "qualifier_code": {
                                "type": "string",
                                "const": safety_codes[0],
                            },
                        },
                        "required": [
                            "claim_id",
                            "claim_type",
                            "source_refs",
                            "qualifier_code",
                        ],
                    },
                    evidence_claim_schema(
                        "c2",
                        ConversationalClaimType.OPERATIONAL_FACT,
                    ),
                    evidence_claim_schema(
                        "c3",
                        c3_type,
                    ),
                    evidence_claim_schema(
                        "c4",
                        c4_type,
                    ),
                ],
            },
        },
        "required": ["response_language", "answer", "claims"],
    }
