from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from services.assistant.v3.contracts import ClosedModel


MAX_CONVERSATIONAL_SEGMENT_CHARS = 900
MAX_CONVERSATIONAL_SEGMENTS = 4
MAX_CONVERSATIONAL_CLAIMS = 8
MAX_CONVERSATIONAL_CLAIMS_PER_SEGMENT = 4

ConversationalSegmentId = Literal["s1", "s2", "s3", "s4"]
ConversationalClaimId = Literal[
    "c1",
    "c2",
    "c3",
    "c4",
    "c5",
    "c6",
    "c7",
    "c8",
]


class ConversationalSegmentKind(str, Enum):
    DIRECT_ANSWER = "direct_answer"
    ANALYSIS = "analysis"
    EVIDENCE_EXPLANATION = "evidence_explanation"
    COMPARISON = "comparison"
    PATTERN = "pattern"
    CONCLUSION = "conclusion"
    UNCERTAINTY = "uncertainty"
    NEXT_STEP = "next_step"
    EXECUTIVE_SUMMARY = "executive_summary"


class ConversationalClaimType(str, Enum):
    OPERATIONAL_FACT = "operational_fact"
    RECORDED_CORRELATION = "recorded_correlation"
    ANALYTICAL_RELATIONSHIP = "analytical_relationship"
    SEMANTIC_CANDIDATE = "semantic_candidate"
    REFERENCE_EXPLANATION = "reference_explanation"
    ADVISORY_GUIDANCE = "advisory_guidance"
    ABSENCE = "absence"
    NON_IMPLICATION = "non_implication"
    LIMITATION = "limitation"


class ConversationalQualifierCode(str, Enum):
    NONE = "NONE"
    SEVERITY = "severity"
    ESCALATED = "escalated"
    RECOMMENDED_PRIORITY = "recommended_priority"
    CORRELATION_NOT_COMPROMISE = "CORRELATION_NOT_COMPROMISE"
    EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS = (
        "EVIDENCE_DOES_NOT_ESTABLISH_UNRECORDED_SECURITY_CONCLUSIONS"
    )
    ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY = (
        "ANALYTICAL_RELATIONSHIP_NOT_CAUSALITY"
    )
    SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION = (
        "SEMANTIC_SIMILARITY_NOT_RECORDED_CORRELATION"
    )
    SHARED_MITRE_NOT_SAME_ATTACKER = "SHARED_MITRE_NOT_SAME_ATTACKER"
    SHARED_HOST_NOT_COMMON_ROOT_CAUSE = "SHARED_HOST_NOT_COMMON_ROOT_CAUSE"
    SAME_CASE_NOT_CAUSALITY = "SAME_CASE_NOT_CAUSALITY"
    CANDIDATE_RANK_NOT_RISK = "CANDIDATE_RANK_NOT_RISK"
    NO_RECORDED_DIFFERENCE_IN_COMPARED_FIELDS = (
        "NO_RECORDED_DIFFERENCE_IN_COMPARED_FIELDS"
    )
    UNSUPPORTED_ACTOR_OR_CAMPAIGN = "UNSUPPORTED_ACTOR_OR_CAMPAIGN"
    EVIDENCE_NOT_MALICIOUSNESS = "EVIDENCE_NOT_MALICIOUSNESS"
    EVIDENCE_NOT_LATERAL_MOVEMENT = "EVIDENCE_NOT_LATERAL_MOVEMENT"
    EVIDENCE_NOT_PERSISTENCE = "EVIDENCE_NOT_PERSISTENCE"
    RISK_BAND_NOT_RECORDED = "RISK_BAND_NOT_RECORDED"
    BUSINESS_IMPACT_NOT_RECORDED = "BUSINESS_IMPACT_NOT_RECORDED"
    REQUESTED_DATA_NOT_RECORDED = "REQUESTED_DATA_NOT_RECORDED"
    CANONICAL_SEVERITY_NOT_RECORDED = "CANONICAL_SEVERITY_NOT_RECORDED"
    NO_AUTHORITATIVE_ESCALATION_BOOLEAN = (
        "NO_AUTHORITATIVE_ESCALATION_BOOLEAN"
    )
    NO_RELATED_INCIDENT_CANDIDATES = "NO_RELATED_INCIDENT_CANDIDATES"
    SEMANTIC_INDEX_DEGRADED = "SEMANTIC_INDEX_DEGRADED"
    REFERENCE_KNOWLEDGE_UNAVAILABLE = "REFERENCE_KNOWLEDGE_UNAVAILABLE"
    ADVISORY_KNOWLEDGE_UNAVAILABLE = "ADVISORY_KNOWLEDGE_UNAVAILABLE"
    EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY = (
        "EVIDENCE_DOES_NOT_ESTABLISH_CAUSALITY"
    )


class ConversationalClaim(ClosedModel):
    claim_id: ConversationalClaimId
    claim_type: ConversationalClaimType
    source_refs: list[str] = Field(default_factory=list, max_length=8)
    qualifier_code: ConversationalQualifierCode = ConversationalQualifierCode.NONE

    @model_validator(mode="after")
    def validate_shape(self):
        if len(self.source_refs) != len(set(self.source_refs)):
            raise ValueError("claim source refs must be unique")
        return self


class ConversationalSegment(ClosedModel):
    segment_id: ConversationalSegmentId
    kind: ConversationalSegmentKind
    text: str = Field(
        min_length=1,
        max_length=MAX_CONVERSATIONAL_SEGMENT_CHARS,
    )
    claim_refs: list[ConversationalClaimId] = Field(
        min_length=1,
        max_length=MAX_CONVERSATIONAL_CLAIMS_PER_SEGMENT,
    )

    @field_validator("text")
    @classmethod
    def require_complete_sentence(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.endswith((".", "!", "?")):
            raise ValueError("segment text must end with sentence punctuation")
        return normalized

    @model_validator(mode="after")
    def validate_unique_claim_refs(self):
        if len(self.claim_refs) != len(set(self.claim_refs)):
            raise ValueError("segment claim refs must be unique")
        return self


class ConversationalAnswer(ClosedModel):
    segments: list[ConversationalSegment] = Field(
        min_length=1,
        max_length=MAX_CONVERSATIONAL_SEGMENTS,
    )


class GroundedConversationalAnswerV31(ClosedModel):
    response_language: Literal["it", "en"]
    answer: ConversationalAnswer
    claims: list[ConversationalClaim] = Field(
        min_length=1,
        max_length=MAX_CONVERSATIONAL_CLAIMS,
    )
