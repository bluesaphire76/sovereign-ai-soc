from __future__ import annotations

from enum import Enum
from typing import Literal, Protocol, Sequence

from pydantic import Field, model_validator

from services.assistant.v3.contracts import AuthorityClass, ClosedModel, Provenance


ProofLanguage = Literal["en", "it"]
PremiseLanguage = Literal["en", "it", "und"]


class EvidenceKind(str, Enum):
    OPERATIONAL_FACT = "OPERATIONAL_FACT"
    RECORDED_CORRELATION = "RECORDED_CORRELATION"
    ANALYTICAL_RELATIONSHIP = "ANALYTICAL_RELATIONSHIP"
    SEMANTIC_CANDIDATE = "SEMANTIC_CANDIDATE"
    REFERENCE_KNOWLEDGE = "REFERENCE_KNOWLEDGE"
    ADVISORY_KNOWLEDGE = "ADVISORY_KNOWLEDGE"
    TYPED_SYNTHESIS = "TYPED_SYNTHESIS"
    ANALYTICAL_BOUNDARY = "ANALYTICAL_BOUNDARY"
    ANALYTICAL_COUNT = "ANALYTICAL_COUNT"
    ANALYTICAL_DISTRIBUTION = "ANALYTICAL_DISTRIBUTION"
    ANALYTICAL_TREND = "ANALYTICAL_TREND"
    ANALYTICAL_COMPARISON = "ANALYTICAL_COMPARISON"
    ANALYTICAL_TOP_K = "ANALYTICAL_TOP_K"
    ANALYTICAL_RESULT_SET = "ANALYTICAL_RESULT_SET"


class AllowedSemanticRole(str, Enum):
    RECORDED_VALUE = "RECORDED_VALUE"
    RECORDED_RELATIONSHIP = "RECORDED_RELATIONSHIP"
    ANALYTICAL_COMPARISON = "ANALYTICAL_COMPARISON"
    CANDIDATE_DISCOVERY = "CANDIDATE_DISCOVERY"
    TECHNICAL_EXPLANATION = "TECHNICAL_EXPLANATION"
    INVESTIGATION_GUIDANCE = "INVESTIGATION_GUIDANCE"
    GROUNDED_SYNTHESIS = "GROUNDED_SYNTHESIS"
    UNCERTAINTY_BOUNDARY = "UNCERTAINTY_BOUNDARY"
    ANALYTICAL_AGGREGATE = "ANALYTICAL_AGGREGATE"


class ProofPredicate(str, Enum):
    INCIDENT_ID = "INCIDENT_ID"
    INCIDENT_TIMESTAMP = "INCIDENT_TIMESTAMP"
    CASE_ID = "CASE_ID"
    CASE_TITLE = "CASE_TITLE"
    STATUS = "STATUS"
    CANONICAL_SEVERITY = "CANONICAL_SEVERITY"
    RISK_SCORE = "RISK_SCORE"
    RISK_NORMALIZATION = "RISK_NORMALIZATION"
    RISK_RECORD = "RISK_RECORD"
    RECOMMENDED_PRIORITY = "RECOMMENDED_PRIORITY"
    HOST = "HOST"
    AGENT = "AGENT"
    USER = "USER"
    DETECTION_RULE = "DETECTION_RULE"
    DETECTION_LEVEL = "DETECTION_LEVEL"
    MITRE_TECHNIQUE = "MITRE_TECHNIQUE"
    MITRE_CONTEXT = "MITRE_CONTEXT"
    TIMELINE_EVENT = "TIMELINE_EVENT"
    OBSERVABLE = "OBSERVABLE"
    PROCESS_NAME = "PROCESS_NAME"
    PROCESS_ID = "PROCESS_ID"
    PARENT_PROCESS = "PARENT_PROCESS"
    EVIDENCE_DETAIL = "EVIDENCE_DETAIL"
    CORRELATION_FLAG = "CORRELATION_FLAG"
    CORRELATION_TYPE = "CORRELATION_TYPE"
    CORRELATION_SCORE = "CORRELATION_SCORE"
    RECORDED_CORRELATION_STATE = "RECORDED_CORRELATION_STATE"
    ESCALATED = "ESCALATED"
    ESCALATION_REASON = "ESCALATION_REASON"
    COMPROMISE_CONFIRMED = "COMPROMISE_CONFIRMED"
    CASE_RELATIONSHIP = "CASE_RELATIONSHIP"
    RECORDED_RELATIONSHIP = "RECORDED_RELATIONSHIP"
    ANALYTICAL_RELATIONSHIP = "ANALYTICAL_RELATIONSHIP"
    SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY"
    CANDIDATE_DISCOVERY = "CANDIDATE_DISCOVERY"
    REFERENCE_EXPLANATION = "REFERENCE_EXPLANATION"
    ADVISORY_GUIDANCE = "ADVISORY_GUIDANCE"
    NON_IMPLICATION = "NON_IMPLICATION"
    CONTEXT_LIMITATION = "CONTEXT_LIMITATION"
    ANALYTICAL_COUNT = "ANALYTICAL_COUNT"
    ANALYTICAL_DISTRIBUTION = "ANALYTICAL_DISTRIBUTION"
    ANALYTICAL_TREND = "ANALYTICAL_TREND"
    ANALYTICAL_PERIOD_COMPARISON = "ANALYTICAL_PERIOD_COMPARISON"
    ANALYTICAL_ENTITY_COMPARISON = "ANALYTICAL_ENTITY_COMPARISON"
    ANALYTICAL_TOP_K = "ANALYTICAL_TOP_K"
    ANALYTICAL_RESULT_SET = "ANALYTICAL_RESULT_SET"


class ProofTemporalConstraint(ClosedModel):
    role: Literal["CURRENT", "PREVIOUS"]
    resolution: str = Field(min_length=1, max_length=80)
    start_utc: str = Field(min_length=1, max_length=80)
    end_utc: str = Field(min_length=1, max_length=80)


class ProofValue(ClosedModel):
    canonical_values: list[str] = Field(min_length=1, max_length=64)
    required_anchors: list[str] = Field(default_factory=list, max_length=16)
    temporal_constraints: list[ProofTemporalConstraint] = Field(
        default_factory=list,
        max_length=2,
    )

    @model_validator(mode="after")
    def validate_values(self):
        if any(not item.strip() for item in self.canonical_values):
            raise ValueError("proof canonical values must be non-empty")
        if any(not item.strip() for item in self.required_anchors):
            raise ValueError("proof required anchors must be non-empty")
        if len(self.canonical_values) != len(set(self.canonical_values)):
            raise ValueError("proof canonical values must be unique")
        if len(self.required_anchors) != len(set(self.required_anchors)):
            raise ValueError("proof required anchors must be unique")
        roles = [item.role for item in self.temporal_constraints]
        if len(roles) != len(set(roles)):
            raise ValueError("proof temporal constraint roles must be unique")
        return self


class ProofScopeKind(str, Enum):
    INCIDENT = "INCIDENT"
    CASE = "CASE"
    INCIDENT_PAIR = "INCIDENT_PAIR"
    GLOBAL = "GLOBAL"


class ProofScope(ClosedModel):
    scope_kind: ProofScopeKind
    incident_ids: list[int] = Field(default_factory=list, max_length=2)
    case_ids: list[int] = Field(default_factory=list, max_length=1)

    @model_validator(mode="after")
    def validate_scope_shape(self):
        if len(self.incident_ids) != len(set(self.incident_ids)):
            raise ValueError("proof scope incident IDs must be unique")
        if len(self.case_ids) != len(set(self.case_ids)):
            raise ValueError("proof scope case IDs must be unique")
        expected = {
            ProofScopeKind.INCIDENT: (1, range(0, 2)),
            ProofScopeKind.CASE: (0, range(1, 2)),
            ProofScopeKind.INCIDENT_PAIR: (2, range(0, 1)),
            ProofScopeKind.GLOBAL: (0, range(0, 1)),
        }[self.scope_kind]
        incident_count, allowed_case_counts = expected
        if len(self.incident_ids) != incident_count:
            raise ValueError("proof scope kind and incident IDs do not match")
        if len(self.case_ids) not in allowed_case_counts:
            raise ValueError("proof scope kind and case IDs do not match")
        return self


class EvidenceProofUnit(ClosedModel):
    proof_unit_id: str = Field(min_length=1, max_length=220)
    authority_class: AuthorityClass
    evidence_kind: EvidenceKind
    scope: ProofScope
    canonical_premise: str = Field(min_length=1, max_length=1400)
    source_refs: list[str] = Field(default_factory=list, max_length=24)
    provenance: Provenance
    premise_language: PremiseLanguage
    allowed_semantic_role: AllowedSemanticRole
    predicate: ProofPredicate
    value: ProofValue

    @model_validator(mode="after")
    def validate_authority_contract(self):
        expected_authority = {
            EvidenceKind.OPERATIONAL_FACT: AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            EvidenceKind.RECORDED_CORRELATION: AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            EvidenceKind.ANALYTICAL_RELATIONSHIP: AuthorityClass.ANALYTICAL_DERIVATION,
            EvidenceKind.SEMANTIC_CANDIDATE: AuthorityClass.SEMANTIC_CANDIDATE,
            EvidenceKind.REFERENCE_KNOWLEDGE: AuthorityClass.REFERENCE_KNOWLEDGE,
            EvidenceKind.ADVISORY_KNOWLEDGE: AuthorityClass.ADVISORY_KNOWLEDGE,
            EvidenceKind.TYPED_SYNTHESIS: AuthorityClass.ANALYTICAL_DERIVATION,
            EvidenceKind.ANALYTICAL_BOUNDARY: AuthorityClass.ANALYTICAL_DERIVATION,
            EvidenceKind.ANALYTICAL_COUNT: AuthorityClass.ANALYTICAL_DERIVATION,
            EvidenceKind.ANALYTICAL_DISTRIBUTION: AuthorityClass.ANALYTICAL_DERIVATION,
            EvidenceKind.ANALYTICAL_TREND: AuthorityClass.ANALYTICAL_DERIVATION,
            EvidenceKind.ANALYTICAL_COMPARISON: AuthorityClass.ANALYTICAL_DERIVATION,
            EvidenceKind.ANALYTICAL_TOP_K: AuthorityClass.ANALYTICAL_DERIVATION,
            EvidenceKind.ANALYTICAL_RESULT_SET: AuthorityClass.ANALYTICAL_DERIVATION,
        }[self.evidence_kind]
        expected_role = {
            EvidenceKind.OPERATIONAL_FACT: AllowedSemanticRole.RECORDED_VALUE,
            EvidenceKind.RECORDED_CORRELATION: AllowedSemanticRole.RECORDED_RELATIONSHIP,
            EvidenceKind.ANALYTICAL_RELATIONSHIP: AllowedSemanticRole.ANALYTICAL_COMPARISON,
            EvidenceKind.SEMANTIC_CANDIDATE: AllowedSemanticRole.CANDIDATE_DISCOVERY,
            EvidenceKind.REFERENCE_KNOWLEDGE: AllowedSemanticRole.TECHNICAL_EXPLANATION,
            EvidenceKind.ADVISORY_KNOWLEDGE: AllowedSemanticRole.INVESTIGATION_GUIDANCE,
            EvidenceKind.TYPED_SYNTHESIS: AllowedSemanticRole.GROUNDED_SYNTHESIS,
            EvidenceKind.ANALYTICAL_BOUNDARY: AllowedSemanticRole.UNCERTAINTY_BOUNDARY,
            EvidenceKind.ANALYTICAL_COUNT: AllowedSemanticRole.ANALYTICAL_AGGREGATE,
            EvidenceKind.ANALYTICAL_DISTRIBUTION: AllowedSemanticRole.ANALYTICAL_AGGREGATE,
            EvidenceKind.ANALYTICAL_TREND: AllowedSemanticRole.ANALYTICAL_AGGREGATE,
            EvidenceKind.ANALYTICAL_COMPARISON: AllowedSemanticRole.ANALYTICAL_AGGREGATE,
            EvidenceKind.ANALYTICAL_TOP_K: AllowedSemanticRole.ANALYTICAL_AGGREGATE,
            EvidenceKind.ANALYTICAL_RESULT_SET: AllowedSemanticRole.ANALYTICAL_AGGREGATE,
        }[self.evidence_kind]
        if self.authority_class is not expected_authority:
            raise ValueError("proof evidence kind and authority class do not match")
        if self.provenance.authority_class is not self.authority_class:
            raise ValueError("proof authority and provenance authority do not match")
        if self.allowed_semantic_role is not expected_role:
            raise ValueError("proof evidence kind and semantic role do not match")
        if len(self.source_refs) != len(set(self.source_refs)):
            raise ValueError("proof source refs must be unique")
        if (
            not self.source_refs
            and self.predicate is not ProofPredicate.CONTEXT_LIMITATION
        ):
            raise ValueError("only a context limitation may omit external source refs")
        if (
            self.predicate
            in {
                ProofPredicate.NON_IMPLICATION,
                ProofPredicate.CONTEXT_LIMITATION,
            }
            and self.evidence_kind is not EvidenceKind.ANALYTICAL_BOUNDARY
        ):
            raise ValueError("semantic boundaries require analytical boundary evidence")
        return self


class EntailmentLabel(str, Enum):
    ENTAILMENT = "ENTAILMENT"
    NEUTRAL = "NEUTRAL"
    CONTRADICTION = "CONTRADICTION"
    UNAVAILABLE = "UNAVAILABLE"


class EntailmentDecisionReason(str, Enum):
    ENTAILED = "ENTAILED"
    NOT_ENTAILED = "NOT_ENTAILED"
    LOW_CONFIDENCE = "LOW_CONFIDENCE"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    INVALID_PROVIDER_OUTPUT = "INVALID_PROVIDER_OUTPUT"


class EntailmentPair(ClosedModel):
    pair_id: str = Field(min_length=1, max_length=240)
    proof_unit_id: str = Field(min_length=1, max_length=220)
    premise: str = Field(min_length=1, max_length=1400)
    premise_language: PremiseLanguage
    hypothesis_id: str = Field(min_length=1, max_length=160)
    hypothesis: str = Field(min_length=1, max_length=1400)
    hypothesis_language: ProofLanguage


class EntailmentDecision(ClosedModel):
    pair_id: str = Field(min_length=1, max_length=240)
    proof_unit_id: str = Field(min_length=1, max_length=220)
    hypothesis_id: str = Field(min_length=1, max_length=160)
    label: EntailmentLabel
    entailment_score: float = Field(default=0.0, ge=0.0, le=1.0)
    neutral_score: float = Field(default=0.0, ge=0.0, le=1.0)
    contradiction_score: float = Field(default=0.0, ge=0.0, le=1.0)
    accepted: bool = False
    reason: EntailmentDecisionReason

    @model_validator(mode="after")
    def validate_acceptance_contract(self):
        if self.accepted and (
            self.label is not EntailmentLabel.ENTAILMENT
            or self.reason is not EntailmentDecisionReason.ENTAILED
        ):
            raise ValueError("only an entailed decision may be accepted")
        if not self.accepted and self.reason is EntailmentDecisionReason.ENTAILED:
            raise ValueError("entailed reason requires an accepted decision")
        if self.label is EntailmentLabel.UNAVAILABLE and self.accepted:
            raise ValueError("an unavailable decision cannot be accepted")
        return self


class EntailmentProviderInfo(ClosedModel):
    backend: str = Field(min_length=1, max_length=80)
    model: str = Field(min_length=1, max_length=500)
    precision: str = Field(min_length=1, max_length=40)
    quantization: str = Field(min_length=1, max_length=40)
    device: str = Field(min_length=1, max_length=80)


class EntailmentProvider(Protocol):
    @property
    def info(self) -> EntailmentProviderInfo:
        ...

    def evaluate(
        self,
        pairs: Sequence[EntailmentPair],
        *,
        batch_size: int,
    ) -> Sequence[EntailmentDecision]:
        ...


class HypothesisFragment(ClosedModel):
    fragment_id: str = Field(min_length=1, max_length=160)
    text: str = Field(min_length=1, max_length=1400)
    language: ProofLanguage


class SemanticProofResult(ClosedModel):
    accepted: bool
    fragment_count: int = Field(ge=1, le=32)
    supported_fragment_ids: list[str] = Field(default_factory=list, max_length=32)
    matched_proof_unit_ids: list[str] = Field(default_factory=list, max_length=160)
    decisions: list[EntailmentDecision] = Field(default_factory=list, max_length=512)
    reason: Literal[
        "all_fragments_entailed",
        "fragment_not_entailed",
        "provider_unavailable",
        "invalid_provider_output",
        "no_candidate_evidence",
    ]

    @model_validator(mode="after")
    def validate_result(self):
        if self.accepted and (
            self.reason != "all_fragments_entailed"
            or len(self.supported_fragment_ids) != self.fragment_count
        ):
            raise ValueError("accepted semantic proof requires every fragment")
        if len(self.supported_fragment_ids) != len(set(self.supported_fragment_ids)):
            raise ValueError("supported fragment IDs must be unique")
        if len(self.matched_proof_unit_ids) != len(set(self.matched_proof_unit_ids)):
            raise ValueError("matched proof unit IDs must be unique")
        return self
