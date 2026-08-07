from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from services.assistant.focus import FocusDimension


class ClaimType(str, Enum):
    RECORDED_FACT = "RECORDED_FACT"
    ABSENCE = "ABSENCE"
    DISTINCT_VALUE = "DISTINCT_VALUE"
    STRUCTURED_REFERENCE = "STRUCTURED_REFERENCE"
    NON_IMPLICATION = "NON_IMPLICATION"
    ADVISORY_GUIDANCE = "ADVISORY_GUIDANCE"
    DERIVATION = "DERIVATION"


class FactFamily(str, Enum):
    IDENTITY = "identity"
    RISK = "risk"
    CORRELATION = "correlation"
    SEVERITY = "severity"
    STATUS = "status"
    HOST = "host"
    EVIDENCE = "evidence"
    PRIORITY = "priority"
    ESCALATION = "escalation"
    COMPROMISE = "compromise"
    THREAT = "threat"
    URGENCY = "urgency"
    IMPACT = "impact"


class FactValueType(str, Enum):
    TEXT = "text"
    NUMBER = "number"
    BOOLEAN = "boolean"
    STRUCTURED = "structured"
    SCALAR = "scalar"


class FactAuthority(str, Enum):
    AUTHORITATIVE = "authoritative"


class SemanticRole(str, Enum):
    IDENTITY = "identity"
    OPAQUE_RECORDED_VALUE = "opaque_recorded_value"
    CANONICAL_VALUE = "canonical_value"
    DISTINCT_VALUE = "distinct_value"
    ASSESSMENT = "assessment"
    PROVENANCE = "provenance"
    EVIDENCE = "evidence"


class FactProvenance(str, Enum):
    RECORDED_OPERATIONAL = "recorded_operational"
    CANONICAL_INCIDENT = "canonical_incident"
    RISK_NORMALIZATION = "risk_normalization"
    RECOMMENDATION = "recommendation"
    EXPLICIT_ASSESSMENT = "explicit_assessment"
    RECORDED_EVIDENCE = "recorded_evidence"


class FactField(str, Enum):
    SOURCE_TYPE = "source_type"
    INCIDENT_ID = "incident_id"
    CASE_ID = "case_id"
    STATUS = "status"
    STATUS_DESCRIPTION = "status_description"
    STATUS_MEANING = "status_meaning"
    STATUS_CONTEXT = "status_context"
    RISK_SCORE = "risk_score"
    RISK_BAND = "risk_band"
    RISK_LABEL = "risk_label"
    RISK_DESCRIPTION = "risk_description"
    RISK_METHOD = "risk_method"
    RISK_SOURCE = "risk_source"
    RISK_FORMULA = "risk_formula"
    RISK_DERIVED_FROM = "risk_derived_from"
    SEVERITY = "severity"
    RISK_NORMALIZATION_SEVERITY = "risk_normalization_severity"
    RECOMMENDED_PRIORITY = "recommended_priority"
    CORRELATED = "correlated"
    CORRELATION_TYPE = "correlation_type"
    CORRELATION_SCORE = "correlation_score"
    AGENT = "agent"
    HOST = "host"
    HOSTNAME = "hostname"
    USER = "user"
    USERNAME = "username"
    EVIDENCE = "evidence"
    LATEST_TIMELINE_EVENT = "latest_timeline_event"
    TIMELINE_EVENTS = "timeline_events"
    EVENTS = "events"
    MITRE = "mitre"
    WAZUH_LEVEL = "wazuh_level"
    COMPROMISE_CONFIRMED = "compromise_confirmed"
    THREAT_ASSESSMENT = "threat_assessment"
    IMMEDIATE_THREAT = "immediate_threat"
    URGENCY = "urgency"
    IMPACT = "impact"
    BUSINESS_IMPACT = "business_impact"
    ESCALATED = "escalated"
    ESCALATION_REASON = "escalation_reason"


class RelationNode(str, Enum):
    CORRELATION = "correlation"
    COMPROMISE = "compromise"
    CAUSALITY = "causality"
    RISK_SCORE = "risk_score"
    CORRELATION_SCORE = "correlation_score"
    PATTERNS = "patterns"
    SEVERITY = "severity"
    RISK_BAND = "risk_band"
    PRIORITY = "priority"
    THREAT = "threat"
    URGENCY = "urgency"
    IMPACT = "impact"
    ESCALATION = "escalation"


class AdvisoryGuidanceCode(str, Enum):
    REVIEW_RELATED_TELEMETRY = "review_related_telemetry"
    FOLLOW_RECORDED_PLAYBOOK = "follow_recorded_playbook"


class NextCheckType(str, Enum):
    REVIEW_ADVISORY_SOURCE = "review_advisory_source"


class LimitationCode(str, Enum):
    CANONICAL_SEVERITY_MISSING = "canonical_severity_missing"
    ADVISORY_CONTEXT_UNAVAILABLE = "advisory_context_unavailable"
    DATA_NOT_RECORDED = "data_not_recorded"


@dataclass(frozen=True)
class FactFieldPolicy:
    field: FactField
    family: FactFamily
    value_type: FactValueType
    authority: FactAuthority
    semantic_role: SemanticRole
    provenance: FactProvenance
    focus_dimension: FocusDimension
    derivation_support_fields: tuple[FactField, ...] = ()


def _policy(
    field: FactField,
    family: FactFamily,
    value_type: FactValueType,
    role: SemanticRole,
    provenance: FactProvenance,
    focus: FocusDimension,
    *,
    derivation_support_fields: tuple[FactField, ...] = (),
) -> FactFieldPolicy:
    return FactFieldPolicy(
        field=field,
        family=family,
        value_type=value_type,
        authority=FactAuthority.AUTHORITATIVE,
        semantic_role=role,
        provenance=provenance,
        focus_dimension=focus,
        derivation_support_fields=derivation_support_fields,
    )


FACT_FIELD_REGISTRY: dict[FactField, FactFieldPolicy] = {
    FactField.SOURCE_TYPE: _policy(FactField.SOURCE_TYPE, FactFamily.IDENTITY, FactValueType.TEXT, SemanticRole.IDENTITY, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.GENERAL),
    FactField.INCIDENT_ID: _policy(FactField.INCIDENT_ID, FactFamily.IDENTITY, FactValueType.SCALAR, SemanticRole.IDENTITY, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.GENERAL),
    FactField.CASE_ID: _policy(FactField.CASE_ID, FactFamily.IDENTITY, FactValueType.SCALAR, SemanticRole.IDENTITY, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.GENERAL),
    FactField.STATUS: _policy(FactField.STATUS, FactFamily.STATUS, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.STATUS),
    FactField.STATUS_DESCRIPTION: _policy(FactField.STATUS_DESCRIPTION, FactFamily.STATUS, FactValueType.TEXT, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.STATUS),
    FactField.STATUS_MEANING: _policy(FactField.STATUS_MEANING, FactFamily.STATUS, FactValueType.TEXT, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.STATUS),
    FactField.STATUS_CONTEXT: _policy(FactField.STATUS_CONTEXT, FactFamily.STATUS, FactValueType.TEXT, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.STATUS),
    FactField.RISK_SCORE: _policy(
        FactField.RISK_SCORE,
        FactFamily.RISK,
        FactValueType.NUMBER,
        SemanticRole.OPAQUE_RECORDED_VALUE,
        FactProvenance.RECORDED_OPERATIONAL,
        FocusDimension.RISK,
        derivation_support_fields=(FactField.RISK_DERIVED_FROM,),
    ),
    FactField.RISK_BAND: _policy(FactField.RISK_BAND, FactFamily.RISK, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.RISK),
    FactField.RISK_LABEL: _policy(FactField.RISK_LABEL, FactFamily.RISK, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.RISK),
    FactField.RISK_DESCRIPTION: _policy(FactField.RISK_DESCRIPTION, FactFamily.RISK, FactValueType.TEXT, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.RISK),
    FactField.RISK_METHOD: _policy(FactField.RISK_METHOD, FactFamily.RISK, FactValueType.TEXT, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.RISK),
    FactField.RISK_SOURCE: _policy(FactField.RISK_SOURCE, FactFamily.RISK, FactValueType.TEXT, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.RISK),
    FactField.RISK_FORMULA: _policy(FactField.RISK_FORMULA, FactFamily.RISK, FactValueType.TEXT, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.RISK),
    FactField.RISK_DERIVED_FROM: _policy(FactField.RISK_DERIVED_FROM, FactFamily.RISK, FactValueType.STRUCTURED, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.RISK),
    FactField.SEVERITY: _policy(FactField.SEVERITY, FactFamily.SEVERITY, FactValueType.TEXT, SemanticRole.CANONICAL_VALUE, FactProvenance.CANONICAL_INCIDENT, FocusDimension.SEVERITY),
    FactField.RISK_NORMALIZATION_SEVERITY: _policy(FactField.RISK_NORMALIZATION_SEVERITY, FactFamily.SEVERITY, FactValueType.TEXT, SemanticRole.DISTINCT_VALUE, FactProvenance.RISK_NORMALIZATION, FocusDimension.SEVERITY),
    FactField.RECOMMENDED_PRIORITY: _policy(FactField.RECOMMENDED_PRIORITY, FactFamily.PRIORITY, FactValueType.TEXT, SemanticRole.DISTINCT_VALUE, FactProvenance.RECOMMENDATION, FocusDimension.PRIORITY),
    FactField.CORRELATED: _policy(FactField.CORRELATED, FactFamily.CORRELATION, FactValueType.BOOLEAN, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.CORRELATION),
    FactField.CORRELATION_TYPE: _policy(FactField.CORRELATION_TYPE, FactFamily.CORRELATION, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.CORRELATION),
    FactField.CORRELATION_SCORE: _policy(FactField.CORRELATION_SCORE, FactFamily.CORRELATION, FactValueType.NUMBER, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.CORRELATION),
    FactField.AGENT: _policy(FactField.AGENT, FactFamily.HOST, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.HOST),
    FactField.HOST: _policy(FactField.HOST, FactFamily.HOST, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.HOST),
    FactField.HOSTNAME: _policy(FactField.HOSTNAME, FactFamily.HOST, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.HOST),
    FactField.USER: _policy(FactField.USER, FactFamily.HOST, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.HOST),
    FactField.USERNAME: _policy(FactField.USERNAME, FactFamily.HOST, FactValueType.TEXT, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.HOST),
    FactField.EVIDENCE: _policy(FactField.EVIDENCE, FactFamily.EVIDENCE, FactValueType.STRUCTURED, SemanticRole.EVIDENCE, FactProvenance.RECORDED_EVIDENCE, FocusDimension.EVIDENCE),
    FactField.LATEST_TIMELINE_EVENT: _policy(FactField.LATEST_TIMELINE_EVENT, FactFamily.EVIDENCE, FactValueType.STRUCTURED, SemanticRole.EVIDENCE, FactProvenance.RECORDED_EVIDENCE, FocusDimension.EVIDENCE),
    FactField.TIMELINE_EVENTS: _policy(FactField.TIMELINE_EVENTS, FactFamily.EVIDENCE, FactValueType.STRUCTURED, SemanticRole.EVIDENCE, FactProvenance.RECORDED_EVIDENCE, FocusDimension.EVIDENCE),
    FactField.EVENTS: _policy(FactField.EVENTS, FactFamily.EVIDENCE, FactValueType.STRUCTURED, SemanticRole.EVIDENCE, FactProvenance.RECORDED_EVIDENCE, FocusDimension.EVIDENCE),
    FactField.MITRE: _policy(FactField.MITRE, FactFamily.EVIDENCE, FactValueType.STRUCTURED, SemanticRole.EVIDENCE, FactProvenance.RECORDED_EVIDENCE, FocusDimension.EVIDENCE),
    FactField.WAZUH_LEVEL: _policy(FactField.WAZUH_LEVEL, FactFamily.EVIDENCE, FactValueType.NUMBER, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.EVIDENCE),
    FactField.COMPROMISE_CONFIRMED: _policy(FactField.COMPROMISE_CONFIRMED, FactFamily.COMPROMISE, FactValueType.BOOLEAN, SemanticRole.ASSESSMENT, FactProvenance.EXPLICIT_ASSESSMENT, FocusDimension.EVIDENCE),
    FactField.THREAT_ASSESSMENT: _policy(FactField.THREAT_ASSESSMENT, FactFamily.THREAT, FactValueType.SCALAR, SemanticRole.ASSESSMENT, FactProvenance.EXPLICIT_ASSESSMENT, FocusDimension.RISK),
    FactField.IMMEDIATE_THREAT: _policy(FactField.IMMEDIATE_THREAT, FactFamily.THREAT, FactValueType.SCALAR, SemanticRole.ASSESSMENT, FactProvenance.EXPLICIT_ASSESSMENT, FocusDimension.RISK),
    FactField.URGENCY: _policy(FactField.URGENCY, FactFamily.URGENCY, FactValueType.SCALAR, SemanticRole.ASSESSMENT, FactProvenance.EXPLICIT_ASSESSMENT, FocusDimension.RISK),
    FactField.IMPACT: _policy(FactField.IMPACT, FactFamily.IMPACT, FactValueType.SCALAR, SemanticRole.ASSESSMENT, FactProvenance.EXPLICIT_ASSESSMENT, FocusDimension.RISK),
    FactField.BUSINESS_IMPACT: _policy(FactField.BUSINESS_IMPACT, FactFamily.IMPACT, FactValueType.SCALAR, SemanticRole.ASSESSMENT, FactProvenance.EXPLICIT_ASSESSMENT, FocusDimension.RISK),
    FactField.ESCALATED: _policy(FactField.ESCALATED, FactFamily.ESCALATION, FactValueType.BOOLEAN, SemanticRole.OPAQUE_RECORDED_VALUE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.ESCALATION),
    FactField.ESCALATION_REASON: _policy(FactField.ESCALATION_REASON, FactFamily.ESCALATION, FactValueType.TEXT, SemanticRole.PROVENANCE, FactProvenance.RECORDED_OPERATIONAL, FocusDimension.ESCALATION),
}


ALLOWED_NON_IMPLICATIONS = frozenset(
    {
        (RelationNode.CORRELATION, RelationNode.COMPROMISE),
        (RelationNode.CORRELATION, RelationNode.CAUSALITY),
    }
)


FORBIDDEN_DERIVATIONS = frozenset(
    {
        (RelationNode.CORRELATION_SCORE, RelationNode.RISK_SCORE),
        (RelationNode.PATTERNS, RelationNode.RISK_SCORE),
        (RelationNode.RISK_SCORE, RelationNode.RISK_BAND),
        (RelationNode.SEVERITY, RelationNode.THREAT),
        (RelationNode.SEVERITY, RelationNode.URGENCY),
        (RelationNode.SEVERITY, RelationNode.IMPACT),
        (RelationNode.CORRELATION, RelationNode.COMPROMISE),
        (RelationNode.CORRELATION, RelationNode.CAUSALITY),
        (RelationNode.PRIORITY, RelationNode.SEVERITY),
        (RelationNode.RISK_BAND, RelationNode.SEVERITY),
    }
)


FACT_RELATION_NODES = {
    FactField.RISK_SCORE: RelationNode.RISK_SCORE,
    FactField.RISK_BAND: RelationNode.RISK_BAND,
    FactField.CORRELATED: RelationNode.CORRELATION,
    FactField.CORRELATION_TYPE: RelationNode.CORRELATION,
    FactField.CORRELATION_SCORE: RelationNode.CORRELATION_SCORE,
    FactField.SEVERITY: RelationNode.SEVERITY,
    FactField.RECOMMENDED_PRIORITY: RelationNode.PRIORITY,
    FactField.COMPROMISE_CONFIRMED: RelationNode.COMPROMISE,
    FactField.THREAT_ASSESSMENT: RelationNode.THREAT,
    FactField.IMMEDIATE_THREAT: RelationNode.THREAT,
    FactField.URGENCY: RelationNode.URGENCY,
    FactField.IMPACT: RelationNode.IMPACT,
    FactField.BUSINESS_IMPACT: RelationNode.IMPACT,
    FactField.ESCALATED: RelationNode.ESCALATION,
}


ClaimValue = (
    StrictBool
    | StrictInt
    | StrictFloat
    | StrictStr
)


def _valid_source_id(value: str) -> bool:
    return (
        value.startswith("S")
        and value[1:].isdigit()
        and int(value[1:]) > 0
    )


class GroundedClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_type: ClaimType
    field: FactField | None = None
    value: ClaimValue | None = None
    provenance: FactProvenance | None = None
    source_ids: list[str] = Field(default_factory=list, max_length=12)
    subject: RelationNode | None = None
    object: RelationNode | None = None
    derived_from: list[FactField] = Field(default_factory=list, max_length=8)
    guidance_code: AdvisoryGuidanceCode | None = None

    @field_validator("source_ids")
    @classmethod
    def validate_source_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("source_ids must be unique")
        if any(not _valid_source_id(value) for value in values):
            raise ValueError("invalid source_id")
        return values

    @field_validator("value")
    @classmethod
    def validate_numeric_value(cls, value: ClaimValue | None) -> ClaimValue | None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("numeric claim values must be finite")
        return value

    @model_validator(mode="after")
    def validate_shape(self) -> "GroundedClaim":
        fact_claims = {
            ClaimType.RECORDED_FACT,
            ClaimType.DISTINCT_VALUE,
        }
        if self.claim_type in fact_claims:
            if (
                self.field is None
                or self.value is None
                or self.provenance is None
                or not self.source_ids
            ):
                raise ValueError(
                    "fact claims require field, value, provenance, and source_ids"
                )
            if self.subject or self.object or self.derived_from or self.guidance_code:
                raise ValueError("fact claim contains incompatible properties")
        elif self.claim_type is ClaimType.ABSENCE:
            if self.field is None or self.value is not None or not self.source_ids:
                raise ValueError("absence claims require field and source_ids")
            if self.subject or self.object or self.derived_from or self.guidance_code:
                raise ValueError("absence claim contains incompatible properties")
        elif self.claim_type is ClaimType.STRUCTURED_REFERENCE:
            if (
                self.field is None
                or self.provenance is None
                or not self.source_ids
            ):
                raise ValueError(
                    "structured references require field, provenance, and source_ids"
                )
            if (
                self.value is not None
                or self.subject
                or self.object
                or self.derived_from
                or self.guidance_code
            ):
                raise ValueError(
                    "structured reference contains incompatible properties"
                )
        elif self.claim_type is ClaimType.NON_IMPLICATION:
            if self.subject is None or self.object is None:
                raise ValueError("non-implication requires subject and object")
            if (
                self.field
                or self.value is not None
                or self.provenance
                or self.derived_from
                or self.guidance_code
            ):
                raise ValueError("non-implication contains incompatible properties")
        elif self.claim_type is ClaimType.ADVISORY_GUIDANCE:
            if self.guidance_code is None or not self.source_ids:
                raise ValueError("advisory guidance requires code and source_ids")
            if (
                self.field
                or self.value is not None
                or self.provenance
                or self.subject
                or self.object
                or self.derived_from
            ):
                raise ValueError("advisory guidance contains incompatible properties")
        elif self.claim_type is ClaimType.DERIVATION:
            if (
                self.field is None
                or self.provenance is None
                or not self.derived_from
                or not self.source_ids
            ):
                raise ValueError(
                    "derivation requires field, provenance, support fields, and sources"
                )
            if self.value is not None or self.subject or self.object or self.guidance_code:
                raise ValueError("derivation contains incompatible properties")
        return self


class StructuredNextCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_type: NextCheckType
    guidance_code: AdvisoryGuidanceCode
    source_ids: list[str] = Field(min_length=1, max_length=12)

    @field_validator("source_ids")
    @classmethod
    def validate_source_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("source_ids must be unique")
        if any(not _valid_source_id(value) for value in values):
            raise ValueError("invalid source_id")
        return values


class GroundedClaimOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claims: list[GroundedClaim] = Field(min_length=1, max_length=32)
    next_check: StructuredNextCheck | None = None
    limitations: list[LimitationCode] = Field(default_factory=list, max_length=8)
    used_advisory_context: bool = False

    @field_validator("limitations")
    @classmethod
    def validate_limitations(
        cls,
        values: list[LimitationCode],
    ) -> list[LimitationCode]:
        if len(values) != len(set(values)):
            raise ValueError("limitations must be unique")
        return values
