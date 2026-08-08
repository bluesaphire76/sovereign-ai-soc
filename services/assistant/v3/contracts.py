from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorityClass(str, Enum):
    OPERATIONAL_AUTHORITATIVE = "OPERATIONAL_AUTHORITATIVE"
    REFERENCE_KNOWLEDGE = "REFERENCE_KNOWLEDGE"
    ADVISORY_KNOWLEDGE = "ADVISORY_KNOWLEDGE"
    SEMANTIC_CANDIDATE = "SEMANTIC_CANDIDATE"


class AnswerIntent(str, Enum):
    FACT_LOOKUP = "FACT_LOOKUP"
    EXPLAIN = "EXPLAIN"
    SUMMARY = "SUMMARY"
    INVESTIGATE = "INVESTIGATE"
    COMPARE = "COMPARE"
    CROSS_INCIDENT_ANALYSIS = "CROSS_INCIDENT_ANALYSIS"
    PATTERN_ANALYSIS = "PATTERN_ANALYSIS"
    NEXT_ACTION = "NEXT_ACTION"
    HANDOVER = "HANDOVER"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"


class AnalyticalFocus(str, Enum):
    RISK = "risk"
    CORRELATION = "correlation"
    SEVERITY = "severity"
    STATUS = "status"
    HOST = "host"
    EVIDENCE = "evidence"
    PRIORITY = "priority"
    ESCALATION = "escalation"
    GENERAL = "general"


class AnalysisScope(str, Enum):
    CURRENT_RECORD = "CURRENT_RECORD"
    CURRENT_CASE = "CURRENT_CASE"
    EXPLICIT_RECORD_SET = "EXPLICIT_RECORD_SET"
    RELATED_INCIDENTS = "RELATED_INCIDENTS"
    GLOBAL = "GLOBAL"


class ContextRequirement(str, Enum):
    IDENTITY = "IDENTITY"
    STATUS = "STATUS"
    ENTITY = "ENTITY"
    DETECTION = "DETECTION"
    RISK = "RISK"
    PRIORITY = "PRIORITY"
    CORRELATION = "CORRELATION"
    MITRE = "MITRE"
    EVIDENCE = "EVIDENCE"
    TIMELINE = "TIMELINE"
    COMPROMISE_STATE = "COMPROMISE_STATE"
    CASE_RELATIONSHIP = "CASE_RELATIONSHIP"
    REFERENCE = "REFERENCE"
    ADVISORY = "ADVISORY"
    CROSS_INCIDENT = "CROSS_INCIDENT"


class FactField(str, Enum):
    SOURCE_TYPE = "source_type"
    INCIDENT_ID = "incident_id"
    CASE_ID = "case_id"
    TITLE = "title"
    STATUS = "status"
    SEVERITY = "severity"
    RISK_NORMALIZATION_SEVERITY = "risk_normalization_severity"
    TIMESTAMP = "timestamp"
    AGENT = "agent"
    HOST = "host"
    USER = "user"
    USERNAME = "username"
    RULE = "rule"
    WAZUH_LEVEL = "wazuh_level"
    RISK_SCORE = "risk_score"
    MITRE = "mitre"
    CORRELATED = "correlated"
    CORRELATION_TYPE = "correlation_type"
    CORRELATION_SCORE = "correlation_score"
    ESCALATION_REASON = "escalation_reason"
    RECOMMENDED_PRIORITY = "recommended_priority"
    LINKED_CASE_IDS = "linked_case_ids"
    LINKED_INCIDENT_COUNT = "linked_incident_count"
    LINKED_INCIDENTS = "linked_incidents"
    LATEST_TIMELINE_EVENT = "latest_timeline_event"
    COMPROMISE_CONFIRMED = "compromise_confirmed"
    OWNER = "owner"
    ASSIGNEE = "assignee"
    SLA_DUE_AT = "sla_due_at"
    STATUS_REASON = "status_reason"
    LATEST_ACTIONS = "latest_actions"
    CLOSURE = "closure"


class IntentScore(ClosedModel):
    intent: AnswerIntent
    similarity: float = Field(ge=-1.0, le=1.0)


class IntentSelection(ClosedModel):
    primary_intent: AnswerIntent
    secondary_intents: list[AnswerIntent] = Field(default_factory=list, max_length=2)
    scores: list[IntentScore] = Field(default_factory=list, max_length=10)
    confidence: float = Field(ge=-1.0, le=1.0)
    routing_status: Literal["ok", "low_confidence", "empty_question", "embedding_unavailable"]
    degraded: bool = False
    routing_ms: float = Field(ge=0.0)

    @model_validator(mode="after")
    def validate_secondary_intents(self):
        if self.primary_intent in self.secondary_intents:
            raise ValueError("primary intent cannot also be secondary")
        if len(set(self.secondary_intents)) != len(self.secondary_intents):
            raise ValueError("secondary intents must be unique")
        return self


class ResolvedScope(ClosedModel):
    analysis_scope: AnalysisScope
    active_incident_ids: list[int] = Field(default_factory=list, max_length=12)
    active_case_ids: list[int] = Field(default_factory=list, max_length=4)
    conversation_followup: bool = False


class ContextLimits(ClosedModel):
    max_operational_atoms: int = Field(default=80, ge=1, le=160)
    max_evidence_atoms: int = Field(default=24, ge=1, le=48)
    max_timeline_atoms: int = Field(default=8, ge=1, le=16)
    max_candidates_discovered: int = Field(default=40, ge=1, le=100)
    max_candidates_rehydrated: int = Field(default=12, ge=1, le=24)
    max_graph_incidents: int = Field(default=8, ge=1, le=16)
    max_reference_atoms: int = Field(default=8, ge=0, le=16)
    max_advisory_atoms: int = Field(default=6, ge=0, le=12)


class ContextPlan(ClosedModel):
    intent: AnswerIntent
    analysis_scope: AnalysisScope
    requirements: list[ContextRequirement] = Field(min_length=1, max_length=16)
    fact_fields: list[FactField] = Field(min_length=1, max_length=32)
    include_cross_incident: bool = False
    include_reference: bool = False
    include_advisory: bool = False
    limits: ContextLimits = Field(default_factory=ContextLimits)
    policy_ms: float = Field(default=0.0, ge=0.0)


class Provenance(ClosedModel):
    authority_class: AuthorityClass
    source_type: str = Field(min_length=1, max_length=64)
    source_record_id: str = Field(min_length=1, max_length=128)
    source_id: str | None = Field(default=None, max_length=32)
    retrieval_method: Literal[
        "operational_query",
        "project_catalog",
        "semantic_retrieval",
        "conversation_reference",
    ]


class AtomBase(ClosedModel):
    atom_id: str = Field(min_length=1, max_length=180)
    authority_class: AuthorityClass
    provenance: Provenance
    incident_id: int | None = Field(default=None, gt=0)
    case_id: int | None = Field(default=None, gt=0)
    timestamp: str | None = Field(default=None, max_length=80)


class IncidentIdentityAtom(AtomBase):
    atom_type: Literal["incident_identity"] = "incident_identity"
    incident_id: int = Field(gt=0)


class CaseIdentityAtom(AtomBase):
    atom_type: Literal["case_identity"] = "case_identity"
    case_id: int = Field(gt=0)
    title: str | None = Field(default=None, max_length=240)


class StatusAtom(AtomBase):
    atom_type: Literal["status"] = "status"
    status: str = Field(min_length=1, max_length=80)
    canonical_severity: str | None = Field(default=None, max_length=80)


class RiskAtom(AtomBase):
    atom_type: Literal["risk"] = "risk"
    risk_score: float | None = None
    risk_normalization_severity: str | None = Field(default=None, max_length=80)


class PriorityAtom(AtomBase):
    atom_type: Literal["priority"] = "priority"
    recommended_priority: str = Field(min_length=1, max_length=80)


class HostAtom(AtomBase):
    atom_type: Literal["host"] = "host"
    host: str = Field(min_length=1, max_length=240)
    representation: Literal["host", "agent"]


class UserAtom(AtomBase):
    atom_type: Literal["user"] = "user"
    user: str = Field(min_length=1, max_length=240)


class DetectionAtom(AtomBase):
    atom_type: Literal["detection"] = "detection"
    rule: str = Field(min_length=1, max_length=500)
    level: int | None = None


class MitreTechniqueAtom(AtomBase):
    atom_type: Literal["mitre_technique"] = "mitre_technique"
    technique_id: str | None = Field(default=None, max_length=32)
    technique_name: str | None = Field(default=None, max_length=240)

    @model_validator(mode="after")
    def require_identifier_or_name(self):
        if self.technique_id is None and self.technique_name is None:
            raise ValueError("MITRE atom requires an ID or name")
        return self


class TimelineEventAtom(AtomBase):
    atom_type: Literal["timeline_event"] = "timeline_event"
    event_type: str = Field(min_length=1, max_length=160)


class ObservableAtom(AtomBase):
    atom_type: Literal["observable"] = "observable"
    observable_type: Literal["ip", "domain", "file_hash", "file", "registry", "other"]
    value: str = Field(min_length=1, max_length=500)


class ProcessAtom(AtomBase):
    atom_type: Literal["process"] = "process"
    process_name: str = Field(min_length=1, max_length=240)
    process_id: str | None = Field(default=None, max_length=80)
    parent_process_name: str | None = Field(default=None, max_length=240)


class EvidenceDetailAtom(AtomBase):
    atom_type: Literal["evidence"] = "evidence"
    evidence_type: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=1, max_length=800)


class RecordedCorrelationAtom(AtomBase):
    atom_type: Literal["recorded_correlation"] = "recorded_correlation"
    correlated: bool | None
    correlation_type: str | None = Field(default=None, max_length=160)
    correlation_score: float | None = None


class CompromiseStateAtom(AtomBase):
    atom_type: Literal["compromise_state"] = "compromise_state"
    compromise_confirmed: bool | None


class CaseRelationshipAtom(AtomBase):
    atom_type: Literal["case_relationship"] = "case_relationship"
    incident_id: int = Field(gt=0)
    case_id: int = Field(gt=0)
    relationship_type: str = Field(min_length=1, max_length=120)


EvidenceAtom = Annotated[
    IncidentIdentityAtom
    | CaseIdentityAtom
    | StatusAtom
    | RiskAtom
    | PriorityAtom
    | HostAtom
    | UserAtom
    | DetectionAtom
    | MitreTechniqueAtom
    | TimelineEventAtom
    | ObservableAtom
    | ProcessAtom
    | EvidenceDetailAtom
    | RecordedCorrelationAtom
    | CompromiseStateAtom
    | CaseRelationshipAtom,
    Field(discriminator="atom_type"),
]


class ReferenceKnowledgeAtom(ClosedModel):
    knowledge_id: str = Field(min_length=1, max_length=180)
    knowledge_type: Literal[
        "mitre_definition",
        "lifecycle_definition",
        "risk_methodology",
        "correlation_semantics",
        "detection_terminology",
    ]
    authority_class: Literal[AuthorityClass.REFERENCE_KNOWLEDGE] = (
        AuthorityClass.REFERENCE_KNOWLEDGE
    )
    subject: str = Field(min_length=1, max_length=240)
    bounded_content: str = Field(min_length=1, max_length=900)
    provenance: Provenance


class AdvisoryKnowledgeAtom(ClosedModel):
    knowledge_id: str = Field(min_length=1, max_length=180)
    knowledge_type: Literal[
        "playbook_guidance",
        "historical_incident_advisory",
        "investigation_guidance",
        "remediation_governance",
    ]
    authority_class: Literal[AuthorityClass.ADVISORY_KNOWLEDGE] = (
        AuthorityClass.ADVISORY_KNOWLEDGE
    )
    subject: str = Field(min_length=1, max_length=240)
    guidance_code: str = Field(min_length=1, max_length=80)
    bounded_content: str = Field(min_length=1, max_length=900)
    retrieved: Literal[True] = True
    used: Literal[False] = False
    provenance: Provenance


KnowledgeAtom = ReferenceKnowledgeAtom | AdvisoryKnowledgeAtom


class DiscoverySignal(str, Enum):
    SHARED_HOST = "SHARED_HOST"
    SHARED_AGENT = "SHARED_AGENT"
    SHARED_USER = "SHARED_USER"
    SHARED_RULE = "SHARED_RULE"
    SHARED_DETECTION_FAMILY = "SHARED_DETECTION_FAMILY"
    SHARED_MITRE = "SHARED_MITRE"
    SHARED_OBSERVABLE = "SHARED_OBSERVABLE"
    SHARED_EVENT_FAMILY = "SHARED_EVENT_FAMILY"
    SHARED_CORRELATION_TYPE = "SHARED_CORRELATION_TYPE"
    SAME_CASE = "SAME_CASE"
    TEMPORAL_PROXIMITY = "TEMPORAL_PROXIMITY"
    SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY"


class IncidentCandidate(ClosedModel):
    candidate_id: str = Field(min_length=1, max_length=180)
    candidate_incident_id: int = Field(gt=0)
    authority_class: Literal[AuthorityClass.SEMANTIC_CANDIDATE] = (
        AuthorityClass.SEMANTIC_CANDIDATE
    )
    discovery_signals: list[DiscoverySignal] = Field(min_length=1, max_length=12)
    semantic_score: float | None = Field(default=None, ge=-1.0, le=1.0)
    deterministic_signal_count: int = Field(ge=0, le=11)
    discovery_source: Literal["deterministic", "semantic", "hybrid"]
    authoritative_rehydrated: Literal[True] = True
    ranking_score: float = Field(ge=0.0)


class RelationshipClass(str, Enum):
    RECORDED_CORRELATION = "RECORDED_CORRELATION"
    ANALYTICAL_RELATIONSHIP = "ANALYTICAL_RELATIONSHIP"
    SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY"


class RelationshipType(str, Enum):
    PLATFORM_RECORDED_CORRELATION = "PLATFORM_RECORDED_CORRELATION"
    SHARED_HOST = "SHARED_HOST"
    SHARED_AGENT = "SHARED_AGENT"
    SHARED_USER = "SHARED_USER"
    SHARED_RULE = "SHARED_RULE"
    SHARED_DETECTION_FAMILY = "SHARED_DETECTION_FAMILY"
    SHARED_MITRE = "SHARED_MITRE"
    SHARED_OBSERVABLE = "SHARED_OBSERVABLE"
    SHARED_EVENT_FAMILY = "SHARED_EVENT_FAMILY"
    SHARED_CORRELATION_TYPE = "SHARED_CORRELATION_TYPE"
    SAME_CASE = "SAME_CASE"
    TEMPORAL_PROXIMITY = "TEMPORAL_PROXIMITY"
    SEMANTIC_SIMILARITY = "SEMANTIC_SIMILARITY"


class AnalyticalRelationship(ClosedModel):
    relationship_id: str = Field(min_length=1, max_length=220)
    relationship_class: RelationshipClass
    relationship_type: RelationshipType
    left_incident_id: int = Field(gt=0)
    right_incident_id: int = Field(gt=0)
    evidence_atom_refs: list[str] = Field(min_length=1, max_length=16)
    provenance: Provenance
    strength: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_distinct_nodes(self):
        if self.left_incident_id == self.right_incident_id:
            raise ValueError("relationship endpoints must be distinct")
        return self


class CrossIncidentEvidenceGraph(ClosedModel):
    incident_ids: list[int] = Field(default_factory=list, max_length=16)
    relationships: list[AnalyticalRelationship] = Field(default_factory=list, max_length=120)
    available_evidence_refs: list[str] = Field(default_factory=list, max_length=320)

    @model_validator(mode="after")
    def validate_evidence_references(self):
        available = set(self.available_evidence_refs)
        for relationship in self.relationships:
            if not set(relationship.evidence_atom_refs).issubset(available):
                raise ValueError("graph relationship references unavailable evidence")
        return self


class ValidatedConversationState(ClosedModel):
    conversation_id: str = Field(min_length=1, max_length=128)
    owner_key: str = Field(min_length=16, max_length=128)
    active_incident_ids: list[int] = Field(default_factory=list, max_length=12)
    active_case_ids: list[int] = Field(default_factory=list, max_length=4)
    related_incident_ids: list[int] = Field(default_factory=list, max_length=12)
    previous_intents: list[AnswerIntent] = Field(default_factory=list, max_length=8)
    previous_focus_dimensions: list[AnalyticalFocus] = Field(default_factory=list, max_length=9)
    validated_atom_refs: list[str] = Field(default_factory=list, max_length=160)
    validated_relationship_refs: list[str] = Field(default_factory=list, max_length=80)
    reference_knowledge_refs: list[str] = Field(default_factory=list, max_length=40)
    advisory_refs: list[str] = Field(default_factory=list, max_length=40)
    response_language: Literal["it", "en"]
    updated_at_epoch: float = Field(ge=0.0)


class ConversationStateRefs(ClosedModel):
    conversation_id: str | None = Field(default=None, max_length=128)
    active_incident_ids: list[int] = Field(default_factory=list, max_length=12)
    active_case_ids: list[int] = Field(default_factory=list, max_length=4)
    related_incident_ids: list[int] = Field(default_factory=list, max_length=12)
    validated_atom_refs: list[str] = Field(default_factory=list, max_length=160)
    validated_relationship_refs: list[str] = Field(default_factory=list, max_length=80)


class SourceRegistryEntry(ClosedModel):
    source_ref: str = Field(min_length=1, max_length=180)
    authority_class: AuthorityClass
    source_type: str = Field(min_length=1, max_length=64)
    source_record_id: str = Field(min_length=1, max_length=128)


class ContextBuildMetrics(ClosedModel):
    intent_routing_ms: float = Field(default=0.0, ge=0.0)
    focus_routing_ms: float = Field(default=0.0, ge=0.0)
    context_policy_ms: float = Field(default=0.0, ge=0.0)
    atom_normalization_ms: float = Field(default=0.0, ge=0.0)
    candidate_retrieval_ms: float = Field(default=0.0, ge=0.0)
    authoritative_rehydration_ms: float = Field(default=0.0, ge=0.0)
    graph_construction_ms: float = Field(default=0.0, ge=0.0)
    reference_retrieval_ms: float = Field(default=0.0, ge=0.0)
    advisory_retrieval_ms: float = Field(default=0.0, ge=0.0)
    conversation_state_ms: float = Field(default=0.0, ge=0.0)
    total_context_build_ms: float = Field(default=0.0, ge=0.0)


class V3AnalyticalContextPackage(ClosedModel):
    question: str = Field(min_length=1, max_length=2000)
    response_language: Literal["it", "en"]
    intent_selection: IntentSelection
    focus_selection: list[AnalyticalFocus] = Field(min_length=1, max_length=9)
    resolved_scope: ResolvedScope
    context_plan: ContextPlan
    operational_atoms: list[EvidenceAtom] = Field(default_factory=list, max_length=160)
    reference_atoms: list[ReferenceKnowledgeAtom] = Field(default_factory=list, max_length=16)
    advisory_atoms: list[AdvisoryKnowledgeAtom] = Field(default_factory=list, max_length=12)
    cross_incident_candidates: list[IncidentCandidate] = Field(default_factory=list, max_length=24)
    cross_incident_graph: CrossIncidentEvidenceGraph
    conversation_state_refs: ConversationStateRefs
    context_limits: ContextLimits
    source_registry: list[SourceRegistryEntry] = Field(default_factory=list, max_length=320)
    metrics: ContextBuildMetrics
