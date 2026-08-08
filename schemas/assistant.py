from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


AssistantScope = Literal["global", "incident", "case"]
AssistantMode = Literal["auto", "standard"]
AssistantStatus = Literal["ok", "fallback"]
AssistantAuthority = Literal["authoritative", "advisory"]
AssistantGenerationKind = Literal["model", "deterministic_fallback"]
AssistantResponseLanguage = Literal["it", "en"]
AssistantIntent = Literal[
    "FACT_LOOKUP",
    "EXPLAIN",
    "SUMMARY",
    "INVESTIGATE",
    "COMPARE",
    "CROSS_INCIDENT_ANALYSIS",
    "PATTERN_ANALYSIS",
    "NEXT_ACTION",
    "HANDOVER",
    "EXECUTIVE_SUMMARY",
]
AssistantAnalysisScope = Literal[
    "CURRENT_RECORD",
    "CURRENT_CASE",
    "EXPLICIT_RECORD_SET",
    "RELATED_INCIDENTS",
    "GLOBAL",
]
AssistantRuntimeState = Literal["warming", "ready", "failed", "stopped"]
AssistantBlockKind = Literal[
    "direct_answer",
    "analysis",
    "next_check",
    "limitations",
]
AssistantValidationStatus = Literal["passed", "failed", "not_run"]
AssistantFallbackReason = Literal[
    "gateway_unavailable",
    "queue_deadline_exceeded",
    "generation_timeout",
    "invalid_visible_output",
    "invalid_json",
    "invalid_json_type",
    "invalid_structured_claim_schema",
    "invalid_structured_output",
    "grounding_validation_failed",
    "focus_validation_failed",
]


class AssistantQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=2000)
    scope: AssistantScope
    incident_id: int | None = Field(default=None, gt=0)
    case_id: int | None = Field(default=None, gt=0)
    requested_mode: AssistantMode = "auto"
    include_semantic_memory: bool = True
    conversation_id: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("message", mode="before")
    @classmethod
    def trim_message(cls, value: str) -> str:
        return str(value or "").strip()

    @field_validator("conversation_id", mode="before")
    @classmethod
    def normalize_conversation_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip()
        if any(character.isspace() for character in normalized):
            raise ValueError("conversation_id cannot contain whitespace")
        return normalized

    @model_validator(mode="after")
    def validate_scope_ids(self):
        if self.scope == "incident":
            if self.incident_id is None:
                raise ValueError("incident scope requires incident_id")
            if self.case_id is not None:
                raise ValueError("incident scope rejects case_id")
        elif self.scope == "case":
            if self.case_id is None:
                raise ValueError("case scope requires case_id")
            if self.incident_id is not None:
                raise ValueError("case scope rejects incident_id")
        elif self.incident_id is not None or self.case_id is not None:
            raise ValueError("global scope rejects incident_id and case_id")
        return self


class AssistantCapabilitiesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool
    feature_key: str = "soc_assistant"
    supported_scopes: list[AssistantScope]
    supported_modes: list[AssistantMode]
    persistent_conversations: bool = False
    streaming: bool = False
    project_documentation_indexed: bool = False
    semantic_memory_supported: bool = True
    write_actions_supported: bool = False
    decision_boundary: str
    runtime_state: AssistantRuntimeState | None = None
    default_profile: Literal["standard"] = "standard"
    loaded_profile: Literal["standard"] | None = None
    runtime_message: str | None = None


class AssistantSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(pattern=r"^S[1-9]\d*$")
    source_type: str
    authority: AssistantAuthority
    record_id: str | None = None
    label: str
    url: str | None = None
    score: float | None = None
    section: str | None = None

    @field_validator("url")
    @classmethod
    def internal_url_only(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value.startswith("/")
            or value.startswith("//")
            or ".." in value
            or any(character.isspace() for character in value)
        ):
            raise ValueError("source URL must be an internal path")
        return value


class AssistantResponseBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: AssistantBlockKind
    text: str = Field(min_length=1, max_length=4000)
    source_ids: list[str] = Field(default_factory=list)

    @field_validator("text", mode="before")
    @classmethod
    def trim_text(cls, value: str) -> str:
        return str(value or "").strip()

    @field_validator("source_ids")
    @classmethod
    def unique_source_ids(cls, value: list[str]) -> list[str]:
        if any(not source_id.startswith("S") for source_id in value):
            raise ValueError("invalid source id")
        return list(dict.fromkeys(value))


class AssistantMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    generation_kind: AssistantGenerationKind = "deterministic_fallback"
    queue_wait_ms: int = 0
    generation_ms: int = 0
    total_latency_ms: int = 0
    effective_profile: Literal["standard"] = "standard"
    effective_model: str = "ai-soc-standard"
    semantic_status: Literal[
        "not_requested",
        "disabled",
        "ok",
        "timed_out",
        "failed",
    ] = "not_requested"
    semantic_elapsed_ms: int = 0
    semantic_degraded: bool = False
    grounding_validation: AssistantValidationStatus = "not_run"
    focus_validation: AssistantValidationStatus = "not_run"
    fallback_reason: AssistantFallbackReason | None = None
    response_language: AssistantResponseLanguage = "en"
    thinking_disabled: bool = True
    source_count: int = 0
    assistant_intent: AssistantIntent | None = None
    secondary_intents: list[AssistantIntent] = Field(default_factory=list, max_length=2)
    analysis_scope: AssistantAnalysisScope | None = None
    context_atoms: int = 0
    operational_atoms: int = 0
    reference_atoms: int = 0
    advisory_atoms: int = 0
    cross_incident_candidates: int = 0
    graph_edges: int = 0
    conversation_followup: bool = False
    context_build_ms: int = 0


class AssistantQueryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AssistantStatus
    generation_kind: AssistantGenerationKind
    answer: str = Field(min_length=1)
    blocks: list[AssistantResponseBlock] = Field(min_length=1)
    scope: AssistantScope
    incident_id: int | None = None
    case_id: int | None = None
    sources: list[AssistantSource] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    metadata: AssistantMetadata = Field(default_factory=AssistantMetadata)

    @model_validator(mode="after")
    def validate_source_references(self):
        known = {source.source_id for source in self.sources}
        referenced = {
            source_id
            for block in self.blocks
            for source_id in block.source_ids
        }
        if not referenced.issubset(known):
            raise ValueError("response block references an unknown source")
        return self
