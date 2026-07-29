from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


AssistantScope = Literal["global", "incident", "case"]
AssistantMode = Literal["auto", "standard", "quality"]
AssistantStatus = Literal["success", "fallback", "unavailable"]
AssistantAuthority = Literal["authoritative", "advisory"]


class AssistantQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(min_length=1, max_length=2000)
    scope: AssistantScope
    incident_id: int | None = Field(default=None, gt=0)
    case_id: int | None = Field(default=None, gt=0)
    requested_mode: AssistantMode = "auto"
    include_semantic_memory: bool = True

    @field_validator("message", mode="before")
    @classmethod
    def trim_message(cls, value: str) -> str:
        return str(value or "").strip()

    @model_validator(mode="after")
    def validate_scope_ids(self):
        if self.scope == "incident":
            if self.incident_id is None:
                raise ValueError("incident scope requires incident_id")
            if self.case_id is not None:
                raise ValueError("incident scope rejects case_id")

        if self.scope == "case":
            if self.case_id is None:
                raise ValueError("case scope requires case_id")
            if self.incident_id is not None:
                raise ValueError("case scope rejects incident_id")

        if self.scope == "global" and (self.incident_id is not None or self.case_id is not None):
            raise ValueError("global scope rejects incident_id and case_id")

        return self


class AssistantCapabilitiesResponse(BaseModel):
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


class AssistantSource(BaseModel):
    source_id: str
    source_type: str
    authority: AssistantAuthority
    record_id: str | None = None
    label: str
    url: str | None = None
    score: float | None = None
    section: str | None = None


class AssistantMetadata(BaseModel):
    provider_key: str | None = None
    provider_type: str | None = None
    profile: str | None = None
    model: str | None = None
    fallback_used: bool = False
    latency_ms: int | None = None
    usage: dict[str, Any] = Field(default_factory=dict)


class AssistantQueryResponse(BaseModel):
    status: AssistantStatus
    answer: str
    scope: AssistantScope
    incident_id: int | None = None
    case_id: int | None = None
    sources: list[AssistantSource] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    metadata: AssistantMetadata = Field(default_factory=AssistantMetadata)
