from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from services.ai_execution.priorities import AiExecutionPriority


AiExecutionStatus = Literal[
    "success",
    "unavailable",
    "queue_full",
    "deadline_exceeded",
    "invalid_response",
    "failed",
]
GatewayRuntimeState = Literal["warming", "ready", "failed", "stopped"]
OutputSchema = Literal[
    "text_v1",
    "json_v1",
    "assistant_grounded_v1",
    "assistant_grounded_v2",
    "assistant_grounded_v3",
]


class StructuredOutputSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_]+$")
    schema_document: dict[str, Any]


class AiExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_]+$")
    priority: AiExecutionPriority
    request_id: str = Field(
        min_length=8,
        max_length=80,
        pattern=r"^[A-Za-z0-9_.:-]+$",
    )
    deadline_ms: int = Field(ge=100, le=300_000)
    system_instructions: str = Field(min_length=1, max_length=16_000)
    input: str = Field(min_length=1, max_length=64_000)
    output_schema: OutputSchema = "text_v1"
    structured_output_schema: StructuredOutputSchema | None = None
    max_output_tokens: int = Field(ge=16, le=2048)
    temperature: float = Field(default=0, ge=0, le=0)

    @field_validator("task", mode="before")
    @classmethod
    def normalize_task(cls, value: Any) -> str:
        raw = getattr(value, "value", value)
        return str(raw or "").strip().lower()

    @model_validator(mode="after")
    def validate_structured_output_schema(self) -> "AiExecutionRequest":
        schema = self.structured_output_schema
        if self.output_schema == "text_v1" and schema is not None:
            raise ValueError("text_v1 does not accept a structured output schema")
        if self.output_schema in {
            "assistant_grounded_v2",
            "assistant_grounded_v3",
        } and schema is None:
            raise ValueError(
                f"{self.output_schema} requires a structured output schema"
            )
        if schema is not None and schema.name != self.output_schema:
            raise ValueError("structured output schema name must match output_schema")
        return self


class AiExecutionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AiExecutionStatus
    task: str
    profile: Literal["standard"] = "standard"
    model: str = "ai-soc-standard"
    output: dict[str, Any] | list[Any] | str | None = None
    finish_reason: str | None = None
    queue_wait_ms: int = 0
    generation_ms: int = 0
    total_ms: int = 0
    degraded: bool = False
    safe_error: str | None = None
    profile_switch_count: int = 0
    profile_load_count: int = 0
    profile_unload_count: int = 0


class GatewayStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state: GatewayRuntimeState
    profile: Literal["standard"] = "standard"
    model: str = "ai-soc-standard"
    queue_depth: int = 0
    active_requests: int = 0
    max_queue: int = 0
    message: str
    last_safe_error: str | None = None
