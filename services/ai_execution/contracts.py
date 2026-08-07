from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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
]


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
    max_output_tokens: int = Field(ge=16, le=2048)
    temperature: float = Field(default=0, ge=0, le=0)

    @field_validator("task", mode="before")
    @classmethod
    def normalize_task(cls, value: Any) -> str:
        raw = getattr(value, "value", value)
        return str(raw or "").strip().lower()


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
