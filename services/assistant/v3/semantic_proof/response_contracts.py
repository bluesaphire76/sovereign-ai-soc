from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from services.assistant.v3.contracts import ClosedModel


MAX_V32_PROPOSITIONS = 8
MAX_V32_SECTIONS = 4
MAX_V32_PROPOSITION_CHARS = 320


class V32SectionKind(str, Enum):
    DIRECT_ANSWER = "direct_answer"
    ANALYSIS = "analysis"
    EVIDENCE = "evidence"
    COMPARISON = "comparison"
    CONCLUSION = "conclusion"
    UNCERTAINTY = "uncertainty"
    NEXT_STEP = "next_step"
    EXECUTIVE_SUMMARY = "executive_summary"


class V32Proposition(ClosedModel):
    proposition_id: str = Field(min_length=2, max_length=3)
    text: str = Field(min_length=1, max_length=MAX_V32_PROPOSITION_CHARS)
    proof_unit_refs: list[str] = Field(min_length=1, max_length=4)
    section_kind: V32SectionKind

    @field_validator("text")
    @classmethod
    def require_sentence(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized.endswith((".", "!", "?")):
            raise ValueError("V3.2 proposition must be a complete sentence")
        return normalized

    @field_validator("proposition_id")
    @classmethod
    def validate_proposition_id(cls, value: str) -> str:
        allowed = {f"p{index}" for index in range(1, MAX_V32_PROPOSITIONS + 1)}
        if value not in allowed:
            raise ValueError("invalid V3.2 proposition ID")
        return value

    @field_validator("proof_unit_refs")
    @classmethod
    def validate_unique_proof_refs(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("V3.2 proposition proof refs must be unique")
        return value


class GroundedResponseDraftV32(ClosedModel):
    response_language: Literal["it", "en"]
    propositions: list[V32Proposition] = Field(
        min_length=1,
        max_length=MAX_V32_PROPOSITIONS,
    )

    @model_validator(mode="after")
    def validate_closed_response(self):
        proposition_ids = [item.proposition_id for item in self.propositions]
        if len(proposition_ids) != len(set(proposition_ids)):
            raise ValueError("V3.2 proposition IDs must be unique")
        section_kinds = {item.section_kind for item in self.propositions}
        if len(section_kinds) > MAX_V32_SECTIONS:
            raise ValueError("V3.2 response exceeds the section-kind budget")
        return self
