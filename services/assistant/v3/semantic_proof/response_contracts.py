from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from services.assistant.v3.contracts import ClosedModel


MAX_V32_PROPOSITIONS = 12
MAX_V32_SECTIONS = 4
MAX_V32_PROPOSITIONS_PER_SECTION = 6
MAX_V32_PROPOSITION_CHARS = 600


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
    proof_unit_ref: str = Field(min_length=1, max_length=220)

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


class V32Section(ClosedModel):
    section_id: str = Field(min_length=2, max_length=2)
    kind: V32SectionKind
    proposition_refs: list[str] = Field(
        min_length=1,
        max_length=MAX_V32_PROPOSITIONS_PER_SECTION,
    )

    @model_validator(mode="after")
    def validate_unique_refs(self):
        if len(self.proposition_refs) != len(set(self.proposition_refs)):
            raise ValueError("V3.2 section proposition refs must be unique")
        return self

    @field_validator("section_id")
    @classmethod
    def validate_section_id(cls, value: str) -> str:
        allowed = {f"s{index}" for index in range(1, MAX_V32_SECTIONS + 1)}
        if value not in allowed:
            raise ValueError("invalid V3.2 section ID")
        return value


class GroundedResponseDraftV32(ClosedModel):
    response_language: Literal["it", "en"]
    propositions: list[V32Proposition] = Field(
        min_length=1,
        max_length=MAX_V32_PROPOSITIONS,
    )
    sections: list[V32Section] = Field(min_length=1, max_length=MAX_V32_SECTIONS)

    @model_validator(mode="after")
    def validate_closed_response_graph(self):
        proposition_ids = [item.proposition_id for item in self.propositions]
        section_ids = [item.section_id for item in self.sections]
        if len(proposition_ids) != len(set(proposition_ids)):
            raise ValueError("V3.2 proposition IDs must be unique")
        if len(section_ids) != len(set(section_ids)):
            raise ValueError("V3.2 section IDs must be unique")
        referenced = [
            proposition_ref
            for section in self.sections
            for proposition_ref in section.proposition_refs
        ]
        if sorted(referenced) != sorted(proposition_ids):
            raise ValueError(
                "every V3.2 proposition must be referenced exactly once"
            )
        return self
