from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Literal

from pydantic import Field, model_validator

from services.assistant.v3.contracts import (
    AnalyticalDimension,
    AnalyticalEntity,
    AnalyticalFilterDescriptor,
    AnalyticalFilterField,
    AnalyticalMeasure,
    AnalyticalOperation,
    AnalyticalResultAtom,
    AnalyticalResultKind,
    AnalyticalTimeWindow,
    AuthorityClass,
    ClosedModel,
)


class AnalyticsRegistryDefinition(ClosedModel):
    definition_id: str = Field(min_length=1, max_length=120)
    operation: AnalyticalOperation
    entity: AnalyticalEntity
    measure: AnalyticalMeasure
    allowed_filters: list[AnalyticalFilterField] = Field(default_factory=list, max_length=12)
    fixed_filters: list[AnalyticalFilterDescriptor] = Field(default_factory=list, max_length=8)
    grouping_dimensions: list[AnalyticalDimension] = Field(default_factory=list, max_length=4)
    joins: list[Literal["CASE_INCIDENTS"]] = Field(default_factory=list, max_length=2)
    execution_strategy: Literal[
        "SQL_AGGREGATE",
        "SQL_RESULT_SET",
        "SQL_THEN_TYPED_DERIVATION",
        "RECORDED_RELATIONSHIP_LOOKUP",
        "SEMANTIC_DISCOVERY_REHYDRATION",
        "REFERENCE_LOOKUP",
    ]
    ordering: Literal["NONE", "VALUE_DESC", "TIME_DESC", "TIME_ASC"] = "NONE"
    maximum_limit: int = Field(default=20, ge=1, le=50)
    requires_time_window: bool = False
    result_kind: AnalyticalResultKind
    authority_class: Literal[AuthorityClass.ANALYTICAL_DERIVATION] = (
        AuthorityClass.ANALYTICAL_DERIVATION
    )
    result_schema: str = Field(min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_registry_contract(self):
        if len(self.allowed_filters) != len(set(self.allowed_filters)):
            raise ValueError("analytics registry filters must be unique")
        if len(self.grouping_dimensions) != len(set(self.grouping_dimensions)):
            raise ValueError("analytics registry dimensions must be unique")
        if len(self.fixed_filters) != len(
            {(item.field, item.operator, tuple(item.values)) for item in self.fixed_filters}
        ):
            raise ValueError("analytics registry fixed filters must be unique")
        if not {item.field for item in self.fixed_filters}.issubset(
            self.allowed_filters
        ):
            raise ValueError("analytics registry fixed filters must be allowed")
        if len(self.joins) != len(set(self.joins)):
            raise ValueError("analytics registry joins must be unique")
        return self


class AnalyticsQueryPlan(ClosedModel):
    definition_id: str = Field(min_length=1, max_length=120)
    operation: AnalyticalOperation
    entity: AnalyticalEntity
    measure: AnalyticalMeasure
    filters: list[AnalyticalFilterDescriptor] = Field(default_factory=list, max_length=12)
    dimensions: list[AnalyticalDimension] = Field(default_factory=list, max_length=4)
    time_window: AnalyticalTimeWindow | None = None
    comparison_window: AnalyticalTimeWindow | None = None
    limit: int = Field(default=20, ge=1, le=50)
    anchor_record_id: int | None = Field(default=None, gt=0)
    previous_result_ref: str | None = Field(default=None, max_length=64)
    previous_result_empty: bool = False
    query_plan_fingerprint: str = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def validate_fingerprint(self):
        payload = self.model_dump(
            mode="json",
            exclude={"query_plan_fingerprint"},
        )
        if self.query_plan_fingerprint != self.fingerprint_for(payload):
            raise ValueError("analytics query-plan fingerprint does not match the plan")
        return self

    @staticmethod
    def fingerprint_for(payload: dict) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @classmethod
    def create(cls, **values):
        candidate = cls.model_construct(
            **values,
            query_plan_fingerprint="0" * 64,
        )
        fingerprint_payload = candidate.model_dump(
            mode="json",
            exclude={"query_plan_fingerprint"},
        )
        return cls(
            **values,
            query_plan_fingerprint=cls.fingerprint_for(fingerprint_payload),
        )


class SemanticAggregation(str, Enum):
    NONE = "NONE"
    COUNT = "COUNT"
    COUNT_DISTINCT = "COUNT_DISTINCT"
    FREQUENCY = "FREQUENCY"
    DISTRIBUTION = "DISTRIBUTION"
    TREND = "TREND"
    PERIOD_COMPARE = "PERIOD_COMPARE"
    ENTITY_COMPARE = "ENTITY_COMPARE"


class SemanticOrdering(str, Enum):
    NONE = "NONE"
    VALUE_ASC = "VALUE_ASC"
    VALUE_DESC = "VALUE_DESC"
    TIME_ASC = "TIME_ASC"
    TIME_DESC = "TIME_DESC"


class SemanticDetailLevel(str, Enum):
    SUMMARY = "SUMMARY"
    RECORDS = "RECORDS"
    EXPLANATION = "EXPLANATION"
    GUIDANCE = "GUIDANCE"


class SemanticQueryAST(ClosedModel):
    """Compositional, non-executable meaning resolved from one user turn."""

    language: Literal["en", "it"]
    source: Literal[AnalyticalEntity.INCIDENT, AnalyticalEntity.CASE]
    target: AnalyticalEntity
    operation: AnalyticalOperation
    aggregation: SemanticAggregation = SemanticAggregation.NONE
    distinct: bool = False
    filters: list[AnalyticalFilterDescriptor] = Field(default_factory=list, max_length=12)
    negative_filters: list[AnalyticalFilterDescriptor] = Field(
        default_factory=list,
        max_length=12,
    )
    group_by: list[AnalyticalDimension] = Field(default_factory=list, max_length=4)
    ordering: SemanticOrdering = SemanticOrdering.NONE
    limit: int = Field(default=20, ge=1, le=50)
    time_window: AnalyticalTimeWindow | None = None
    comparison_window: AnalyticalTimeWindow | None = None
    anchor_record_id: int | None = Field(default=None, gt=0)
    use_previous_result: bool = False
    previous_result_ref: str | None = Field(default=None, max_length=64)
    previous_result_empty: bool = False
    detail_level: SemanticDetailLevel = SemanticDetailLevel.SUMMARY
    confidence: float = Field(ge=0.0, le=1.0)
    parser_backend: Literal["joint_ast_ranker"] = "joint_ast_ranker"

    @model_validator(mode="after")
    def validate_semantic_composition(self):
        positive = {(item.field, tuple(item.values)) for item in self.filters}
        negative = {(item.field, tuple(item.values)) for item in self.negative_filters}
        if positive.intersection(negative):
            raise ValueError("semantic AST contains contradictory filters")
        if self.distinct and self.aggregation is not SemanticAggregation.COUNT_DISTINCT:
            raise ValueError("distinct projection requires count-distinct aggregation")
        if self.operation is AnalyticalOperation.COMPARE_PERIODS:
            if self.time_window is None or self.comparison_window is None:
                raise ValueError("period comparison requires two typed windows")
        elif self.comparison_window is not None:
            raise ValueError("comparison window requires period comparison")
        if self.use_previous_result and self.previous_result_ref is None:
            raise ValueError("previous-result composition requires a typed reference")
        if not self.use_previous_result and (
            self.previous_result_ref is not None or self.previous_result_empty
        ):
            raise ValueError("previous-result state is inconsistent")
        return self


class AnalyticsRouteScore(ClosedModel):
    definition_id: str = Field(min_length=1, max_length=120)
    similarity: float = Field(ge=-1.0, le=1.0)


class AnalyticsRouteDecision(ClosedModel):
    accepted: bool
    definition_id: str | None = Field(default=None, max_length=120)
    confidence: float = Field(ge=-1.0, le=1.0)
    routing_status: Literal[
        "ok",
        "low_confidence",
        "ambiguous",
        "empty_question",
        "embedding_unavailable",
        "missing_typed_context",
        "ambiguous_time_window",
        "unsupported_literal",
    ]
    scores: list[AnalyticsRouteScore] = Field(default_factory=list, max_length=32)
    routing_ms: float = Field(default=0.0, ge=0.0)


class AnalyticsBuildResult(ClosedModel):
    plan: AnalyticsQueryPlan
    result_atom: AnalyticalResultAtom
    response_language: Literal["it", "en"]
    semantic_index_status: Literal[
        "not_requested",
        "ready",
        "degraded",
        "unavailable",
    ] = "not_requested"
    operational_retrieval_ms: int = Field(default=0, ge=0)
    interpretation_ms: int = Field(default=0, ge=0)
    execution_ms: int = Field(default=0, ge=0)
