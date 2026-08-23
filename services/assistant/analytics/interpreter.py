from __future__ import annotations

import re
import threading
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, Sequence

from models import Incident
from services.assistant.analytics.contracts import (
    AnalyticsQueryPlan,
    AnalyticsRouteDecision,
    AnalyticsRouteScore,
)
from services.assistant.analytics.registry import (
    ANALYTICS_SEMANTIC_REGISTRY,
    DEFAULT_ANALYTICS_REGISTRY,
    AnalyticsRegistry,
    AnalyticsSemanticDescriptor,
)
from services.assistant.analytics.temporal import ZurichTemporalResolver
from services.assistant.focus import (
    cosine_similarity,
    get_shared_semantic_embedding_provider,
    normalize_embedding_text,
)
from services.assistant.v3.contracts import (
    AnalyticalEntity,
    AnalyticalFilterDescriptor,
    AnalyticalFilterField,
    AnalyticalOperation,
    ValidatedConversationState,
)


_ANCHOR_ID_PATTERN = re.compile(
    r"\b(?:incident(?:e|o)?|incident|al|to)\s*#?\s*(\d{1,9})\b",
    re.IGNORECASE,
)
_LIMIT_PATTERN = re.compile(r"\b(?:top|primi|prime)\s+(\d{1,2})\b", re.IGNORECASE)
_INCIDENT_STATUSES = (
    "FALSE_POSITIVE",
    "INVESTIGATING",
    "CONTAINED",
    "ESCALATED",
    "RESOLVED",
    "TRIAGED",
    "CLOSED",
    "NEW",
)
_CASE_STATUSES = (
    "FALSE_POSITIVE",
    "INVESTIGATING",
    "ESCALATED",
    "TRIAGED",
    "CLOSED",
    "OPEN",
)
_RECORDED_RISK_VALUES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _normalized(value: str) -> str:
    folded = unicodedata.normalize("NFKD", value.casefold())
    return " ".join("".join(ch for ch in folded if not unicodedata.combining(ch)).split())


def _contains_closed_value(question: str, value: str) -> bool:
    question_tokens = tuple(
        "".join(
            character if character.isalnum() or character == "_" else " "
            for character in question
        ).split()
    )
    value_tokens = tuple(value.casefold().replace("_", " ").split())
    return any(
        question_tokens[offset : offset + len(value_tokens)] == value_tokens
        for offset in range(len(question_tokens) - len(value_tokens) + 1)
    )


class AnalyticsEmbeddingProvider(Protocol):
    def embed(self, text: str) -> Sequence[float]: ...


@dataclass(frozen=True)
class AnalyticsRoutingConfig:
    minimum_similarity: float = 0.30
    ambiguity_margin: float = 0.012


@dataclass(frozen=True)
class AnalyticsInterpretationResult:
    decision: AnalyticsRouteDecision
    plan: AnalyticsQueryPlan | None = None


class SemanticAnalyticsRouter:
    def __init__(
        self,
        *,
        embedding_provider: AnalyticsEmbeddingProvider | None = None,
        descriptors: tuple[AnalyticsSemanticDescriptor, ...] = ANALYTICS_SEMANTIC_REGISTRY,
        config: AnalyticsRoutingConfig | None = None,
    ) -> None:
        self._embedding_provider = embedding_provider or get_shared_semantic_embedding_provider()
        self._descriptors = descriptors
        self._config = config or AnalyticsRoutingConfig()
        self._vectors: dict[str, tuple[tuple[float, ...], ...]] = {}
        self._lock = threading.Lock()

    def _ensure_vectors(self) -> None:
        with self._lock:
            if len(self._vectors) == len(self._descriptors):
                return
            self._vectors = {
                descriptor.definition_id: tuple(
                    tuple(
                        float(value)
                        for value in self._embedding_provider.embed(
                            normalize_embedding_text(
                                f"Global SOC analytics query. {prototype}"
                            )
                        )
                    )
                    for prototype in descriptor.prototype_texts
                )
                for descriptor in self._descriptors
            }

    def warm(self) -> bool:
        try:
            self._ensure_vectors()
        except Exception:
            return False
        return True

    def route(
        self,
        question: str,
        *,
        request_embedding: Sequence[float] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> AnalyticsRouteDecision:
        started = clock()
        normalized = normalize_embedding_text(question)
        if not normalized:
            return AnalyticsRouteDecision(
                accepted=False,
                confidence=0.0,
                routing_status="empty_question",
                routing_ms=max(0.0, (clock() - started) * 1000),
            )
        try:
            self._ensure_vectors()
            vector = (
                tuple(float(value) for value in request_embedding)
                if request_embedding is not None
                else tuple(float(value) for value in self._embedding_provider.embed(normalized))
            )
            ranked = sorted(
                (
                    (
                        descriptor.definition_id,
                        max(
                            cosine_similarity(vector, prototype)
                            for prototype in self._vectors[descriptor.definition_id]
                        ),
                    )
                    for descriptor in self._descriptors
                ),
                key=lambda item: (-item[1], item[0]),
            )
        except Exception:
            return AnalyticsRouteDecision(
                accepted=False,
                confidence=0.0,
                routing_status="embedding_unavailable",
                routing_ms=max(0.0, (clock() - started) * 1000),
            )
        scores = [
            AnalyticsRouteScore(definition_id=definition_id, similarity=score)
            for definition_id, score in ranked
        ]
        definition_id, confidence = ranked[0]
        if confidence < self._config.minimum_similarity:
            return AnalyticsRouteDecision(
                accepted=False,
                confidence=confidence,
                routing_status="low_confidence",
                scores=scores,
                routing_ms=max(0.0, (clock() - started) * 1000),
            )
        if len(ranked) > 1 and confidence - ranked[1][1] < self._config.ambiguity_margin:
            return AnalyticsRouteDecision(
                accepted=False,
                confidence=confidence,
                routing_status="ambiguous",
                scores=scores,
                routing_ms=max(0.0, (clock() - started) * 1000),
            )
        return AnalyticsRouteDecision(
            accepted=True,
            definition_id=definition_id,
            confidence=confidence,
            routing_status="ok",
            scores=scores,
            routing_ms=max(0.0, (clock() - started) * 1000),
        )


class GlobalAnalyticsInterpreter:
    def __init__(
        self,
        *,
        router: SemanticAnalyticsRouter | None = None,
        registry: AnalyticsRegistry | None = None,
        temporal_resolver: ZurichTemporalResolver | None = None,
    ) -> None:
        self._router = router or SemanticAnalyticsRouter()
        self._registry = registry or DEFAULT_ANALYTICS_REGISTRY
        self._temporal = temporal_resolver or ZurichTemporalResolver()

    @staticmethod
    def _sql_identity(
        db: Any,
        question: str,
        *,
        column: Any,
        apply_authorized_scope: Callable[[Any], Any] | None = None,
        maximum: int = 500,
    ) -> str | None:
        try:
            query = db.query(column)
            if apply_authorized_scope is not None:
                query = apply_authorized_scope(query)
            rows = query.filter(column.isnot(None)).distinct().limit(maximum).all()
        except Exception:
            return None
        candidates = []
        for row in rows:
            value = row[0] if isinstance(row, tuple) else getattr(row, column.key, None)
            text = str(value or "").strip()
            if text and _normalized(text) in question:
                candidates.append(text)
        return max(candidates, key=len) if candidates else None

    def interpret(
        self,
        question: str,
        *,
        db: Any,
        conversation: ValidatedConversationState | None,
        request_embedding: Sequence[float] | None = None,
        apply_authorized_incident_scope: Callable[[Any], Any] | None = None,
        now: datetime | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> AnalyticsInterpretationResult:
        decision = self._router.route(
            question,
            request_embedding=request_embedding,
            clock=clock,
        )
        if not decision.accepted or decision.definition_id is None:
            return AnalyticsInterpretationResult(decision)
        definition = self._registry.resolve(decision.definition_id)
        if definition is None:
            return AnalyticsInterpretationResult(
                decision.model_copy(
                    update={"accepted": False, "routing_status": "unsupported_literal"}
                )
            )
        normalized = _normalized(question)
        filters: list[AnalyticalFilterDescriptor] = list(definition.fixed_filters)
        statuses = _CASE_STATUSES if definition.entity is AnalyticalEntity.CASE else _INCIDENT_STATUSES
        for status in statuses:
            if _contains_closed_value(normalized, status):
                filters.append(
                    AnalyticalFilterDescriptor(
                        field=AnalyticalFilterField.STATUS,
                        operator="EQ",
                        values=[status],
                    )
                )
                break
        for value in _RECORDED_RISK_VALUES:
            if not _contains_closed_value(normalized, value):
                continue
            field = (
                AnalyticalFilterField.SEVERITY
                if definition.entity is AnalyticalEntity.CASE
                else AnalyticalFilterField.RECORDED_RISK
            )
            filters.append(
                AnalyticalFilterDescriptor(field=field, operator="EQ", values=[value])
            )
            break

        agent = self._sql_identity(
            db,
            normalized,
            column=Incident.agent,
            apply_authorized_scope=apply_authorized_incident_scope,
        )
        if agent:
            filters.append(
                AnalyticalFilterDescriptor(
                    field=AnalyticalFilterField.AGENT,
                    operator="EQ",
                    values=[agent],
                )
            )

        anchor_match = _ANCHOR_ID_PATTERN.search(normalized)
        anchor_id = int(anchor_match.group(1)) if anchor_match else None
        if definition.operation in {
            AnalyticalOperation.RELATED_RECORDS,
            AnalyticalOperation.SIMILAR_RECORDS,
        } and anchor_id is None:
            previous = conversation.global_query if conversation else None
            if previous and previous.operation is AnalyticalOperation.SIMILAR_RECORDS:
                anchor_filter = next(
                    (
                        item
                        for item in previous.filters
                        if item.field is AnalyticalFilterField.INCIDENT_ID
                    ),
                    None,
                )
                if anchor_filter and anchor_filter.values[0].isdigit():
                    anchor_id = int(anchor_filter.values[0])
        if anchor_id is not None:
            filters.append(
                AnalyticalFilterDescriptor(
                    field=AnalyticalFilterField.INCIDENT_ID,
                    operator="EQ",
                    values=[str(anchor_id)],
                )
            )

        previous_ref = None
        previous_result_empty = False
        if definition.definition_id == "incident_count_previous_result":
            previous = conversation.global_query if conversation else None
            if previous is None:
                return AnalyticsInterpretationResult(
                    decision.model_copy(
                        update={"accepted": False, "routing_status": "missing_typed_context"}
                    )
                )
            if previous.result_incident_ids:
                filters.append(
                    AnalyticalFilterDescriptor(
                        field=AnalyticalFilterField.INCIDENT_ID,
                        operator="IN",
                        values=[str(value) for value in previous.result_incident_ids],
                    )
                )
            else:
                previous_result_empty = True
            previous_ref = previous.query_plan_fingerprint

        compare_periods = definition.operation is AnalyticalOperation.COMPARE_PERIODS
        temporal = self._temporal.resolve(
            question,
            now=now,
            compare_periods=compare_periods,
        )
        if definition.requires_time_window and temporal.current is None:
            return AnalyticsInterpretationResult(
                decision.model_copy(
                    update={"accepted": False, "routing_status": "unsupported_literal"}
                )
            )
        limit_match = _LIMIT_PATTERN.search(normalized)
        requested_limit = int(limit_match.group(1)) if limit_match else None
        default_limit = 5 if definition.operation is AnalyticalOperation.TOP_K else definition.maximum_limit
        limit = min(requested_limit or default_limit, definition.maximum_limit)
        try:
            plan = AnalyticsQueryPlan.create(
                definition_id=definition.definition_id,
                operation=definition.operation,
                entity=definition.entity,
                measure=definition.measure,
                filters=filters,
                dimensions=definition.grouping_dimensions,
                time_window=temporal.current,
                comparison_window=temporal.previous,
                limit=limit,
                anchor_record_id=anchor_id,
                previous_result_ref=previous_ref,
                previous_result_empty=previous_result_empty,
            )
            self._registry.validate_plan(plan)
        except ValueError:
            return AnalyticsInterpretationResult(
                decision.model_copy(
                    update={"accepted": False, "routing_status": "unsupported_literal"}
                )
            )
        return AnalyticsInterpretationResult(decision=decision, plan=plan)


_DEFAULT_ANALYTICS_ROUTER = SemanticAnalyticsRouter()


def get_semantic_analytics_router() -> SemanticAnalyticsRouter:
    return _DEFAULT_ANALYTICS_ROUTER
