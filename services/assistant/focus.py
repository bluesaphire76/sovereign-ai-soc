from __future__ import annotations

import math
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, Sequence

from qdrant_knowledge import embedding_runtime_snapshot, get_knowledge_base


class FocusDimension(str, Enum):
    RISK = "risk"
    CORRELATION = "correlation"
    SEVERITY = "severity"
    STATUS = "status"
    HOST = "host"
    EVIDENCE = "evidence"
    PRIORITY = "priority"
    ESCALATION = "escalation"
    GENERAL = "general"


@dataclass(frozen=True)
class FocusDescriptor:
    dimension: FocusDimension
    description: str
    semantic_examples: tuple[str, ...]
    allowed_fact_fields: tuple[str, ...]
    supporting_fact_fields: tuple[str, ...] = ()
    excluded_fact_fields: tuple[str, ...] = ()

    @property
    def embedding_text(self) -> str:
        examples = " ".join(
            f"Example: {example}" for example in self.semantic_examples
        )
        return f"{self.description} {examples}".strip()


_LONG_FORM_FIELDS = (
    "ai_analysis",
    "correlation_summary",
    "latest_stored_analysis",
    "summary",
)


FOCUS_REGISTRY: tuple[FocusDescriptor, ...] = (
    FocusDescriptor(
        dimension=FocusDimension.RISK,
        description=(
            "Questions about the recorded numeric risk score or risk information "
            "for an incident or case, without inventing a qualitative risk band."
        ),
        semantic_examples=(
            "How is this incident scored?",
            "Qual e il punteggio di rischio registrato?",
        ),
        allowed_fact_fields=("risk_score",),
        supporting_fact_fields=(
            "risk_band",
            "risk_label",
            "risk_description",
            "risk_method",
            "risk_source",
            "risk_formula",
            "risk_derived_from",
            "threat_assessment",
            "immediate_threat",
            "urgency",
            "impact",
            "business_impact",
        ),
        excluded_fact_fields=("recommended_priority", *_LONG_FORM_FIELDS),
    ),
    FocusDescriptor(
        dimension=FocusDimension.CORRELATION,
        description=(
            "Questions about whether correlation is recorded, its type, or its "
            "numeric correlation score, without inferring compromise or causality."
        ),
        semantic_examples=(
            "What correlation was recorded for this incident?",
            "Quali informazioni di correlazione sono registrate?",
        ),
        allowed_fact_fields=(
            "correlated",
            "correlation_type",
            "correlation_score",
        ),
        excluded_fact_fields=("correlation_summary", "rule", "events"),
    ),
    FocusDescriptor(
        dimension=FocusDimension.SEVERITY,
        description=(
            "Questions about canonical incident severity and its separation from "
            "the distinct severity recorded by risk normalization."
        ),
        semantic_examples=(
            "Preserve and report the recorded severity provenance.",
            "Mantieni distinta la severita canonica da quella normalizzata.",
        ),
        allowed_fact_fields=("severity",),
        supporting_fact_fields=("risk_normalization_severity",),
        excluded_fact_fields=("recommended_priority", "ai_analysis"),
    ),
    FocusDescriptor(
        dimension=FocusDimension.STATUS,
        description=(
            "Questions about the currently recorded incident or case status as an "
            "opaque operational value."
        ),
        semantic_examples=(
            "What status is recorded?",
            "Qual e lo stato registrato?",
        ),
        allowed_fact_fields=("status",),
        supporting_fact_fields=(
            "status_description",
            "status_meaning",
            "status_context",
        ),
        excluded_fact_fields=_LONG_FORM_FIELDS,
    ),
    FocusDescriptor(
        dimension=FocusDimension.HOST,
        description=(
            "Questions identifying the recorded host, endpoint, agent, user, or "
            "account associated with the scoped record."
        ),
        semantic_examples=(
            "Which endpoint is associated with this incident?",
            "Quale agente e associato all'incidente?",
        ),
        allowed_fact_fields=("agent", "host", "hostname", "user", "username"),
        excluded_fact_fields=_LONG_FORM_FIELDS,
    ),
    FocusDescriptor(
        dimension=FocusDimension.EVIDENCE,
        description=(
            "Questions about recorded evidence, timeline events, observable event "
            "facts, or supporting security references."
        ),
        semantic_examples=(
            "What evidence is recorded in the timeline?",
            "Quali evidenze o eventi risultano registrati?",
        ),
        allowed_fact_fields=(
            "evidence",
            "latest_timeline_event",
            "timeline_events",
            "events",
        ),
        supporting_fact_fields=("mitre", "compromise_confirmed"),
        excluded_fact_fields=("ai_analysis", "correlation_summary"),
    ),
    FocusDescriptor(
        dimension=FocusDimension.PRIORITY,
        description=(
            "Questions specifically about the separately recorded recommended "
            "priority, not canonical severity or a qualitative risk band."
        ),
        semantic_examples=(
            "What priority is recommended?",
            "Quale priorita e raccomandata?",
        ),
        allowed_fact_fields=("recommended_priority",),
        excluded_fact_fields=("severity", "risk_normalization_severity"),
    ),
    FocusDescriptor(
        dimension=FocusDimension.ESCALATION,
        description=(
            "Questions about an explicitly recorded escalation state or its "
            "recorded reason, without deriving state from a missing reason."
        ),
        semantic_examples=(
            "Is an escalation state explicitly recorded?",
            "Esiste uno stato di escalation esplicitamente registrato?",
        ),
        allowed_fact_fields=("escalated",),
        supporting_fact_fields=("escalation_reason",),
        excluded_fact_fields=_LONG_FORM_FIELDS,
    ),
    FocusDescriptor(
        dimension=FocusDimension.GENERAL,
        description=(
            "Broad or ambiguous requests for a concise operational overview when "
            "no specific analytical dimension is sufficiently confident."
        ),
        semantic_examples=(
            "Give me a concise overview of this record.",
            "Fornisci una breve panoramica operativa.",
        ),
        allowed_fact_fields=("status", "severity", "risk_score", "correlated"),
        excluded_fact_fields=(
            "agent",
            "correlation_summary",
            "latest_timeline_event",
            "recommended_priority",
            "rule",
            *_LONG_FORM_FIELDS,
        ),
    ),
)


@dataclass(frozen=True)
class FocusRoutingConfig:
    minimum_similarity: float = 0.42
    general_preference_margin: float = 0.04
    max_dimensions: int = 4


@dataclass(frozen=True)
class FocusSelection:
    dimensions: tuple[FocusDimension, ...]
    scores: Mapping[FocusDimension, float] = field(default_factory=dict)
    confidence: float = 0.0
    focus_routing_ms: float = 0.0
    focus_degraded: bool = False
    routing_status: str = "ok"


class FocusEmbeddingProvider(Protocol):
    def embed(self, text: str) -> Sequence[float]:
        ...


class FocusEmbeddingUnavailable(RuntimeError):
    pass


class SharedSemanticEmbeddingProvider:
    def __init__(self) -> None:
        self._encode_lock = threading.Lock()

    def embed(self, text: str) -> tuple[float, ...]:
        snapshot = embedding_runtime_snapshot()
        if not snapshot.get("embedding_ready"):
            raise FocusEmbeddingUnavailable(
                str(snapshot.get("embedding_cache_state") or "not_ready")
            )
        with self._encode_lock:
            snapshot = embedding_runtime_snapshot()
            if not snapshot.get("embedding_ready"):
                raise FocusEmbeddingUnavailable(
                    str(snapshot.get("embedding_cache_state") or "not_ready")
                )
            vector = get_knowledge_base().embed(text)
        return tuple(float(value) for value in vector)


def normalize_embedding_text(value: str) -> str:
    return unicodedata.normalize("NFKC", " ".join(str(value or "").split()))


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or len(left) != len(right):
        return 0.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return max(-1.0, min(1.0, dot / (left_norm * right_norm)))


def general_focus_selection(
    *,
    focus_routing_ms: float = 0.0,
    focus_degraded: bool = False,
    routing_status: str = "low_confidence",
    scores: Mapping[FocusDimension, float] | None = None,
) -> FocusSelection:
    return FocusSelection(
        dimensions=(FocusDimension.GENERAL,),
        scores=scores or {},
        confidence=0.0,
        focus_routing_ms=max(0.0, focus_routing_ms),
        focus_degraded=focus_degraded,
        routing_status=routing_status,
    )


class SemanticFocusRouter:
    def __init__(
        self,
        *,
        embedding_provider: FocusEmbeddingProvider | None = None,
        registry: tuple[FocusDescriptor, ...] = FOCUS_REGISTRY,
        config: FocusRoutingConfig | None = None,
    ) -> None:
        self._embedding_provider = (
            embedding_provider or SharedSemanticEmbeddingProvider()
        )
        self._registry = registry
        self._config = config or FocusRoutingConfig()
        self._descriptor_vectors: dict[FocusDimension, tuple[float, ...]] = {}
        self._cache_lock = threading.Lock()

    @property
    def descriptor_cache_size(self) -> int:
        with self._cache_lock:
            return len(self._descriptor_vectors)

    def _ensure_descriptor_vectors(self) -> None:
        with self._cache_lock:
            if len(self._descriptor_vectors) == len(self._registry):
                return
            vectors = {
                descriptor.dimension: tuple(
                    float(value)
                    for value in self._embedding_provider.embed(
                        normalize_embedding_text(descriptor.embedding_text)
                    )
                )
                for descriptor in self._registry
            }
            self._descriptor_vectors = vectors

    def warm(self) -> bool:
        try:
            self._ensure_descriptor_vectors()
        except Exception:
            return False
        return True

    def route(
        self,
        analyst_question: str,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> FocusSelection:
        started = clock()
        question = normalize_embedding_text(analyst_question)
        if not question:
            return general_focus_selection(
                focus_routing_ms=(clock() - started) * 1000,
                routing_status="empty_question",
            )
        try:
            self._ensure_descriptor_vectors()
            question_vector = self._embedding_provider.embed(question)
            scores = {
                descriptor.dimension: cosine_similarity(
                    question_vector,
                    self._descriptor_vectors[descriptor.dimension],
                )
                for descriptor in self._registry
            }
        except Exception:
            return general_focus_selection(
                focus_routing_ms=(clock() - started) * 1000,
                focus_degraded=True,
                routing_status="embedding_unavailable",
            )

        specific = [
            descriptor
            for descriptor in self._registry
            if descriptor.dimension is not FocusDimension.GENERAL
        ]
        ranked = sorted(
            specific,
            key=lambda descriptor: scores[descriptor.dimension],
            reverse=True,
        )
        top_score = scores[ranked[0].dimension] if ranked else 0.0
        general_score = scores.get(FocusDimension.GENERAL, 0.0)
        routing_ms = (clock() - started) * 1000
        if (
            top_score < self._config.minimum_similarity
            or general_score >= top_score + self._config.general_preference_margin
        ):
            return general_focus_selection(
                focus_routing_ms=routing_ms,
                routing_status="low_confidence",
                scores=scores,
            )

        selected = {
            descriptor.dimension
            for descriptor in ranked[: self._config.max_dimensions]
            if scores[descriptor.dimension] >= self._config.minimum_similarity
        }
        dimensions = tuple(
            descriptor.dimension
            for descriptor in specific
            if descriptor.dimension in selected
        )
        if not dimensions:
            return general_focus_selection(
                focus_routing_ms=routing_ms,
                routing_status="low_confidence",
                scores=scores,
            )
        return FocusSelection(
            dimensions=dimensions,
            scores=scores,
            confidence=max(scores[dimension] for dimension in dimensions),
            focus_routing_ms=max(0.0, routing_ms),
            focus_degraded=False,
            routing_status="ok",
        )


_DESCRIPTORS_BY_DIMENSION = {
    descriptor.dimension: descriptor for descriptor in FOCUS_REGISTRY
}
_IDENTITY_FIELDS = ("source_type", "incident_id", "case_id")


def build_focused_fact_view(
    *,
    fact_inventory: dict[str, Any],
    focus: FocusSelection,
) -> dict[str, Any]:
    view: dict[str, Any] = {}
    for field_name in _IDENTITY_FIELDS:
        if field_name not in fact_inventory:
            continue
        value = fact_inventory[field_name]
        if field_name == "source_type" or value is not None:
            view[field_name] = value

    dimensions = tuple(
        dimension
        for dimension in focus.dimensions
        if dimension is not FocusDimension.GENERAL
    ) or (FocusDimension.GENERAL,)
    selected_fields: list[str] = []
    for dimension in dimensions:
        descriptor = _DESCRIPTORS_BY_DIMENSION.get(dimension)
        if descriptor is None:
            continue
        selected_fields.extend(descriptor.allowed_fact_fields)
        selected_fields.extend(descriptor.supporting_fact_fields)
    for field_name in dict.fromkeys(selected_fields):
        if field_name in fact_inventory:
            view[field_name] = fact_inventory[field_name]
    return view


_DEFAULT_FOCUS_ROUTER = SemanticFocusRouter()


def get_semantic_focus_router() -> SemanticFocusRouter:
    return _DEFAULT_FOCUS_ROUTER
