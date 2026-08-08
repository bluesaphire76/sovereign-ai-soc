from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from services.assistant.focus import (
    SharedSemanticEmbeddingProvider,
    cosine_similarity,
    normalize_embedding_text,
)
from services.assistant.v3.contracts import AnswerIntent, IntentScore, IntentSelection


class IntentEmbeddingProvider(Protocol):
    def embed(self, text: str) -> Sequence[float]:
        ...


@dataclass(frozen=True)
class IntentDescriptor:
    intent: AnswerIntent
    description: str
    semantic_examples: tuple[str, ...]

    @property
    def embedding_text(self) -> str:
        examples = " ".join(f"Example: {value}" for value in self.semantic_examples)
        return f"{self.description} {examples}"


INTENT_REGISTRY = (
    IntentDescriptor(
        AnswerIntent.FACT_LOOKUP,
        "Retrieve one or a few explicitly recorded operational values without interpretation.",
        ("What status is recorded?", "Qual e il valore attuale registrato?"),
    ),
    IntentDescriptor(
        AnswerIntent.EXPLAIN,
        "Explain the meaning and significance of the scoped security record using supporting facts.",
        ("Help me understand this detection.", "Spiegami cosa rappresenta questo incidente."),
    ),
    IntentDescriptor(
        AnswerIntent.SUMMARY,
        "Provide a balanced operational overview of the scoped incident or case.",
        ("Summarize this record.", "Dammi una panoramica operativa."),
    ),
    IntentDescriptor(
        AnswerIntent.INVESTIGATE,
        "Analyze what happened and identify the recorded evidence and timeline that support it.",
        ("What happened and what evidence supports it?", "Analizza eventi ed evidenze disponibili."),
    ),
    IntentDescriptor(
        AnswerIntent.COMPARE,
        "Compare two or more explicit security records and describe evidenced differences and similarities.",
        ("Compare these two incidents.", "Confronta i record selezionati."),
    ),
    IntentDescriptor(
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        "Discover and analyze candidate connections between the scoped incident and other incidents.",
        ("Could this connect to other incidents?", "Cerca possibili collegamenti con altri incidenti."),
    ),
    IntentDescriptor(
        AnswerIntent.PATTERN_ANALYSIS,
        "Find recurring evidence-backed patterns across multiple security incidents.",
        ("Find recurring patterns across alerts.", "Individua schemi ricorrenti tra gli incidenti."),
    ),
    IntentDescriptor(
        AnswerIntent.NEXT_ACTION,
        "Identify bounded analyst verification steps or investigation guidance without executing actions.",
        ("What should the analyst verify next?", "Quali controlli conviene fare adesso?"),
    ),
    IntentDescriptor(
        AnswerIntent.HANDOVER,
        "Prepare a factual analyst handover with state, evidence, outstanding checks and context.",
        ("Prepare this for shift handover.", "Prepara il passaggio di consegne per il SOC."),
    ),
    IntentDescriptor(
        AnswerIntent.EXECUTIVE_SUMMARY,
        "Provide a concise leadership-oriented summary of operational impact and current handling state.",
        ("Give leadership an executive summary.", "Prepara una sintesi per il management."),
    ),
)


@dataclass(frozen=True)
class IntentRoutingConfig:
    minimum_similarity: float = 0.40
    secondary_intent_margin: float = 0.035
    max_selected_intents: int = 2
    degraded_intent: AnswerIntent = AnswerIntent.SUMMARY


class SemanticIntentRouter:
    def __init__(
        self,
        *,
        embedding_provider: IntentEmbeddingProvider | None = None,
        registry: tuple[IntentDescriptor, ...] = INTENT_REGISTRY,
        config: IntentRoutingConfig | None = None,
    ) -> None:
        self._embedding_provider = embedding_provider or SharedSemanticEmbeddingProvider()
        self._registry = registry
        self._config = config or IntentRoutingConfig()
        self._vectors: dict[AnswerIntent, tuple[float, ...]] = {}
        self._lock = threading.Lock()

    @property
    def descriptor_cache_size(self) -> int:
        with self._lock:
            return len(self._vectors)

    def _ensure_vectors(self) -> None:
        with self._lock:
            if len(self._vectors) == len(self._registry):
                return
            self._vectors = {
                item.intent: tuple(
                    float(value)
                    for value in self._embedding_provider.embed(
                        normalize_embedding_text(item.embedding_text)
                    )
                )
                for item in self._registry
            }

    def warm(self) -> bool:
        try:
            self._ensure_vectors()
        except Exception:
            return False
        return True

    def _degraded(
        self,
        *,
        started: float,
        clock: Callable[[], float],
        status: str,
    ) -> IntentSelection:
        return IntentSelection(
            primary_intent=self._config.degraded_intent,
            confidence=0.0,
            routing_status=status,
            degraded=status == "embedding_unavailable",
            routing_ms=max(0.0, (clock() - started) * 1000),
        )

    def route(
        self,
        analyst_question: str,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> IntentSelection:
        started = clock()
        question = normalize_embedding_text(analyst_question)
        if not question:
            return self._degraded(started=started, clock=clock, status="empty_question")
        try:
            self._ensure_vectors()
            question_vector = self._embedding_provider.embed(question)
            ranked = sorted(
                (
                    (item.intent, cosine_similarity(question_vector, self._vectors[item.intent]))
                    for item in self._registry
                ),
                key=lambda item: (-item[1], item[0].value),
            )
        except Exception:
            return self._degraded(
                started=started,
                clock=clock,
                status="embedding_unavailable",
            )
        scores = [IntentScore(intent=intent, similarity=score) for intent, score in ranked]
        primary, confidence = ranked[0]
        if confidence < self._config.minimum_similarity:
            return IntentSelection(
                primary_intent=self._config.degraded_intent,
                scores=scores,
                confidence=confidence,
                routing_status="low_confidence",
                routing_ms=max(0.0, (clock() - started) * 1000),
            )
        secondary = [
            intent
            for intent, score in ranked[1:]
            if score >= self._config.minimum_similarity
            and confidence - score <= self._config.secondary_intent_margin
        ][: max(0, self._config.max_selected_intents - 1)]
        return IntentSelection(
            primary_intent=primary,
            secondary_intents=secondary,
            scores=scores,
            confidence=confidence,
            routing_status="ok",
            routing_ms=max(0.0, (clock() - started) * 1000),
        )


_DEFAULT_INTENT_ROUTER = SemanticIntentRouter()


def neutral_intent_selection(
    *,
    degraded: bool = True,
    routing_status: str = "embedding_unavailable",
) -> IntentSelection:
    return IntentSelection(
        primary_intent=AnswerIntent.SUMMARY,
        confidence=0.0,
        routing_status=routing_status,
        degraded=degraded,
        routing_ms=0.0,
    )


def get_semantic_intent_router() -> SemanticIntentRouter:
    return _DEFAULT_INTENT_ROUTER
