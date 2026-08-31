from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Protocol, Sequence, TypeVar

from services.assistant.focus import cosine_similarity, normalize_embedding_text


class PrimitiveEmbeddingProvider(Protocol):
    def embed(self, text: str) -> Sequence[float]: ...


class LocalSemanticEmbeddingProvider:
    """Bounded multilingual E5 encoder dedicated to non-generative NLU slots."""

    def __init__(self, *, model_path: str | None = None) -> None:
        self._model_path = model_path or os.getenv(
            "AI_SOC_SEMANTIC_NLU_EMBEDDING_MODEL",
            "/opt/ai-soc/models/semantic-nlu/multilingual-e5-small",
        )
        self._model = None
        self._load_lock = threading.Lock()
        self._encode_lock = threading.Lock()

    def _encoder(self):
        with self._load_lock:
            if self._model is None:
                from sentence_transformers import SentenceTransformer

                self._model = SentenceTransformer(
                    self._model_path,
                    local_files_only=True,
                    device="cpu",
                )
            return self._model

    def _encode(self, text: str, *, role: str) -> tuple[float, ...]:
        with self._encode_lock:
            vector = self._encoder().encode(
                f"{role}: {text}",
                normalize_embeddings=True,
                show_progress_bar=False,
            )
        return tuple(float(value) for value in vector)

    def embed(self, text: str) -> tuple[float, ...]:
        return self._encode(text, role="query")

    def embed_concept(self, text: str) -> tuple[float, ...]:
        return self._encode(text, role="passage")


class ActionPrimitive(str, Enum):
    RETRIEVE = "RETRIEVE"
    COUNT = "COUNT"
    RANK = "RANK"
    DISTRIBUTE = "DISTRIBUTE"
    TREND = "TREND"
    COMPARE = "COMPARE"
    RELATE = "RELATE"
    SIMILAR = "SIMILAR"
    EXPLAIN = "EXPLAIN"
    ADVISE = "ADVISE"
    EXCLUDE = "EXCLUDE"
    OTHER = "OTHER"


class EntityPrimitive(str, Enum):
    INCIDENT = "INCIDENT"
    CASE = "CASE"
    AGENT = "AGENT"
    DETECTION_RULE = "DETECTION_RULE"
    MITRE_TECHNIQUE = "MITRE_TECHNIQUE"
    STATUS = "STATUS"
    RISK = "RISK"
    TIME = "TIME"
    SLA = "SLA"
    OTHER = "OTHER"


class TemporalRelationPrimitive(str, Enum):
    START_BOUNDARY = "START_BOUNDARY"
    END_BOUNDARY = "END_BOUNDARY"
    RANGE_BOUNDARY = "RANGE_BOUNDARY"
    CURRENT_PERIOD = "CURRENT_PERIOD"
    PREVIOUS_PERIOD = "PREVIOUS_PERIOD"
    NEUTRAL = "NEUTRAL"


class DayPartPrimitive(str, Enum):
    MORNING = "MORNING"
    AFTERNOON = "AFTERNOON"
    EVENING = "EVENING"
    NIGHT = "NIGHT"
    NONE = "NONE"


ACTION_CONCEPTS: Mapping[ActionPrimitive, str | tuple[str, ...]] = {
    ActionPrimitive.RETRIEVE: (
        "show or list records; mostrare o elencare record",
        "find, locate or retrieve records; trovare, cercare o recuperare record",
        "keep, restrict or filter a result; tenere, restringere o filtrare un risultato",
        "inspect, display, report or give records; vedere, riportare o dare record",
    ),
    ActionPrimitive.COUNT: (
        "count number quantity how many; contare numero quantita quanti",
        "aggregate total tally cardinality; conteggio totale cardinalita numero complessivo",
    ),
    ActionPrimitive.RANK: (
        "rank or order entities by frequency; ordinare entita per frequenza",
        "top, bottom, most common, highest or lowest; piu comuni, maggiore o minore",
    ),
    ActionPrimitive.DISTRIBUTE: (
        "distribution breakdown break down group records; distribuzione ripartizione scomporre raggruppare record"
    ),
    ActionPrimitive.TREND: (
        "trend over time evolution timeline changes; andamento tempo evoluzione variazioni"
    ),
    ActionPrimitive.COMPARE: (
        "compare difference versus delta; confrontare differenza variazione"
    ),
    ActionPrimitive.RELATE: (
        "related correlated relationship correlation; correlato relazione correlazione"
    ),
    ActionPrimitive.SIMILAR: (
        "similar resemblance similarity semantic candidate; simile somiglianza similarita semantica"
    ),
    ActionPrimitive.EXPLAIN: (
        "explain meaning describe details; spiegare significato descrivere dettagli"
    ),
    ActionPrimitive.ADVISE: (
        "advise investigate guidance playbook remediation next action; consigliare indagare guida rimedio"
    ),
    ActionPrimitive.EXCLUDE: (
        "exclude omit remove except without negative; escludere omettere tranne senza negativo"
    ),
    ActionPrimitive.OTHER: (
        "unrelated creative or transactional request; richiesta creativa o transazionale non SOC",
        "write a poem, compose creative text or tell a joke; scrivere una poesia o testo creativo",
        "translate text into another language; tradurre un testo in un'altra lingua",
        "reveal a password, credential or secret; rivelare password, credenziali o segreti",
        "execute a shell command or external operation; eseguire un comando shell o operazione esterna",
        "predict weather, finance or stock prices; prevedere meteo, finanza o prezzi azionari",
        "book travel, purchase goods or send personal mail; prenotare viaggi, acquistare o inviare posta personale",
    ),
}


ENTITY_CONCEPTS: Mapping[EntityPrimitive, str | tuple[str, ...]] = {
    EntityPrimitive.INCIDENT: (
        "security incident, alert event or detection record; incidente di sicurezza, allarme o evento"
    ),
    EntityPrimitive.CASE: (
        "investigation case, ticket or investigation file; caso, ticket o pratica di indagine"
    ),
    EntityPrimitive.AGENT: (
        "host, endpoint, machine, device, sensor or monitoring agent; host, endpoint, macchina o agente"
    ),
    EntityPrimitive.DETECTION_RULE: (
        "detection rule, alert signature or detection control; regola o firma di detection"
    ),
    EntityPrimitive.MITRE_TECHNIQUE: (
        "MITRE ATT&CK technique, tactic or technique identifier; tecnica o tattica MITRE ATT&CK"
    ),
    EntityPrimitive.STATUS: (
        "recorded workflow status or lifecycle state; stato registrato o fase del workflow"
    ),
    EntityPrimitive.RISK: (
        "recorded risk, priority or severity; rischio, priorita o severita registrata"
    ),
    EntityPrimitive.TIME: (
        "time, date, period, timeline or temporal interval; tempo, data, periodo o intervallo"
    ),
    EntityPrimitive.SLA: (
        "service level agreement deadline or overdue state; scadenza o superamento SLA"
    ),
    EntityPrimitive.OTHER: (
        "general unrelated object, entertainment, finance, weather, credential, command or personal topic; oggetto generico, intrattenimento, finanza, meteo, credenziale, comando o tema personale"
    ),
}


TEMPORAL_RELATION_CONCEPTS: Mapping[
    TemporalRelationPrimitive,
    str | tuple[str, ...],
] = {
    TemporalRelationPrimitive.START_BOUNDARY: (
        "since or from a starting time; da o a partire da un momento iniziale",
        "after or later than a date; dopo o successivo a una data",
    ),
    TemporalRelationPrimitive.END_BOUNDARY: (
        "before or earlier than a date; prima o precedente a una data",
        "until, through or up to an end time; fino o entro un momento finale",
    ),
    TemporalRelationPrimitive.RANGE_BOUNDARY: (
        "between two dates or within a range; tra due date o in un intervallo",
        "from one date to another date; da una data a un'altra data",
    ),
    TemporalRelationPrimitive.CURRENT_PERIOD: (
        "this current present ongoing period; questo corrente presente periodo",
        "now, at present or immediately; ora, adesso o in questo momento",
    ),
    TemporalRelationPrimitive.PREVIOUS_PERIOD: (
        "last previous preceding prior period; scorso precedente periodo passato",
        "yesterday or the preceding day; ieri o il giorno precedente",
    ),
    TemporalRelationPrimitive.NEUTRAL: (
        "during on at time date; durante nel al tempo data"
    ),
}


DAY_PART_CONCEPTS: Mapping[DayPartPrimitive, str | tuple[str, ...]] = {
    DayPartPrimitive.MORNING: (
        "morning before noon; mattina prima di mezzogiorno"
    ),
    DayPartPrimitive.AFTERNOON: (
        "afternoon after noon; pomeriggio dopo mezzogiorno"
    ),
    DayPartPrimitive.EVENING: (
        "evening after work; sera dopo il lavoro"
    ),
    DayPartPrimitive.NIGHT: "tonight or night; stanotte o notte",
    DayPartPrimitive.NONE: "ordinary time with no part of day; tempo senza parte del giorno",
}


PrimitiveT = TypeVar("PrimitiveT", bound=Enum)


@dataclass(frozen=True)
class PrimitiveDecision:
    primitive: Enum
    confidence: float
    margin: float


class SemanticPrimitiveResolver:
    """Embedding classifier for independent semantic slots, never full query plans."""

    def __init__(
        self,
        *,
        embedding_provider: PrimitiveEmbeddingProvider | None = None,
    ) -> None:
        self._embedding_provider = embedding_provider or LocalSemanticEmbeddingProvider()
        self._vectors: dict[str, tuple[float, ...]] = {}
        self._query_cache: dict[str, tuple[float, ...]] = {}
        self._lock = threading.Lock()

    def _embed(self, text: str, *, concept: bool = False) -> tuple[float, ...]:
        normalized = normalize_embedding_text(text)
        cache_key = f"concept:{normalized}" if concept else f"query:{normalized}"
        with self._lock:
            cached = self._query_cache.get(cache_key)
        if cached is not None:
            return cached
        concept_encoder = getattr(self._embedding_provider, "embed_concept", None)
        encoded = (
            concept_encoder(normalized)
            if concept and callable(concept_encoder)
            else self._embedding_provider.embed(normalized)
        )
        vector = tuple(float(value) for value in encoded)
        with self._lock:
            if len(self._query_cache) >= 2048:
                self._query_cache.pop(next(iter(self._query_cache)))
            self._query_cache[cache_key] = vector
        return vector

    def _classify(
        self,
        text: str,
        concepts: Mapping[PrimitiveT, str | tuple[str, ...]],
    ) -> PrimitiveDecision:
        query = self._embed(text)
        ranked: list[tuple[PrimitiveT, float]] = []
        for primitive, descriptions in concepts.items():
            selected_descriptions = (
                (descriptions,) if isinstance(descriptions, str) else descriptions
            )
            scores: list[float] = []
            for index, description in enumerate(selected_descriptions):
                key = f"{primitive.__class__.__name__}:{primitive.value}:{index}"
                with self._lock:
                    prototype = self._vectors.get(key)
                if prototype is None:
                    prototype = self._embed(description, concept=True)
                    with self._lock:
                        self._vectors[key] = prototype
                scores.append(cosine_similarity(query, prototype))
            ranked.append((primitive, max(scores)))
        ranked.sort(key=lambda item: (-item[1], item[0].value))
        selected, confidence = ranked[0]
        runner_up = ranked[1][1] if len(ranked) > 1 else -1.0
        return PrimitiveDecision(
            primitive=selected,
            confidence=confidence,
            margin=confidence - runner_up,
        )

    def action(self, text: str) -> PrimitiveDecision:
        return self._classify(text, ACTION_CONCEPTS)

    def entity(self, text: str) -> PrimitiveDecision:
        return self._classify(text, ENTITY_CONCEPTS)

    def closed_value(
        self,
        text: str,
        concepts: Mapping[str, str],
    ) -> tuple[str, float, float]:
        query = self._embed(text)
        ranked = sorted(
            (
                (
                    name,
                    cosine_similarity(
                        query,
                        self._embed(description, concept=True),
                    ),
                )
                for name, description in concepts.items()
            ),
            key=lambda item: (-item[1], item[0]),
        )
        selected, confidence = ranked[0]
        runner_up = ranked[1][1] if len(ranked) > 1 else -1.0
        return selected, confidence, confidence - runner_up

    def temporal_relation(self, text: str) -> PrimitiveDecision:
        return self._classify(text, TEMPORAL_RELATION_CONCEPTS)

    def day_part(self, text: str) -> PrimitiveDecision:
        return self._classify(text, DAY_PART_CONCEPTS)

    def warm(self) -> bool:
        try:
            for concepts in (
                ACTION_CONCEPTS,
                ENTITY_CONCEPTS,
                TEMPORAL_RELATION_CONCEPTS,
                DAY_PART_CONCEPTS,
            ):
                for values in concepts.values():
                    selected_values = (values,) if isinstance(values, str) else values
                    for value in selected_values:
                        self._embed(value, concept=True)
        except Exception:
            return False
        return True
