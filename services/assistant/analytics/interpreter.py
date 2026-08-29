from __future__ import annotations

import math
import time
import threading
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Callable, Mapping, Protocol, Sequence

from models import Incident
from services.assistant.analytics.contracts import (
    AnalyticsQueryPlan,
    AnalyticsRegistryDefinition,
    AnalyticsRouteDecision,
    AnalyticsRouteScore,
    SemanticAggregation,
    SemanticDetailLevel,
    SemanticOrdering,
    SemanticQueryAST,
)
from services.assistant.analytics.nlu_runtime import (
    DependencyDocument,
    DependencyParser,
    DependencyToken,
    get_dependency_parser,
)
from services.assistant.analytics.joint_parser import (
    JointSemanticEvidence,
    JointSemanticPlanRanker,
    get_joint_semantic_plan_ranker,
)
from services.assistant.analytics.literal_resolution import (
    has_discourse_reference,
    numeric_literals,
    normalized_literal_tokens,
    resolve_closed_literals,
)
from services.assistant.analytics.registry import DEFAULT_ANALYTICS_REGISTRY, AnalyticsRegistry
from services.assistant.analytics.semantic_primitives import (
    ActionPrimitive,
    EntityPrimitive,
    DayPartPrimitive,
    PrimitiveDecision,
    PrimitiveEmbeddingProvider,
    SemanticPrimitiveResolver,
    TemporalRelationPrimitive,
)
from services.assistant.analytics.temporal import ZurichTemporalResolver
from services.assistant.v3.knowledge import MITRE_REFERENCE_CATALOG
from services.assistant.v3.contracts import (
    AnalyticalDimension,
    AnalyticalEntity,
    AnalyticalFilterDescriptor,
    AnalyticalFilterField,
    AnalyticalMeasure,
    AnalyticalOperation,
    GlobalConversationQueryState,
    ValidatedConversationState,
)


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
_CASE_STATUSES = (*_INCIDENT_STATUSES, "OPEN")
_RECORDED_RISK_VALUES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_STATUS_CONCEPTS: Mapping[str, str] = {
    "FALSE_POSITIVE": "false positive dismissed benign; falso positivo benigno scartato",
    "INVESTIGATING": "under active investigation; in investigazione o in analisi",
    "CONTAINED": "contained isolated controlled; contenuto isolato sotto controllo",
    "ESCALATED": "escalated transferred to higher response; escalation inoltrata",
    "RESOLVED": "resolved completed remediated; risolto completato rimediato",
    "TRIAGED": "triaged assessed classified; triage valutato classificato",
    "CLOSED": "closed finished inactive; chiuso concluso inattivo",
    "NEW": "new unprocessed workflow state; nuovo stato non lavorato",
    "OPEN": "open active unresolved; aperto attivo non risolto",
}


@dataclass(frozen=True)
class AnalyticsInterpretationResult:
    decision: AnalyticsRouteDecision
    plan: AnalyticsQueryPlan | None = None
    semantic_ast: SemanticQueryAST | None = None


@dataclass(frozen=True)
class EntityMention:
    token: DependencyToken
    primitive: EntityPrimitive
    confidence: float
    margin: float
    interrogative: bool


@dataclass(frozen=True)
class SemanticFrame:
    document: DependencyDocument
    action: PrimitiveDecision
    mentions: tuple[EntityMention, ...]
    evidence_mentions: tuple[EntityMention, ...]
    action_evidence: tuple[PrimitiveDecision, ...]
    target: EntityMention | None
    superlative: bool
    negative: bool
    quantified: bool
    action_confident: bool


class AnalyticsEmbeddingProvider(PrimitiveEmbeddingProvider, Protocol):
    pass


@dataclass(frozen=True)
class AnalyticsRoutingConfig:
    minimum_similarity: float = 0.78
    ambiguity_margin: float = 0.008


_ENTITY_MAP: Mapping[EntityPrimitive, AnalyticalEntity] = {
    EntityPrimitive.INCIDENT: AnalyticalEntity.INCIDENT,
    EntityPrimitive.CASE: AnalyticalEntity.CASE,
    EntityPrimitive.AGENT: AnalyticalEntity.AGENT,
    EntityPrimitive.DETECTION_RULE: AnalyticalEntity.DETECTION_RULE,
    EntityPrimitive.MITRE_TECHNIQUE: AnalyticalEntity.MITRE_TECHNIQUE,
    EntityPrimitive.STATUS: AnalyticalEntity.STATUS,
    EntityPrimitive.RISK: AnalyticalEntity.RECORDED_RISK,
    EntityPrimitive.TIME: AnalyticalEntity.TIME,
}

_PRIMITIVE_BY_ANALYTICAL_ENTITY = {
    value: key for key, value in _ENTITY_MAP.items()
}


def _action_for_definition(definition_id: str, operation: AnalyticalOperation) -> ActionPrimitive:
    if definition_id == "mitre_reference_lookup":
        return ActionPrimitive.EXPLAIN
    return {
        AnalyticalOperation.COUNT: ActionPrimitive.COUNT,
        AnalyticalOperation.LIST: ActionPrimitive.RETRIEVE,
        AnalyticalOperation.TOP_K: ActionPrimitive.RANK,
        AnalyticalOperation.DISTRIBUTION: ActionPrimitive.DISTRIBUTE,
        AnalyticalOperation.TREND: ActionPrimitive.TREND,
        AnalyticalOperation.COMPARE_PERIODS: ActionPrimitive.COMPARE,
        AnalyticalOperation.COMPARE_ENTITIES: ActionPrimitive.COMPARE,
        AnalyticalOperation.RELATED_RECORDS: ActionPrimitive.RELATE,
        AnalyticalOperation.SIMILAR_RECORDS: ActionPrimitive.SIMILAR,
    }[operation]


class SemanticAnalyticsRouter:
    """Compositional semantic decomposer over UD roles and atomic concepts."""

    def __init__(
        self,
        *,
        embedding_provider: AnalyticsEmbeddingProvider | None = None,
        descriptors: object | None = None,
        config: AnalyticsRoutingConfig | None = None,
        dependency_parser: DependencyParser | None = None,
        primitive_resolver: SemanticPrimitiveResolver | None = None,
    ) -> None:
        del descriptors
        self._parser = dependency_parser or get_dependency_parser()
        self._primitives = primitive_resolver or SemanticPrimitiveResolver(
            embedding_provider=embedding_provider
        )
        self._config = config or AnalyticsRoutingConfig()

    @property
    def primitives(self) -> SemanticPrimitiveResolver:
        return self._primitives

    def warm(self) -> bool:
        return self._parser.warm() and self._primitives.warm()

    @staticmethod
    def _descendants(
        document: DependencyDocument,
        token_id: int,
        *,
        depth: int = 2,
    ) -> tuple[DependencyToken, ...]:
        selected: list[DependencyToken] = []
        frontier = [token_id]
        for _ in range(depth):
            next_frontier: list[int] = []
            for parent_id in frontier:
                children = document.children(parent_id)
                selected.extend(children)
                next_frontier.extend(item.token_id for item in children)
            frontier = next_frontier
        return tuple(selected)

    def _phrase(self, document: DependencyDocument, token: DependencyToken) -> str:
        modifiers = tuple(
            item
            for item in document.children(token.token_id)
            if item.relation in {"compound", "flat", "fixed"}
            and item.upos in {"NOUN", "PROPN", "ADJ"}
        )
        return " ".join(item.lemma for item in sorted((*modifiers, token), key=lambda x: x.token_id))

    def frame(self, question: str) -> SemanticFrame:
        document = self._parser.parse(question)
        mentions: list[EntityMention] = []
        for token in document.tokens:
            if token.upos not in {"NOUN", "PROPN"}:
                continue
            decision = self._primitives.entity(self._phrase(document, token))
            descendants = self._descendants(document, token.token_id)
            interrogative = any(
                item.feature("PronType") == "Int" for item in descendants
            )
            mentions.append(
                EntityMention(
                    token=token,
                    primitive=decision.primitive,
                    confidence=decision.confidence,
                    margin=decision.margin,
                    interrogative=interrogative,
                )
            )

        evidence_mentions = tuple(
            item
            for item in mentions
            if item.confidence >= 0.79 and item.margin >= 0.002
        )
        mentions = [item for item in evidence_mentions if item.margin >= 0.02]
        primary_sentence = next(
            (
                sentence_id
                for sentence_id in sorted(
                    {
                        item.token.sentence_id
                        for item in mentions
                        if item.primitive
                        not in {EntityPrimitive.TIME, EntityPrimitive.OTHER}
                    }
                )
            ),
            None,
        )
        leading_comparison = next(
            (
                item.sentence_id
                for item in document.tokens
                if item.relation == "root"
                and (
                    decision := self._primitives.action(item.lemma)
                ).primitive
                is ActionPrimitive.COMPARE
                and decision.margin >= 0.01
            ),
            None,
        )
        if leading_comparison is not None and (
            primary_sentence is None or leading_comparison < primary_sentence
        ):
            primary_sentence = leading_comparison
        primary_sentences: set[int] | None = None
        if primary_sentence is not None:
            primary_sentences = {primary_sentence}
            selected_sentence = primary_sentence
            maximum_sentence = max(item.sentence_id for item in document.tokens)
            while selected_sentence < maximum_sentence:
                has_terminal = any(
                    item.sentence_id == selected_sentence
                    and item.upos == "PUNCT"
                    and item.text in {".", "?", "!"}
                    for item in document.tokens
                )
                if has_terminal:
                    break
                selected_sentence += 1
                primary_sentences.add(selected_sentence)
        scoped_mentions = [
            item
            for item in mentions
            if primary_sentences is None
            or item.token.sentence_id in primary_sentences
        ]

        target = next(
            (
                item
                for item in sorted(
                    scoped_mentions,
                    key=lambda value: (
                        not value.interrogative,
                        -value.confidence,
                        value.token.token_id,
                    ),
                )
                if item.interrogative
            ),
            None,
        )
        if target is None:
            target = next(
                (
                    item
                    for item in sorted(
                    scoped_mentions,
                        key=lambda value: (
                            value.token.relation not in {"obj", "nsubj", "nsubj:pass", "root"},
                            -value.confidence,
                            value.token.token_id,
                        ),
                    )
                    if item.primitive is not EntityPrimitive.TIME
                ),
                None,
            )
        numbered_target = next(
            (
                item
                for item in scoped_mentions
                if item.primitive
                in {
                    EntityPrimitive.AGENT,
                    EntityPrimitive.DETECTION_RULE,
                    EntityPrimitive.MITRE_TECHNIQUE,
                }
                and any(
                    child.upos == "NUM"
                    for child in document.children(item.token.token_id)
                )
            ),
            None,
        )
        if numbered_target is not None:
            target = numbered_target

        action_candidates: list[tuple[DependencyToken, PrimitiveDecision]] = []
        for token in document.tokens:
            if primary_sentences is not None and token.sentence_id not in primary_sentences:
                continue
            if token.upos in {"VERB", "ADJ", "ADV", "INTJ", "X"} and token.relation in {
                "root",
                "obj",
                "xcomp",
                "amod",
                "advmod",
                "acl",
                "acl:relcl",
                "discourse",
            }:
                action_candidates.append((token, self._primitives.action(token.lemma)))
                if token.upos == "VERB":
                    particles = tuple(
                        item
                        for item in document.children(token.token_id)
                        if item.relation in {"compound:prt", "fixed"}
                    )
                    if particles:
                        phrase = " ".join(
                            item.lemma
                            for item in sorted(
                                (token, *particles),
                                key=lambda value: value.token_id,
                            )
                        )
                        action_candidates.append(
                            (token, self._primitives.action(phrase))
                        )
                    objects = tuple(
                        item
                        for item in document.children(token.token_id)
                        if item.relation in {"obj", "nsubj", "nsubj:pass", "xcomp"}
                        and item.upos in {"NOUN", "PROPN"}
                    )
                    for selected_object in objects:
                        action_candidates.append(
                            (
                                token,
                                self._primitives.action(
                                    f"{token.lemma} {self._phrase(document, selected_object)}"
                                ),
                            )
                        )
        for token in document.tokens:
            if primary_sentences is not None and token.sentence_id not in primary_sentences:
                continue
            if token.upos in {"ADP", "SCONJ"}:
                decision = self._primitives.action(token.lemma)
                if (
                    decision.primitive is ActionPrimitive.EXCLUDE
                    and decision.margin >= 0.01
                ):
                    action_candidates.append((token, decision))
        for token in document.tokens:
            if primary_sentences is not None and token.sentence_id not in primary_sentences:
                continue
            mention_token_ids = {item.token.token_id for item in scoped_mentions}
            if token.upos in {"NOUN", "PROPN"}:
                decision = self._primitives.action(token.lemma)
                if token.token_id not in mention_token_ids or decision.primitive in {
                    ActionPrimitive.COUNT,
                    ActionPrimitive.DISTRIBUTE,
                    ActionPrimitive.TREND,
                    ActionPrimitive.COMPARE,
                    ActionPrimitive.RELATE,
                    ActionPrimitive.SIMILAR,
                    ActionPrimitive.EXPLAIN,
                }:
                    action_candidates.append((token, decision))
        default_action = self._primitives.action("retrieve")
        action = default_action
        count_candidates = [
            decision
            for token, decision in action_candidates
            if decision.primitive is ActionPrimitive.COUNT
            and decision.margin
            >= (0.005 if token.relation in {"root", "obj", "nsubj"} else 0.025)
        ]
        quantified_candidates: list[PrimitiveDecision] = []
        for token in document.tokens:
            if primary_sentences is not None and token.sentence_id not in primary_sentences:
                continue
            if token.feature("PronType") != "Int":
                continue
            decision = self._primitives.action(token.lemma)
            if decision.primitive is ActionPrimitive.COUNT and decision.margin >= 0.025:
                quantified_candidates.append(decision)
            head = document.token(token.head_id)
            if head is not None and head.upos in {"ADJ", "ADV", "NUM"}:
                head_decision = self._primitives.action(head.lemma)
                if (
                    head_decision.primitive is ActionPrimitive.COUNT
                    and head_decision.margin >= 0.015
                ):
                    quantified_candidates.append(head_decision)
        def supports_action(
            token: DependencyToken,
            decision: PrimitiveDecision,
            preferred: ActionPrimitive,
        ) -> bool:
            if decision.primitive is not preferred:
                return False
            if preferred is ActionPrimitive.RANK:
                temporal_role = self._primitives.temporal_relation(token.lemma)
                if (
                    token.upos == "ADV"
                    and temporal_role.primitive
                    is TemporalRelationPrimitive.CURRENT_PERIOD
                    and temporal_role.confidence >= 0.835
                    and temporal_role.margin >= 0.005
                ):
                    return False
                domain_token_ids = {
                    item.token.token_id
                    for item in scoped_mentions
                    if item.primitive
                    not in {EntityPrimitive.TIME, EntityPrimitive.OTHER}
                }
                head = document.token(token.head_id)
                head_has_domain_argument = bool(
                    head is not None
                    and any(
                        child.token_id in domain_token_ids
                        for child in document.children(head.token_id)
                    )
                )
                rank_role = (
                    token.relation in {"root", "compound"}
                    or (
                        token.relation == "advmod"
                        and (
                            token.head_id in domain_token_ids
                            or head_has_domain_argument
                        )
                    )
                    or (
                        token.feature("Degree") == "Sup"
                        and (
                            token.head_id in domain_token_ids
                            or token.relation in {"amod", "obj"}
                        )
                    )
                )
                return (
                    rank_role
                    and decision.confidence >= 0.82
                    and decision.margin >= 0.003
                )
            threshold = 0.015
            if preferred is ActionPrimitive.EXCLUDE:
                if token.relation == "root":
                    threshold = 0.005
                elif token.upos in {"ADP", "SCONJ"}:
                    threshold = 0.01
                else:
                    threshold = 0.025
            return decision.margin >= threshold

        for preferred in (
            ActionPrimitive.SIMILAR,
            ActionPrimitive.RELATE,
            ActionPrimitive.COMPARE,
            ActionPrimitive.EXPLAIN,
            ActionPrimitive.EXCLUDE,
            ActionPrimitive.RANK,
            ActionPrimitive.ADVISE,
            ActionPrimitive.TREND,
            ActionPrimitive.DISTRIBUTE,
        ):
            candidates = [
                decision
                for token, decision in action_candidates
                if supports_action(token, decision, preferred)
            ]
            if candidates:
                action = max(candidates, key=lambda item: item.confidence)
                break
        quantified = bool(quantified_candidates)
        if quantified_candidates and action.primitive is not ActionPrimitive.COMPARE:
            action = max(quantified_candidates, key=lambda item: item.confidence)
        elif count_candidates and action.primitive in {
            ActionPrimitive.RETRIEVE,
            ActionPrimitive.COUNT,
        }:
            action = max(count_candidates, key=lambda item: item.confidence)
        if action.primitive is ActionPrimitive.RETRIEVE:
            unrelated = [
                decision
                for token, decision in action_candidates
                if token.relation == "root"
                and token.upos in {"VERB", "ADJ"}
                and decision.primitive is ActionPrimitive.OTHER
                and decision.confidence >= 0.8
                and decision.margin >= 0.01
            ]
            if unrelated:
                action = max(unrelated, key=lambda item: item.confidence)
        action_confident = (
            quantified
            or bool(count_candidates)
            or action.primitive in {ActionPrimitive.EXCLUDE, ActionPrimitive.RANK}
            or any(
            decision.primitive
            not in {ActionPrimitive.RETRIEVE, ActionPrimitive.OTHER}
            and decision.margin >= 0.015
            for _token, decision in action_candidates
            )
            or any(
            token.relation == "root"
            and decision.primitive is ActionPrimitive.RETRIEVE
            and decision.confidence >= 0.82
            and decision.margin >= 0.003
            for token, decision in action_candidates
            )
        )
        closed_literal_parts = {
            normalized_literal_tokens(value)
            for value in (*_INCIDENT_STATUSES, *_RECORDED_RISK_VALUES)
        }
        explicit_exclusion = any(
            decision.primitive is ActionPrimitive.EXCLUDE
            and decision.confidence >= 0.82
            and decision.margin >= 0.01
            and normalized_literal_tokens(token.text) not in closed_literal_parts
            for token, decision in action_candidates
        )
        return SemanticFrame(
            document=document,
            action=action,
            mentions=tuple(mentions),
            evidence_mentions=evidence_mentions,
            action_evidence=tuple(decision for _token, decision in action_candidates),
            target=target,
            superlative=any(
                item.feature("Degree") == "Sup"
                and (
                    (decision := self._primitives.action(item.lemma)).primitive
                    is ActionPrimitive.RANK
                )
                and decision.margin >= 0.015
                for item in document.tokens
                if primary_sentences is None
                or item.sentence_id in primary_sentences
            ),
            negative=any(
                item.feature("Polarity") == "Neg"
                or item.feature("PronType") == "Neg"
                for item in document.tokens
            )
            or explicit_exclusion,
            quantified=quantified,
            action_confident=action_confident,
        )

    def route(
        self,
        question: str,
        *,
        request_embedding: Sequence[float] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> AnalyticsRouteDecision:
        del request_embedding
        started = clock()
        if not question.strip():
            return AnalyticsRouteDecision(
                accepted=False,
                confidence=0.0,
                routing_status="empty_question",
                routing_ms=max(0.0, (clock() - started) * 1000),
            )
        try:
            frame = self.frame(question)
        except Exception:
            return AnalyticsRouteDecision(
                accepted=False,
                confidence=0.0,
                routing_status="embedding_unavailable",
                routing_ms=max(0.0, (clock() - started) * 1000),
            )
        confidence = min(
            1.0,
            max(
                frame.action.confidence,
                frame.target.confidence if frame.target is not None else 0.0,
            ),
        )
        return AnalyticsRouteDecision(
            accepted=frame.target is not None or bool(frame.mentions),
            confidence=confidence,
            routing_status="ok" if frame.target is not None or frame.mentions else "low_confidence",
            routing_ms=max(0.0, (clock() - started) * 1000),
        )


_DEFAULT_JOINT_PLAN_RANKER = get_joint_semantic_plan_ranker()


class GlobalAnalyticsInterpreter:
    def __init__(
        self,
        *,
        router: SemanticAnalyticsRouter | None = None,
        registry: AnalyticsRegistry | None = None,
        temporal_resolver: ZurichTemporalResolver | None = None,
        plan_ranker: JointSemanticPlanRanker | None = None,
    ) -> None:
        self._router = router or SemanticAnalyticsRouter()
        self._registry = registry or DEFAULT_ANALYTICS_REGISTRY
        self._temporal = temporal_resolver or ZurichTemporalResolver()
        self._plan_ranker = plan_ranker or _DEFAULT_JOINT_PLAN_RANKER

    @staticmethod
    def _row_value(row: Any, column: Any) -> Any:
        try:
            return row[0]
        except (IndexError, KeyError, TypeError):
            return getattr(row, column.key, None)

    @classmethod
    def _sql_identities(
        cls,
        db: Any,
        document: DependencyDocument,
        *,
        column: Any,
        apply_authorized_scope: Callable[[Any], Any] | None = None,
        maximum: int = 500,
    ) -> tuple[str, ...]:
        try:
            query = db.query(column)
            if apply_authorized_scope is not None:
                query = apply_authorized_scope(query)
            rows = query.filter(column.isnot(None)).distinct().limit(maximum).all()
        except Exception:
            return ()
        candidates = tuple(
            dict.fromkeys(
                text
                for row in rows
                if (text := str(cls._row_value(row, column) or "").strip())
            )
        )
        return resolve_closed_literals(document, candidates, maximum=10)

    @staticmethod
    def _numeric_tokens(document: DependencyDocument) -> tuple[int, ...]:
        return numeric_literals(document)

    @staticmethod
    def _incident_numeric_reference(frame: SemanticFrame) -> int | None:
        incident_token_ids = {
            mention.token.token_id
            for mention in frame.evidence_mentions
            if mention.primitive is EntityPrimitive.INCIDENT
        }
        temporal_token_ids = {
            mention.token.token_id
            for mention in frame.evidence_mentions
            if mention.primitive is EntityPrimitive.TIME
        }
        for token in reversed(frame.document.tokens):
            if token.upos != "NUM" or not token.text.isdigit():
                continue
            head = frame.document.token(token.head_id)
            if token.head_id in temporal_token_ids:
                continue
            if (
                head is not None
                and frame.document.language in {"en", "it"}
                and ZurichTemporalResolver().canonical_period_term(
                    head.lemma,
                    language=frame.document.language,
                )
                is not None
            ):
                continue
            if (
                token.head_id in incident_token_ids
                or (
                    head is not None
                    and any(
                        child.token_id in incident_token_ids
                        for child in frame.document.children(head.token_id)
                    )
                )
            ):
                value = int(token.text)
                return value if value > 0 else None
            value = int(token.text)
            if value > 0:
                return value
        return None

    @staticmethod
    def _mitre_identifier(document: DependencyDocument) -> str | None:
        selected = resolve_closed_literals(document, MITRE_REFERENCE_CATALOG, maximum=1)
        return selected[0] if selected else None

    def _calendar_period_shift(
        self,
        document: DependencyDocument,
    ) -> int | None:
        for period_token in document.tokens:
            if self._temporal.canonical_period_term(
                period_token.lemma,
                language=document.language,
            ) is None:
                continue
            if any(
                child.upos == "NUM"
                for child in document.children(period_token.token_id)
            ):
                continue
            structural_modifiers = tuple(document.children(period_token.token_id)) + tuple(
                sibling
                for sibling in document.children(period_token.head_id)
                if sibling.token_id > period_token.token_id
            )
            for modifier in structural_modifiers:
                if (
                    modifier.upos != "ADJ"
                    or modifier.relation not in {"amod", "nmod", "obl"}
                ):
                    continue
                modifier_period = self._router.primitives.temporal_relation(
                    f"{modifier.lemma} {period_token.lemma}"
                )
                if (
                    modifier_period.primitive
                    is not TemporalRelationPrimitive.PREVIOUS_PERIOD
                    or modifier_period.confidence < 0.82
                    or modifier_period.margin < 0.01
                ):
                    continue
                boundary = max(
                    (
                        self._router.primitives.temporal_relation(child.lemma)
                        for child in document.children(modifier.token_id)
                        if child.relation in {"case", "mark", "fixed"}
                    ),
                    key=lambda item: (item.margin, item.confidence),
                    default=None,
                )
                if (
                    boundary is not None
                    and boundary.primitive is TemporalRelationPrimitive.END_BOUNDARY
                    and boundary.confidence >= 0.84
                    and boundary.margin >= 0.005
                ):
                    return 2
                return 1
        return None

    def _has_discourse_reference(self, document: DependencyDocument) -> bool:
        if has_discourse_reference(document):
            return True
        for modifier in document.tokens:
            if modifier.upos not in {"ADJ", "DET"} or modifier.relation not in {
                "amod",
                "det",
            }:
                continue
            head = document.token(modifier.head_id)
            if head is None or self._temporal.canonical_period_term(
                head.lemma,
                language=document.language,
            ) is not None:
                continue
            relation = self._router.primitives.temporal_relation(modifier.lemma)
            if (
                relation.primitive is TemporalRelationPrimitive.PREVIOUS_PERIOD
                and relation.confidence >= 0.82
                and relation.margin >= 0.008
            ):
                return True
        return False

    @staticmethod
    def _previous_state(
        conversation: ValidatedConversationState | None,
    ) -> GlobalConversationQueryState | None:
        return conversation.global_query if conversation is not None else None

    def _joint_evidence(
        self,
        frame: SemanticFrame,
        *,
        db: Any,
        conversation: ValidatedConversationState | None,
        apply_authorized_incident_scope: Callable[[Any], Any] | None,
        now: datetime | None,
    ) -> JointSemanticEvidence:
        action_scores: dict[ActionPrimitive, float] = {}
        for decision in (frame.action, *frame.action_evidence):
            evidence_score = min(
                1.0,
                decision.confidence * (0.55 + min(0.45, decision.margin * 12)),
            )
            action_scores[decision.primitive] = max(
                action_scores.get(decision.primitive, 0.0),
                evidence_score,
            )
        negated_action_scores: dict[ActionPrimitive, float] = {}
        for marker in frame.document.tokens:
            if marker.upos not in {"ADP", "SCONJ"}:
                continue
            exclusion = self._router.primitives.action(marker.lemma)
            if (
                exclusion.primitive is not ActionPrimitive.EXCLUDE
                or exclusion.margin < 0.01
            ):
                continue
            scope_root = frame.document.token(marker.head_id)
            if scope_root is None:
                continue
            for scoped in (
                scope_root,
                *self._router._descendants(
                    frame.document,
                    scope_root.token_id,
                    depth=3,
                ),
            ):
                if scoped.upos not in {"VERB", "ADJ", "NOUN", "PROPN"}:
                    continue
                decision = self._router.primitives.action(scoped.lemma)
                if decision.margin < 0.01:
                    continue
                negated_action_scores[decision.primitive] = max(
                    negated_action_scores.get(decision.primitive, 0.0),
                    decision.confidence,
                )

        entity_scores: dict[EntityPrimitive, float] = {}
        for mention in frame.evidence_mentions:
            evidence_score = min(
                1.0,
                mention.confidence * min(1.0, mention.margin * 30),
            )
            entity_scores[mention.primitive] = max(
                entity_scores.get(mention.primitive, 0.0),
                evidence_score,
            )
        joint_entity_scores, target_entity_scores = (
            self._plan_ranker.semantic_entity_scores(
                tuple(
                    (
                        token.lemma,
                        token.relation
                        in {"root", "obj", "nsubj", "nsubj:pass"},
                    )
                    for token in frame.document.tokens
                    if token.upos in {"NOUN", "PROPN"}
                )
            )
        )
        for primitive, score in joint_entity_scores.items():
            entity_scores[primitive] = max(
                entity_scores.get(primitive, 0.0),
                score,
            )

        agents = self._sql_identities(
            db,
            frame.document,
            column=Incident.agent,
            apply_authorized_scope=apply_authorized_incident_scope,
        )
        rules = self._sql_identities(
            db,
            frame.document,
            column=Incident.rule,
            apply_authorized_scope=apply_authorized_incident_scope,
        )
        temporal_present = any(
            mention.primitive is EntityPrimitive.TIME
            for mention in frame.evidence_mentions
        ) or any(
            self._temporal.is_temporal_term(
                token.text,
                language=frame.document.language,
                now=now,
            )
            for token in frame.document.tokens
            if token.upos in {"ADV", "NOUN", "NUM", "PROPN"}
        )
        temporal_comparison = (
            action_scores.get(ActionPrimitive.COMPARE, 0.0) >= 0.4
            and temporal_present
        )
        return JointSemanticEvidence(
            primary_action=frame.action.primitive,
            primary_action_reliable=(
                frame.quantified
                or (
                    frame.action.margin >= 0.015
                    and frame.action.primitive not in negated_action_scores
                )
            ),
            action_scores=action_scores,
            entity_scores=entity_scores,
            target_entity_scores=target_entity_scores,
            negated_action_scores=negated_action_scores,
            authoritative_agent_count=len(agents),
            authoritative_rule_count=len(rules),
            numeric_reference=self._incident_numeric_reference(frame) is not None,
            mitre_reference=self._mitre_identifier(frame.document) is not None,
            temporal_present=temporal_present,
            temporal_comparison=temporal_comparison,
            demonstrative_reference=self._has_discourse_reference(frame.document),
            previous=self._previous_state(conversation),
        )

    @staticmethod
    def _frame_for_definition(
        frame: SemanticFrame,
        definition: AnalyticsRegistryDefinition,
        *,
        confidence: float,
    ) -> SemanticFrame:
        selected_action = _action_for_definition(
            definition.definition_id,
            definition.operation,
        )
        if (
            definition.definition_id == "incident_list"
            and frame.action.primitive is ActionPrimitive.EXPLAIN
            and frame.action_confident
        ):
            selected_action = ActionPrimitive.EXPLAIN
        action = PrimitiveDecision(
            primitive=selected_action,
            confidence=max(frame.action.confidence, confidence),
            margin=max(frame.action.margin, 0.02),
        )
        target_primitive = _PRIMITIVE_BY_ANALYTICAL_ENTITY.get(definition.entity)
        if target_primitive is None:
            target_primitive = EntityPrimitive.INCIDENT
        target = max(
            (
                mention
                for mention in frame.evidence_mentions
                if mention.primitive is target_primitive
            ),
            key=lambda mention: (mention.confidence, mention.margin),
            default=None,
        )
        if target is None:
            token = next(
                (
                    item
                    for item in frame.document.tokens
                    if item.relation == "root"
                ),
                frame.document.tokens[0],
            )
            target = EntityMention(
                token=token,
                primitive=target_primitive,
                confidence=confidence,
                margin=0.02,
                interrogative=False,
            )
        mentions = frame.mentions
        if not any(item.primitive is target_primitive for item in mentions):
            mentions = (*mentions, target)
        return replace(
            frame,
            action=action,
            mentions=mentions,
            target=target,
            action_confident=True,
        )

    def _semantic_filters(
        self,
        frame: SemanticFrame,
        *,
        source: AnalyticalEntity,
        db: Any,
        question: str,
        apply_authorized_incident_scope: Callable[[Any], Any] | None,
    ) -> tuple[list[AnalyticalFilterDescriptor], list[AnalyticalFilterDescriptor], tuple[str, ...]]:
        del question
        filters: list[AnalyticalFilterDescriptor] = []
        negative_filters: list[AnalyticalFilterDescriptor] = []
        statuses = _CASE_STATUSES if source is AnalyticalEntity.CASE else _INCIDENT_STATUSES
        selected_statuses = list(
            resolve_closed_literals(frame.document, statuses, maximum=len(statuses))
        )
        if not selected_statuses:
            domain_token_ids = {
                item.token.token_id
                for item in frame.mentions
                if item.primitive
                in {EntityPrimitive.INCIDENT, EntityPrimitive.CASE}
            }
            status_spans: list[str] = []
            for token in frame.document.tokens:
                if token.upos not in {"ADJ", "VERB"}:
                    continue
                if token.relation not in {"amod", "acl", "acl:relcl", "xcomp"}:
                    continue
                head = frame.document.token(token.head_id)
                if (
                    token.head_id not in domain_token_ids
                    and (head is None or head.head_id not in domain_token_ids)
                ):
                    continue
                status_spans.append(token.lemma)
            selected_statuses.extend(
                self._plan_ranker.semantic_statuses(
                    status_spans,
                    allowed=statuses,
                )
            )
            for token in frame.document.tokens:
                if selected_statuses:
                    break
                if token.upos not in {"ADJ", "VERB"}:
                    continue
                if token.relation not in {"amod", "acl", "acl:relcl", "xcomp"}:
                    continue
                head = frame.document.token(token.head_id)
                if (
                    token.head_id not in domain_token_ids
                    and (head is None or head.head_id not in domain_token_ids)
                ):
                    continue
                status, confidence, margin = self._router.primitives.closed_value(
                    token.lemma,
                    {value: _STATUS_CONCEPTS[value] for value in statuses},
                )
                minimum_confidence, minimum_margin = (
                    (0.84, 0.01)
                    if source is AnalyticalEntity.CASE
                    else (0.87, 0.035)
                )
                if (
                    confidence >= minimum_confidence
                    and margin >= minimum_margin
                ):
                    selected_statuses.append(status)
        if selected_statuses:
            descriptor = AnalyticalFilterDescriptor(
                field=AnalyticalFilterField.STATUS,
                operator=("NOT_IN" if len(selected_statuses) > 1 else "NOT_EQ")
                if frame.negative
                else ("IN" if len(selected_statuses) > 1 else "EQ"),
                values=list(dict.fromkeys(selected_statuses)),
            )
            (negative_filters if frame.negative else filters).append(descriptor)

        selected_risks = list(
            resolve_closed_literals(
                frame.document,
                _RECORDED_RISK_VALUES,
                maximum=len(_RECORDED_RISK_VALUES),
            )
        )
        if selected_risks:
            field = (
                AnalyticalFilterField.SEVERITY
                if source is AnalyticalEntity.CASE
                else AnalyticalFilterField.RECORDED_RISK
            )
            descriptor = AnalyticalFilterDescriptor(
                field=field,
                operator=("NOT_IN" if len(selected_risks) > 1 else "NOT_EQ")
                if frame.negative
                else ("IN" if len(selected_risks) > 1 else "EQ"),
                values=selected_risks,
            )
            (negative_filters if frame.negative else filters).append(descriptor)

        agents = self._sql_identities(
            db,
            frame.document,
            column=Incident.agent,
            apply_authorized_scope=apply_authorized_incident_scope,
        )
        if agents:
            filters.append(
                AnalyticalFilterDescriptor(
                    field=AnalyticalFilterField.AGENT,
                    operator="IN" if len(agents) > 1 else "EQ",
                    values=list(agents),
                )
            )
        rules = self._sql_identities(
            db,
            frame.document,
            column=Incident.rule,
            apply_authorized_scope=apply_authorized_incident_scope,
        )
        if rules:
            filters.append(
                AnalyticalFilterDescriptor(
                    field=AnalyticalFilterField.DETECTION_RULE,
                    operator="IN" if len(rules) > 1 else "EQ",
                    values=list(rules),
                )
            )
        return filters, negative_filters, agents

    @staticmethod
    def _dimension(entity: AnalyticalEntity) -> AnalyticalDimension | None:
        return {
            AnalyticalEntity.AGENT: AnalyticalDimension.AGENT,
            AnalyticalEntity.DETECTION_RULE: AnalyticalDimension.DETECTION_RULE,
            AnalyticalEntity.MITRE_TECHNIQUE: AnalyticalDimension.MITRE_TECHNIQUE,
            AnalyticalEntity.STATUS: AnalyticalDimension.STATUS,
            AnalyticalEntity.RECORDED_RISK: AnalyticalDimension.RECORDED_RISK,
            AnalyticalEntity.TIME: AnalyticalDimension.DAY,
        }.get(entity)

    def _compose_ast(
        self,
        question: str,
        *,
        frame: SemanticFrame,
        db: Any,
        conversation: ValidatedConversationState | None,
        apply_authorized_incident_scope: Callable[[Any], Any] | None,
        now: datetime | None,
    ) -> SemanticQueryAST:
        previous = self._previous_state(conversation)
        action = frame.action.primitive
        if action is ActionPrimitive.OTHER:
            raise ValueError("unsupported semantic action")
        target = _ENTITY_MAP.get(frame.target.primitive) if frame.target is not None else None
        if action is ActionPrimitive.DISTRIBUTE:
            dimensional_mentions = [
                item
                for item in frame.mentions
                if item.primitive
                in {
                    EntityPrimitive.STATUS,
                    EntityPrimitive.RISK,
                    EntityPrimitive.MITRE_TECHNIQUE,
                    EntityPrimitive.DETECTION_RULE,
                    EntityPrimitive.AGENT,
                }
            ]
            if dimensional_mentions:
                target = _ENTITY_MAP[
                    max(dimensional_mentions, key=lambda item: item.confidence).primitive
                ]
        if target in {AnalyticalEntity.STATUS, AnalyticalEntity.RECORDED_RISK} and frame.action.primitive not in {
            ActionPrimitive.DISTRIBUTE,
            ActionPrimitive.RANK,
        }:
            target = None
        if target is AnalyticalEntity.TIME and frame.action.primitive is not ActionPrimitive.TREND:
            target = None
        if target is None and previous is not None:
            target = previous.entity
        target = target or AnalyticalEntity.INCIDENT
        source = (
            AnalyticalEntity.CASE
            if target is AnalyticalEntity.CASE
            or any(item.primitive is EntityPrimitive.CASE for item in frame.mentions)
            else AnalyticalEntity.INCIDENT
        )
        filters, negative_filters, agents = self._semantic_filters(
            frame,
            source=source,
            db=db,
            question=question,
            apply_authorized_incident_scope=apply_authorized_incident_scope,
        )

        demonstrative = self._has_discourse_reference(frame.document)
        filter_only_followup = previous is not None and (
            frame.target is None
            or all(item.primitive is EntityPrimitive.TIME for item in frame.mentions)
            or demonstrative
            or (
                action is ActionPrimitive.RETRIEVE
                and bool(filters or negative_filters)
                and source is AnalyticalEntity.INCIDENT
            )
        )
        if filter_only_followup:
            prior_fields = {item.field for item in [*filters, *negative_filters]}
            filters = [
                item for item in previous.filters if item.field not in prior_fields
            ] + filters

        inherited_dimension_filters: list[AnalyticalFilterDescriptor] = []
        if previous is not None and filter_only_followup:
            dimension_fields = {
                AnalyticalDimension.AGENT: AnalyticalFilterField.AGENT,
                AnalyticalDimension.DETECTION_RULE: AnalyticalFilterField.DETECTION_RULE,
                AnalyticalDimension.STATUS: AnalyticalFilterField.STATUS,
                AnalyticalDimension.RECORDED_RISK: AnalyticalFilterField.RECORDED_RISK,
            }
            for dimension in previous.dimensions:
                field = dimension_fields.get(dimension)
                if field is None or any(item.field is field for item in filters):
                    continue
                values = list(
                    dict.fromkeys(
                        item.value
                        for item in previous.result_dimension_values
                        if item.dimension is dimension
                    )
                )
                if values:
                    inherited_dimension_filters.append(
                        AnalyticalFilterDescriptor(
                            field=field,
                            operator="IN" if len(values) > 1 else "EQ",
                            values=values,
                        )
                    )
            filters.extend(inherited_dimension_filters)

        mitre_identifier = self._mitre_identifier(frame.document)
        operation = AnalyticalOperation.LIST
        aggregation = SemanticAggregation.NONE
        distinct = False
        group_by: list[AnalyticalDimension] = []
        ordering = SemanticOrdering.TIME_DESC
        detail_level = SemanticDetailLevel.RECORDS
        sla_requested = any(
            item.primitive is EntityPrimitive.SLA and item.confidence >= 0.8
            for item in frame.mentions
        )
        if action is ActionPrimitive.COUNT:
            operation = AnalyticalOperation.COUNT
            distinct = target is AnalyticalEntity.AGENT
            aggregation = (
                SemanticAggregation.COUNT_DISTINCT
                if distinct
                else SemanticAggregation.COUNT
            )
            ordering = SemanticOrdering.NONE
            detail_level = SemanticDetailLevel.SUMMARY
        elif action is ActionPrimitive.SIMILAR:
            operation = AnalyticalOperation.SIMILAR_RECORDS
            detail_level = SemanticDetailLevel.RECORDS
        elif action is ActionPrimitive.RELATE:
            operation = AnalyticalOperation.RELATED_RECORDS
            target = AnalyticalEntity.RECORDED_CORRELATION
            detail_level = SemanticDetailLevel.RECORDS
        elif action is ActionPrimitive.COMPARE:
            operation = (
                AnalyticalOperation.COMPARE_ENTITIES
                if len(agents) >= 2
                else AnalyticalOperation.COMPARE_PERIODS
            )
            aggregation = (
                SemanticAggregation.ENTITY_COMPARE
                if len(agents) >= 2
                else SemanticAggregation.PERIOD_COMPARE
            )
            target = AnalyticalEntity.AGENT if len(agents) >= 2 else AnalyticalEntity.INCIDENT
            if target is AnalyticalEntity.AGENT:
                group_by = [AnalyticalDimension.AGENT]
            ordering = SemanticOrdering.VALUE_DESC
            detail_level = SemanticDetailLevel.SUMMARY
        elif action is ActionPrimitive.TREND:
            operation = AnalyticalOperation.TREND
            target = AnalyticalEntity.TIME
            aggregation = SemanticAggregation.TREND
            group_by = [AnalyticalDimension.DAY]
            ordering = SemanticOrdering.TIME_ASC
        elif action is ActionPrimitive.DISTRIBUTE:
            operation = AnalyticalOperation.DISTRIBUTION
            aggregation = SemanticAggregation.DISTRIBUTION
        elif action is ActionPrimitive.EXPLAIN:
            operation = AnalyticalOperation.LIST
            target = (
                AnalyticalEntity.MITRE_TECHNIQUE
                if mitre_identifier is not None
                else AnalyticalEntity.INCIDENT
            )
            detail_level = SemanticDetailLevel.EXPLANATION
            if mitre_identifier is not None:
                filters = [
                    AnalyticalFilterDescriptor(
                        field=AnalyticalFilterField.MITRE_TECHNIQUE,
                        operator="EQ",
                        values=[mitre_identifier],
                    )
                ]
                negative_filters = []
        elif action is ActionPrimitive.ADVISE:
            operation = AnalyticalOperation.LIST
            target = AnalyticalEntity.INCIDENT
            detail_level = SemanticDetailLevel.GUIDANCE
        if source is AnalyticalEntity.CASE and sla_requested:
            operation = AnalyticalOperation.LIST
            aggregation = SemanticAggregation.NONE
            target = AnalyticalEntity.CASE
            detail_level = SemanticDetailLevel.RECORDS
            filters.append(
                AnalyticalFilterDescriptor(
                    field=AnalyticalFilterField.SLA_STATE,
                    operator="EQ",
                    values=["BREACHED"],
                )
            )

        inherit_previous_composition = bool(
            previous is not None
            and filter_only_followup
            and action in {ActionPrimitive.RETRIEVE, ActionPrimitive.EXCLUDE}
            and previous.operation
            in {
                AnalyticalOperation.LIST,
                AnalyticalOperation.TOP_K,
                AnalyticalOperation.DISTRIBUTION,
                AnalyticalOperation.TREND,
            }
        )
        if inherit_previous_composition:
            operation = previous.operation
            target = previous.entity
            group_by = list(previous.dimensions)
            distinct = previous.distinct
            aggregation = {
                AnalyticalOperation.TOP_K: SemanticAggregation.FREQUENCY,
                AnalyticalOperation.DISTRIBUTION: SemanticAggregation.DISTRIBUTION,
                AnalyticalOperation.TREND: SemanticAggregation.TREND,
            }.get(operation, SemanticAggregation.NONE)
            ordering = {
                AnalyticalOperation.TOP_K: SemanticOrdering.VALUE_DESC,
                AnalyticalOperation.DISTRIBUTION: SemanticOrdering.VALUE_DESC,
                AnalyticalOperation.TREND: SemanticOrdering.TIME_ASC,
            }.get(operation, SemanticOrdering.TIME_DESC)
            detail_level = SemanticDetailLevel(previous.detail_level)

        ranked_target = target in {
            AnalyticalEntity.AGENT,
            AnalyticalEntity.DETECTION_RULE,
            AnalyticalEntity.MITRE_TECHNIQUE,
        }
        has_incident_measure = any(
            item.primitive is EntityPrimitive.INCIDENT and item is not frame.target
            for item in frame.mentions
        )
        if operation is AnalyticalOperation.LIST and (
            action is ActionPrimitive.RANK
            or (frame.superlative and ranked_target)
            or (
                ranked_target
                and has_incident_measure
                and frame.target is not None
                and frame.target.interrogative
            )
        ):
            operation = (
                AnalyticalOperation.DISTRIBUTION
                if target is AnalyticalEntity.MITRE_TECHNIQUE
                else AnalyticalOperation.TOP_K
            )
            aggregation = SemanticAggregation.FREQUENCY
            ordering = SemanticOrdering.VALUE_DESC
        dimension = self._dimension(target)
        if dimension is not None and operation in {
            AnalyticalOperation.TOP_K,
            AnalyticalOperation.DISTRIBUTION,
        }:
            group_by = [dimension]

        rank_previous_comparison = bool(
            previous is not None
            and filter_only_followup
            and action is ActionPrimitive.RANK
            and previous.registry_definition_id == "incident_compare_agent_periods"
        )
        if rank_previous_comparison:
            operation = AnalyticalOperation.COMPARE_PERIODS
            aggregation = SemanticAggregation.PERIOD_COMPARE
            target = AnalyticalEntity.AGENT
            group_by = [AnalyticalDimension.AGENT]
            ordering = SemanticOrdering.VALUE_DESC
            detail_level = SemanticDetailLevel.SUMMARY

        grouped_period_comparison = bool(
            operation is AnalyticalOperation.COMPARE_PERIODS
            and previous is not None
            and (
                previous.dimensions == [AnalyticalDimension.AGENT]
                or previous.registry_definition_id == "incident_compare_agent_periods"
            )
            and filter_only_followup
        )
        if grouped_period_comparison:
            target = AnalyticalEntity.AGENT
            group_by = [AnalyticalDimension.AGENT]

        compare_periods = operation is AnalyticalOperation.COMPARE_PERIODS
        temporal_relations: list[PrimitiveDecision] = []
        for item in frame.document.tokens:
            if item.upos not in {"ADP", "SCONJ", "ADV", "ADJ", "DET"}:
                continue
            decision = self._router.primitives.temporal_relation(item.lemma)
            head = frame.document.token(item.head_id)
            head_children = frame.document.children(head.token_id) if head is not None else ()
            head_subtree_ids = (
                {
                    head.token_id,
                    *(
                        child.token_id
                        for child in self._router._descendants(
                            frame.document,
                            head.token_id,
                            depth=2,
                        )
                    ),
                }
                if head is not None
                else set()
            )
            head_has_non_temporal_entity = any(
                mention.token.token_id in head_subtree_ids
                and mention.primitive
                in {
                    EntityPrimitive.INCIDENT,
                    EntityPrimitive.CASE,
                    EntityPrimitive.AGENT,
                    EntityPrimitive.DETECTION_RULE,
                    EntityPrimitive.MITRE_TECHNIQUE,
                    EntityPrimitive.STATUS,
                    EntityPrimitive.RISK,
                    EntityPrimitive.SLA,
                }
                for mention in frame.evidence_mentions
            )
            head_subtree_literal_parts = {
                part
                for token in frame.document.tokens
                if token.token_id in head_subtree_ids
                for part in normalized_literal_tokens(token.text)
            }
            head_has_authoritative_agent = any(
                set(normalized_literal_tokens(agent)).issubset(
                    head_subtree_literal_parts
                )
                for agent in agents
            )
            relation_has_temporal_head = bool(
                head is not None
                and (
                    self._temporal.is_temporal_term(
                        head.text,
                        language=frame.document.language,
                        now=now,
                    )
                    or self._temporal.is_temporal_term(
                        head.lemma,
                        language=frame.document.language,
                        now=now,
                    )
                    or (
                        head.upos == "NUM"
                        and any(not character.isalnum() for character in head.text)
                    )
                    or any(
                        (
                            self._temporal.is_temporal_term(
                                child.text,
                                language=frame.document.language,
                                now=now,
                            )
                            or self._temporal.canonical_period_term(
                                child.lemma,
                                language=frame.document.language,
                            )
                            is not None
                        )
                        for child in (
                            *head_children,
                            *self._router._descendants(
                                frame.document,
                                head.token_id,
                                depth=2,
                            ),
                        )
                    )
                )
            )
            if decision.primitive in {
                TemporalRelationPrimitive.CURRENT_PERIOD,
                TemporalRelationPrimitive.PREVIOUS_PERIOD,
            }:
                if (
                    head is None
                    or self._temporal.canonical_period_term(
                        head.lemma,
                        language=frame.document.language,
                    )
                    is None
                    or any(
                        child.upos == "NUM"
                        for child in frame.document.children(head.token_id)
                    )
                ):
                    continue
            elif (
                item.upos not in {"ADP", "SCONJ", "ADV"}
                or not relation_has_temporal_head
            ):
                continue
            if (
                decision.primitive
                in {
                    TemporalRelationPrimitive.START_BOUNDARY,
                    TemporalRelationPrimitive.END_BOUNDARY,
                    TemporalRelationPrimitive.RANGE_BOUNDARY,
                }
                and item.relation not in {"case", "mark", "fixed"}
            ):
                continue
            if (
                decision.primitive
                in {
                    TemporalRelationPrimitive.START_BOUNDARY,
                    TemporalRelationPrimitive.END_BOUNDARY,
                    TemporalRelationPrimitive.RANGE_BOUNDARY,
                }
                and head is not None
                and (
                    head_has_non_temporal_entity
                    or head_has_authoritative_agent
                    or not (
                        self._temporal.is_temporal_term(
                            head.text,
                            language=frame.document.language,
                            now=now,
                        )
                        or self._temporal.is_temporal_term(
                            head.lemma,
                            language=frame.document.language,
                            now=now,
                        )
                        or (
                            head.upos in {"NOUN", "NUM"}
                            and relation_has_temporal_head
                        )
                    )
                )
            ):
                continue
            temporal_relations.append(decision)
        eligible_temporal_relations = tuple(
            item
            for item in temporal_relations
            if item.margin
            >= (
                0.008
                if item.primitive
                in {
                    TemporalRelationPrimitive.CURRENT_PERIOD,
                    TemporalRelationPrimitive.PREVIOUS_PERIOD,
                }
                else 0.005
            )
            and (
                item.primitive
                in {
                    TemporalRelationPrimitive.CURRENT_PERIOD,
                    TemporalRelationPrimitive.PREVIOUS_PERIOD,
                }
                or item.confidence >= 0.84
            )
            and item.primitive is not TemporalRelationPrimitive.NEUTRAL
        )
        boundary_relations = tuple(
            item
            for item in eligible_temporal_relations
            if item.primitive
            in {
                TemporalRelationPrimitive.START_BOUNDARY,
                TemporalRelationPrimitive.END_BOUNDARY,
                TemporalRelationPrimitive.RANGE_BOUNDARY,
            }
        )
        temporal_relation = max(
            boundary_relations or eligible_temporal_relations,
            key=lambda item: (item.margin, item.confidence),
            default=None,
        )
        temporal = self._temporal.resolve(
            question,
            now=now,
            compare_periods=compare_periods,
            document=frame.document,
            temporal_relation=(
                temporal_relation.primitive.value if temporal_relation else None
            ),
            day_part=(
                day_part.primitive.value
                if (
                    day_part := max(
                        (
                            self._router.primitives.day_part(item.lemma)
                            for item in frame.document.tokens
                            if item.upos == "NOUN"
                            and item.relation
                            in {"obl", "obl:unmarked", "advmod", "root"}
                        ),
                        key=lambda item: (item.margin, item.confidence),
                        default=None,
                    )
                )
                is not None
                and day_part.primitive is not DayPartPrimitive.NONE
                and day_part.confidence >= 0.86
                and day_part.margin >= 0.015
                else None
            ),
            calendar_period_shift=self._calendar_period_shift(frame.document),
        )
        if temporal.routing_status == "ambiguous_time_window":
            raise ValueError("ambiguous_time_window")
        time_window = temporal.current
        comparison_window = temporal.previous
        leading_current_discourse = next(
            (
                token
                for token in frame.document.tokens
                if token.upos == "ADV"
                and token.relation == "advmod"
                and token.token_id < token.head_id
                and (
                    role := self._router.primitives.temporal_relation(token.lemma)
                ).primitive
                is TemporalRelationPrimitive.CURRENT_PERIOD
                and role.confidence >= 0.835
                and role.margin >= 0.005
            ),
            None,
        )
        additional_temporal_scope = any(
            token.token_id != leading_current_discourse.token_id
            and (
                self._temporal.canonical_period_term(
                    token.text,
                    language=frame.document.language,
                )
                is not None
                or self._temporal.is_temporal_term(
                    token.text,
                    language=frame.document.language,
                    now=now,
                )
            )
            for token in frame.document.tokens
        ) if leading_current_discourse is not None else False
        if (
            previous is not None
            and leading_current_discourse is not None
            and not additional_temporal_scope
        ):
            time_window = None
            comparison_window = None
        if rank_previous_comparison:
            time_window = previous.time_window
            comparison_window = previous.comparison_window
        elif (
            grouped_period_comparison
            and previous.time_window is not None
            and temporal.current is not None
        ):
            time_window = previous.time_window
            comparison_window = temporal.current
        if filter_only_followup and time_window is None:
            time_window = previous.time_window
            comparison_window = (
                getattr(previous, "comparison_window", None)
                if operation is AnalyticalOperation.COMPARE_PERIODS
                else None
            )
        if compare_periods and time_window is None and previous is not None:
            time_window = previous.time_window
            if time_window is not None:
                temporal = self._temporal.resolve(
                    question,
                    now=now,
                    compare_periods=True,
                    document=frame.document,
                    temporal_relation=(
                        temporal_relation.primitive.value if temporal_relation else None
                    ),
                )
                comparison_window = temporal.previous

        domain_mention = any(
            item.primitive not in {EntityPrimitive.TIME, EntityPrimitive.OTHER}
            for item in frame.mentions
        )
        noun_request = any(
            item.token.relation
            in {"root", "obj", "nsubj", "nsubj:pass", "compound"}
            for item in frame.mentions
            if item.primitive is not EntityPrimitive.OTHER
        )
        authoritative_identity = bool(agents) or any(
            item.field is AnalyticalFilterField.DETECTION_RULE for item in filters
        )
        contextual_request = previous is not None or time_window is not None
        unresolved_predicate = any(
            item.relation == "root" and item.upos in {"VERB", "ADJ"}
            for item in frame.document.tokens
        ) and not frame.action_confident
        if (
            frame.target is not None
            and frame.target.primitive is EntityPrimitive.OTHER
            and frame.target.token.relation
            in {"root", "obj", "nsubj", "nsubj:pass"}
            and not frame.action_confident
        ):
            raise ValueError("unsupported semantic target")
        if unresolved_predicate and not contextual_request and not sla_requested:
            raise ValueError("unsupported semantic predicate")
        if not (
            mitre_identifier is not None
            or authoritative_identity
            or contextual_request
            or domain_mention
        ):
            raise ValueError("unsupported semantic request")
        if not (
            frame.action_confident
            or noun_request
            or authoritative_identity
            or contextual_request
            or mitre_identifier is not None
        ):
            raise ValueError("unsupported semantic action")

        anchor_reference = self._incident_numeric_reference(frame)
        anchor_id = (
            anchor_reference
            if anchor_reference is not None
            and (
                operation
                in {
                    AnalyticalOperation.RELATED_RECORDS,
                    AnalyticalOperation.SIMILAR_RECORDS,
                }
                or (
                    detail_level is SemanticDetailLevel.EXPLANATION
                    and target is AnalyticalEntity.INCIDENT
                )
                or (
                    detail_level is SemanticDetailLevel.GUIDANCE
                    and target is AnalyticalEntity.INCIDENT
                )
            )
            else None
        )
        if anchor_id is None and operation in {
            AnalyticalOperation.RELATED_RECORDS,
            AnalyticalOperation.SIMILAR_RECORDS,
        } and previous is not None:
            anchor_filter = next(
                (
                    item
                    for item in previous.filters
                    if item.field is AnalyticalFilterField.INCIDENT_ID
                    and item.values[0].isdigit()
                ),
                None,
            )
            if anchor_filter is not None:
                anchor_id = int(anchor_filter.values[0])
        if anchor_id is not None:
            filters.append(
                AnalyticalFilterDescriptor(
                    field=AnalyticalFilterField.INCIDENT_ID,
                    operator="EQ",
                    values=[str(anchor_id)],
                )
            )

        use_previous = bool(
            previous is not None
            and (demonstrative or filter_only_followup)
            and operation in {
                AnalyticalOperation.COUNT,
                AnalyticalOperation.LIST,
            }
            and previous.result_incident_ids is not None
        )
        previous_ref = previous.query_plan_fingerprint if use_previous else None
        previous_empty = False
        if use_previous:
            if previous.result_incident_ids:
                filters.append(
                    AnalyticalFilterDescriptor(
                        field=AnalyticalFilterField.INCIDENT_ID,
                        operator="IN",
                        values=[str(value) for value in previous.result_incident_ids],
                    )
                )
            else:
                previous_empty = True

        requested_limit = next(
            (
                value
                for token in frame.document.tokens
                if token.upos == "NUM" and token.text.isdigit()
                for value in [int(token.text)]
                if 1 <= value <= 50
                and not (
                    time_window is not None
                    and (frame.document.token(token.head_id) or token).relation
                    in {"obl", "nmod", "advmod"}
                )
                and not any(
                    mention.token.token_id == token.head_id
                    and mention.primitive is EntityPrimitive.TIME
                    for mention in frame.mentions
                )
            ),
            None,
        )
        limit = requested_limit or (
            1
            if rank_previous_comparison
            or (grouped_period_comparison and frame.superlative)
            else 5
            if operation in {AnalyticalOperation.TOP_K, AnalyticalOperation.DISTRIBUTION}
            else previous.limit
            if inherit_previous_composition and previous is not None
            else 20
        )
        confidence = min(
            1.0,
            max(
                frame.action.confidence,
                frame.target.confidence if frame.target is not None else 0.8,
            ),
        )
        return SemanticQueryAST(
            language=frame.document.language,
            source=source,
            target=target,
            operation=operation,
            aggregation=aggregation,
            distinct=distinct,
            filters=filters,
            negative_filters=negative_filters,
            group_by=group_by,
            ordering=ordering,
            limit=limit,
            time_window=time_window,
            comparison_window=comparison_window,
            anchor_record_id=anchor_id,
            use_previous_result=use_previous,
            previous_result_ref=previous_ref,
            previous_result_empty=previous_empty,
            detail_level=detail_level,
            confidence=confidence,
        )

    def _definition_for(self, ast: SemanticQueryAST) -> str:
        if ast.operation is AnalyticalOperation.RELATED_RECORDS:
            return "recorded_related_incidents"
        if ast.operation is AnalyticalOperation.SIMILAR_RECORDS:
            return "semantic_similar_incidents"
        if ast.source is AnalyticalEntity.CASE:
            if any(
                item.field is AnalyticalFilterField.SLA_STATE
                for item in [*ast.filters, *ast.negative_filters]
            ):
                return "case_sla_breached_list"
            return "case_count" if ast.operation is AnalyticalOperation.COUNT else "case_list"
        if ast.use_previous_result:
            return (
                "incident_count_previous_result"
                if ast.operation is AnalyticalOperation.COUNT
                else "incident_list"
            )
        if ast.operation is AnalyticalOperation.COUNT:
            return (
                "incident_distinct_agents"
                if ast.target is AnalyticalEntity.AGENT and ast.distinct
                else "incident_count"
            )
        if ast.operation is AnalyticalOperation.LIST:
            if (
                ast.target is AnalyticalEntity.MITRE_TECHNIQUE
                and ast.detail_level is SemanticDetailLevel.EXPLANATION
            ):
                return "mitre_reference_lookup"
            return "incident_list"
        if ast.operation is AnalyticalOperation.TOP_K:
            selected = {
                AnalyticalEntity.AGENT: "incident_top_agents",
                AnalyticalEntity.DETECTION_RULE: "incident_top_detection_rules",
            }.get(ast.target)
            if selected is None:
                raise ValueError("unsupported ranked entity")
            return selected
        if ast.operation is AnalyticalOperation.DISTRIBUTION:
            selected = {
                AnalyticalEntity.MITRE_TECHNIQUE: "incident_mitre_distribution",
                AnalyticalEntity.STATUS: "incident_status_distribution",
                AnalyticalEntity.RECORDED_RISK: "incident_risk_distribution",
            }.get(ast.target)
            if selected is None:
                raise ValueError("unsupported distribution entity")
            return selected
        if ast.operation is AnalyticalOperation.TREND:
            return "incident_trend"
        if ast.operation is AnalyticalOperation.COMPARE_PERIODS:
            return (
                "incident_compare_agent_periods"
                if ast.group_by == [AnalyticalDimension.AGENT]
                else "incident_compare_periods"
            )
        if ast.operation is AnalyticalOperation.COMPARE_ENTITIES:
            return "incident_compare_agents"
        raise ValueError("unsupported semantic composition")

    def _plan_for(self, ast: SemanticQueryAST, definition_id: str) -> AnalyticsQueryPlan:
        definition = self._registry.resolve(definition_id)
        if definition is None:
            raise ValueError("unknown definition")
        filters = [*definition.fixed_filters, *ast.filters, *ast.negative_filters]
        deduplicated = list(
            {
                (item.field, item.operator, tuple(item.values)): item
                for item in filters
            }.values()
        )
        plan = AnalyticsQueryPlan.create(
            definition_id=definition.definition_id,
            operation=definition.operation,
            entity=definition.entity,
            measure=definition.measure,
            filters=deduplicated,
            dimensions=ast.group_by,
            time_window=ast.time_window,
            comparison_window=ast.comparison_window,
            limit=min(ast.limit, definition.maximum_limit),
            anchor_record_id=ast.anchor_record_id,
            previous_result_ref=ast.previous_result_ref,
            previous_result_empty=ast.previous_result_empty,
        )
        self._registry.validate_plan(plan)
        return plan

    def _legacy_interpret(
        self,
        question: str,
        *,
        decision: AnalyticsRouteDecision,
        db: Any,
        conversation: ValidatedConversationState | None,
        apply_authorized_incident_scope: Callable[[Any], Any] | None,
        now: datetime | None,
    ) -> AnalyticsInterpretationResult:
        definition = self._registry.resolve(decision.definition_id or "")
        if definition is None:
            return AnalyticsInterpretationResult(
                decision.model_copy(update={"accepted": False, "routing_status": "unsupported_literal"})
            )
        document = get_dependency_parser().parse(question)
        filters = list(definition.fixed_filters)
        statuses = _CASE_STATUSES if definition.entity is AnalyticalEntity.CASE else _INCIDENT_STATUSES
        selected_statuses = resolve_closed_literals(document, statuses, maximum=1)
        if selected_statuses:
            filters.append(
                AnalyticalFilterDescriptor(
                    field=AnalyticalFilterField.STATUS,
                    operator="EQ",
                    values=[selected_statuses[0]],
                )
            )
        selected_risks = resolve_closed_literals(
            document,
            _RECORDED_RISK_VALUES,
            maximum=1,
        )
        if selected_risks:
            filters.append(
                AnalyticalFilterDescriptor(
                    field=(
                        AnalyticalFilterField.SEVERITY
                        if definition.entity is AnalyticalEntity.CASE
                        else AnalyticalFilterField.RECORDED_RISK
                    ),
                    operator="EQ",
                    values=[selected_risks[0]],
                )
            )
        agents = self._sql_identities(
            db,
            document,
            column=Incident.agent,
            apply_authorized_scope=apply_authorized_incident_scope,
        )
        if agents:
            filters.append(
                AnalyticalFilterDescriptor(
                    field=AnalyticalFilterField.AGENT,
                    operator="EQ",
                    values=[agents[0]],
                )
            )
        numeric = numeric_literals(document)
        anchor_id = numeric[-1] if numeric and definition.operation in {
            AnalyticalOperation.RELATED_RECORDS,
            AnalyticalOperation.SIMILAR_RECORDS,
        } else None
        previous = self._previous_state(conversation)
        previous_ref = None
        previous_empty = False
        if definition.definition_id == "incident_count_previous_result":
            if previous is None:
                return AnalyticsInterpretationResult(
                    decision.model_copy(update={"accepted": False, "routing_status": "missing_typed_context"})
                )
            previous_ref = previous.query_plan_fingerprint
            if previous.result_incident_ids:
                filters.append(
                    AnalyticalFilterDescriptor(
                        field=AnalyticalFilterField.INCIDENT_ID,
                        operator="IN",
                        values=[str(value) for value in previous.result_incident_ids],
                    )
                )
            else:
                previous_empty = True
        temporal = self._temporal.resolve(
            question,
            now=now,
            compare_periods=definition.operation is AnalyticalOperation.COMPARE_PERIODS,
            document=document,
        )
        if temporal.routing_status == "ambiguous_time_window":
            return AnalyticsInterpretationResult(
                decision.model_copy(update={"accepted": False, "routing_status": "ambiguous_time_window"})
            )
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
                limit=5 if definition.operation is AnalyticalOperation.TOP_K else definition.maximum_limit,
                anchor_record_id=anchor_id,
                previous_result_ref=previous_ref,
                previous_result_empty=previous_empty,
            )
            self._registry.validate_plan(plan)
        except ValueError:
            return AnalyticsInterpretationResult(
                decision.model_copy(update={"accepted": False, "routing_status": "unsupported_literal"})
            )
        return AnalyticsInterpretationResult(decision=decision, plan=plan)

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
        if not isinstance(self._router, SemanticAnalyticsRouter):
            decision = self._router.route(
                question,
                request_embedding=request_embedding,
                clock=clock,
            )
            if not decision.accepted or decision.definition_id is None:
                return AnalyticsInterpretationResult(decision)
            return self._legacy_interpret(
                question,
                decision=decision,
                db=db,
                conversation=conversation,
                apply_authorized_incident_scope=apply_authorized_incident_scope,
                now=now,
            )

        started = clock()
        if not question.strip():
            return AnalyticsInterpretationResult(
                AnalyticsRouteDecision(
                    accepted=False,
                    confidence=0.0,
                    routing_status="empty_question",
                    routing_ms=max(0.0, (clock() - started) * 1000),
                )
            )
        try:
            frame = self._router.frame(question)
            joint_question_vector = (
                tuple(float(value) for value in request_embedding)
                if request_embedding is not None and len(request_embedding) == 768
                else self._plan_ranker.encode_question(question)
            )
            source_candidates = self._plan_ranker.rank_source_plans(
                question_vector=joint_question_vector,
            )
            if (
                source_candidates
                and source_candidates[0].candidate_id == "UNSUPPORTED"
                and source_candidates[0].similarity >= 0.8
                and (
                    len(source_candidates) == 1
                    or source_candidates[0].similarity
                    - source_candidates[1].similarity
                    >= 0.5
                )
            ):
                raise ValueError("unsupported semantic request")
            evidence = replace(
                self._joint_evidence(
                    frame,
                    db=db,
                    conversation=conversation,
                    apply_authorized_incident_scope=apply_authorized_incident_scope,
                    now=now,
                ),
                source_plan_scores={
                    item.candidate_id: item.similarity
                    for item in source_candidates
                },
            )
            joint_decision = self._plan_ranker.rank(
                question,
                evidence=evidence,
                definitions=self._registry.definitions,
                question_vector=joint_question_vector,
            )
            if not joint_decision.accepted or joint_decision.definition_id is None:
                raise ValueError("unsupported semantic request")
            selected_definition = self._registry.resolve(
                joint_decision.definition_id
            )
            if selected_definition is None:
                raise ValueError("unsupported semantic request")
            frame = self._frame_for_definition(
                frame,
                selected_definition,
                confidence=joint_decision.confidence,
            )
            ast = self._compose_ast(
                question,
                frame=frame,
                db=db,
                conversation=conversation,
                apply_authorized_incident_scope=apply_authorized_incident_scope,
                now=now,
            )
            definition_id = self._definition_for(ast)
            plan = self._plan_for(ast, definition_id)
        except ValueError as exc:
            status = (
                "ambiguous_time_window"
                if str(exc) == "ambiguous_time_window"
                else "unsupported_literal"
            )
            return AnalyticsInterpretationResult(
                AnalyticsRouteDecision(
                    accepted=False,
                    confidence=0.0,
                    routing_status=status,
                    routing_ms=max(0.0, (clock() - started) * 1000),
                )
            )
        except Exception:
            return AnalyticsInterpretationResult(
                AnalyticsRouteDecision(
                    accepted=False,
                    confidence=0.0,
                    routing_status="embedding_unavailable",
                    routing_ms=max(0.0, (clock() - started) * 1000),
                )
            )
        decision = AnalyticsRouteDecision(
            accepted=True,
            definition_id=definition_id,
            confidence=joint_decision.confidence,
            routing_status="ok",
            scores=[
                AnalyticsRouteScore(
                    definition_id=item.definition_id,
                    similarity=math.tanh(item.score / 4),
                )
                for item in joint_decision.candidates
                if item.definition_id != "__unsupported__"
            ],
            routing_ms=max(0.0, (clock() - started) * 1000),
        )
        return AnalyticsInterpretationResult(decision=decision, plan=plan, semantic_ast=ast)


_DEFAULT_ANALYTICS_ROUTER = SemanticAnalyticsRouter()
_NLU_PREWARM_LOCK = threading.Lock()
_NLU_PREWARM_THREAD: threading.Thread | None = None
_NLU_PREWARM_STATE = "cold"
_NLU_PREWARM_MS: int | None = None


def get_semantic_analytics_router() -> SemanticAnalyticsRouter:
    return _DEFAULT_ANALYTICS_ROUTER


def semantic_nlu_runtime_snapshot() -> dict[str, object]:
    with _NLU_PREWARM_LOCK:
        return {
            "semantic_nlu_state": _NLU_PREWARM_STATE,
            "semantic_nlu_prewarm_ms": _NLU_PREWARM_MS,
            "semantic_nlu_backend": (
                "stanza_ud+multilingual_e5_small+joint_multilingual_mpnet"
            ),
        }


def start_semantic_nlu_prewarm() -> None:
    global _NLU_PREWARM_THREAD, _NLU_PREWARM_STATE, _NLU_PREWARM_MS
    with _NLU_PREWARM_LOCK:
        if _NLU_PREWARM_STATE in {"loading", "ready"}:
            return
        _NLU_PREWARM_STATE = "loading"
        _NLU_PREWARM_MS = None

    def load() -> None:
        global _NLU_PREWARM_STATE, _NLU_PREWARM_MS
        started = time.monotonic()
        ready = (
            _DEFAULT_ANALYTICS_ROUTER.warm()
            and _DEFAULT_JOINT_PLAN_RANKER.warm()
        )
        with _NLU_PREWARM_LOCK:
            _NLU_PREWARM_STATE = "ready" if ready else "unavailable"
            _NLU_PREWARM_MS = max(0, int((time.monotonic() - started) * 1000))

    thread = threading.Thread(
        target=load,
        name="assistant-semantic-nlu-prewarm",
        daemon=True,
    )
    with _NLU_PREWARM_LOCK:
        _NLU_PREWARM_THREAD = thread
    thread.start()
