from __future__ import annotations

import json
import math
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

import numpy as np
from safetensors import safe_open
from sentence_transformers import SentenceTransformer

from services.assistant.analytics.contracts import AnalyticsRegistryDefinition
from services.assistant.analytics.semantic_primitives import (
    ActionPrimitive,
    EntityPrimitive,
)
from services.assistant.v3.contracts import (
    AnalyticalEntity,
    AnalyticalOperation,
    GlobalConversationQueryState,
)


DEFAULT_MODEL_PATH = (
    "/opt/ai-soc/models/semantic-nlu/paraphrase-multilingual-mpnet-base-v2"
)
DEFAULT_HEAD_PATH = Path(__file__).with_name("models") / "joint_plan_ranker.safetensors"


@dataclass(frozen=True)
class JointSemanticEvidence:
    primary_action: ActionPrimitive
    primary_action_reliable: bool
    action_scores: Mapping[ActionPrimitive, float]
    entity_scores: Mapping[EntityPrimitive, float]
    target_entity_scores: Mapping[EntityPrimitive, float]
    negated_action_scores: Mapping[ActionPrimitive, float]
    authoritative_agent_count: int = 0
    authoritative_rule_count: int = 0
    numeric_reference: bool = False
    mitre_reference: bool = False
    temporal_present: bool = False
    temporal_comparison: bool = False
    demonstrative_reference: bool = False
    previous: GlobalConversationQueryState | None = None
    source_plan_scores: Mapping[str, float] | None = None


@dataclass(frozen=True)
class JointPlanCandidate:
    definition_id: str
    score: float
    learned_score: float
    structural_score: float


@dataclass(frozen=True)
class JointPlanDecision:
    accepted: bool
    definition_id: str | None
    confidence: float
    margin: float
    candidates: tuple[JointPlanCandidate, ...]


@dataclass(frozen=True)
class SemanticCandidateScore:
    candidate_id: str
    similarity: float


_ACTION_BY_OPERATION = {
    AnalyticalOperation.COUNT: ActionPrimitive.COUNT,
    AnalyticalOperation.LIST: ActionPrimitive.RETRIEVE,
    AnalyticalOperation.TOP_K: ActionPrimitive.RANK,
    AnalyticalOperation.DISTRIBUTION: ActionPrimitive.DISTRIBUTE,
    AnalyticalOperation.TREND: ActionPrimitive.TREND,
    AnalyticalOperation.COMPARE_PERIODS: ActionPrimitive.COMPARE,
    AnalyticalOperation.COMPARE_ENTITIES: ActionPrimitive.COMPARE,
    AnalyticalOperation.RELATED_RECORDS: ActionPrimitive.RELATE,
    AnalyticalOperation.SIMILAR_RECORDS: ActionPrimitive.SIMILAR,
}

_ENTITY_PRIMITIVE = {
    AnalyticalEntity.INCIDENT: EntityPrimitive.INCIDENT,
    AnalyticalEntity.CASE: EntityPrimitive.CASE,
    AnalyticalEntity.AGENT: EntityPrimitive.AGENT,
    AnalyticalEntity.DETECTION_RULE: EntityPrimitive.DETECTION_RULE,
    AnalyticalEntity.MITRE_TECHNIQUE: EntityPrimitive.MITRE_TECHNIQUE,
    AnalyticalEntity.STATUS: EntityPrimitive.STATUS,
    AnalyticalEntity.RECORDED_RISK: EntityPrimitive.RISK,
    AnalyticalEntity.TIME: EntityPrimitive.TIME,
}

_ENTITY_DESCRIPTIONS = {
    EntityPrimitive.INCIDENT: "security incident alert event detection record",
    EntityPrimitive.CASE: "investigation case ticket investigation file",
    EntityPrimitive.AGENT: "host endpoint machine device node computer reporting agent",
    EntityPrimitive.DETECTION_RULE: "detection rule signature detection control",
    EntityPrimitive.MITRE_TECHNIQUE: "MITRE ATT&CK technique tactic identifier",
    EntityPrimitive.STATUS: "workflow state category or status value",
    EntityPrimitive.RISK: "risk severity priority band",
    EntityPrimitive.TIME: "time date period interval timeline",
    EntityPrimitive.SLA: "SLA service deadline overdue state",
    EntityPrimitive.OTHER: "unrelated object outside SOC security data",
}

_STATUS_DESCRIPTIONS = {
    "FALSE_POSITIVE": "false positive benign dismissed; falso positivo benigno scartato",
    "INVESTIGATING": "under active investigation or analysis; in investigazione o analisi",
    "CONTAINED": "contained isolated under control; contenuto isolato sotto controllo",
    "ESCALATED": "escalated to higher response; inoltrato in escalation",
    "RESOLVED": "resolved completed remediated; risolto completato rimediato",
    "TRIAGED": "triaged assessed and classified; valutato e classificato in triage",
    "CLOSED": "closed permanently completed and inactive; chiuso definitivamente concluso",
    "NEW": "new unprocessed workflow state; nuovo stato non lavorato",
    "OPEN": "open active unresolved workflow state; aperto attivo non risolto",
}


class JointSemanticPlanRanker:
    """Learned whole-query scoring plus closed-schema structural consistency."""

    def __init__(
        self,
        *,
        model_path: str | None = None,
        head_path: str | Path | None = None,
    ) -> None:
        self._model_path = model_path or os.getenv(
            "AI_SOC_SEMANTIC_NLU_JOINT_MODEL",
            DEFAULT_MODEL_PATH,
        )
        self._head_path = Path(
            head_path
            or os.getenv(
                "AI_SOC_SEMANTIC_NLU_JOINT_HEAD",
                str(DEFAULT_HEAD_PATH),
            )
        )
        self._encoder: SentenceTransformer | None = None
        self._weight: np.ndarray | None = None
        self._bias: np.ndarray | None = None
        self._classes: tuple[str, ...] = ()
        self._source_weight: np.ndarray | None = None
        self._source_bias: np.ndarray | None = None
        self._source_classes: tuple[str, ...] = ()
        self._entity_vectors: np.ndarray | None = None
        self._status_vectors: np.ndarray | None = None
        self._load_lock = threading.Lock()
        self._encode_lock = threading.Lock()

    def _load(self) -> None:
        if self._encoder is not None:
            return
        with self._load_lock:
            if self._encoder is not None:
                return
            with safe_open(str(self._head_path), framework="np") as handle:
                metadata = handle.metadata()
                classes = json.loads(metadata.get("classes", "[]"))
                weight = np.asarray(handle.get_tensor("weight"), dtype=np.float32)
                bias = np.asarray(handle.get_tensor("bias"), dtype=np.float32)
                source_classes = json.loads(metadata.get("source_classes", "[]"))
                source_weight = np.asarray(
                    handle.get_tensor("source_weight"),
                    dtype=np.float32,
                )
                source_bias = np.asarray(
                    handle.get_tensor("source_bias"),
                    dtype=np.float32,
                )
            if not classes or weight.shape != (len(classes), 768):
                raise RuntimeError("joint semantic ranker head is invalid")
            if bias.shape != (len(classes),):
                raise RuntimeError("joint semantic ranker bias is invalid")
            if (
                not source_classes
                or source_weight.shape != (len(source_classes), 768)
                or source_bias.shape != (len(source_classes),)
            ):
                raise RuntimeError("joint source-plan ranker head is invalid")
            self._encoder = SentenceTransformer(
                self._model_path,
                local_files_only=True,
                device="cpu",
            )
            self._weight = weight
            self._bias = bias
            self._classes = tuple(str(value) for value in classes)
            self._source_weight = source_weight
            self._source_bias = source_bias
            self._source_classes = tuple(str(value) for value in source_classes)

    def warm(self) -> bool:
        try:
            self._load()
            self._encode("semantic parser prewarm")
        except Exception:
            return False
        return True

    def _encode(self, question: str) -> np.ndarray:
        self._load()
        assert self._encoder is not None
        with self._encode_lock:
            encoded = self._encoder.encode(
                [question],
                normalize_embeddings=True,
                show_progress_bar=False,
            )[0]
        return np.asarray(encoded, dtype=np.float32)

    def encode_question(self, question: str) -> tuple[float, ...]:
        return tuple(float(value) for value in self._encode(question))

    def _encode_many(self, texts: Sequence[str]) -> np.ndarray:
        self._load()
        assert self._encoder is not None
        with self._encode_lock:
            encoded = self._encoder.encode(
                list(texts),
                normalize_embeddings=True,
                show_progress_bar=False,
            )
        return np.asarray(encoded, dtype=np.float32)

    def semantic_entity_scores(
        self,
        spans: Sequence[tuple[str, bool]],
    ) -> tuple[dict[EntityPrimitive, float], dict[EntityPrimitive, float]]:
        if not spans:
            return {}, {}
        if self._entity_vectors is None:
            self._entity_vectors = self._encode_many(
                tuple(_ENTITY_DESCRIPTIONS.values())
            )
        vectors = self._encode_many(tuple(item[0] for item in spans))
        similarities = vectors @ self._entity_vectors.T
        entities = tuple(_ENTITY_DESCRIPTIONS)
        all_scores: dict[EntityPrimitive, float] = {}
        target_scores: dict[EntityPrimitive, float] = {}
        for row, (_text, target_role) in zip(similarities, spans):
            selected_index = int(np.argmax(row))
            selected = entities[selected_index]
            score = max(0.0, min(1.0, float(row[selected_index])))
            all_scores[selected] = max(all_scores.get(selected, 0.0), score)
            if target_role and score >= 0.3:
                target_scores[selected] = max(
                    target_scores.get(selected, 0.0),
                    score,
                )
        return all_scores, target_scores

    def semantic_statuses(
        self,
        spans: Sequence[str],
        *,
        allowed: Sequence[str],
    ) -> tuple[str, ...]:
        if not spans or not allowed:
            return ()
        if self._status_vectors is None:
            self._status_vectors = self._encode_many(
                tuple(_STATUS_DESCRIPTIONS.values())
            )
        status_names = tuple(_STATUS_DESCRIPTIONS)
        allowed_set = set(allowed)
        allowed_indexes = tuple(
            index
            for index, name in enumerate(status_names)
            if name in allowed_set
        )
        vectors = self._encode_many(tuple(spans))
        similarities = vectors @ self._status_vectors.T
        selected: list[str] = []
        for row in similarities:
            ranked = sorted(
                allowed_indexes,
                key=lambda index: (-float(row[index]), status_names[index]),
            )
            if not ranked:
                continue
            best = ranked[0]
            runner_up = ranked[1] if len(ranked) > 1 else best
            score = float(row[best])
            margin = score - float(row[runner_up])
            if score >= 0.5 and margin >= 0.035:
                selected.append(status_names[best])
        return tuple(dict.fromkeys(selected))

    def score_semantic_candidates(
        self,
        question: str,
        candidates: Mapping[str, str],
    ) -> tuple[SemanticCandidateScore, ...]:
        """Rank a closed candidate registry without emitting text or executable data."""
        if not candidates:
            return ()
        candidate_ids = tuple(candidates)
        vectors = self._encode_many(
            (question, *(candidates[candidate_id] for candidate_id in candidate_ids))
        )
        similarities = vectors[1:] @ vectors[0]
        return tuple(
            sorted(
                (
                    SemanticCandidateScore(
                        candidate_id=candidate_id,
                        similarity=float(similarity),
                    )
                    for candidate_id, similarity in zip(
                        candidate_ids,
                        similarities,
                    )
                ),
                key=lambda item: (-item.similarity, item.candidate_id),
            )
        )

    def rank_source_plans(
        self,
        question: str | None = None,
        *,
        question_vector: Sequence[float] | None = None,
    ) -> tuple[SemanticCandidateScore, ...]:
        vector = (
            np.asarray(question_vector, dtype=np.float32)
            if question_vector is not None
            else self._encode(question or "")
        )
        if vector.shape != (768,):
            raise ValueError("joint source-plan vector has invalid dimensions")
        assert self._source_weight is not None and self._source_bias is not None
        probabilities = self._softmax(
            self._source_weight @ vector + self._source_bias
        )
        return tuple(
            sorted(
                (
                    SemanticCandidateScore(
                        candidate_id=candidate_id,
                        similarity=float(probability),
                    )
                    for candidate_id, probability in zip(
                        self._source_classes,
                        probabilities,
                    )
                ),
                key=lambda item: (-item.similarity, item.candidate_id),
            )
        )

    @staticmethod
    def _softmax(values: np.ndarray) -> np.ndarray:
        shifted = values - np.max(values)
        exponent = np.exp(shifted)
        return exponent / np.sum(exponent)

    @staticmethod
    def _structural_score(
        definition: AnalyticsRegistryDefinition,
        evidence: JointSemanticEvidence,
    ) -> float:
        score = 0.0
        expected_action = _ACTION_BY_OPERATION[definition.operation]
        score += 1.05 * evidence.action_scores.get(expected_action, 0.0)
        score -= 2.5 * evidence.negated_action_scores.get(expected_action, 0.0)
        if expected_action is evidence.primary_action and evidence.primary_action_reliable:
            score += 0.55
        elif (
            evidence.primary_action_reliable
            and evidence.primary_action is not ActionPrimitive.OTHER
        ):
            score -= 0.75

        expected_entity = _ENTITY_PRIMITIVE.get(definition.entity)
        if expected_entity is not None:
            score += 0.35 * evidence.entity_scores.get(expected_entity, 0.0)
            score += 7.0 * evidence.target_entity_scores.get(expected_entity, 0.0)

        definition_id = definition.definition_id
        case_evidence = evidence.entity_scores.get(EntityPrimitive.CASE, 0.0)
        if definition_id.startswith("case_"):
            score += 1.2 * case_evidence
        else:
            score -= 0.45 * case_evidence

        if definition_id == "case_sla_breached_list":
            score += 1.25 * evidence.entity_scores.get(EntityPrimitive.SLA, 0.0)
        if definition_id == "incident_distinct_agents":
            score += 0.45 * evidence.entity_scores.get(EntityPrimitive.AGENT, 0.0)
        if definition_id == "incident_top_agents":
            score += 0.65 * evidence.entity_scores.get(EntityPrimitive.AGENT, 0.0)
        if definition_id == "incident_top_detection_rules":
            score += 0.65 * evidence.entity_scores.get(
                EntityPrimitive.DETECTION_RULE,
                0.0,
            )
        if definition_id == "incident_mitre_distribution":
            score += 0.65 * evidence.entity_scores.get(
                EntityPrimitive.MITRE_TECHNIQUE,
                0.0,
            )
        if definition_id == "incident_status_distribution":
            score += 0.7 * evidence.entity_scores.get(EntityPrimitive.STATUS, 0.0)
        if definition_id == "incident_risk_distribution":
            score += 0.7 * evidence.entity_scores.get(EntityPrimitive.RISK, 0.0)
        if definition_id == "incident_trend":
            score += 0.55 * evidence.entity_scores.get(EntityPrimitive.TIME, 0.0)
        if definition_id == "incident_compare_periods":
            score += 0.9 if evidence.temporal_comparison else 0.0
        if definition_id == "incident_compare_agents":
            score += 1.8 if evidence.authoritative_agent_count >= 2 else -0.45
        if definition_id == "mitre_reference_lookup":
            score += 1.7 if evidence.mitre_reference else -0.3
        if definition_id == "recorded_related_incidents":
            relationship_score = evidence.action_scores.get(ActionPrimitive.RELATE, 0.0)
            score += 2.25 * relationship_score
            score += 4.0 * (evidence.source_plan_scores or {}).get(
                "RELATIONSHIP",
                0.0,
            )
            if (
                evidence.primary_action_reliable
                and evidence.primary_action is ActionPrimitive.EXPLAIN
                and relationship_score < 0.4
            ):
                score -= 4.0
            score += 0.45 if evidence.numeric_reference else -0.3
        if definition_id == "semantic_similar_incidents":
            similarity_score = evidence.action_scores.get(ActionPrimitive.SIMILAR, 0.0)
            score += 2.25 * similarity_score
            score += 4.0 * (evidence.source_plan_scores or {}).get(
                "SIMILARITY",
                0.0,
            )
            if (
                evidence.primary_action_reliable
                and evidence.primary_action is ActionPrimitive.EXPLAIN
                and similarity_score < 0.4
            ):
                score -= 4.0
            score += 0.45 if evidence.numeric_reference else -0.3
        if definition_id == "incident_list":
            score -= 0.8 * max(
                evidence.action_scores.get(ActionPrimitive.RELATE, 0.0),
                evidence.action_scores.get(ActionPrimitive.SIMILAR, 0.0),
            )
            if (
                evidence.numeric_reference
                and evidence.primary_action is ActionPrimitive.EXPLAIN
            ):
                score += 2.0
        if definition_id == "incident_count_previous_result":
            score += 1.5 if evidence.demonstrative_reference else -2.0
            score += 0.8 if evidence.previous is not None else -2.0
            score += (
                2.0
                if evidence.primary_action is ActionPrimitive.COUNT
                else -2.0
            )
        if evidence.previous is not None and evidence.demonstrative_reference:
            if definition_id == evidence.previous.registry_definition_id:
                score += 3.0
            if definition_id == "incident_list":
                score += 0.45
        return score

    def rank(
        self,
        question: str,
        *,
        evidence: JointSemanticEvidence,
        definitions: Sequence[AnalyticsRegistryDefinition],
        question_vector: Sequence[float] | None = None,
    ) -> JointPlanDecision:
        vector = (
            np.asarray(question_vector, dtype=np.float32)
            if question_vector is not None
            else self._encode(question)
        )
        if vector.shape != (768,):
            raise ValueError("joint semantic plan vector has invalid dimensions")
        assert self._weight is not None and self._bias is not None
        learned = self._softmax(self._weight @ vector + self._bias)
        learned_by_class = dict(zip(self._classes, learned.tolist()))
        definitions_by_id = {
            definition.definition_id: definition for definition in definitions
        }
        candidates: list[JointPlanCandidate] = []
        for definition in definitions:
            learned_probability = learned_by_class.get(definition.definition_id)
            if learned_probability is None:
                compatible_classes = (
                    candidate.definition_id
                    for candidate in definitions_by_id.values()
                    if candidate.operation is definition.operation
                    and candidate.measure is definition.measure
                    and candidate.definition_id in learned_by_class
                )
                learned_probability = max(
                    (
                        learned_by_class[class_id]
                        for class_id in compatible_classes
                    ),
                    default=0.0,
                )
            learned_score = math.log(
                max(learned_probability, 1e-9)
            )
            structural = self._structural_score(definition, evidence)
            candidates.append(
                JointPlanCandidate(
                    definition_id=definition.definition_id,
                    score=learned_score + (1.65 * structural),
                    learned_score=learned_score,
                    structural_score=structural,
                )
            )

        unsupported_score = math.log(
            max(learned_by_class.get("__unsupported__", 0.0), 1e-9)
        )
        unsupported_evidence = max(
            evidence.action_scores.get(ActionPrimitive.OTHER, 0.0),
            evidence.entity_scores.get(EntityPrimitive.OTHER, 0.0),
        )
        unsupported_structural = (
            2.0
            if evidence.primary_action is ActionPrimitive.OTHER
            or unsupported_evidence >= 0.78
            else -0.8
        )
        candidates.append(
            JointPlanCandidate(
                definition_id="__unsupported__",
                score=unsupported_score + (1.65 * unsupported_structural),
                learned_score=unsupported_score,
                structural_score=unsupported_structural,
            )
        )
        candidates.sort(key=lambda item: (-item.score, item.definition_id))
        selected = candidates[0]
        runner_up = candidates[1]
        margin = selected.score - runner_up.score
        accepted = selected.definition_id != "__unsupported__" and margin >= 0.08
        return JointPlanDecision(
            accepted=accepted,
            definition_id=selected.definition_id if accepted else None,
            confidence=1.0 / (1.0 + math.exp(-margin)),
            margin=margin,
            candidates=tuple(candidates[:5]),
        )


_DEFAULT_JOINT_PLAN_RANKER = JointSemanticPlanRanker()


def get_joint_semantic_plan_ranker() -> JointSemanticPlanRanker:
    return _DEFAULT_JOINT_PLAN_RANKER
