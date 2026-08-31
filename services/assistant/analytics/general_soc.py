from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Callable, Mapping

from services.assistant.analytics.contracts import (
    AnalyticsExecutionStrategy,
    AnalyticsRegistryDefinition,
)
from services.assistant.analytics.joint_parser import (
    JointSemanticPlanRanker,
    SemanticCandidateScore,
    get_joint_semantic_plan_ranker,
)
from services.assistant.v3.contracts import (
    AnswerIntent,
    IntentScore,
    IntentSelection,
)


class GeneralSocSourcePlan(str, Enum):
    OPERATIONAL_ANALYTICS = "OPERATIONAL_ANALYTICS"
    OPERATIONAL_FACT = "OPERATIONAL_FACT"
    REFERENCE = "REFERENCE"
    PLAYBOOK = "PLAYBOOK"
    INVESTIGATION = "INVESTIGATION"
    REMEDIATION = "REMEDIATION"
    RELATIONSHIP = "RELATIONSHIP"
    SIMILARITY = "SIMILARITY"
    UNSUPPORTED = "UNSUPPORTED"


GENERAL_SOC_ANALYTICS_EXECUTION_STRATEGIES: Mapping[
    GeneralSocSourcePlan,
    frozenset[AnalyticsExecutionStrategy],
] = MappingProxyType(
    {
        GeneralSocSourcePlan.OPERATIONAL_ANALYTICS: frozenset(
            {
                "SQL_AGGREGATE",
                "SQL_RESULT_SET",
                "SQL_THEN_TYPED_DERIVATION",
                "RECORDED_RELATIONSHIP_LOOKUP",
                "SEMANTIC_DISCOVERY_REHYDRATION",
            }
        ),
        GeneralSocSourcePlan.OPERATIONAL_FACT: frozenset({"SQL_RESULT_SET"}),
        GeneralSocSourcePlan.REFERENCE: frozenset({"REFERENCE_LOOKUP"}),
        GeneralSocSourcePlan.PLAYBOOK: frozenset(),
        GeneralSocSourcePlan.INVESTIGATION: frozenset(),
        GeneralSocSourcePlan.REMEDIATION: frozenset(),
        GeneralSocSourcePlan.RELATIONSHIP: frozenset(
            {"RECORDED_RELATIONSHIP_LOOKUP"}
        ),
        GeneralSocSourcePlan.SIMILARITY: frozenset(
            {"SEMANTIC_DISCOVERY_REHYDRATION"}
        ),
        GeneralSocSourcePlan.UNSUPPORTED: frozenset(),
    }
)


def source_plan_uses_analytics_builder(source_plan: GeneralSocSourcePlan) -> bool:
    return bool(GENERAL_SOC_ANALYTICS_EXECUTION_STRATEGIES[source_plan])


def source_plan_allows_analytics_definition(
    source_plan: GeneralSocSourcePlan,
    definition: AnalyticsRegistryDefinition,
) -> bool:
    return (
        definition.execution_strategy
        in GENERAL_SOC_ANALYTICS_EXECUTION_STRATEGIES[source_plan]
    )


@dataclass(frozen=True)
class GeneralSocPlanDescriptor:
    source_plan: GeneralSocSourcePlan
    intent: AnswerIntent
    include_advisory: bool
    semantic_description: str


@dataclass(frozen=True)
class GeneralSocPlanDecision:
    accepted: bool
    source_plan: GeneralSocSourcePlan
    intent_selection: IntentSelection
    include_advisory: bool
    confidence: float
    margin: float
    candidates: tuple[SemanticCandidateScore, ...]
    query_embedding: tuple[float, ...] = ()


GENERAL_SOC_PLAN_REGISTRY = (
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.OPERATIONAL_ANALYTICS,
        intent=AnswerIntent.FACT_LOOKUP,
        include_advisory=False,
        semantic_description=(
            "Compute an authorized aggregate, list, ranking, distribution, trend, "
            "comparison, or filtered operational result from platform records."
        ),
    ),
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.OPERATIONAL_FACT,
        intent=AnswerIntent.FACT_LOOKUP,
        include_advisory=False,
        semantic_description=(
            "Retrieve an exact recorded cybersecurity entity, identifier, attribute, "
            "state, or operational fact from the platform."
        ),
    ),
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.REFERENCE,
        intent=AnswerIntent.EXPLAIN,
        include_advisory=True,
        semantic_description=(
            "Explain a cybersecurity concept, MITRE ATT&CK technique, detection "
            "concept, or bounded security reference definition."
        ),
    ),
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.PLAYBOOK,
        intent=AnswerIntent.NEXT_ACTION,
        include_advisory=True,
        semantic_description=(
            "Provide security playbook procedures, validation checks, and analyst "
            "steps for an observed detection or behavior."
        ),
    ),
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.INVESTIGATION,
        intent=AnswerIntent.INVESTIGATE,
        include_advisory=True,
        semantic_description=(
            "Guide a SOC analyst through evidence collection and investigation of "
            "suspicious activity without claiming unrecorded facts."
        ),
    ),
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.REMEDIATION,
        intent=AnswerIntent.NEXT_ACTION,
        include_advisory=True,
        semantic_description=(
            "Recommend bounded defensive containment, remediation, validation, or "
            "risk reduction actions based on available advisory guidance."
        ),
    ),
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.RELATIONSHIP,
        intent=AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        include_advisory=False,
        semantic_description=(
            "Retrieve or analyze an authoritative recorded relationship between "
            "explicit security records."
        ),
    ),
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.SIMILARITY,
        intent=AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        include_advisory=True,
        semantic_description=(
            "Discover semantically similar security records as supporting candidates, "
            "without treating similarity as operational authority."
        ),
    ),
    GeneralSocPlanDescriptor(
        source_plan=GeneralSocSourcePlan.UNSUPPORTED,
        intent=AnswerIntent.SUMMARY,
        include_advisory=False,
        semantic_description=(
            "A request unrelated to SOC operations, cybersecurity analytics, security "
            "references, investigation guidance, or defensive remediation."
        ),
    ),
)


class GeneralSocSemanticPlanRouter:
    """Selects a typed source plan from whole-query semantic evidence."""

    def __init__(
        self,
        *,
        ranker: JointSemanticPlanRanker | None = None,
        registry: tuple[GeneralSocPlanDescriptor, ...] = GENERAL_SOC_PLAN_REGISTRY,
        minimum_similarity: float = 0.45,
        ambiguity_margin: float = 0.08,
    ) -> None:
        self._ranker = ranker or get_joint_semantic_plan_ranker()
        self._registry = registry
        self._minimum_similarity = minimum_similarity
        self._ambiguity_margin = ambiguity_margin
        self._by_id: Mapping[str, GeneralSocPlanDescriptor] = {
            item.source_plan.value: item for item in registry
        }

    def route(
        self,
        question: str,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> GeneralSocPlanDecision:
        started = clock()
        query_embedding: tuple[float, ...] = ()
        try:
            query_embedding = self._ranker.encode_question(question)
            candidates = self._ranker.rank_source_plans(
                question_vector=query_embedding,
            )
        except Exception:
            candidates = ()
        selected_score = candidates[0].similarity if candidates else 0.0
        selected = self._by_id.get(
            candidates[0].candidate_id if candidates else "",
            self._by_id[GeneralSocSourcePlan.UNSUPPORTED.value],
        )
        execution_groups = {
            GeneralSocSourcePlan.OPERATIONAL_ANALYTICS: "analytics",
            GeneralSocSourcePlan.OPERATIONAL_FACT: "analytics",
            GeneralSocSourcePlan.RELATIONSHIP: "analytics",
            GeneralSocSourcePlan.SIMILARITY: "analytics",
            GeneralSocSourcePlan.REFERENCE: "reference",
            GeneralSocSourcePlan.PLAYBOOK: "advisory",
            GeneralSocSourcePlan.INVESTIGATION: "advisory",
            GeneralSocSourcePlan.REMEDIATION: "advisory",
            GeneralSocSourcePlan.UNSUPPORTED: "unsupported",
        }
        grouped_scores: dict[str, float] = {}
        for candidate in candidates:
            descriptor = self._by_id.get(candidate.candidate_id)
            if descriptor is None:
                continue
            group = execution_groups[descriptor.source_plan]
            grouped_scores[group] = grouped_scores.get(group, 0.0) + candidate.similarity
        selected_group = execution_groups[selected.source_plan]
        selected_group_score = grouped_scores.get(selected_group, 0.0)
        runner_up_score = max(
            (
                score
                for group, score in grouped_scores.items()
                if group != selected_group
            ),
            default=0.0,
        )
        margin = selected_group_score - runner_up_score
        accepted = (
            selected.source_plan is not GeneralSocSourcePlan.UNSUPPORTED
            and selected_group_score >= self._minimum_similarity
            and margin >= self._ambiguity_margin
        )
        routing_status = "ok" if accepted else "low_confidence"
        intent_scores = [
            IntentScore(
                intent=self._by_id[item.candidate_id].intent,
                similarity=max(-1.0, min(1.0, item.similarity)),
            )
            for item in candidates
            if item.candidate_id in self._by_id
        ]
        deduplicated_scores = list(
            {
                item.intent: item
                for item in sorted(
                    intent_scores,
                    key=lambda item: (item.similarity, item.intent.value),
                )
            }.values()
        )
        deduplicated_scores.sort(
            key=lambda item: (-item.similarity, item.intent.value)
        )
        intent_selection = IntentSelection(
            primary_intent=(selected.intent if accepted else AnswerIntent.SUMMARY),
            scores=deduplicated_scores[:10],
            confidence=max(-1.0, min(1.0, selected_score)),
            routing_status=routing_status,
            degraded=not candidates,
            routing_ms=max(0.0, (clock() - started) * 1000),
        )
        return GeneralSocPlanDecision(
            accepted=accepted,
            source_plan=selected.source_plan,
            intent_selection=intent_selection,
            include_advisory=accepted and selected.include_advisory,
            confidence=selected_score,
            margin=margin,
            candidates=candidates,
            query_embedding=query_embedding,
        )


_DEFAULT_GENERAL_SOC_ROUTER = GeneralSocSemanticPlanRouter()


def get_general_soc_semantic_plan_router() -> GeneralSocSemanticPlanRouter:
    return _DEFAULT_GENERAL_SOC_ROUTER
