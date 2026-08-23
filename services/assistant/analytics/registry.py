from __future__ import annotations

from dataclasses import dataclass

from services.assistant.analytics.contracts import (
    AnalyticsQueryPlan,
    AnalyticsRegistryDefinition,
)
from services.assistant.v3.contracts import (
    AnalyticalDimension,
    AnalyticalEntity,
    AnalyticalFilterDescriptor,
    AnalyticalFilterField,
    AnalyticalMeasure,
    AnalyticalOperation,
    AnalyticalResultKind,
)


@dataclass(frozen=True)
class AnalyticsSemanticDescriptor:
    definition_id: str
    description: str
    semantic_examples: tuple[str, ...]

    @property
    def prototype_texts(self) -> tuple[str, ...]:
        return (self.description, *self.semantic_examples)


ANALYTICS_REGISTRY = (
    AnalyticsRegistryDefinition(
        definition_id="incident_count",
        operation=AnalyticalOperation.COUNT,
        entity=AnalyticalEntity.INCIDENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.INCIDENT_ID,
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
            AnalyticalFilterField.RECORDED_RISK,
            AnalyticalFilterField.RECORDED_CORRELATION,
        ],
        execution_strategy="SQL_AGGREGATE",
        maximum_limit=1,
        result_kind=AnalyticalResultKind.COUNT,
        result_schema="scalar_count",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_count_previous_result",
        operation=AnalyticalOperation.COUNT,
        entity=AnalyticalEntity.INCIDENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[AnalyticalFilterField.INCIDENT_ID, AnalyticalFilterField.STATUS],
        execution_strategy="SQL_AGGREGATE",
        maximum_limit=1,
        result_kind=AnalyticalResultKind.COUNT,
        result_schema="scalar_count",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_list",
        operation=AnalyticalOperation.LIST,
        entity=AnalyticalEntity.INCIDENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.INCIDENT_ID,
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
            AnalyticalFilterField.RECORDED_RISK,
            AnalyticalFilterField.RECORDED_CORRELATION,
        ],
        execution_strategy="SQL_RESULT_SET",
        ordering="TIME_DESC",
        maximum_limit=20,
        result_kind=AnalyticalResultKind.RESULT_SET,
        result_schema="incident_result_set",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_top_agents",
        operation=AnalyticalOperation.TOP_K,
        entity=AnalyticalEntity.AGENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[AnalyticalFilterField.STATUS],
        grouping_dimensions=[AnalyticalDimension.AGENT],
        execution_strategy="SQL_AGGREGATE",
        ordering="VALUE_DESC",
        maximum_limit=10,
        requires_time_window=True,
        result_kind=AnalyticalResultKind.TOP_K,
        result_schema="ranked_dimension_counts",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_top_detection_rules",
        operation=AnalyticalOperation.TOP_K,
        entity=AnalyticalEntity.DETECTION_RULE,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[AnalyticalFilterField.STATUS, AnalyticalFilterField.AGENT],
        grouping_dimensions=[AnalyticalDimension.DETECTION_RULE],
        execution_strategy="SQL_AGGREGATE",
        ordering="VALUE_DESC",
        maximum_limit=10,
        requires_time_window=True,
        result_kind=AnalyticalResultKind.TOP_K,
        result_schema="ranked_dimension_counts",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_mitre_distribution",
        operation=AnalyticalOperation.DISTRIBUTION,
        entity=AnalyticalEntity.MITRE_TECHNIQUE,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[AnalyticalFilterField.STATUS, AnalyticalFilterField.AGENT],
        grouping_dimensions=[AnalyticalDimension.MITRE_TECHNIQUE],
        execution_strategy="SQL_THEN_TYPED_DERIVATION",
        ordering="VALUE_DESC",
        maximum_limit=10,
        requires_time_window=True,
        result_kind=AnalyticalResultKind.DISTRIBUTION,
        result_schema="ranked_dimension_counts",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_status_distribution",
        operation=AnalyticalOperation.DISTRIBUTION,
        entity=AnalyticalEntity.STATUS,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[AnalyticalFilterField.AGENT],
        grouping_dimensions=[AnalyticalDimension.STATUS],
        execution_strategy="SQL_AGGREGATE",
        ordering="VALUE_DESC",
        maximum_limit=20,
        result_kind=AnalyticalResultKind.DISTRIBUTION,
        result_schema="dimension_counts",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_trend",
        operation=AnalyticalOperation.TREND,
        entity=AnalyticalEntity.TIME,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
        ],
        grouping_dimensions=[AnalyticalDimension.DAY],
        execution_strategy="SQL_THEN_TYPED_DERIVATION",
        ordering="TIME_ASC",
        maximum_limit=31,
        requires_time_window=True,
        result_kind=AnalyticalResultKind.TREND,
        result_schema="daily_counts",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_compare_periods",
        operation=AnalyticalOperation.COMPARE_PERIODS,
        entity=AnalyticalEntity.INCIDENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
        ],
        execution_strategy="SQL_AGGREGATE",
        maximum_limit=2,
        requires_time_window=True,
        result_kind=AnalyticalResultKind.COMPARISON,
        result_schema="period_comparison",
    ),
    AnalyticsRegistryDefinition(
        definition_id="recorded_related_incidents",
        operation=AnalyticalOperation.RELATED_RECORDS,
        entity=AnalyticalEntity.RECORDED_CORRELATION,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[AnalyticalFilterField.INCIDENT_ID],
        execution_strategy="RECORDED_RELATIONSHIP_LOOKUP",
        ordering="TIME_DESC",
        maximum_limit=20,
        result_kind=AnalyticalResultKind.RESULT_SET,
        result_schema="recorded_relationship_result_set",
    ),
    AnalyticsRegistryDefinition(
        definition_id="semantic_similar_incidents",
        operation=AnalyticalOperation.SIMILAR_RECORDS,
        entity=AnalyticalEntity.INCIDENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[AnalyticalFilterField.INCIDENT_ID],
        execution_strategy="SEMANTIC_DISCOVERY_REHYDRATION",
        ordering="VALUE_DESC",
        maximum_limit=12,
        result_kind=AnalyticalResultKind.RESULT_SET,
        result_schema="semantic_candidate_result_set",
    ),
    AnalyticsRegistryDefinition(
        definition_id="case_count",
        operation=AnalyticalOperation.COUNT,
        entity=AnalyticalEntity.CASE,
        measure=AnalyticalMeasure.CASE_COUNT,
        allowed_filters=[
            AnalyticalFilterField.CASE_ID,
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.SEVERITY,
            AnalyticalFilterField.SLA_STATE,
        ],
        execution_strategy="SQL_AGGREGATE",
        maximum_limit=1,
        result_kind=AnalyticalResultKind.COUNT,
        result_schema="scalar_count",
    ),
    AnalyticsRegistryDefinition(
        definition_id="case_sla_breached_list",
        operation=AnalyticalOperation.LIST,
        entity=AnalyticalEntity.CASE,
        measure=AnalyticalMeasure.CASE_COUNT,
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.SEVERITY,
            AnalyticalFilterField.SLA_STATE,
        ],
        fixed_filters=[
            AnalyticalFilterDescriptor(
                field=AnalyticalFilterField.SLA_STATE,
                operator="EQ",
                values=["BREACHED"],
            )
        ],
        execution_strategy="SQL_RESULT_SET",
        ordering="TIME_DESC",
        maximum_limit=20,
        result_kind=AnalyticalResultKind.RESULT_SET,
        result_schema="case_result_set",
    ),
    AnalyticsRegistryDefinition(
        definition_id="case_list",
        operation=AnalyticalOperation.LIST,
        entity=AnalyticalEntity.CASE,
        measure=AnalyticalMeasure.CASE_COUNT,
        allowed_filters=[
            AnalyticalFilterField.CASE_ID,
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.SEVERITY,
            AnalyticalFilterField.SLA_STATE,
        ],
        execution_strategy="SQL_RESULT_SET",
        ordering="TIME_DESC",
        maximum_limit=20,
        result_kind=AnalyticalResultKind.RESULT_SET,
        result_schema="case_result_set",
    ),
)


ANALYTICS_SEMANTIC_REGISTRY = (
    AnalyticsSemanticDescriptor(
        "incident_count",
        "Count security incidents that satisfy explicit filters or a resolved time window.",
        (
            "How many HIGH incidents occurred this week?",
            "Quanti incidenti HIGH abbiamo avuto questa settimana?",
            "How many NEW incidents were recorded in the last 24 hours?",
            "Quanti incidenti NEW ci sono stati nelle ultime 24 ore?",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "incident_count_previous_result",
        "Count a typed subset of incident IDs returned by the immediately preceding global analytics result.",
        (
            "Of the incidents returned before, how many are still NEW?",
            "Di questi, quanti risultano ancora NEW?",
            "Among those results, count the incidents with the selected status.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "incident_list",
        "List authoritative incident records matching an agent, status, rule, identifier, or time window.",
        (
            "Show incidents from darkstar-windows in the last seven days.",
            "Mostrami gli incidenti di darkstar-windows degli ultimi 7 giorni.",
            "Find incidents matching these operational filters.",
            "Elenca gli incidenti con questi filtri operativi.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "incident_top_agents",
        "Rank hosts or monitoring agents by authoritative incident count.",
        (
            "Which hosts generated the most incidents in the last seven days?",
            "Quali host hanno generato piu incidenti negli ultimi 7 giorni?",
            "Rank agents by number of incidents.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "incident_top_detection_rules",
        "Rank detection rules by authoritative incident count.",
        (
            "Which detection rules generated the most incidents in the last thirty days?",
            "Quali regole di detection hanno generato piu incidenti negli ultimi 30 giorni?",
            "Top detection rules by incident volume.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "incident_mitre_distribution",
        "Compute the distribution of recorded MITRE techniques across incidents.",
        (
            "Which MITRE techniques are most frequent in incidents from last month?",
            "Quali tecniche MITRE sono piu frequenti negli incidenti dell'ultimo mese?",
            "Distribution of MITRE techniques in the selected period.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "incident_status_distribution",
        "Compute an incident distribution grouped by recorded status.",
        (
            "How are incidents distributed by status?",
            "Distribuzione degli incidenti per stato.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "incident_trend",
        "Show the incident count trend over a resolved period.",
        (
            "Show the daily incident trend for the last month.",
            "Mostra il trend giornaliero degli incidenti dell'ultimo mese.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "incident_compare_periods",
        "Compare authoritative incident counts between adjacent equal time periods.",
        (
            "Compare the number of incidents in the last seven days with the previous seven days.",
            "Confronta il numero di incidenti degli ultimi 7 giorni con i 7 giorni precedenti.",
            "Compare this period with the previous period.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "recorded_related_incidents",
        "Retrieve incidents explicitly recorded by the platform as correlated to an anchor incident.",
        (
            "Which incidents are recorded as correlated with incident 5333?",
            "Quali incidenti risultano correlati al 5333?",
            "Show platform-recorded incident relationships for this incident.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "semantic_similar_incidents",
        "Discover semantically similar incident candidates and rehydrate them from SQL.",
        (
            "Which incidents are semantically similar to incident 5333?",
            "Quali incidenti sono semanticamente simili al 5333?",
            "Find similarity candidates for this incident without treating them as correlated.",
            "Do the similar results belong to the same attack?",
            "I risultati simili fanno parte dello stesso attacco?",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "case_count",
        "Count authoritative case records matching closed case filters.",
        (
            "How many open cases are there?",
            "Quanti casi aperti ci sono?",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "case_sla_breached_list",
        "List authoritative non-closed cases whose recorded SLA due time has passed.",
        (
            "Which cases have exceeded their SLA?",
            "Quali casi hanno superato lo SLA?",
            "Show overdue open cases.",
        ),
    ),
    AnalyticsSemanticDescriptor(
        "case_list",
        "List authoritative cases matching a recorded status, severity, agent, or identifier.",
        (
            "Show open cases assigned to this agent.",
            "Elenca i casi aperti per questo agente.",
            "List the matching case records.",
        ),
    ),
)


class AnalyticsRegistry:
    def __init__(
        self,
        definitions: tuple[AnalyticsRegistryDefinition, ...] = ANALYTICS_REGISTRY,
    ) -> None:
        self._definitions = {item.definition_id: item for item in definitions}
        if len(self._definitions) != len(definitions):
            raise ValueError("analytics registry definition IDs must be unique")

    @property
    def definitions(self) -> tuple[AnalyticsRegistryDefinition, ...]:
        return tuple(self._definitions.values())

    def resolve(self, definition_id: str) -> AnalyticsRegistryDefinition | None:
        return self._definitions.get(definition_id)

    def validate_plan(self, plan: AnalyticsQueryPlan) -> AnalyticsRegistryDefinition:
        definition = self.resolve(plan.definition_id)
        if definition is None:
            raise ValueError("analytics plan references an unknown registry definition")
        if (
            plan.operation is not definition.operation
            or plan.entity is not definition.entity
            or plan.measure is not definition.measure
        ):
            raise ValueError("analytics plan does not match its registry definition")
        if not {item.field for item in plan.filters}.issubset(definition.allowed_filters):
            raise ValueError("analytics plan contains an unregistered filter")
        plan_filters = {
            (item.field, item.operator, tuple(item.values)) for item in plan.filters
        }
        required_filters = {
            (item.field, item.operator, tuple(item.values))
            for item in definition.fixed_filters
        }
        if not required_filters.issubset(plan_filters):
            raise ValueError("analytics plan omits a registered fixed filter")
        if not set(plan.dimensions).issubset(definition.grouping_dimensions):
            raise ValueError("analytics plan contains an unregistered dimension")
        if plan.limit > definition.maximum_limit:
            raise ValueError("analytics plan exceeds its registered limit")
        if definition.requires_time_window and plan.time_window is None:
            raise ValueError("analytics plan requires an explicit time window")
        if definition.operation is AnalyticalOperation.COMPARE_PERIODS:
            if plan.comparison_window is None:
                raise ValueError("period comparison requires two time windows")
        elif plan.comparison_window is not None:
            raise ValueError("comparison window is not registered for this operation")
        if definition.operation in {
            AnalyticalOperation.RELATED_RECORDS,
            AnalyticalOperation.SIMILAR_RECORDS,
        } and plan.anchor_record_id is None:
            raise ValueError("record relationship operation requires an anchor ID")
        if definition.definition_id == "incident_count_previous_result":
            if plan.previous_result_ref is None:
                raise ValueError("previous-result analytics requires typed prior state")
            has_id_filter = any(
                item.field is AnalyticalFilterField.INCIDENT_ID
                for item in plan.filters
            )
            if plan.previous_result_empty == has_id_filter:
                raise ValueError("previous-result empty-set contract is inconsistent")
        elif plan.previous_result_ref is not None or plan.previous_result_empty:
            raise ValueError("previous-result state is not registered for this operation")
        return definition


DEFAULT_ANALYTICS_REGISTRY = AnalyticsRegistry()
