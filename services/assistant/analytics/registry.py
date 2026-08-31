from __future__ import annotations

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
        definition_id="incident_distinct_agents",
        operation=AnalyticalOperation.COUNT,
        entity=AnalyticalEntity.AGENT,
        measure=AnalyticalMeasure.RECORD_COUNT,
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
            AnalyticalFilterField.RECORDED_RISK,
        ],
        execution_strategy="SQL_AGGREGATE",
        maximum_limit=1,
        result_kind=AnalyticalResultKind.COUNT,
        result_schema="scalar_distinct_count",
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
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
            AnalyticalFilterField.RECORDED_RISK,
        ],
        grouping_dimensions=[AnalyticalDimension.AGENT],
        execution_strategy="SQL_AGGREGATE",
        ordering="VALUE_DESC",
        maximum_limit=10,
        result_kind=AnalyticalResultKind.TOP_K,
        result_schema="ranked_dimension_counts",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_top_detection_rules",
        operation=AnalyticalOperation.TOP_K,
        entity=AnalyticalEntity.DETECTION_RULE,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
            AnalyticalFilterField.RECORDED_RISK,
        ],
        grouping_dimensions=[AnalyticalDimension.DETECTION_RULE],
        execution_strategy="SQL_AGGREGATE",
        ordering="VALUE_DESC",
        maximum_limit=10,
        result_kind=AnalyticalResultKind.TOP_K,
        result_schema="ranked_dimension_counts",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_mitre_distribution",
        operation=AnalyticalOperation.DISTRIBUTION,
        entity=AnalyticalEntity.MITRE_TECHNIQUE,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
            AnalyticalFilterField.RECORDED_RISK,
        ],
        grouping_dimensions=[AnalyticalDimension.MITRE_TECHNIQUE],
        execution_strategy="SQL_THEN_TYPED_DERIVATION",
        ordering="VALUE_DESC",
        maximum_limit=10,
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
        definition_id="incident_risk_distribution",
        operation=AnalyticalOperation.DISTRIBUTION,
        entity=AnalyticalEntity.RECORDED_RISK,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
        ],
        grouping_dimensions=[AnalyticalDimension.RECORDED_RISK],
        execution_strategy="SQL_AGGREGATE",
        ordering="VALUE_DESC",
        maximum_limit=20,
        result_kind=AnalyticalResultKind.DISTRIBUTION,
        result_schema="dimension_counts",
    ),
    AnalyticsRegistryDefinition(
        definition_id="mitre_reference_lookup",
        operation=AnalyticalOperation.LIST,
        entity=AnalyticalEntity.MITRE_TECHNIQUE,
        measure=AnalyticalMeasure.RECORD_COUNT,
        allowed_filters=[AnalyticalFilterField.MITRE_TECHNIQUE],
        execution_strategy="REFERENCE_LOOKUP",
        maximum_limit=1,
        result_kind=AnalyticalResultKind.RESULT_SET,
        result_schema="mitre_reference_result",
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
        definition_id="incident_compare_agent_periods",
        operation=AnalyticalOperation.COMPARE_PERIODS,
        entity=AnalyticalEntity.AGENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.DETECTION_RULE,
            AnalyticalFilterField.RECORDED_RISK,
        ],
        grouping_dimensions=[AnalyticalDimension.AGENT],
        execution_strategy="SQL_AGGREGATE",
        ordering="VALUE_DESC",
        maximum_limit=10,
        requires_time_window=True,
        result_kind=AnalyticalResultKind.COMPARISON,
        result_schema="grouped_period_comparison",
    ),
    AnalyticsRegistryDefinition(
        definition_id="incident_compare_agents",
        operation=AnalyticalOperation.COMPARE_ENTITIES,
        entity=AnalyticalEntity.AGENT,
        measure=AnalyticalMeasure.INCIDENT_COUNT,
        allowed_filters=[
            AnalyticalFilterField.AGENT,
            AnalyticalFilterField.STATUS,
            AnalyticalFilterField.DETECTION_RULE,
            AnalyticalFilterField.RECORDED_RISK,
        ],
        grouping_dimensions=[AnalyticalDimension.AGENT],
        execution_strategy="SQL_AGGREGATE",
        ordering="VALUE_DESC",
        maximum_limit=10,
        result_kind=AnalyticalResultKind.COMPARISON,
        result_schema="entity_comparison",
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
        elif plan.previous_result_ref is not None:
            if definition.definition_id != "incident_list":
                raise ValueError("previous-result state is not registered for this operation")
            has_id_filter = any(
                item.field is AnalyticalFilterField.INCIDENT_ID
                for item in plan.filters
            )
            if plan.previous_result_empty == has_id_filter:
                raise ValueError("previous-result list empty-set contract is inconsistent")
        elif plan.previous_result_empty:
            raise ValueError("previous-result state is not registered for this operation")
        return definition


DEFAULT_ANALYTICS_REGISTRY = AnalyticsRegistry()
