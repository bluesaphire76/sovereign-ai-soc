from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from sqlalchemy import false, func

from models import Incident, IncidentCase
from services.assistant.analytics.contracts import AnalyticsQueryPlan
from services.assistant.analytics.normalization import normalize_mitre_facts
from services.assistant.analytics.registry import (
    DEFAULT_ANALYTICS_REGISTRY,
    AnalyticsRegistry,
    AnalyticsRegistryDefinition,
)
from services.assistant.analytics.temporal import ZURICH
from services.assistant.v3.contracts import (
    AnalyticalDimension,
    AnalyticalDimensionValue,
    AnalyticalEntity,
    AnalyticalFilterField,
    AnalyticalOperation,
    AnalyticalResultAtom,
    AnalyticalResultRow,
    AuthorityClass,
    Provenance,
)
from services.assistant.v3.semantic_index import (
    IncidentSemanticIndex,
    get_incident_semantic_index,
    incident_source_fingerprint,
    semantic_query_text_from_facts,
)
from services.assistant.v3.knowledge import MITRE_REFERENCE_CATALOG


class AnalyticsAccessPolicy(Protocol):
    def apply_incident_scope(
        self,
        query: Any,
        *,
        current_user: Mapping[str, Any] | None,
    ) -> Any: ...

    def apply_case_scope(
        self,
        query: Any,
        *,
        current_user: Mapping[str, Any] | None,
    ) -> Any: ...


@dataclass(frozen=True)
class PlatformAnalyticsAccessPolicy:
    readable_roles: frozenset[str] = frozenset({"ADMIN", "ANALYST"})

    def _allowed(self, current_user: Mapping[str, Any] | None) -> bool:
        if current_user is None:
            return True
        return str(current_user.get("role") or "").strip().upper() in self.readable_roles

    def apply_incident_scope(
        self,
        query: Any,
        *,
        current_user: Mapping[str, Any] | None,
    ) -> Any:
        return query if self._allowed(current_user) else query.filter(false())

    def apply_case_scope(
        self,
        query: Any,
        *,
        current_user: Mapping[str, Any] | None,
    ) -> Any:
        return query if self._allowed(current_user) else query.filter(false())


@dataclass(frozen=True)
class AnalyticsExecutionOutcome:
    result_atom: AnalyticalResultAtom
    anchor_incident: Incident | None = None
    incident_rows: tuple[Incident, ...] = ()
    case_rows: tuple[IncidentCase, ...] = ()
    semantic_scores: tuple[tuple[int, float], ...] = ()
    semantic_index_status: str = "not_requested"
    execution_ms: int = 0


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _mitre_values(value: Any) -> list[str]:
    values: list[str] = []
    for item in normalize_mitre_facts(value):
        selected = item.get("id") or item.get("name")
        text = " ".join(str(selected or "").split())[:240]
        if text and text not in values:
            values.append(text)
    return values[:12]


class AuthoritativeAnalyticsExecutor:
    def __init__(
        self,
        *,
        registry: AnalyticsRegistry | None = None,
        access_policy: AnalyticsAccessPolicy | None = None,
        incident_semantic_index: IncidentSemanticIndex | None = None,
    ) -> None:
        self._registry = registry or DEFAULT_ANALYTICS_REGISTRY
        self._access = access_policy or PlatformAnalyticsAccessPolicy()
        self._semantic_index = incident_semantic_index or get_incident_semantic_index()

    def _incident_query(
        self,
        db: Any,
        *entities: Any,
        current_user: Mapping[str, Any] | None,
    ) -> Any:
        query = db.query(*(entities or (Incident,)))
        return self._access.apply_incident_scope(query, current_user=current_user)

    def _case_query(
        self,
        db: Any,
        *entities: Any,
        current_user: Mapping[str, Any] | None,
    ) -> Any:
        query = db.query(*(entities or (IncidentCase,)))
        return self._access.apply_case_scope(query, current_user=current_user)

    @staticmethod
    def _apply_time(query: Any, plan: AnalyticsQueryPlan, *, column: Any) -> Any:
        if plan.time_window is None:
            return query
        return query.filter(
            column >= plan.time_window.start_utc,
            column < plan.time_window.end_utc,
        )

    @staticmethod
    def _apply_incident_filters(query: Any, plan: AnalyticsQueryPlan) -> Any:
        for item in plan.filters:
            values = item.values
            if item.field is AnalyticalFilterField.INCIDENT_ID:
                numeric = [int(value) for value in values if value.isdigit()]
                if item.operator == "IN":
                    query = query.filter(Incident.id.in_(numeric))
                elif item.operator == "NOT_IN":
                    query = query.filter(Incident.id.notin_(numeric))
                elif item.operator == "NOT_EQ":
                    query = query.filter(Incident.id != numeric[0])
                else:
                    query = query.filter(Incident.id == numeric[0])
            elif item.field is AnalyticalFilterField.STATUS:
                query = AuthoritativeAnalyticsExecutor._apply_values(
                    query, Incident.status, item.operator, values
                )
            elif item.field is AnalyticalFilterField.AGENT:
                query = AuthoritativeAnalyticsExecutor._apply_values(
                    query, Incident.agent, item.operator, values
                )
            elif item.field is AnalyticalFilterField.DETECTION_RULE:
                query = AuthoritativeAnalyticsExecutor._apply_values(
                    query, Incident.rule, item.operator, values
                )
            elif item.field is AnalyticalFilterField.RECORDED_RISK:
                query = AuthoritativeAnalyticsExecutor._apply_values(
                    query, Incident.recommended_priority, item.operator, values
                )
            elif item.field is AnalyticalFilterField.RECORDED_CORRELATION:
                query = query.filter(Incident.correlated.is_(values[0].lower() == "true"))
            elif item.field is AnalyticalFilterField.SEVERITY:
                raise ValueError("incident severity is not a registered SQL field")
            else:
                raise ValueError("unsupported incident analytics filter")
        return query

    @staticmethod
    def _apply_values(query: Any, column: Any, operator: str, values: list[str]) -> Any:
        if operator == "IN":
            return query.filter(column.in_(values))
        if operator == "NOT_IN":
            return query.filter(column.notin_(values))
        if operator == "NOT_EQ":
            return query.filter(column != values[0])
        return query.filter(column == values[0])

    @staticmethod
    def _apply_case_filters(
        query: Any,
        plan: AnalyticsQueryPlan,
        *,
        now: datetime,
    ) -> Any:
        for item in plan.filters:
            values = item.values
            if item.field is AnalyticalFilterField.CASE_ID:
                numeric = [int(value) for value in values if value.isdigit()]
                if item.operator == "IN":
                    query = query.filter(IncidentCase.id.in_(numeric))
                elif item.operator == "NOT_IN":
                    query = query.filter(IncidentCase.id.notin_(numeric))
                elif item.operator == "NOT_EQ":
                    query = query.filter(IncidentCase.id != numeric[0])
                else:
                    query = query.filter(IncidentCase.id == numeric[0])
            elif item.field is AnalyticalFilterField.STATUS:
                query = AuthoritativeAnalyticsExecutor._apply_values(
                    query, IncidentCase.status, item.operator, values
                )
            elif item.field is AnalyticalFilterField.AGENT:
                query = AuthoritativeAnalyticsExecutor._apply_values(
                    query, IncidentCase.agent, item.operator, values
                )
            elif item.field is AnalyticalFilterField.SEVERITY:
                query = AuthoritativeAnalyticsExecutor._apply_values(
                    query, IncidentCase.severity, item.operator, values
                )
            elif item.field is AnalyticalFilterField.SLA_STATE:
                if values[0] != "BREACHED":
                    raise ValueError("unsupported case SLA state")
                query = query.filter(
                    IncidentCase.sla_due_at.isnot(None),
                    IncidentCase.sla_due_at < now,
                    IncidentCase.status.notin_({"CLOSED", "FALSE_POSITIVE"}),
                )
            else:
                raise ValueError("unsupported case analytics filter")
        return query

    @staticmethod
    def _row_value(row: Any, index: int, name: str) -> Any:
        try:
            return row[index]
        except (IndexError, KeyError, TypeError):
            return getattr(row, name)

    def execute(
        self,
        plan: AnalyticsQueryPlan,
        *,
        db: Any,
        current_user: Mapping[str, Any] | None,
        now: datetime | None = None,
        clock: Any = time.monotonic,
    ) -> AnalyticsExecutionOutcome:
        started = clock()
        definition = self._registry.validate_plan(plan)
        current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        incident_rows: tuple[Incident, ...] = ()
        anchor_incident: Incident | None = None
        case_rows: tuple[IncidentCase, ...] = ()
        semantic_scores: tuple[tuple[int, float], ...] = ()
        semantic_status = "not_requested"
        scalar_value: int | float | None = None
        result_rows: list[AnalyticalResultRow] = []
        result_ids: list[int] = []
        truncated = False

        if definition.execution_strategy == "REFERENCE_LOOKUP":
            selected_filter = next(
                (
                    item
                    for item in plan.filters
                    if item.field is AnalyticalFilterField.MITRE_TECHNIQUE
                ),
                None,
            )
            technique_id = selected_filter.values[0] if selected_filter else ""
            if technique_id in MITRE_REFERENCE_CATALOG:
                result_rows = [
                    AnalyticalResultRow(
                        row_id=f"mitre:{technique_id}",
                        dimensions=[
                            AnalyticalDimensionValue(
                                dimension=AnalyticalDimension.MITRE_TECHNIQUE,
                                value=technique_id,
                            )
                        ],
                    )
                ]
        elif plan.entity is AnalyticalEntity.CASE:
            query = self._case_query(db, current_user=current_user)
            query = self._apply_case_filters(query, plan, now=current_time)
            if plan.operation is AnalyticalOperation.COUNT:
                scalar_value = int(query.count())
            elif plan.operation is AnalyticalOperation.LIST:
                rows = query.order_by(
                    IncidentCase.created_at.desc(), IncidentCase.id.desc()
                ).limit(plan.limit + 1).all()
                truncated = len(rows) > plan.limit
                case_rows = tuple(rows[: plan.limit])
                result_ids = [int(row.id) for row in case_rows]
                result_rows = [
                    AnalyticalResultRow(
                        row_id=f"case:{row.id}",
                        case_id=int(row.id),
                        dimensions=[
                            AnalyticalDimensionValue(
                                dimension=AnalyticalDimension.STATUS,
                                value=str(row.status or "UNKNOWN"),
                            ),
                            AnalyticalDimensionValue(
                                dimension=AnalyticalDimension.SEVERITY,
                                value=str(row.severity or "UNKNOWN"),
                            ),
                        ],
                        status=str(row.status or "UNKNOWN"),
                        timestamp=(row.created_at.isoformat() if row.created_at else None),
                    )
                    for row in case_rows
                ]
            else:
                raise ValueError("operation is not implemented for cases")
        elif definition.execution_strategy == "RECORDED_RELATIONSHIP_LOOKUP":
            anchor_query = self._incident_query(db, current_user=current_user)
            anchor = anchor_query.filter(Incident.id == plan.anchor_record_id).first()
            if anchor is None:
                raise ValueError("recorded relationship anchor is unavailable")
            anchor_incident = anchor
            try:
                summary = json.loads(anchor.correlation_summary or "{}")
            except (TypeError, ValueError):
                summary = {}
            details = summary.get("related_event_details") if isinstance(summary, dict) else []
            related_ids = []
            for item in details if isinstance(details, list) else []:
                incident_id = item.get("id") if isinstance(item, dict) else None
                if (
                    isinstance(incident_id, int)
                    and incident_id > 0
                    and incident_id != anchor.id
                    and incident_id not in related_ids
                ):
                    related_ids.append(incident_id)
            query = self._incident_query(db, current_user=current_user)
            rows = (
                query.filter(Incident.id.in_(related_ids))
                .order_by(Incident.timestamp.desc(), Incident.id.desc())
                .limit(plan.limit + 1)
                .all()
                if related_ids
                else []
            )
            truncated = len(rows) > plan.limit
            incident_rows = tuple(rows[: plan.limit])
            result_ids = [int(row.id) for row in incident_rows]
            result_rows = self._incident_result_rows(incident_rows)
        elif definition.execution_strategy == "SEMANTIC_DISCOVERY_REHYDRATION":
            anchor_query = self._incident_query(db, current_user=current_user)
            anchor = anchor_query.filter(Incident.id == plan.anchor_record_id).first()
            if anchor is None:
                raise ValueError("semantic discovery anchor is unavailable")
            anchor_incident = anchor
            query_result = self._semantic_index.query(
                semantic_query_text_from_facts(
                    {
                        "rule": anchor.rule,
                        "agent": anchor.agent,
                        "mitre": anchor.mitre,
                        "correlation_type": anchor.correlation_type,
                    }
                ),
                exclude_incident_id=int(anchor.id),
                limit=plan.limit,
            )
            semantic_status = query_result.status
            candidate_ids = [item.incident_id for item in query_result.hits]
            query = self._incident_query(db, current_user=current_user)
            rows = query.filter(Incident.id.in_(candidate_ids)).all() if candidate_ids else []
            rows_by_id = {int(row.id): row for row in rows}
            accepted = []
            for hit in query_result.hits:
                row = rows_by_id.get(hit.incident_id)
                if row is None or incident_source_fingerprint(row) != hit.source_fingerprint:
                    continue
                accepted.append((row, hit.score))
            accepted.sort(key=lambda item: (-item[1], int(item[0].id)))
            incident_rows = tuple(item[0] for item in accepted[: plan.limit])
            semantic_scores = tuple(
                (int(item[0].id), float(item[1])) for item in accepted[: plan.limit]
            )
            result_ids = [int(row.id) for row in incident_rows]
            score_by_id = dict(semantic_scores)
            result_rows = [
                row.model_copy(update={"measure_value": score_by_id[row.incident_id]})
                for row in self._incident_result_rows(incident_rows)
            ]
        elif plan.operation is AnalyticalOperation.COUNT:
            if plan.previous_result_empty:
                scalar_value = 0
            else:
                query = self._incident_query(db, current_user=current_user)
                query = self._apply_time(query, plan, column=Incident.timestamp)
                query = self._apply_incident_filters(query, plan)
                if plan.entity is AnalyticalEntity.AGENT:
                    scalar_value = int(
                        query.filter(Incident.agent.isnot(None))
                        .with_entities(func.count(func.distinct(Incident.agent)))
                        .scalar()
                        or 0
                    )
                else:
                    scalar_value = int(query.count())
        elif plan.operation is AnalyticalOperation.LIST:
            if plan.previous_result_empty:
                rows = []
            else:
                query = self._incident_query(db, current_user=current_user)
                query = self._apply_time(query, plan, column=Incident.timestamp)
                query = self._apply_incident_filters(query, plan)
                rows = query.order_by(Incident.timestamp.desc(), Incident.id.desc()).limit(
                    plan.limit + 1
                ).all()
            truncated = len(rows) > plan.limit
            incident_rows = tuple(rows[: plan.limit])
            result_ids = [int(row.id) for row in incident_rows]
            result_rows = self._incident_result_rows(incident_rows)
        elif plan.operation is AnalyticalOperation.TOP_K:
            dimension = plan.dimensions[0]
            column = {
                AnalyticalDimension.AGENT: Incident.agent,
                AnalyticalDimension.DETECTION_RULE: Incident.rule,
            }.get(dimension)
            if column is None:
                raise ValueError("unregistered SQL grouping dimension")
            query = self._incident_query(
                db,
                column,
                func.count(Incident.id).label("record_count"),
                current_user=current_user,
            )
            query = self._apply_time(query, plan, column=Incident.timestamp)
            query = self._apply_incident_filters(query, plan)
            rows = (
                query.filter(column.isnot(None))
                .group_by(column)
                .order_by(func.count(Incident.id).desc(), column.asc())
                .limit(plan.limit)
                .all()
            )
            result_rows = [
                AnalyticalResultRow(
                    row_id=f"{dimension.value}:{index}",
                    dimensions=[
                        AnalyticalDimensionValue(
                            dimension=dimension,
                            value=str(self._row_value(row, 0, column.key)),
                        )
                    ],
                    measure_value=int(self._row_value(row, 1, "record_count")),
                )
                for index, row in enumerate(rows, start=1)
            ]
        elif plan.operation in {AnalyticalOperation.DISTRIBUTION, AnalyticalOperation.TREND}:
            result_rows = self._typed_distribution(
                db,
                plan,
                current_user=current_user,
            )
        elif plan.operation is AnalyticalOperation.COMPARE_PERIODS:
            result_rows = self._period_comparison(
                db,
                plan,
                current_user=current_user,
            )
        elif plan.operation is AnalyticalOperation.COMPARE_ENTITIES:
            query = self._incident_query(
                db,
                Incident.agent,
                func.count(Incident.id).label("record_count"),
                current_user=current_user,
            )
            query = self._apply_time(query, plan, column=Incident.timestamp)
            query = self._apply_incident_filters(query, plan)
            rows = (
                query.filter(Incident.agent.isnot(None))
                .group_by(Incident.agent)
                .order_by(func.count(Incident.id).desc(), Incident.agent.asc())
                .limit(plan.limit)
                .all()
            )
            result_rows = [
                AnalyticalResultRow(
                    row_id=f"agent:{index}",
                    dimensions=[
                        AnalyticalDimensionValue(
                            dimension=AnalyticalDimension.AGENT,
                            value=str(self._row_value(row, 0, "agent")),
                        )
                    ],
                    measure_value=int(self._row_value(row, 1, "record_count")),
                )
                for index, row in enumerate(rows, start=1)
            ]
        else:
            raise ValueError("registered analytics operation is not implemented")

        result_atom = AnalyticalResultAtom(
            atom_id=f"analytics:{plan.query_plan_fingerprint}",
            authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
            provenance=Provenance(
                authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
                source_type="analytics_registry",
                source_record_id=definition.definition_id,
                retrieval_method="deterministic_derivation",
            ),
            result_kind=definition.result_kind,
            operation=plan.operation,
            entity=plan.entity,
            measure=plan.measure,
            filters=plan.filters,
            time_window=plan.time_window,
            comparison_window=plan.comparison_window,
            dimensions=plan.dimensions,
            scalar_value=scalar_value,
            rows=result_rows,
            result_ids=result_ids,
            result_truncated=truncated,
            registry_definition_id=definition.definition_id,
            query_plan_fingerprint=plan.query_plan_fingerprint,
        )
        return AnalyticsExecutionOutcome(
            result_atom=result_atom,
            anchor_incident=anchor_incident,
            incident_rows=incident_rows,
            case_rows=case_rows,
            semantic_scores=semantic_scores,
            semantic_index_status=semantic_status,
            execution_ms=max(0, int((clock() - started) * 1000)),
        )

    @staticmethod
    def _incident_result_rows(rows: tuple[Incident, ...]) -> list[AnalyticalResultRow]:
        return [
            AnalyticalResultRow(
                row_id=f"incident:{row.id}",
                incident_id=int(row.id),
                dimensions=[
                    AnalyticalDimensionValue(
                        dimension=AnalyticalDimension.AGENT,
                        value=str(row.agent or "UNKNOWN"),
                    ),
                    AnalyticalDimensionValue(
                        dimension=AnalyticalDimension.DETECTION_RULE,
                        value=str(row.rule or "UNKNOWN"),
                    ),
                    AnalyticalDimensionValue(
                        dimension=AnalyticalDimension.STATUS,
                        value=str(row.status or "UNKNOWN"),
                    ),
                ],
                timestamp=str(row.timestamp or "") or None,
                status=str(row.status or "UNKNOWN"),
            )
            for row in rows
        ]

    def _typed_distribution(
        self,
        db: Any,
        plan: AnalyticsQueryPlan,
        *,
        current_user: Mapping[str, Any] | None,
    ) -> list[AnalyticalResultRow]:
        query = self._incident_query(db, current_user=current_user)
        query = self._apply_time(query, plan, column=Incident.timestamp)
        query = self._apply_incident_filters(query, plan)
        dimension = plan.dimensions[0]
        if dimension in {
            AnalyticalDimension.STATUS,
            AnalyticalDimension.RECORDED_RISK,
        }:
            column = (
                Incident.status
                if dimension is AnalyticalDimension.STATUS
                else Incident.recommended_priority
            )
            rows = (
                self._incident_query(
                    db,
                    column,
                    func.count(Incident.id).label("record_count"),
                    current_user=current_user,
                )
            )
            rows = self._apply_time(rows, plan, column=Incident.timestamp)
            rows = self._apply_incident_filters(rows, plan)
            grouped = (
                rows.group_by(column)
                .order_by(func.count(Incident.id).desc(), column.asc())
                .limit(plan.limit)
                .all()
            )
            return [
                AnalyticalResultRow(
                    row_id=f"status:{index}",
                    dimensions=[
                        AnalyticalDimensionValue(
                            dimension=dimension,
                            value=str(self._row_value(row, 0, column.key) or "UNKNOWN"),
                        )
                    ],
                    measure_value=int(self._row_value(row, 1, "record_count")),
                )
                for index, row in enumerate(grouped, start=1)
            ]
        selected = query.with_entities(Incident.id, Incident.timestamp, Incident.mitre).all()
        counts: Counter[str] = Counter()
        if dimension is AnalyticalDimension.MITRE_TECHNIQUE:
            for row in selected:
                for value in _mitre_values(self._row_value(row, 2, "mitre")):
                    counts[value] += 1
        elif dimension is AnalyticalDimension.DAY:
            for row in selected:
                parsed = _parse_timestamp(self._row_value(row, 1, "timestamp"))
                if parsed is not None:
                    counts[parsed.astimezone(ZURICH).date().isoformat()] += 1
        else:
            raise ValueError("unregistered typed derivation dimension")
        ordered = sorted(
            counts.items(),
            key=(lambda item: item[0]) if dimension is AnalyticalDimension.DAY else (lambda item: (-item[1], item[0])),
        )[: plan.limit]
        return [
            AnalyticalResultRow(
                row_id=f"{dimension.value}:{index}",
                dimensions=[AnalyticalDimensionValue(dimension=dimension, value=value)],
                measure_value=count,
            )
            for index, (value, count) in enumerate(ordered, start=1)
        ]

    def _period_comparison(
        self,
        db: Any,
        plan: AnalyticsQueryPlan,
        *,
        current_user: Mapping[str, Any] | None,
    ) -> list[AnalyticalResultRow]:
        if plan.time_window is None or plan.comparison_window is None:
            raise ValueError("period comparison windows are missing")

        if plan.dimensions == [AnalyticalDimension.AGENT]:
            def grouped_window(start: str, end: str) -> dict[str, int]:
                query = self._incident_query(
                    db,
                    Incident.agent,
                    func.count(Incident.id).label("record_count"),
                    current_user=current_user,
                )
                query = query.filter(
                    Incident.timestamp >= start,
                    Incident.timestamp < end,
                    Incident.agent.isnot(None),
                )
                query = self._apply_incident_filters(query, plan)
                rows = query.group_by(Incident.agent).all()
                return {
                    str(self._row_value(row, 0, "agent")): int(
                        self._row_value(row, 1, "record_count")
                    )
                    for row in rows
                }

            current_counts = grouped_window(
                plan.time_window.start_utc,
                plan.time_window.end_utc,
            )
            previous_counts = grouped_window(
                plan.comparison_window.start_utc,
                plan.comparison_window.end_utc,
            )
            agents = sorted(
                current_counts.keys() | previous_counts.keys(),
                key=lambda agent: (
                    -abs(current_counts.get(agent, 0) - previous_counts.get(agent, 0)),
                    -current_counts.get(agent, 0),
                    agent,
                ),
            )[: plan.limit]
            return [
                AnalyticalResultRow(
                    row_id=f"agent-period:{index}",
                    dimensions=[
                        AnalyticalDimensionValue(
                            dimension=AnalyticalDimension.AGENT,
                            value=agent,
                        )
                    ],
                    measure_value=current_counts.get(agent, 0),
                    comparison_value=previous_counts.get(agent, 0),
                    delta_value=(
                        current_counts.get(agent, 0) - previous_counts.get(agent, 0)
                    ),
                )
                for index, agent in enumerate(agents, start=1)
            ]

        def count_window(start: str, end: str) -> int:
            query = self._incident_query(db, current_user=current_user)
            query = query.filter(Incident.timestamp >= start, Incident.timestamp < end)
            query = self._apply_incident_filters(query, plan)
            return int(query.count())

        return [
            AnalyticalResultRow(
                row_id="period:current",
                dimensions=[
                    AnalyticalDimensionValue(
                        dimension=AnalyticalDimension.DAY,
                        value=(
                            f"{plan.time_window.start_utc}/{plan.time_window.end_utc}"
                        ),
                    )
                ],
                measure_value=count_window(
                    plan.time_window.start_utc,
                    plan.time_window.end_utc,
                ),
            ),
            AnalyticalResultRow(
                row_id="period:previous",
                dimensions=[
                    AnalyticalDimensionValue(
                        dimension=AnalyticalDimension.DAY,
                        value=(
                            f"{plan.comparison_window.start_utc}/{plan.comparison_window.end_utc}"
                        ),
                    )
                ],
                measure_value=count_window(
                    plan.comparison_window.start_utc,
                    plan.comparison_window.end_utc,
                ),
            ),
        ]
