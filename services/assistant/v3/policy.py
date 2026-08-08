from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from services.assistant.focus import FocusDimension, FocusSelection
from services.assistant.v3.contracts import (
    AnalysisScope,
    AnswerIntent,
    ContextLimits,
    ContextPlan,
    ContextRequirement,
    FactField,
    IntentSelection,
    ResolvedScope,
    ValidatedConversationState,
)


_IDENTITY = (FactField.SOURCE_TYPE, FactField.INCIDENT_ID, FactField.CASE_ID, FactField.TITLE)
_STATUS = (FactField.STATUS, FactField.SEVERITY)
_ENTITY = (FactField.AGENT, FactField.HOST, FactField.USER, FactField.USERNAME)
_DETECTION = (FactField.RULE, FactField.WAZUH_LEVEL)
_RISK = (FactField.RISK_SCORE, FactField.RISK_NORMALIZATION_SEVERITY)
_CORRELATION = (
    FactField.CORRELATED,
    FactField.CORRELATION_TYPE,
    FactField.CORRELATION_SCORE,
)
_TIMELINE = (FactField.TIMESTAMP, FactField.LATEST_TIMELINE_EVENT)
_CASE = (
    FactField.LINKED_CASE_IDS,
    FactField.LINKED_INCIDENT_COUNT,
    FactField.LINKED_INCIDENTS,
    FactField.OWNER,
    FactField.ASSIGNEE,
    FactField.SLA_DUE_AT,
    FactField.STATUS_REASON,
)


def _unique(values: Iterable[Any]) -> list[Any]:
    return list(dict.fromkeys(values))


def resolve_analysis_scope(
    *,
    request_scope: str,
    incident_id: int | None,
    case_id: int | None,
    intent: IntentSelection,
    conversation_state: ValidatedConversationState | None,
) -> ResolvedScope:
    cross_intents = {
        AnswerIntent.COMPARE,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.PATTERN_ANALYSIS,
    }
    active_incidents = [incident_id] if incident_id is not None else []
    active_cases = [case_id] if case_id is not None else []
    followup = conversation_state is not None
    if conversation_state is not None:
        if not active_incidents and conversation_state.active_incident_ids:
            active_incidents = list(conversation_state.active_incident_ids)
        if not active_cases and conversation_state.active_case_ids:
            active_cases = list(conversation_state.active_case_ids)
        if intent.primary_intent in cross_intents:
            active_incidents = _unique(
                [*active_incidents, *conversation_state.related_incident_ids]
            )[:12]

    if intent.primary_intent in cross_intents:
        scope = (
            AnalysisScope.EXPLICIT_RECORD_SET
            if len(active_incidents) > 1
            else AnalysisScope.RELATED_INCIDENTS
        )
    elif request_scope == "incident" or active_incidents:
        scope = AnalysisScope.CURRENT_RECORD
    elif request_scope == "case" or active_cases:
        scope = AnalysisScope.CURRENT_CASE
    else:
        scope = AnalysisScope.GLOBAL
    return ResolvedScope(
        analysis_scope=scope,
        active_incident_ids=active_incidents,
        active_case_ids=active_cases,
        conversation_followup=followup,
    )


@dataclass(frozen=True)
class ContextPolicyEngine:
    limits: ContextLimits = ContextLimits()

    def plan(
        self,
        *,
        intent: IntentSelection,
        focus: FocusSelection,
        resolved_scope: ResolvedScope,
        available_facts: dict[str, Any],
        conversation_state: ValidatedConversationState | None,
        clock: Callable[[], float] = time.monotonic,
    ) -> ContextPlan:
        del conversation_state
        started = clock()
        primary = intent.primary_intent
        requirements: list[ContextRequirement] = [ContextRequirement.IDENTITY]
        fields: list[FactField] = list(_IDENTITY)

        if primary is AnswerIntent.FACT_LOOKUP:
            requirements.extend(self._focus_requirements(focus))
            fields.extend(self._focus_fields(focus))
        elif primary is AnswerIntent.EXECUTIVE_SUMMARY:
            requirements.extend(
                [ContextRequirement.STATUS, ContextRequirement.RISK, ContextRequirement.PRIORITY]
            )
            fields.extend((*_STATUS, *_RISK, FactField.RECOMMENDED_PRIORITY, *_ENTITY))
        else:
            requirements.extend(
                [
                    ContextRequirement.STATUS,
                    ContextRequirement.ENTITY,
                    ContextRequirement.DETECTION,
                    ContextRequirement.RISK,
                    ContextRequirement.PRIORITY,
                    ContextRequirement.CORRELATION,
                    ContextRequirement.MITRE,
                    ContextRequirement.COMPROMISE_STATE,
                    ContextRequirement.CASE_RELATIONSHIP,
                ]
            )
            fields.extend(
                (
                    *_STATUS,
                    *_ENTITY,
                    *_DETECTION,
                    *_RISK,
                    FactField.RECOMMENDED_PRIORITY,
                    *_CORRELATION,
                    FactField.MITRE,
                    FactField.COMPROMISE_CONFIRMED,
                    *_CASE,
                )
            )

        if primary in {AnswerIntent.EXPLAIN, AnswerIntent.INVESTIGATE, AnswerIntent.HANDOVER}:
            requirements.extend(
                [ContextRequirement.EVIDENCE, ContextRequirement.TIMELINE, ContextRequirement.REFERENCE]
            )
            fields.extend(_TIMELINE)
        if primary in {
            AnswerIntent.INVESTIGATE,
            AnswerIntent.NEXT_ACTION,
            AnswerIntent.CROSS_INCIDENT_ANALYSIS,
            AnswerIntent.PATTERN_ANALYSIS,
            AnswerIntent.HANDOVER,
        }:
            requirements.append(ContextRequirement.ADVISORY)
        cross = primary in {
            AnswerIntent.COMPARE,
            AnswerIntent.CROSS_INCIDENT_ANALYSIS,
            AnswerIntent.PATTERN_ANALYSIS,
        }
        if cross:
            requirements.extend(
                [
                    ContextRequirement.CROSS_INCIDENT,
                    ContextRequirement.EVIDENCE,
                    ContextRequirement.TIMELINE,
                    ContextRequirement.REFERENCE,
                ]
            )
            fields.extend(_TIMELINE)

        available = set(available_facts)
        linked_incidents = available_facts.get("linked_incidents")
        if isinstance(linked_incidents, list):
            for linked in linked_incidents[: plan_limit_for_linked_records(self.limits)]:
                if isinstance(linked, dict):
                    available.update(linked)
        selected_fields = [field for field in _unique(fields) if field.value in available]
        # Identity names remain in the plan even when absent so downstream normalization
        # can distinguish unavailable data from policy exclusion.
        for identity in _IDENTITY:
            if identity not in selected_fields:
                selected_fields.insert(0, identity)
        return ContextPlan(
            intent=primary,
            analysis_scope=resolved_scope.analysis_scope,
            requirements=_unique(requirements),
            fact_fields=_unique(selected_fields),
            include_cross_incident=cross,
            include_reference=ContextRequirement.REFERENCE in requirements,
            include_advisory=ContextRequirement.ADVISORY in requirements,
            limits=self.limits,
            policy_ms=max(0.0, (clock() - started) * 1000),
        )

    @staticmethod
    def _focus_requirements(focus: FocusSelection) -> list[ContextRequirement]:
        mapping = {
            FocusDimension.STATUS: ContextRequirement.STATUS,
            FocusDimension.SEVERITY: ContextRequirement.STATUS,
            FocusDimension.RISK: ContextRequirement.RISK,
            FocusDimension.PRIORITY: ContextRequirement.PRIORITY,
            FocusDimension.HOST: ContextRequirement.ENTITY,
            FocusDimension.CORRELATION: ContextRequirement.CORRELATION,
            FocusDimension.EVIDENCE: ContextRequirement.EVIDENCE,
            FocusDimension.ESCALATION: ContextRequirement.STATUS,
            FocusDimension.GENERAL: ContextRequirement.STATUS,
        }
        return _unique(mapping[item] for item in focus.dimensions)

    @staticmethod
    def _focus_fields(focus: FocusSelection) -> list[FactField]:
        mapping = {
            FocusDimension.STATUS: (FactField.STATUS,),
            FocusDimension.SEVERITY: (FactField.SEVERITY, FactField.RISK_NORMALIZATION_SEVERITY),
            FocusDimension.RISK: (FactField.RISK_SCORE,),
            FocusDimension.PRIORITY: (FactField.RECOMMENDED_PRIORITY,),
            FocusDimension.HOST: (*_ENTITY,),
            FocusDimension.CORRELATION: (*_CORRELATION,),
            FocusDimension.EVIDENCE: (FactField.LATEST_TIMELINE_EVENT, FactField.MITRE),
            FocusDimension.ESCALATION: (FactField.ESCALATION_REASON,),
            FocusDimension.GENERAL: (*_STATUS, FactField.RISK_SCORE, FactField.CORRELATED),
        }
        return _unique(field for item in focus.dimensions for field in mapping[item])


def advisory_retrieval_allowed(intent: IntentSelection) -> bool:
    return intent.primary_intent in {
        AnswerIntent.INVESTIGATE,
        AnswerIntent.NEXT_ACTION,
        AnswerIntent.CROSS_INCIDENT_ANALYSIS,
        AnswerIntent.PATTERN_ANALYSIS,
        AnswerIntent.HANDOVER,
    }


def plan_limit_for_linked_records(limits: ContextLimits) -> int:
    return min(10, limits.max_graph_incidents)
