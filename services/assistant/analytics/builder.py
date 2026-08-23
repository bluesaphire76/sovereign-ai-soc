from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Sequence

from models import Incident, IncidentCase
from services.assistant.analytics.contracts import AnalyticsBuildResult
from services.assistant.analytics.execution import (
    AnalyticsAccessPolicy,
    AnalyticsExecutionOutcome,
    AuthoritativeAnalyticsExecutor,
    PlatformAnalyticsAccessPolicy,
)
from services.assistant.analytics.normalization import normalize_mitre_facts
from services.assistant.analytics.interpreter import (
    GlobalAnalyticsInterpreter,
)
from services.assistant.retrieval import RetrievalResult
from services.assistant.sources import SourceRecord
from services.assistant.v3.atoms import OperationalAtomNormalizer
from services.assistant.v3.contracts import (
    AnalysisScope,
    AnalyticalEntity,
    AnalyticalFilterField,
    AnalyticalFocus,
    AnalyticalOperation,
    AnswerIntent,
    AuthorityClass,
    ContextBuildMetrics,
    ContextLimits,
    ContextPlan,
    ContextRequirement,
    ConversationStateRefs,
    CrossIncidentEvidenceGraph,
    DiscoverySignal,
    FactField,
    GlobalConversationQueryState,
    IncidentCandidate,
    IntentSelection,
    MitreTechniqueAtom,
    Provenance,
    RelationshipRegistry,
    ResolvedScope,
    SourceRegistryEntry,
    V3AnalyticalContextPackage,
    ValidatedConversationState,
)
from services.assistant.v3.conversation import (
    ConversationStateStore,
    conversation_owner_key,
    get_conversation_state_store,
    updated_conversation_state,
)
from services.assistant.v3.graph import (
    CrossIncidentGraphBuilder,
    RecordedCorrelationLink,
)
from services.assistant.v3.knowledge import ReferenceKnowledgeProvider


class GlobalAnalyticsResolutionError(Exception):
    def __init__(self, routing_status: str) -> None:
        super().__init__(routing_status)
        self.routing_status = routing_status


@dataclass(frozen=True)
class GlobalAnalyticsContext:
    package: V3AnalyticalContextPackage
    retrieval: RetrievalResult
    sources: tuple[SourceRecord, ...]
    build_result: AnalyticsBuildResult


def _mitre_facts(value: Any) -> list[dict[str, str]]:
    return normalize_mitre_facts(value)


def _incident_facts(row: Incident) -> dict[str, Any]:
    return {
        "source_type": "incident",
        "incident_id": int(row.id),
        "status": row.status,
        "timestamp": row.timestamp,
        "agent": row.agent,
        "rule": row.rule,
        "wazuh_level": row.level,
        "mitre": _mitre_facts(row.mitre),
        "risk_score": row.risk_score,
        "correlated": row.correlated,
        "correlation_type": row.correlation_type,
        "correlation_score": row.correlation_score,
        "escalation_reason": row.escalation_reason,
        "recommended_priority": row.recommended_priority,
    }


def _case_facts(row: IncidentCase) -> dict[str, Any]:
    return {
        "source_type": "case",
        "case_id": int(row.id),
        "title": row.title,
        "status": row.status,
        "severity": row.severity,
        "agent": row.agent,
        "risk_score": row.risk_score,
        "correlation_type": row.correlation_type,
        "owner": row.owner,
        "assignee": row.assignee,
        "sla_due_at": row.sla_due_at.isoformat() if row.sla_due_at else None,
    }


def _intent_for(
    outcome: AnalyticsExecutionOutcome,
    *,
    detail_level: str = "SUMMARY",
) -> AnswerIntent:
    operation = outcome.result_atom.operation
    if operation in {
        AnalyticalOperation.COMPARE_PERIODS,
        AnalyticalOperation.COMPARE_ENTITIES,
    }:
        return AnswerIntent.COMPARE
    if detail_level == "EXPLANATION":
        return AnswerIntent.EXPLAIN
    if detail_level == "GUIDANCE":
        return AnswerIntent.NEXT_ACTION
    if operation in {
        AnalyticalOperation.RELATED_RECORDS,
        AnalyticalOperation.SIMILAR_RECORDS,
    } and outcome.result_atom.result_ids:
        return AnswerIntent.CROSS_INCIDENT_ANALYSIS
    return AnswerIntent.SUMMARY


def _focus_for(outcome: AnalyticsExecutionOutcome) -> list[AnalyticalFocus]:
    atom = outcome.result_atom
    focus: list[AnalyticalFocus] = []
    if atom.entity is AnalyticalEntity.AGENT or any(
        item.field is AnalyticalFilterField.AGENT for item in atom.filters
    ):
        focus.append(AnalyticalFocus.HOST)
    if atom.entity is AnalyticalEntity.STATUS or any(
        item.field is AnalyticalFilterField.STATUS for item in atom.filters
    ):
        focus.append(AnalyticalFocus.STATUS)
    if atom.entity is AnalyticalEntity.RECORDED_RISK or any(
        item.field is AnalyticalFilterField.RECORDED_RISK for item in atom.filters
    ):
        focus.append(AnalyticalFocus.RISK)
    if atom.entity is AnalyticalEntity.RECORDED_CORRELATION:
        focus.append(AnalyticalFocus.CORRELATION)
    if atom.entity in {
        AnalyticalEntity.DETECTION_RULE,
        AnalyticalEntity.MITRE_TECHNIQUE,
    }:
        focus.append(AnalyticalFocus.EVIDENCE)
    return list(dict.fromkeys(focus)) or [AnalyticalFocus.GENERAL]


class GlobalAnalyticsContextBuilder:
    def __init__(
        self,
        *,
        interpreter: GlobalAnalyticsInterpreter | None = None,
        executor: AuthoritativeAnalyticsExecutor | None = None,
        access_policy: AnalyticsAccessPolicy | None = None,
        atom_normalizer: OperationalAtomNormalizer | None = None,
        graph_builder: CrossIncidentGraphBuilder | None = None,
        reference_provider: ReferenceKnowledgeProvider | None = None,
        conversation_store: ConversationStateStore | None = None,
    ) -> None:
        self._access = access_policy or PlatformAnalyticsAccessPolicy()
        self._interpreter = interpreter or GlobalAnalyticsInterpreter()
        self._executor = executor or AuthoritativeAnalyticsExecutor(
            access_policy=self._access
        )
        self._atoms = atom_normalizer or OperationalAtomNormalizer()
        self._graph = graph_builder or CrossIncidentGraphBuilder()
        self._reference = reference_provider or ReferenceKnowledgeProvider()
        self._conversations = conversation_store or get_conversation_state_store()

    @staticmethod
    def _row_id(row: Any) -> int:
        try:
            return int(row[0])
        except (IndexError, KeyError, TypeError):
            return int(row.id)

    def _authorized_ids(
        self,
        db: Any,
        model: Any,
        values: Sequence[int],
        *,
        current_user: Mapping[str, Any] | None,
    ) -> set[int]:
        selected = list(dict.fromkeys(value for value in values if value > 0))
        if not selected:
            return set()
        query = db.query(model.id).filter(model.id.in_(selected))
        query = (
            self._access.apply_incident_scope(query, current_user=current_user)
            if model is Incident
            else self._access.apply_case_scope(query, current_user=current_user)
        )
        return {self._row_id(row) for row in query.all()}

    def _authorized_conversation(
        self,
        conversation: ValidatedConversationState | None,
        *,
        db: Any,
        current_user: Mapping[str, Any] | None,
    ) -> ValidatedConversationState | None:
        if conversation is None:
            return None
        global_query = conversation.global_query
        global_incident_ids = global_query.result_incident_ids if global_query else []
        global_case_ids = global_query.result_case_ids if global_query else []
        incident_ids = self._authorized_ids(
            db,
            Incident,
            [
                *conversation.active_incident_ids,
                *conversation.related_incident_ids,
                *global_incident_ids,
            ],
            current_user=current_user,
        )
        case_ids = self._authorized_ids(
            db,
            IncidentCase,
            [*conversation.active_case_ids, *global_case_ids],
            current_user=current_user,
        )
        if global_query is not None:
            global_query = global_query.model_copy(
                update={
                    "result_incident_ids": [
                        value
                        for value in global_query.result_incident_ids
                        if value in incident_ids
                    ],
                    "result_case_ids": [
                        value for value in global_query.result_case_ids if value in case_ids
                    ],
                }
            )
        return conversation.model_copy(
            update={
                "active_incident_ids": [
                    value for value in conversation.active_incident_ids if value in incident_ids
                ],
                "related_incident_ids": [
                    value for value in conversation.related_incident_ids if value in incident_ids
                ],
                "active_case_ids": [
                    value for value in conversation.active_case_ids if value in case_ids
                ],
                "global_query": global_query,
            }
        )

    @staticmethod
    def _context_plan(
        intent: AnswerIntent,
        *,
        include_reference: bool = False,
    ) -> ContextPlan:
        limits = ContextLimits(
            max_operational_atoms=160,
            max_evidence_atoms=32,
            max_timeline_atoms=4,
            max_candidates_discovered=40,
            max_candidates_rehydrated=15,
            max_graph_incidents=16,
            max_reference_atoms=4 if include_reference else 0,
            max_advisory_atoms=0,
        )
        requirements = [
            ContextRequirement.IDENTITY,
            ContextRequirement.STATUS,
            ContextRequirement.ENTITY,
            ContextRequirement.DETECTION,
            ContextRequirement.RISK,
            ContextRequirement.CORRELATION,
            ContextRequirement.MITRE,
        ]
        if include_reference:
            requirements = [ContextRequirement.MITRE, ContextRequirement.REFERENCE]
        if intent is AnswerIntent.CROSS_INCIDENT_ANALYSIS:
            requirements.append(ContextRequirement.CROSS_INCIDENT)
        return ContextPlan(
            intent=intent,
            analysis_scope=AnalysisScope.GLOBAL,
            requirements=requirements,
            fact_fields=[
                FactField.SOURCE_TYPE,
                FactField.INCIDENT_ID,
                FactField.CASE_ID,
                FactField.TITLE,
                FactField.STATUS,
                FactField.SEVERITY,
                FactField.TIMESTAMP,
                FactField.AGENT,
                FactField.RULE,
                FactField.WAZUH_LEVEL,
                FactField.RISK_SCORE,
                FactField.MITRE,
                FactField.CORRELATED,
                FactField.CORRELATION_TYPE,
                FactField.CORRELATION_SCORE,
                FactField.ESCALATION_REASON,
                FactField.RECOMMENDED_PRIORITY,
                FactField.OWNER,
                FactField.ASSIGNEE,
                FactField.SLA_DUE_AT,
            ],
            include_cross_incident=intent is AnswerIntent.CROSS_INCIDENT_ANALYSIS,
            include_reference=include_reference,
            limits=limits,
        )

    @staticmethod
    def _sources(outcome: AnalyticsExecutionOutcome) -> list[SourceRecord]:
        atom = outcome.result_atom
        sources = [
            SourceRecord(
                source_type="analytics_registry",
                authority="authoritative",
                record_id=atom.registry_definition_id,
                label=f"Analytics definition {atom.registry_definition_id}",
                excerpt=(
                    "Closed server-side analytics definition evaluated over the "
                    "authorized SQL record scope."
                ),
                provenance_class="analytical_relationship",
            )
        ]
        incidents = [
            *([outcome.anchor_incident] if outcome.anchor_incident is not None else []),
            *outcome.incident_rows,
        ]
        for row in {int(item.id): item for item in incidents}.values():
            sources.append(
                SourceRecord(
                    source_type="incident",
                    authority="authoritative",
                    record_id=str(row.id),
                    label=f"Incident {row.id}",
                    excerpt="Authoritative incident row selected by the analytics plan.",
                    url=f"/incidents/{row.id}",
                )
            )
        for row in outcome.case_rows:
            sources.append(
                SourceRecord(
                    source_type="case",
                    authority="authoritative",
                    record_id=str(row.id),
                    label=f"Case {row.id}",
                    excerpt="Authoritative case row selected by the analytics plan.",
                    url=f"/cases/{row.id}",
                )
            )
        return sources

    def build(
        self,
        *,
        payload: Any,
        response_language: str,
        db: Any,
        current_user: Mapping[str, Any] | None,
        request_embedding: Sequence[float] | None = None,
        now: datetime | None = None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> GlobalAnalyticsContext:
        started = clock()
        owner_key = conversation_owner_key(current_user)
        conversation_started = clock()
        conversation = self._conversations.load(
            owner_key=owner_key,
            conversation_id=getattr(payload, "conversation_id", None),
        )
        conversation = self._authorized_conversation(
            conversation,
            db=db,
            current_user=current_user,
        )
        conversation_ms = max(0.0, (clock() - conversation_started) * 1000)
        interpreted = self._interpreter.interpret(
            payload.message,
            db=db,
            conversation=conversation,
            request_embedding=request_embedding,
            apply_authorized_incident_scope=lambda query: (
                self._access.apply_incident_scope(query, current_user=current_user)
            ),
            now=now,
            clock=clock,
        )
        if interpreted.plan is None:
            raise GlobalAnalyticsResolutionError(interpreted.decision.routing_status)
        outcome = self._executor.execute(
            interpreted.plan,
            db=db,
            current_user=current_user,
            now=now,
            clock=clock,
        )
        intent = _intent_for(
            outcome,
            detail_level=(
                interpreted.semantic_ast.detail_level.value
                if interpreted.semantic_ast
                else "SUMMARY"
            ),
        )
        focus = _focus_for(outcome)
        include_reference = bool(
            interpreted.semantic_ast
            and interpreted.semantic_ast.target is AnalyticalEntity.MITRE_TECHNIQUE
            and interpreted.semantic_ast.detail_level.value == "EXPLANATION"
        )
        context_plan = self._context_plan(
            intent,
            include_reference=include_reference,
        )
        record_rows = [
            *([outcome.anchor_incident] if outcome.anchor_incident is not None else []),
            *outcome.incident_rows,
        ]
        operational_atoms = [outcome.result_atom]
        for row in {int(item.id): item for item in record_rows}.values():
            operational_atoms.extend(
                self._atoms.normalize(
                    facts=_incident_facts(row),
                    plan=context_plan,
                )
            )
        for row in outcome.case_rows:
            operational_atoms.extend(
                self._atoms.normalize(
                    facts=_case_facts(row),
                    plan=context_plan,
                )
            )
        operational_atoms = list(
            {item.atom_id: item for item in operational_atoms}.values()
        )[: context_plan.limits.max_operational_atoms]
        reference_started = clock()
        reference_inputs = []
        if include_reference:
            technique_filter = next(
                (
                    item
                    for item in interpreted.plan.filters
                    if item.field is AnalyticalFilterField.MITRE_TECHNIQUE
                ),
                None,
            )
            if technique_filter is not None:
                technique_id = technique_filter.values[0]
                reference_inputs.append(
                    MitreTechniqueAtom(
                        atom_id=f"reference-input:mitre:{technique_id}",
                        authority_class=AuthorityClass.REFERENCE_KNOWLEDGE,
                        provenance=Provenance(
                            authority_class=AuthorityClass.REFERENCE_KNOWLEDGE,
                            source_type="project_mitre_catalog",
                            source_record_id=technique_id,
                            retrieval_method="project_catalog",
                        ),
                        technique_id=technique_id,
                    )
                )
        reference_atoms = self._reference.retrieve(
            plan=context_plan,
            operational_atoms=reference_inputs,
        )
        reference_ms = max(0.0, (clock() - reference_started) * 1000)

        candidates: list[IncidentCandidate] = []
        recorded_links: list[RecordedCorrelationLink] = []
        anchor_id = interpreted.plan.anchor_record_id
        if interpreted.plan.operation is AnalyticalOperation.SIMILAR_RECORDS:
            score_by_id = dict(outcome.semantic_scores)
            candidates = [
                IncidentCandidate(
                    candidate_id=(
                        f"semantic-candidate:{anchor_id}:{incident_id}:"
                        f"{interpreted.plan.query_plan_fingerprint[:12]}"
                    ),
                    candidate_incident_id=incident_id,
                    discovery_signals=[DiscoverySignal.SEMANTIC_SIMILARITY],
                    semantic_score=score,
                    deterministic_signal_count=0,
                    discovery_source="semantic",
                    authoritative_rehydrated=True,
                    ranking_score=max(0.0, score),
                )
                for incident_id, score in outcome.semantic_scores
            ]
        elif interpreted.plan.operation is AnalyticalOperation.RELATED_RECORDS:
            atom_refs_by_incident: dict[int, list[str]] = {}
            for atom in operational_atoms:
                if atom.incident_id is not None:
                    atom_refs_by_incident.setdefault(atom.incident_id, []).append(atom.atom_id)
            anchor_refs = atom_refs_by_incident.get(anchor_id or 0, [])
            correlation_refs = [
                ref for ref in anchor_refs if ref.endswith(":recorded-correlation")
            ]
            identity_refs = [ref for ref in anchor_refs if ref.endswith(":identity")]
            for incident_id in outcome.result_atom.result_ids:
                related_identity = [
                    ref
                    for ref in atom_refs_by_incident.get(incident_id, [])
                    if ref.endswith(":identity")
                ]
                refs = tuple([*correlation_refs, *identity_refs, *related_identity])
                if refs and anchor_id is not None:
                    recorded_links.append(
                        RecordedCorrelationLink(
                            left_incident_id=anchor_id,
                            right_incident_id=incident_id,
                            evidence_atom_refs=refs,
                            source_record_id=str(anchor_id),
                        )
                    )

        graph_started = clock()
        graph = self._graph.build(
            anchor_incident_id=anchor_id,
            candidates=candidates,
            operational_atoms=operational_atoms,
            recorded_links=recorded_links,
            max_incidents=context_plan.limits.max_graph_incidents,
        )
        graph_ms = max(0.0, (clock() - graph_started) * 1000)
        active_incidents = list(
            dict.fromkeys(
                [
                    *([anchor_id] if anchor_id is not None else []),
                    *outcome.result_atom.result_ids,
                ]
            )
        )[:12]
        active_cases = [int(row.id) for row in outcome.case_rows][:4]
        resolved_scope = ResolvedScope(
            analysis_scope=AnalysisScope.GLOBAL,
            active_incident_ids=active_incidents,
            active_case_ids=active_cases,
            conversation_followup=conversation is not None,
        )
        selection = IntentSelection(
            primary_intent=intent,
            confidence=interpreted.decision.confidence,
            routing_status="ok",
            routing_ms=interpreted.decision.routing_ms,
        )
        registry: dict[str, SourceRegistryEntry] = {}
        for atom in operational_atoms:
            registry[atom.atom_id] = SourceRegistryEntry(
                source_ref=atom.atom_id,
                authority_class=atom.authority_class,
                source_type=atom.provenance.source_type,
                source_record_id=atom.provenance.source_record_id,
            )
        for candidate in candidates:
            registry[candidate.candidate_id] = SourceRegistryEntry(
                source_ref=candidate.candidate_id,
                authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
                source_type="incident",
                source_record_id=str(candidate.candidate_incident_id),
            )
        for atom in reference_atoms:
            registry[atom.knowledge_id] = SourceRegistryEntry(
                source_ref=atom.knowledge_id,
                authority_class=atom.authority_class,
                source_type=atom.provenance.source_type,
                source_record_id=atom.provenance.source_record_id,
            )

        global_state = GlobalConversationQueryState(
            registry_definition_id=interpreted.plan.definition_id,
            operation=interpreted.plan.operation,
            entity=interpreted.plan.entity,
            measure=interpreted.plan.measure,
            filters=interpreted.plan.filters,
            time_window=interpreted.plan.time_window,
            comparison_window=interpreted.plan.comparison_window,
            dimensions=interpreted.plan.dimensions,
            distinct=bool(interpreted.semantic_ast.distinct) if interpreted.semantic_ast else False,
            limit=interpreted.plan.limit,
            anchor_record_id=interpreted.plan.anchor_record_id,
            detail_level=(
                interpreted.semantic_ast.detail_level.value
                if interpreted.semantic_ast
                else "SUMMARY"
            ),
            result_incident_ids=outcome.result_atom.result_ids,
            result_case_ids=[int(row.id) for row in outcome.case_rows],
            result_dimension_values=[
                dimension
                for row in outcome.result_atom.rows
                for dimension in row.dimensions
            ][:50],
            query_plan_fingerprint=interpreted.plan.query_plan_fingerprint,
        )
        conversation_id = getattr(payload, "conversation_id", None)
        if conversation_id:
            state = updated_conversation_state(
                existing=conversation,
                conversation_id=conversation_id,
                owner_key=owner_key,
                active_incident_ids=active_incidents,
                active_case_ids=active_cases,
                related_incident_ids=outcome.result_atom.result_ids,
                intent=intent,
                focus_dimensions=focus,
                atom_refs=[item.atom_id for item in operational_atoms],
                relationship_refs=[item.relationship_id for item in graph.relationships],
                reference_refs=[item.knowledge_id for item in reference_atoms],
                advisory_refs=[],
                response_language=response_language,
                now=wall_clock(),
                global_query=global_state,
            )
            self._conversations.save(state)
            conversation_refs = ConversationStateRefs(
                conversation_id=conversation_id,
                active_incident_ids=state.active_incident_ids,
                active_case_ids=state.active_case_ids,
                related_incident_ids=state.related_incident_ids,
                validated_atom_refs=state.validated_atom_refs,
                validated_relationship_refs=state.validated_relationship_refs,
                global_query_plan_fingerprint=interpreted.plan.query_plan_fingerprint,
                global_result_incident_ids=global_state.result_incident_ids,
                global_result_case_ids=global_state.result_case_ids,
            )
        else:
            conversation_refs = ConversationStateRefs(
                active_incident_ids=active_incidents,
                active_case_ids=active_cases,
                related_incident_ids=outcome.result_atom.result_ids,
                validated_atom_refs=[item.atom_id for item in operational_atoms],
                validated_relationship_refs=[
                    item.relationship_id for item in graph.relationships
                ],
                global_query_plan_fingerprint=interpreted.plan.query_plan_fingerprint,
                global_result_incident_ids=global_state.result_incident_ids,
                global_result_case_ids=global_state.result_case_ids,
            )

        total_ms = max(0.0, (clock() - started) * 1000)
        metrics = ContextBuildMetrics(
            intent_routing_ms=interpreted.decision.routing_ms,
            conversation_state_ms=conversation_ms,
            scope_resolution_ms=0.0,
            context_policy_ms=0.0,
            atom_normalization_ms=max(
                0.0,
                total_ms
                - interpreted.decision.routing_ms
                - conversation_ms
                - outcome.execution_ms
                - graph_ms,
            ),
            candidate_retrieval_ms=(
                outcome.execution_ms
                if interpreted.plan.operation is AnalyticalOperation.SIMILAR_RECORDS
                else 0.0
            ),
            semantic_index_query_ms=(
                outcome.execution_ms
                if interpreted.plan.operation is AnalyticalOperation.SIMILAR_RECORDS
                else 0.0
            ),
            authoritative_rehydration_ms=(
                outcome.execution_ms
                if interpreted.plan.operation
                in {
                    AnalyticalOperation.SIMILAR_RECORDS,
                    AnalyticalOperation.RELATED_RECORDS,
                }
                else 0.0
            ),
            semantic_raw_candidate_count=len(outcome.semantic_scores),
            candidate_discovered_count=len(outcome.semantic_scores),
            candidate_selected_count=len(candidates),
            authoritative_rehydration_count=(
                len(outcome.incident_rows) + len(outcome.case_rows)
            ),
            graph_construction_ms=graph_ms,
            reference_retrieval_ms=reference_ms,
            total_context_build_ms=total_ms,
        )
        package = V3AnalyticalContextPackage(
            question=payload.message,
            response_language="it" if response_language == "it" else "en",
            intent_selection=selection,
            focus_selection=focus,
            resolved_scope=resolved_scope,
            context_plan=context_plan,
            operational_atoms=operational_atoms,
            cross_incident_candidates=candidates,
            cross_incident_graph=graph,
            conversation_state_refs=conversation_refs,
            context_limits=context_plan.limits,
            source_registry=list(registry.values()),
            relationship_registry=RelationshipRegistry(
                relationships=graph.relationships
            ),
            reference_atoms=reference_atoms,
            semantic_index_status=(
                outcome.semantic_index_status
                if outcome.semantic_index_status
                in {"ready", "degraded", "unavailable"}
                else "not_requested"
            ),
            metrics=metrics,
        )
        semantic_status = {
            "ready": "available",
            "degraded": "retrieval_failed",
            "unavailable": "retrieval_failed",
        }.get(outcome.semantic_index_status, "not_requested")
        sources = self._sources(outcome)
        sources.extend(
            SourceRecord(
                source_type=item.provenance.source_type,
                authority="reference",
                record_id=item.provenance.source_record_id,
                label=item.subject,
                excerpt=item.bounded_content,
                provenance_class="reference_knowledge",
            )
            for item in reference_atoms
        )
        retrieval = RetrievalResult(
            scope="global",
            fact_inventory={
                "analytics_plan": interpreted.plan.model_dump(mode="json"),
                "analytics_result": outcome.result_atom.model_dump(mode="json"),
            },
            sources=sources,
            limitations=(
                ["Semantic discovery was unavailable; SQL authority remains unchanged."]
                if interpreted.plan.operation is AnalyticalOperation.SIMILAR_RECORDS
                and outcome.semantic_index_status != "ready"
                else []
            ),
            semantic_memory_requested=(
                interpreted.plan.operation is AnalyticalOperation.SIMILAR_RECORDS
            ),
            semantic_memory_attempted=(
                interpreted.plan.operation is AnalyticalOperation.SIMILAR_RECORDS
            ),
            semantic_memory_available=outcome.semantic_index_status == "ready",
            authoritative_elapsed_ms=outcome.execution_ms,
            semantic_elapsed_ms=(
                outcome.execution_ms
                if interpreted.plan.operation is AnalyticalOperation.SIMILAR_RECORDS
                else 0
            ),
            semantic_candidates=len(outcome.semantic_scores),
            semantic_sources_accepted=len(outcome.semantic_scores),
            semantic_status=semantic_status,
            semantic_degraded=(
                interpreted.plan.operation is AnalyticalOperation.SIMILAR_RECORDS
                and outcome.semantic_index_status != "ready"
            ),
        )
        build_result = AnalyticsBuildResult(
            plan=interpreted.plan,
            result_atom=outcome.result_atom,
            response_language="it" if response_language == "it" else "en",
            semantic_index_status=package.semantic_index_status,
            operational_retrieval_ms=outcome.execution_ms,
            interpretation_ms=max(0, int(interpreted.decision.routing_ms)),
            execution_ms=outcome.execution_ms,
        )
        return GlobalAnalyticsContext(
            package=package,
            retrieval=retrieval,
            sources=tuple(sources),
            build_result=build_result,
        )
