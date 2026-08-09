from __future__ import annotations

import time
from typing import Any, Callable, Mapping

from services.assistant.focus import FocusSelection
from services.assistant.v3.atoms import OperationalAtomNormalizer, authoritative_source_ids
from services.assistant.v3.contracts import (
    AnalyticalFocus,
    AnswerIntent,
    AuthorityClass,
    ContextBuildMetrics,
    ConversationStateRefs,
    IntentSelection,
    RelationshipRegistry,
    SourceRegistryEntry,
    V3AnalyticalContextPackage,
)
from services.assistant.v3.conversation import (
    ConversationStateStore,
    conversation_owner_key,
    get_conversation_state_store,
    updated_conversation_state,
)
from services.assistant.v3.cross_incident import (
    CrossIncidentCandidateRetriever,
    SemanticIncidentHit,
    semantic_incident_hits,
)
from services.assistant.v3.graph import CrossIncidentGraphBuilder
from services.assistant.v3.knowledge import (
    ReferenceKnowledgeProvider,
    normalize_advisory_sources,
)
from services.assistant.v3.policy import ContextPolicyEngine, resolve_analysis_scope
from services.assistant.v3.semantic_index import (
    IncidentSemanticIndex,
    get_incident_semantic_index,
    semantic_query_text_from_facts,
)


class V3AnalyticalContextBuilder:
    def __init__(
        self,
        *,
        policy_engine: ContextPolicyEngine | None = None,
        atom_normalizer: OperationalAtomNormalizer | None = None,
        candidate_retriever: CrossIncidentCandidateRetriever | None = None,
        graph_builder: CrossIncidentGraphBuilder | None = None,
        reference_provider: ReferenceKnowledgeProvider | None = None,
        conversation_store: ConversationStateStore | None = None,
        incident_semantic_index: IncidentSemanticIndex | None = None,
    ) -> None:
        self._policy = policy_engine or ContextPolicyEngine()
        self._atoms = atom_normalizer or OperationalAtomNormalizer()
        self._candidates = candidate_retriever or CrossIncidentCandidateRetriever()
        self._graph = graph_builder or CrossIncidentGraphBuilder()
        self._reference = reference_provider or ReferenceKnowledgeProvider()
        self._conversations = conversation_store or get_conversation_state_store()
        self._incident_index = incident_semantic_index or get_incident_semantic_index()

    def build(
        self,
        *,
        payload: Any,
        response_language: str,
        intent_selection: IntentSelection,
        focus_selection: FocusSelection,
        retrieval: Any,
        db: Any,
        current_user: Mapping[str, Any] | None,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> V3AnalyticalContextPackage:
        started = clock()
        owner_key = conversation_owner_key(current_user)
        conversation_started = clock()
        conversation = self._conversations.load(
            owner_key=owner_key,
            conversation_id=getattr(payload, "conversation_id", None),
            db=db,
        )
        conversation_ms = max(0.0, (clock() - conversation_started) * 1000)
        cross_intents = {
            AnswerIntent.COMPARE,
            AnswerIntent.CROSS_INCIDENT_ANALYSIS,
            AnswerIntent.PATTERN_ANALYSIS,
        }
        linked_incident_facts: list[dict[str, Any]] = []
        linked_incidents = retrieval.fact_inventory.get("linked_incidents")
        if isinstance(linked_incidents, list):
            for linked in linked_incidents:
                if not isinstance(linked, dict) or not isinstance(
                    linked.get("incident_id"), int
                ):
                    continue
                facts = {"source_type": "incident", **linked}
                if payload.case_id is not None:
                    facts["linked_case_ids"] = [payload.case_id]
                linked_incident_facts.append(facts)
        requested_compare_incident_ids = list(
            getattr(payload, "compare_incident_ids", []) or []
        )
        explicit_incident_ids = list(requested_compare_incident_ids)
        if (
            intent_selection.primary_intent in cross_intents
            and payload.case_id is not None
        ):
            explicit_incident_ids.extend(
                facts["incident_id"] for facts in linked_incident_facts
            )
        resolved_scope = resolve_analysis_scope(
            request_scope=payload.scope,
            incident_id=payload.incident_id,
            case_id=payload.case_id,
            intent=intent_selection,
            conversation_state=conversation,
            explicit_incident_ids=explicit_incident_ids,
            explicit_compare_incident_ids=requested_compare_incident_ids,
        )
        plan = self._policy.plan(
            intent=intent_selection,
            focus=focus_selection,
            resolved_scope=resolved_scope,
            available_facts=retrieval.fact_inventory,
            conversation_state=conversation,
            clock=clock,
        )
        assigned_sources = list(retrieval.sources)
        source_ids = authoritative_source_ids(assigned_sources)
        atom_started = clock()
        operational_atoms = self._atoms.normalize(
            facts=retrieval.fact_inventory,
            plan=plan,
            source_ids=source_ids,
        )
        if linked_incident_facts:
            for linked in linked_incident_facts[: plan.limits.max_graph_incidents]:
                operational_atoms.extend(
                    self._atoms.normalize(
                        facts=linked,
                        plan=plan,
                        source_ids=source_ids,
                    )
                )
        atom_ms = max(0.0, (clock() - atom_started) * 1000)

        candidate_result = None
        anchor_facts = None
        if payload.incident_id is not None:
            anchor_facts = retrieval.fact_inventory
        elif linked_incident_facts:
            anchor_facts = linked_incident_facts[0]
        anchor_incident_id = (
            anchor_facts.get("incident_id") if anchor_facts is not None else None
        )
        semantic_index_status = "not_requested"
        semantic_index_query_ms = 0.0
        if plan.include_cross_incident and isinstance(anchor_incident_id, int):
            selected_incident_ids = [
                value
                for value in resolved_scope.active_incident_ids
                if value != anchor_incident_id
            ]
            semantic_hits = semantic_incident_hits(assigned_sources)
            semantic_result = self._incident_index.query(
                semantic_query_text_from_facts(anchor_facts),
                exclude_incident_id=anchor_incident_id,
                limit=plan.limits.max_candidates_discovered,
            )
            semantic_index_status = semantic_result.status
            semantic_index_query_ms = semantic_result.query_ms
            if semantic_result.status == "ready":
                semantic_hits = [
                    SemanticIncidentHit(
                        incident_id=item.incident_id,
                        score=item.score,
                        source_fingerprint=item.source_fingerprint,
                    )
                    for item in semantic_result.hits
                ]
            candidate_result = self._candidates.retrieve(
                db=db,
                anchor_facts=anchor_facts,
                semantic_hits=semantic_hits,
                explicit_incident_ids=selected_incident_ids,
                limits=plan.limits,
                clock=clock,
            )
            for incident in candidate_result.incidents:
                operational_atoms.extend(
                    self._atoms.normalize(
                        facts=incident.facts,
                        plan=plan,
                        source_ids=source_ids,
                    )
                )
        candidates = list(candidate_result.candidates) if candidate_result else []
        requested_active = set(resolved_scope.active_incident_ids)
        validated_active = [
            incident_id
            for incident_id in [
                anchor_incident_id,
                *(item.candidate_incident_id for item in candidates),
            ]
            if isinstance(incident_id, int) and incident_id in requested_active
        ]
        if requested_active:
            resolved_scope = resolved_scope.model_copy(
                update={"active_incident_ids": list(dict.fromkeys(validated_active))}
            )
        operational_atoms = list(
            {atom.atom_id: atom for atom in operational_atoms}.values()
        )[: plan.limits.max_operational_atoms]

        graph_started = clock()
        graph = self._graph.build(
            anchor_incident_id=anchor_incident_id,
            candidates=candidates,
            operational_atoms=operational_atoms,
            max_incidents=plan.limits.max_graph_incidents,
        )
        graph_ms = max(0.0, (clock() - graph_started) * 1000)

        reference_started = clock()
        reference_atoms = self._reference.retrieve(
            plan=plan,
            operational_atoms=operational_atoms,
        )
        reference_ms = max(0.0, (clock() - reference_started) * 1000)
        advisory_started = clock()
        advisory_atoms = normalize_advisory_sources(assigned_sources, plan=plan)
        advisory_ms = max(0.0, (clock() - advisory_started) * 1000)

        focus_dimensions = [AnalyticalFocus(item.value) for item in focus_selection.dimensions]
        conversation_id = getattr(payload, "conversation_id", None)
        if conversation_id:
            state = updated_conversation_state(
                existing=conversation,
                conversation_id=conversation_id,
                owner_key=owner_key,
                active_incident_ids=resolved_scope.active_incident_ids,
                active_case_ids=resolved_scope.active_case_ids,
                related_incident_ids=[item.candidate_incident_id for item in candidates],
                intent=intent_selection.primary_intent,
                focus_dimensions=focus_dimensions,
                atom_refs=[item.atom_id for item in operational_atoms],
                relationship_refs=[item.relationship_id for item in graph.relationships],
                reference_refs=[item.knowledge_id for item in reference_atoms],
                advisory_refs=[item.knowledge_id for item in advisory_atoms],
                response_language=response_language,
                now=wall_clock(),
            )
            self._conversations.save(state)
            conversation_refs = ConversationStateRefs(
                conversation_id=state.conversation_id,
                active_incident_ids=state.active_incident_ids,
                active_case_ids=state.active_case_ids,
                related_incident_ids=state.related_incident_ids,
                validated_atom_refs=state.validated_atom_refs,
                validated_relationship_refs=state.validated_relationship_refs,
            )
        else:
            conversation_refs = ConversationStateRefs(
                active_incident_ids=resolved_scope.active_incident_ids,
                active_case_ids=resolved_scope.active_case_ids,
                related_incident_ids=[item.candidate_incident_id for item in candidates],
                validated_atom_refs=[item.atom_id for item in operational_atoms],
                validated_relationship_refs=[item.relationship_id for item in graph.relationships],
            )

        registry: dict[str, SourceRegistryEntry] = {}
        for atom in operational_atoms:
            registry[atom.atom_id] = SourceRegistryEntry(
                source_ref=atom.atom_id,
                authority_class=atom.authority_class,
                source_type=atom.provenance.source_type,
                source_record_id=atom.provenance.source_record_id,
            )
        for atom in [*reference_atoms, *advisory_atoms]:
            registry[atom.knowledge_id] = SourceRegistryEntry(
                source_ref=atom.knowledge_id,
                authority_class=atom.authority_class,
                source_type=atom.provenance.source_type,
                source_record_id=atom.provenance.source_record_id,
            )
        for candidate in candidates:
            registry[candidate.candidate_id] = SourceRegistryEntry(
                source_ref=candidate.candidate_id,
                authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
                source_type="cross_incident_candidate",
                source_record_id=str(candidate.candidate_incident_id),
            )
        total_ms = max(
            0.0,
            (clock() - started) * 1000
            + intent_selection.routing_ms
            + focus_selection.focus_routing_ms,
        )
        return V3AnalyticalContextPackage(
            question=payload.message,
            response_language="it" if response_language == "it" else "en",
            intent_selection=intent_selection,
            focus_selection=focus_dimensions,
            resolved_scope=resolved_scope,
            context_plan=plan,
            operational_atoms=operational_atoms,
            reference_atoms=reference_atoms,
            advisory_atoms=advisory_atoms,
            cross_incident_candidates=candidates,
            cross_incident_graph=graph,
            conversation_state_refs=conversation_refs,
            context_limits=plan.limits,
            source_registry=list(registry.values()),
            relationship_registry=RelationshipRegistry(relationships=graph.relationships),
            semantic_index_status=semantic_index_status,
            metrics=ContextBuildMetrics(
                intent_routing_ms=intent_selection.routing_ms,
                focus_routing_ms=focus_selection.focus_routing_ms,
                context_policy_ms=plan.policy_ms,
                atom_normalization_ms=atom_ms,
                candidate_retrieval_ms=(
                    candidate_result.candidate_retrieval_ms if candidate_result else 0.0
                ),
                semantic_index_query_ms=semantic_index_query_ms,
                authoritative_rehydration_ms=(
                    candidate_result.authoritative_rehydration_ms if candidate_result else 0.0
                ),
                graph_construction_ms=graph_ms,
                reference_retrieval_ms=reference_ms,
                advisory_retrieval_ms=advisory_ms,
                conversation_state_ms=conversation_ms,
                total_context_build_ms=total_ms,
            ),
        )
