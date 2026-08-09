from __future__ import annotations

from services.assistant.v3.contracts import (
    AdvisoryKnowledgeAtom,
    AnalysisScope,
    AnalyticalFocus,
    AnalyticalRelationship,
    AnswerIntent,
    AuthorityClass,
    ContextBuildMetrics,
    ContextLimits,
    ContextPlan,
    ContextRequirement,
    ConversationStateRefs,
    CrossIncidentEvidenceGraph,
    DetectionAtom,
    DiscoverySignal,
    FactField,
    HostAtom,
    IncidentCandidate,
    IncidentIdentityAtom,
    IntentSelection,
    MitreTechniqueAtom,
    Provenance,
    RecordedCorrelationAtom,
    ReferenceKnowledgeAtom,
    RelationshipClass,
    RelationshipRegistry,
    RelationshipType,
    ResolvedScope,
    RiskAtom,
    SourceRegistryEntry,
    StatusAtom,
    TimelineEventAtom,
    V3AnalyticalContextPackage,
)


def operational_provenance(incident_id: int) -> Provenance:
    return Provenance(
        authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
        source_type="incident",
        source_record_id=str(incident_id),
        source_id=f"S{incident_id}",
        retrieval_method="operational_query",
    )


def analytical_package(
    intent: AnswerIntent = AnswerIntent.CROSS_INCIDENT_ANALYSIS,
    *,
    include_semantic: bool = True,
    include_advisory: bool = True,
) -> V3AnalyticalContextPackage:
    p1 = operational_provenance(1)
    p2 = operational_provenance(2)
    atoms = [
        IncidentIdentityAtom(
            atom_id="incident:1:identity",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p1,
            incident_id=1,
            timestamp="2026-08-08T10:00:00Z",
        ),
        StatusAtom(
            atom_id="incident:1:status",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p1,
            incident_id=1,
            status="OPEN",
            canonical_severity=None,
        ),
        HostAtom(
            atom_id="incident:1:host",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p1,
            incident_id=1,
            host="endpoint-a",
            representation="agent",
        ),
        DetectionAtom(
            atom_id="incident:1:detection",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p1,
            incident_id=1,
            rule="Registry changed",
            level=10,
        ),
        MitreTechniqueAtom(
            atom_id="incident:1:mitre:T1112",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p1,
            incident_id=1,
            technique_id="T1112",
            technique_name="Modify Registry",
        ),
        RiskAtom(
            atom_id="incident:1:risk",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p1,
            incident_id=1,
            risk_score=72,
        ),
        RecordedCorrelationAtom(
            atom_id="incident:1:recorded-correlation",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p1,
            incident_id=1,
            correlated=True,
            correlation_type="endpoint_pattern",
            correlation_score=75,
        ),
        TimelineEventAtom(
            atom_id="incident:1:timeline",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p1,
            incident_id=1,
            timestamp="2026-08-08T10:01:00Z",
            event_type="INCIDENT_CREATED",
        ),
        IncidentIdentityAtom(
            atom_id="incident:2:identity",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p2,
            incident_id=2,
            timestamp="2026-08-08T11:00:00Z",
        ),
        StatusAtom(
            atom_id="incident:2:status",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p2,
            incident_id=2,
            status="INVESTIGATING",
            canonical_severity=None,
        ),
        HostAtom(
            atom_id="incident:2:host",
            authority_class=AuthorityClass.OPERATIONAL_AUTHORITATIVE,
            provenance=p2,
            incident_id=2,
            host="endpoint-a",
            representation="agent",
        ),
    ]
    analytical = AnalyticalRelationship(
        relationship_id="relationship:shared-host",
        relationship_class=RelationshipClass.ANALYTICAL_RELATIONSHIP,
        relationship_type=RelationshipType.SHARED_AGENT,
        authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
        left_incident_id=1,
        right_incident_id=2,
        evidence_atom_refs=["incident:1:host", "incident:2:host"],
        provenance=Provenance(
            authority_class=AuthorityClass.ANALYTICAL_DERIVATION,
            source_type="cross_incident_discovery",
            source_record_id="candidate:incident:2",
            retrieval_method="deterministic_derivation",
        ),
    )
    relationships = [analytical]
    signals = [DiscoverySignal.SHARED_AGENT]
    if include_semantic:
        signals.append(DiscoverySignal.SEMANTIC_SIMILARITY)
        relationships.append(
            AnalyticalRelationship(
                relationship_id="relationship:semantic",
                relationship_class=RelationshipClass.SEMANTIC_SIMILARITY,
                relationship_type=RelationshipType.SEMANTIC_SIMILARITY,
                authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
                left_incident_id=1,
                right_incident_id=2,
                evidence_atom_refs=["candidate:incident:2"],
                provenance=Provenance(
                    authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
                    source_type="incident_semantic_index",
                    source_record_id="candidate:incident:2",
                    retrieval_method="semantic_retrieval",
                ),
                strength=0.82,
            )
        )
    candidate = IncidentCandidate(
        candidate_id="candidate:incident:2",
        candidate_incident_id=2,
        discovery_signals=signals,
        semantic_score=0.82 if include_semantic else None,
        deterministic_signal_count=1,
        discovery_source="hybrid" if include_semantic else "deterministic",
        ranking_score=5.64,
    )
    reference = ReferenceKnowledgeAtom(
        knowledge_id="reference:mitre:T1112",
        knowledge_type="mitre_definition",
        subject="T1112",
        bounded_content="T1112 = Modify Registry.",
        provenance=Provenance(
            authority_class=AuthorityClass.REFERENCE_KNOWLEDGE,
            source_type="project_mitre_catalog",
            source_record_id="services/assistant/v3/knowledge.py",
            retrieval_method="project_catalog",
        ),
    )
    advisories = []
    if include_advisory:
        advisories.append(
            AdvisoryKnowledgeAtom(
                knowledge_id="advisory:registry-review",
                knowledge_type="playbook_guidance",
                subject="Registry investigation playbook",
                guidance_code="review_telemetry",
                bounded_content="Review registry and adjacent process telemetry.",
                provenance=Provenance(
                    authority_class=AuthorityClass.ADVISORY_KNOWLEDGE,
                    source_type="knowledge_base",
                    source_record_id="registry-review",
                    source_id="S3",
                    retrieval_method="semantic_retrieval",
                ),
            )
        )
    available_refs = [item.atom_id for item in atoms] + [candidate.candidate_id]
    graph = CrossIncidentEvidenceGraph(
        incident_ids=[1, 2],
        relationships=relationships,
        available_evidence_refs=available_refs,
    )
    source_registry = [
        SourceRegistryEntry(
            source_ref=item.atom_id,
            authority_class=item.authority_class,
            source_type=item.provenance.source_type,
            source_record_id=item.provenance.source_record_id,
        )
        for item in atoms
    ]
    source_registry.extend(
        [
            SourceRegistryEntry(
                source_ref=candidate.candidate_id,
                authority_class=AuthorityClass.SEMANTIC_CANDIDATE,
                source_type="cross_incident_candidate",
                source_record_id="2",
            ),
            SourceRegistryEntry(
                source_ref=reference.knowledge_id,
                authority_class=AuthorityClass.REFERENCE_KNOWLEDGE,
                source_type=reference.provenance.source_type,
                source_record_id=reference.provenance.source_record_id,
            ),
        ]
    )
    source_registry.extend(
        SourceRegistryEntry(
            source_ref=item.knowledge_id,
            authority_class=AuthorityClass.ADVISORY_KNOWLEDGE,
            source_type=item.provenance.source_type,
            source_record_id=item.provenance.source_record_id,
        )
        for item in advisories
    )
    return V3AnalyticalContextPackage(
        question="Explain this incident and related incidents.",
        response_language="en",
        intent_selection=IntentSelection(
            primary_intent=intent,
            confidence=1.0,
            routing_status="ok",
            routing_ms=0.0,
        ),
        focus_selection=[AnalyticalFocus.CORRELATION, AnalyticalFocus.EVIDENCE],
        resolved_scope=ResolvedScope(
            analysis_scope=(
                AnalysisScope.RELATED_INCIDENTS
                if intent
                in {
                    AnswerIntent.COMPARE,
                    AnswerIntent.CROSS_INCIDENT_ANALYSIS,
                    AnswerIntent.PATTERN_ANALYSIS,
                }
                else AnalysisScope.CURRENT_RECORD
            ),
            active_incident_ids=[1],
        ),
        context_plan=ContextPlan(
            intent=intent,
            analysis_scope=AnalysisScope.RELATED_INCIDENTS,
            requirements=[
                ContextRequirement.IDENTITY,
                ContextRequirement.STATUS,
                ContextRequirement.CROSS_INCIDENT,
                ContextRequirement.REFERENCE,
                ContextRequirement.ADVISORY,
            ],
            fact_fields=[
                FactField.SOURCE_TYPE,
                FactField.INCIDENT_ID,
                FactField.STATUS,
                FactField.SEVERITY,
                FactField.AGENT,
                FactField.RULE,
                FactField.WAZUH_LEVEL,
                FactField.RISK_SCORE,
                FactField.MITRE,
                FactField.CORRELATED,
                FactField.CORRELATION_TYPE,
                FactField.CORRELATION_SCORE,
                FactField.LATEST_TIMELINE_EVENT,
            ],
            include_cross_incident=True,
            include_reference=True,
            include_advisory=include_advisory,
            limits=ContextLimits(),
        ),
        operational_atoms=atoms,
        reference_atoms=[reference],
        advisory_atoms=advisories,
        cross_incident_candidates=[candidate],
        cross_incident_graph=graph,
        conversation_state_refs=ConversationStateRefs(active_incident_ids=[1]),
        context_limits=ContextLimits(),
        source_registry=source_registry,
        relationship_registry=RelationshipRegistry(relationships=relationships),
        metrics=ContextBuildMetrics(),
    )
