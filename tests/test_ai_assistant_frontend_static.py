from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "frontend" / "src" / "components" / "assistant"
ANSWER = COMPONENTS / "AssistantAnswer.tsx"
TECHNICAL_DETAILS = COMPONENTS / "AssistantTechnicalDetails.tsx"
CAPABILITY_DETAILS = COMPONENTS / "AssistantCapabilityDetails.tsx"
PANEL = COMPONENTS / "ContextualAssistantPanel.tsx"
GLOBAL_WORKSPACE = COMPONENTS / "GlobalAssistantWorkspace.tsx"
STATES = COMPONENTS / "AssistantStates.tsx"
PRESENTATION = COMPONENTS / "assistantPresentation.ts"
CLIENT = ROOT / "frontend" / "src" / "lib" / "assistant.ts"


def test_grounded_answer_uses_typed_hierarchy_and_direct_source_links() -> None:
    source = ANSWER.read_text(encoding="utf-8")

    assert "answerBlocks.map" in source
    assert "whitespace-pre-wrap" in source
    assert "ASSISTANT_BLOCK_LABELS" in source
    assert "block.source_ids.map" in source
    assert "block.provenance_classes.map" in source
    assert 'href={`#${sourceTargetId}`}' in source
    assert "document.getElementById(sourceTargetId)?.focus()" in source
    assert "Evidence and sources" in source
    assert "Limitations" in source
    assert source.index("Evidence and sources") < source.index("Limitations")
    assert "<AssistantSources" in source
    assert "<details" not in source


def test_technical_details_expose_the_complete_grounded_runtime_contract() -> None:
    source = TECHNICAL_DETAILS.read_text(encoding="utf-8")

    for label in (
        "Requested mode",
        "Semantic memory requested",
        "Response generation kind",
        "Metadata generation kind",
        "Queue wait",
        "Generation time",
        "Total latency",
        "Effective profile",
        "Effective model",
        "Semantic retrieval",
        "Semantic elapsed",
        "Grounding validation",
        "Focus validation",
        "Fallback reason",
        "Source count",
        "Thinking disabled",
        "Effective intent",
        "Secondary intents",
        "Analysis scope",
        "Cross-incident candidates",
        "Semantic index",
        "Semantic proof",
        "Plan validation",
        "Context build",
        "Architecture",
        "Provider generations",
        "Automatic retries",
        "Model switches",
        "Prompt tokens",
        "Structured output tokens",
        "Analytics plan fingerprint",
    ):
        assert label in source

    for metadata_field in (
        "generation_kind",
        "queue_wait_ms",
        "generation_ms",
        "total_latency_ms",
        "effective_profile",
        "effective_model",
        "semantic_status",
        "semantic_elapsed_ms",
        "semantic_degraded",
        "grounding_validation",
        "focus_validation",
        "fallback_reason",
        "response_language",
        "thinking_disabled",
        "source_count",
        "assistant_intent",
        "secondary_intents",
        "analysis_scope",
        "context_atoms",
        "operational_atoms",
        "reference_atoms",
        "advisory_atoms",
        "cross_incident_candidates",
        "graph_edges",
        "conversation_followup",
        "context_build_ms",
        "intent_routing_ms",
        "focus_routing_ms",
        "scope_resolution_ms",
        "context_policy_ms",
        "operational_retrieval_ms",
        "atom_normalization_ms",
        "semantic_candidate_ms",
        "semantic_index_query_ms",
        "authoritative_rehydration_ms",
        "semantic_raw_candidates",
        "semantic_threshold_rejects",
        "semantic_invalid_rejects",
        "semantic_duplicate_rejects",
        "semantic_excluded_rejects",
        "cross_incident_candidates_discovered",
        "authoritative_rehydration_count",
        "stale_candidate_rejects",
        "graph_ms",
        "reference_retrieval_ms",
        "advisory_retrieval_ms",
        "conversation_state_ms",
        "response_architecture",
        "plan_sections",
        "plan_units",
        "cross_incident_units",
        "reference_units",
        "advisory_units",
        "plan_validation_status",
        "schema_build_ms",
        "schema_chars",
        "plan_validation_ms",
        "rendering_ms",
        "prompt_chars",
        "prompt_tokens",
        "structured_output_tokens",
        "provider_generation_count",
        "automatic_retries",
        "model_switches",
        "finish_reason",
        "semantic_proof_status",
        "semantic_proof_ms",
        "semantic_proof_pairs",
        "typed_guard_rejects",
        "deterministic_proofs",
        "nli_proofs",
        "semantic_proof_model",
        "semantic_proof_revision",
        "semantic_index_status",
        "analytics_operation",
        "analytics_entity",
        "analytics_definition_id",
        "analytics_query_plan_fingerprint",
        "analytics_result_count",
        "analytics_window_start_utc",
        "analytics_window_end_utc",
    ):
        assert f"metadata.{metadata_field}" in source

    for retired in (
        "Citation validation",
        "Citation repair",
        "Reasoning retry",
        "Prompt evaluation",
        "Cache state",
    ):
        assert retired not in source


def test_readiness_is_manual_and_reports_gateway_states() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert 'capabilities.runtime_state === "warming"' in source
    assert 'capabilities.runtime_state === "ready"' in source
    assert 'label: "WARMING"' in source
    assert 'label: "READY"' in source
    assert "Refresh Assistant readiness" in source
    assert "setInterval" not in source
    assert "setTimeout" not in source
    assert "conversation_id: currentConversationId()" in source
    assert "key={`${props.scope}:${props.targetId}`}" in source
    assert "capabilities.semantic_runtime_state" in source


def test_global_and_contextual_turns_preserve_request_metadata_and_shared_states() -> None:
    global_source = GLOBAL_WORKSPACE.read_text(encoding="utf-8")
    contextual_source = PANEL.read_text(encoding="utf-8")
    state_source = STATES.read_text(encoding="utf-8")

    for source in (global_source, contextual_source):
        assert "requestedMode" in source
        assert "semanticMemoryRequested" in source
        assert "<AssistantGenerationState" in source
        assert "<AssistantFailureState" in source
        assert "<AssistantCapabilityDetails" in source

    assert "No answer published" in state_source
    assert "No fallback answer returned" in state_source
    assert "No {scope} state was changed." in state_source
    assert "Try again" in state_source


def test_runtime_details_preserve_every_capability_field() -> None:
    source = CAPABILITY_DETAILS.read_text(encoding="utf-8")

    for capability_field in (
        "feature_key",
        "enabled",
        "runtime_state",
        "runtime_message",
        "default_profile",
        "loaded_profile",
        "supported_scopes",
        "supported_modes",
        "persistent_conversations",
        "streaming",
        "project_documentation_indexed",
        "semantic_memory_supported",
        "write_actions_supported",
        "semantic_runtime_state",
        "embedding_backend",
        "embedding_cache_state",
        "semantic_proof_runtime_state",
        "semantic_proof_model",
        "semantic_proof_revision",
        "decision_boundary",
    ):
        assert f"capabilities.{capability_field}" in source


def test_conversation_timeline_preserves_turns_and_pending_state() -> None:
    source = PANEL.read_text(encoding="utf-8")

    assert "AssistantTimelineTurn" in source
    assert "setTurns((current) => [" in source
    assert 'status: "pending"' in source
    assert 'status: "completed"' in source
    assert 'role="log"' in source
    assert 'aria-label="SOC Assistant conversation"' in source
    assert "turns.map" in source
    assert "setResponse(null)" not in source
    assert "timelineEndRef.current?.scrollIntoView" in source


def test_v3_provenance_classes_are_readable_and_semantically_distinct() -> None:
    source = (COMPONENTS / "AssistantSources.tsx").read_text(encoding="utf-8")

    for label in (
        "Operational source",
        "Reference knowledge",
        "Advisory / playbook",
        "Analytical relationship",
        "Semantic candidate",
    ):
        assert label in PRESENTATION.read_text(encoding="utf-8")
    assert "PROVENANCE_ORDER" in source
    assert "Semantic similarity is advisory" in source
    assert "provenance_class" in source


def test_client_contract_is_structured_and_internal_links_are_safe() -> None:
    source = CLIENT.read_text(encoding="utf-8")

    assert 'export type AssistantGenerationKind = "model" | "deterministic_fallback"' in source
    assert 'export type AssistantSemanticState' in source
    assert "blocks: AssistantResponseBlock[]" in source
    assert "!Array.isArray(response.blocks)" in source
    assert "isSafeInternalAssistantUrl" in source
    assert '!value.startsWith("/") || value.startsWith("//")' in source
    assert "citation" not in source.lower()
    assert "repair" not in source.lower()
    for fallback_reason in (
        "invalid_visible_output",
        "invalid_json",
        "invalid_json_type",
        "invalid_structured_claim_schema",
    ):
        assert fallback_reason in source
    assert "AI generation timed out." in source
    assert "The governed AI provider is currently unavailable." in source
    assert 'kind: "aborted"' in source


def test_frontend_has_no_direct_provider_or_unsafe_html_path() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [*COMPONENTS.glob("*.tsx"), PRESENTATION, CLIENT]
    )
    for forbidden in (
        "dangerouslySetInnerHTML",
        ".innerHTML",
        "127.0.0.1:8081",
        "localhost:8081",
        "/v1/chat/completions",
        "reasoning_content",
        "/no_think",
        "chat_template_kwargs",
        "[S#]",
    ):
        assert forbidden not in source
