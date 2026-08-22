from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "frontend" / "src" / "components" / "assistant"
ANSWER = COMPONENTS / "AssistantAnswer.tsx"
PANEL = COMPONENTS / "ContextualAssistantPanel.tsx"
PRESENTATION = COMPONENTS / "assistantPresentation.ts"
CLIENT = ROOT / "frontend" / "src" / "lib" / "assistant.ts"


def test_grounded_answer_uses_conversational_prose_with_subordinate_sources() -> None:
    source = ANSWER.read_text(encoding="utf-8")

    assert "response.blocks.map" in source
    assert "whitespace-pre-wrap" in source
    assert "BLOCK_LABELS" not in source
    assert "block.source_ids.map" not in source
    assert "block.provenance_classes.map" not in source
    assert "border-l-2 border-slate-700" not in source
    assert "Sources (" in source
    assert "<details" in source
    assert "<details open" not in source


def test_technical_details_only_expose_the_grounded_runtime_contract() -> None:
    source = ANSWER.read_text(encoding="utf-8")

    for label in (
        "Generation kind",
        "Queue wait",
        "Generation time",
        "Total latency",
        "Profile",
        "Model",
        "Semantic status",
        "Semantic elapsed",
        "Grounding validation",
        "Focus validation",
        "Fallback reason",
        "Source count",
        "Thinking disabled",
        "Effective intent",
        "Analysis scope",
        "Cross-incident context",
        "Semantic index",
        "Plan validation",
        "Context build",
        "Architecture",
        "Provider generations",
        "Automatic retries",
        "Model switches",
    ):
        assert label in source
    for retired in (
        "Citation validation",
        "Citation repair",
        "Reasoning retry",
        "Requested profile",
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
