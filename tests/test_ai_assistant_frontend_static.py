from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = ROOT / "frontend" / "src" / "components" / "assistant"
ANSWER = COMPONENTS / "AssistantAnswer.tsx"
PANEL = COMPONENTS / "ContextualAssistantPanel.tsx"
PRESENTATION = COMPONENTS / "assistantPresentation.ts"
CLIENT = ROOT / "frontend" / "src" / "lib" / "assistant.ts"


def test_grounded_blocks_have_adjacent_source_chips() -> None:
    source = ANSWER.read_text(encoding="utf-8")

    for label in ("Direct answer", "Analysis", "Next check", "Limitations"):
        assert label in source
    assert "block.source_ids.map" in source
    assert "revealSource(sourceId)" in source
    assert "source.authority" in source
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


def test_client_contract_is_structured_and_internal_links_are_safe() -> None:
    source = CLIENT.read_text(encoding="utf-8")

    assert 'export type AssistantGenerationKind = "model" | "deterministic_fallback"' in source
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
