from __future__ import annotations

import pytest
from pydantic import ValidationError

from schemas.assistant import (
    AssistantQueryRequest,
    AssistantQueryResponse,
    AssistantResponseBlock,
    AssistantSource,
)


def test_scope_ids_are_closed_and_deterministic() -> None:
    incident = AssistantQueryRequest(
        message=" Explain ",
        scope="incident",
        incident_id=245,
    )
    assert incident.message == "Explain"
    assert incident.requested_mode == "auto"

    invalid_payloads = (
        {"message": "x", "scope": "incident"},
        {"message": "x", "scope": "case", "case_id": 4, "incident_id": 3},
        {"message": "x", "scope": "global", "case_id": 4},
        {"message": "x", "scope": "global", "requested_mode": "quality"},
        {"message": "x", "scope": "global", "provider": "local_ollama"},
    )
    for payload in invalid_payloads:
        with pytest.raises(ValidationError):
            AssistantQueryRequest.model_validate(payload)

    with pytest.raises(ValidationError):
        AssistantQueryRequest(
            message="Continue",
            scope="incident",
            incident_id=245,
            conversation_id="unsafe thread",
        )


def test_source_urls_must_be_internal_paths() -> None:
    valid = AssistantSource(
        source_id="S1",
        source_type="incident",
        authority="authoritative",
        label="Incident 245",
        url="/incidents/245",
    )
    assert valid.url == "/incidents/245"

    for unsafe in (
        "https://example.invalid",
        "//example.invalid/path",
        "/incidents/../admin",
        "/incidents/245 bad",
    ):
        with pytest.raises(ValidationError):
            AssistantSource(
                source_id="S1",
                source_type="incident",
                authority="authoritative",
                label="Incident",
                url=unsafe,
            )


def test_response_rejects_unknown_backend_source_reference() -> None:
    with pytest.raises(ValidationError):
        AssistantQueryResponse(
            status="ok",
            generation_kind="model",
            answer="Grounded answer.",
            blocks=[
                AssistantResponseBlock(
                    kind="direct_answer",
                    text="Grounded answer.",
                    source_ids=["S2"],
                )
            ],
            scope="incident",
            incident_id=245,
            sources=[
                AssistantSource(
                    source_id="S1",
                    source_type="incident",
                    authority="authoritative",
                    label="Incident 245",
                    url="/incidents/245",
                )
            ],
        )


def test_response_contract_has_only_grounded_runtime_metadata() -> None:
    response = AssistantQueryResponse(
        status="fallback",
        generation_kind="deterministic_fallback",
        answer="Recorded facts remain available.",
        blocks=[
            AssistantResponseBlock(
                kind="direct_answer",
                text="Recorded facts remain available.",
            )
        ],
        scope="global",
    )
    metadata = response.metadata.model_dump()

    assert metadata["effective_profile"] == "standard"
    assert metadata["effective_model"] == "ai-soc-standard"
    assert metadata["thinking_disabled"] is True
    for retired in (
        "citation_validation_status",
        "citation_repair_attempted",
        "reasoning_retry_performed",
        "requested_profile",
        "provider_base_url",
    ):
        assert retired not in metadata
