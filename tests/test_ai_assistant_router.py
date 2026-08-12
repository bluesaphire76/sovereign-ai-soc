from __future__ import annotations

from fastapi import HTTPException
from fastapi.testclient import TestClient

from api import app
from schemas.assistant import (
    AssistantMetadata,
    AssistantQueryResponse,
    AssistantResponseBlock,
    AssistantSource,
)
from services.assistant.orchestrator import AssistantError


client = TestClient(app)


def _auth(monkeypatch, role: str = "ANALYST") -> None:
    monkeypatch.setattr(
        "security.rbac.get_current_user",
        lambda authorization: {"id": 1, "username": "ana", "role": role},
    )
    monkeypatch.setattr(
        "security.rbac.mark_active_user",
        lambda current_user: None,
    )
    monkeypatch.setattr(
        "security.rbac.write_security_audit",
        lambda **kwargs: None,
    )


def _assistant_response() -> AssistantQueryResponse:
    return AssistantQueryResponse(
        status="ok",
        generation_kind="model",
        answer="Incident 245 has recorded severity LOW.",
        blocks=[
            AssistantResponseBlock(
                kind="direct_answer",
                text="Incident 245 has recorded severity LOW.",
                source_ids=["S1"],
            )
        ],
        scope="incident",
        incident_id=245,
        sources=[
            AssistantSource(
                source_id="S1",
                source_type="incident",
                authority="authoritative",
                record_id="245",
                label="Incident 245",
                url="/incidents/245",
            )
        ],
        metadata=AssistantMetadata(
            generation_kind="model",
            queue_wait_ms=10,
            generation_ms=420,
            total_latency_ms=500,
            semantic_status="ok",
            grounding_validation="passed",
            focus_validation="passed",
            source_count=1,
        ),
    )


def test_capabilities_endpoint_is_authenticated_and_gateway_owned(
    monkeypatch,
) -> None:
    _auth(monkeypatch, role="ADMIN")
    monkeypatch.setattr(
        "services.assistant.orchestrator.assistant_runtime_snapshot",
        lambda: {
            "runtime_state": "ready",
            "loaded_profile": "standard",
            "runtime_message": "Standard inference model is ready.",
        },
    )
    monkeypatch.setenv("AI_SOC_ASSISTANT_ENABLED", "true")

    response = client.get(
        "/assistant/capabilities",
        headers={"Authorization": "Bearer test"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is True
    assert payload["supported_modes"] == ["auto", "standard"]
    assert payload["runtime_state"] == "ready"
    assert payload["loaded_profile"] == "standard"
    assert "router_base_url" not in payload


def test_query_endpoint_returns_blocks_and_safe_slim_audit(
    monkeypatch,
) -> None:
    _auth(monkeypatch)
    audits = []
    monkeypatch.setattr(
        "routers.assistant.run_assistant_query",
        lambda payload, current_user=None: _assistant_response(),
    )
    monkeypatch.setattr(
        "routers.assistant.write_security_audit",
        lambda **kwargs: audits.append(kwargs),
    )

    response = client.post(
        "/assistant/query",
        headers={"Authorization": "Bearer test"},
        json={
            "message": "Raw question should not be stored",
            "scope": "incident",
            "incident_id": 245,
        },
    )

    assert response.status_code == 200
    assert response.json()["blocks"][0]["source_ids"] == ["S1"]
    details = audits[0]["details"]
    assert audits[0]["event_type"] == "AI_ASSISTANT_QUERY_COMPLETED"
    assert "message_sha256" in details
    assert "Raw question should not be stored" not in str(details)
    assert details["source_type_counts"] == {"incident": 1}
    assert details["source_refs"] == [
        {
            "source_id": "S1",
            "source_type": "incident",
            "record_id": "245",
            "provenance_class": "operational_source",
        }
    ]
    assert details["generation_kind"] == "model"
    assert details["effective_profile"] == "standard"
    assert details["effective_model"] == "ai-soc-standard"
    assert details["grounding_validation"] == "passed"
    assert details["focus_validation"] == "passed"
    assert "citation" not in str(details).lower()
    assert "prompt" not in str(details).lower()
    assert "answer" not in str(details).lower()


def test_query_endpoint_maps_expected_and_unexpected_failures_safely(
    monkeypatch,
) -> None:
    _auth(monkeypatch)
    audits = []
    monkeypatch.setattr(
        "routers.assistant.write_security_audit",
        lambda **kwargs: audits.append(kwargs),
    )
    monkeypatch.setattr(
        "routers.assistant.run_assistant_query",
        lambda payload, current_user=None: (_ for _ in ()).throw(
            AssistantError(
                category="IncidentNotFound",
                status_code=404,
                message="Incident not found.",
            )
        ),
    )
    missing = client.post(
        "/assistant/query",
        headers={"Authorization": "Bearer test"},
        json={"message": "Explain", "scope": "incident", "incident_id": 999},
    )
    assert missing.status_code == 404
    assert missing.json()["detail"]["error_category"] == "IncidentNotFound"

    monkeypatch.setattr(
        "routers.assistant.run_assistant_query",
        lambda payload, current_user=None: (_ for _ in ()).throw(
            RuntimeError("private provider path")
        ),
    )
    failed = client.post(
        "/assistant/query",
        headers={"Authorization": "Bearer test"},
        json={"message": "Do not store me", "scope": "global"},
    )
    assert failed.status_code == 503
    assert "private provider path" not in str(failed.json())
    assert "Do not store me" not in str(audits[-1]["details"])


def test_viewer_and_unauthenticated_requests_are_denied(monkeypatch) -> None:
    _auth(monkeypatch, role="VIEWER")
    viewer = client.get(
        "/assistant/capabilities",
        headers={"Authorization": "Bearer test"},
    )
    assert viewer.status_code == 403

    monkeypatch.setattr(
        "security.rbac.get_current_user",
        lambda authorization: (_ for _ in ()).throw(
            HTTPException(status_code=401, detail="Authentication required.")
        ),
    )
    assert client.get("/assistant/capabilities").status_code == 401
