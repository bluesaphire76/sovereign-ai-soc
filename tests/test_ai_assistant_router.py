from __future__ import annotations

from fastapi import HTTPException
from fastapi.testclient import TestClient

from api import app
from schemas.assistant import AssistantMetadata, AssistantQueryResponse, AssistantSource
from services.assistant.orchestrator import AssistantError


client = TestClient(app)


def _auth(monkeypatch, role: str = "ANALYST") -> None:
    monkeypatch.setattr(
        "security.rbac.get_current_user",
        lambda authorization: {"id": 1, "username": "ana", "role": role},
    )
    monkeypatch.setattr("security.rbac.mark_active_user", lambda current_user: None)
    monkeypatch.setattr("security.rbac.write_security_audit", lambda **kwargs: None)


def _assistant_response() -> AssistantQueryResponse:
    return AssistantQueryResponse(
        status="success",
        answer="Grounded answer [S1].",
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
        limitations=[],
        metadata=AssistantMetadata(
            provider_key="local_llama_cpp",
            provider_type="LOCAL_LLAMA_CPP",
            profile="standard",
            model="ai-soc-standard",
            latency_ms=12,
        ),
    )


def test_capabilities_endpoint_is_authenticated_and_safe(monkeypatch) -> None:
    _auth(monkeypatch, role="ADMIN")
    monkeypatch.setenv("AI_SOC_ASSISTANT_ENABLED", "false")

    response = client.get("/assistant/capabilities", headers={"Authorization": "Bearer test"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["enabled"] is False
    assert payload["feature_key"] == "soc_assistant"
    assert payload["supported_scopes"] == ["global", "incident", "case"]
    assert "router_base_url" not in payload
    assert "prompt" not in payload


def test_query_endpoint_returns_response_and_safe_audit(monkeypatch) -> None:
    _auth(monkeypatch, role="ANALYST")
    audits = []
    monkeypatch.setattr("routers.assistant.run_assistant_query", lambda payload, current_user=None: _assistant_response())
    monkeypatch.setattr("routers.assistant.write_security_audit", lambda **kwargs: audits.append(kwargs))

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
    assert response.json()["answer"] == "Grounded answer [S1]."
    assert audits[0]["event_type"] == "AI_ASSISTANT_QUERY_COMPLETED"
    details = audits[0]["details"]
    assert "message_sha256" in details
    assert "Raw question should not be stored" not in str(details)
    assert details["source_type_counts"] == {"incident": 1}


def test_query_endpoint_maps_missing_incident_to_safe_404(monkeypatch) -> None:
    _auth(monkeypatch, role="ANALYST")
    audits = []

    def fail(payload, current_user=None):
        raise AssistantError(category="IncidentNotFound", status_code=404, message="Incident not found.")

    monkeypatch.setattr("routers.assistant.run_assistant_query", fail)
    monkeypatch.setattr("routers.assistant.write_security_audit", lambda **kwargs: audits.append(kwargs))

    response = client.post(
        "/assistant/query",
        headers={"Authorization": "Bearer test"},
        json={"message": "Explain", "scope": "incident", "incident_id": 999},
    )

    assert response.status_code == 404
    assert response.json()["detail"]["error_category"] == "IncidentNotFound"
    assert audits[0]["event_type"] == "AI_ASSISTANT_QUERY_FAILED"


def test_query_endpoint_maps_disabled_feature_to_safe_503(monkeypatch) -> None:
    _auth(monkeypatch, role="ADMIN")
    monkeypatch.setattr(
        "routers.assistant.run_assistant_query",
        lambda payload, current_user=None: (_ for _ in ()).throw(
            AssistantError(category="AssistantDisabled", status_code=503, message="SOC assistant is disabled.")
        ),
    )
    monkeypatch.setattr("routers.assistant.write_security_audit", lambda **kwargs: None)

    response = client.post(
        "/assistant/query",
        headers={"Authorization": "Bearer test"},
        json={"message": "Explain", "scope": "global"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "message": "SOC assistant is disabled.",
        "error_category": "AssistantDisabled",
    }


def test_query_endpoint_hides_unexpected_exception_detail(monkeypatch) -> None:
    _auth(monkeypatch, role="ANALYST")
    audits = []

    def fail(payload, current_user=None):
        raise RuntimeError("stack trace internal detail")

    monkeypatch.setattr("routers.assistant.run_assistant_query", fail)
    monkeypatch.setattr("routers.assistant.write_security_audit", lambda **kwargs: audits.append(kwargs))

    response = client.post(
        "/assistant/query",
        headers={"Authorization": "Bearer test"},
        json={"message": "Do not store this raw question", "scope": "global"},
    )

    assert response.status_code == 503
    assert "internal detail" not in str(response.json())
    assert "Do not store this raw question" not in str(audits[0]["details"])
    assert audits[0]["details"]["error_category"] == "ProviderUnavailable"


def test_viewer_and_unauthenticated_requests_are_denied(monkeypatch) -> None:
    _auth(monkeypatch, role="VIEWER")
    viewer_response = client.get("/assistant/capabilities", headers={"Authorization": "Bearer test"})
    assert viewer_response.status_code == 403

    monkeypatch.setattr(
        "security.rbac.get_current_user",
        lambda authorization: (_ for _ in ()).throw(HTTPException(status_code=401, detail="Authentication required.")),
    )
    unauthenticated_response = client.get("/assistant/capabilities")
    assert unauthenticated_response.status_code == 401
