from routers.remediation import get_incident_remediation_plan


def test_remediation_plan_endpoint_returns_read_only_fallback_plan():
    response = get_incident_remediation_plan(42)

    assert response["source"] == "fallback"
    assert response["execution_supported"] is False
    assert response["plan"]["incident_id"] == 42
    assert response["plan"]["execution_supported"] is False
    assert response["validation"]["valid"] is True


def test_remediation_plan_endpoint_rejects_invalid_incident_id():
    try:
        get_incident_remediation_plan(0)
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 404
    else:
        raise AssertionError("Expected HTTPException for invalid incident id")
