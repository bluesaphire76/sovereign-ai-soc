from __future__ import annotations

import json
from pathlib import Path

from routers.synthetic_tests import build_synthetic_incident
from security.rbac import is_request_authorized


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "frontend" / "src" / "app"
DASHBOARD = APP / "page.tsx"
EXECUTIVE = APP / "executive" / "page.tsx"
HEALTH = APP / "health" / "page.tsx"
DETECTION_QUALITY = APP / "detection-quality" / "page.tsx"
SEMANTIC_STYLES = ROOT / "frontend" / "src" / "lib" / "semantic-styles.ts"
NAVIGATION = ROOT / "frontend" / "src" / "lib" / "navigation.ts"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_dashboard_preserves_operational_data_and_prioritizes_attention() -> None:
    source = read(DASHBOARD)

    for endpoint in (
        "/metrics/summary",
        "/incidents?${incidentParams.toString()}",
        "/cases?limit=100",
        "/metrics/top-hosts?limit=8",
        "/metrics/risk-distribution",
        "/metrics/incident-trend?days=7",
        "/metrics/queue-aging",
        "/metrics/detection-funnel",
    ):
        assert endpoint in source

    for capability in (
        "Priority Case Queue",
        "Top Noisy Hosts",
        "Incident Stream",
        "Reset filters",
        "Previous",
        "Next",
    ):
        assert capability in source

    assert source.index("Priority Case Queue") < source.index("Incident Risk Distribution")
    assert "window.setInterval" in source
    assert "}, 30000);" in source
    assert "EnterpriseMetricStrip" in source
    assert "EnterpriseStatusBadge" in source
    assert "EnterpriseSeverityBadge" in source


def test_executive_preserves_decision_hierarchy_and_supporting_queues() -> None:
    source = read(EXECUTIVE)

    assert 'authFetch(`/executive/summary`' in source
    assert "}, 30000);" in source
    for capability in (
        "Executive decision brief",
        "Management action queue",
        "Operating assurance",
        "Exposure matrix",
        "Operational hotspots",
        "Cases requiring attention",
        "Open high-risk incident queue",
        "Latest AI case analysis",
    ):
        assert capability in source

    assert source.index("<ExecutiveDecisionBrief") < source.index("<OperatingAssurance")
    assert source.index("<ManagementActionQueue") < source.index("<OperatingAssurance")
    assert "riskScoreTone" in source
    assert "severityTone" in source
    assert "function toneClasses" not in source


def test_health_keeps_runtime_detail_polling_and_native_links() -> None:
    source = read(HEALTH)

    assert 'authFetch(`/platform/health`' in source
    assert "}, 30000);" in source
    for capability in (
        "Latest processed incident",
        "Worker / ingest metrics",
        "Ingest & backlog",
        "Batch outcome",
        "AI triage",
        "Provider registry",
        "Open llama.cpp native UI",
        "Details",
        "JSON.stringify(item.details",
    ):
        assert capability in source

    for component in (
        '"postgres"',
        '"wazuh_indexer"',
        '"wazuh_ingest"',
        '"ai_soc_worker"',
        '"ai_runtime"',
        '"qdrant"',
    ):
        assert component in source

    assert "riskScoreTone(health.latest_incident.risk_score)" in source
    assert "EnterpriseStatusBadge" in source
    assert "function statusClasses" not in source


def test_detection_quality_keeps_calculations_runner_rbac_and_guidance() -> None:
    source = read(DETECTION_QUALITY)

    for endpoint in (
        "/incidents?${params.toString()}",
        "/synthetic-tests/scenarios",
        "/synthetic-tests/run",
        "/detection-quality/action-guidance",
    ):
        assert endpoint in source

    assert 'currentUser?.role === "ADMIN" || currentUser?.role === "ANALYST"' in source
    assert 'currentUser?.role === "VIEWER"' in source
    assert "Read-only access: synthetic test execution" in source
    assert "Math.round((correlationScore + priorityScore + mitreScore) / 3)" in source
    assert "priorityMatchesSyntheticExpectation" in source
    assert "extractMitreIds" in source
    assert "}, 30000);" in source

    for capability in (
        "Synthetic test runner",
        "Synthetic scenario coverage",
        "Scenario quality breakdown",
        "Latest synthetic incidents",
        "Generate AI suggestion",
        "Non-authoritative LLM-assisted execution guidance",
        "Deterministic metrics and analyst review remain authoritative",
    ):
        assert capability in source


def test_overview_semantics_and_external_observability_remain_canonical() -> None:
    semantics = read(SEMANTIC_STYLES)
    navigation = read(NAVIGATION)

    assert 'status === "CRITICAL"' in semantics
    assert 'severity === "LOW"' in semantics
    assert 'if (severity === "LOW") return "low"' in semantics
    assert 'low: {' in semantics
    assert 'badge: "border-sky-800 bg-sky-950/60 text-sky-200"' in semantics
    assert 'label: "Observability"' in navigation
    assert "external: true" in navigation
    assert "roles: OPERATOR_ROLES" in navigation


def test_overview_api_rbac_remains_unchanged_for_all_standard_roles() -> None:
    for role in ("ADMIN", "ANALYST", "VIEWER"):
        user = {"role": role}

        for path in (
            "/metrics/summary",
            "/executive/summary",
            "/platform/health",
            "/incidents",
            "/detection-quality/action-guidance",
        ):
            method = "POST" if path.endswith("action-guidance") else "GET"
            assert is_request_authorized(method, path, user)

    for role in ("ADMIN", "ANALYST"):
        user = {"role": role}
        assert is_request_authorized("GET", "/synthetic-tests/scenarios", user)
        assert is_request_authorized("POST", "/synthetic-tests/run", user)

    viewer = {"role": "VIEWER"}
    assert not is_request_authorized("GET", "/synthetic-tests/scenarios", viewer)
    assert not is_request_authorized("POST", "/synthetic-tests/run", viewer)


def test_detection_quality_synthetic_fixture_builds_without_persistence() -> None:
    incident = build_synthetic_incident(
        scenario_name="ssh_bruteforce",
        index=1,
        host="ux09-safe-fixture",
        created_by="ux09-validation",
    )
    raw_alert = json.loads(incident.raw_alert)

    assert incident.id is None
    assert incident.agent == "ux09-safe-fixture"
    assert incident.correlated is True
    assert raw_alert["synthetic"] is True
    assert raw_alert["scenario"] == "ssh_bruteforce"
    assert raw_alert["data"]["expected_priority"] == incident.recommended_priority
