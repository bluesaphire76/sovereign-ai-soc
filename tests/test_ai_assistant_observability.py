from __future__ import annotations

import json
from pathlib import Path

import yaml

import routers.metrics as metrics_module
from security.rbac import PUBLIC_AUTH_PATHS
from services.ai_execution.errors import GatewayUnavailable


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_PATH = ROOT / (
    "deploy/observability/grafana/dashboards/"
    "ai-soc-assistant-observability.json"
)
PROMETHEUS_PATH = ROOT / "deploy/observability/prometheus/prometheus.yml"
ALERTS_PATH = ROOT / (
    "deploy/observability/prometheus/rules/ai-soc-assistant-alerts.yml"
)
ALLOY_PATH = ROOT / "deploy/observability/alloy/config.alloy"


def test_assistant_dashboard_is_closed_and_covers_end_to_end_signals() -> None:
    dashboard = json.loads(DASHBOARD_PATH.read_text(encoding="utf-8"))
    panels = dashboard["panels"]
    panel_ids = [panel["id"] for panel in panels]
    expressions = [
        target["expr"]
        for panel in panels
        for target in panel.get("targets", [])
    ]
    expression_text = "\n".join(expressions)

    assert dashboard["uid"] == "ai-soc-assistant-observability"
    assert dashboard["title"] == "AI SOC Assistant - End-to-End Observability"
    assert len(panel_ids) == len(set(panel_ids))
    assert len(panels) >= 40
    assert all("job=" in expression for expression in expressions)
    for metric in (
        "ai_execution_gateway_ready",
        "ai_execution_queue_capacity",
        "ai_execution_request_duration_seconds_bucket",
        "ai_execution_generations_total",
        "ai_execution_generation_duration_seconds_bucket",
        "ai_execution_tokens_total",
        "ai_execution_profile_switch_total",
        "assistant_v3_responses_total",
        "assistant_v32_semantic_proof_seconds_bucket",
        "assistant_v32_semantic_proof_decisions_total",
        "ai_execution_grounding_rejections_total",
        "ai_execution_fallback_total",
        "assistant_v3_stage_duration_seconds_bucket",
        "assistant_semantic_degraded_total",
        "ai_soc_gpu_utilization_percent",
    ):
        assert metric in expression_text


def test_prometheus_scrapes_gateway_metrics_through_read_only_bridge() -> None:
    config = yaml.safe_load(PROMETHEUS_PATH.read_text(encoding="utf-8"))
    jobs = {item["job_name"]: item for item in config["scrape_configs"]}

    gateway = jobs["ai-inference-gateway"]
    assert gateway["metrics_path"] == "/metrics/ai-inference"
    assert gateway["static_configs"] == [{"targets": ["127.0.0.1:8008"]}]
    assert "/metrics/ai-inference" in PUBLIC_AUTH_PATHS


def test_gateway_metrics_bridge_returns_raw_payload_and_fails_closed(
    monkeypatch,
) -> None:
    payload = b"# TYPE ai_execution_gateway_ready gauge\nai_execution_gateway_ready 1\n"

    class ReadyClient:
        def prometheus_metrics(self, *, timeout_seconds):
            assert timeout_seconds == 5.0
            return payload

    monkeypatch.setattr(metrics_module, "AiExecutionClient", ReadyClient)
    response = metrics_module.ai_inference_metrics()
    assert response.status_code == 200
    assert response.body == payload

    class UnavailableClient:
        def prometheus_metrics(self, *, timeout_seconds):
            raise GatewayUnavailable()

    monkeypatch.setattr(metrics_module, "AiExecutionClient", UnavailableClient)
    response = metrics_module.ai_inference_metrics()
    assert response.status_code == 503
    assert b"metrics unavailable" in response.body


def test_metrics_router_does_not_expose_a_generation_bridge() -> None:
    paths = {route.path for route in metrics_module.metrics_router.routes}
    assert paths == {"/metrics", "/metrics/ai-inference"}
    assert "/v1/generate" not in paths


def test_assistant_alerts_cover_runtime_safety_failures() -> None:
    config = yaml.safe_load(ALERTS_PATH.read_text(encoding="utf-8"))
    alerts = {
        rule["alert"]
        for group in config["groups"]
        for rule in group["rules"]
    }

    assert {
        "AiSocInferenceGatewayMetricsDown",
        "AiSocInferenceGatewayNotReady",
        "AiSocInferenceQueueSaturation",
        "AiSocAssistantDeadlineExceeded",
        "AiSocAssistantInferenceLatencyHigh",
        "AiSocAssistantProfileSwitchInvariantBroken",
        "AiSocAssistantProofRuntimeUnavailable",
        "AiSocAssistantStructuralFallback",
        "AiSocAssistantApiError",
    } <= alerts


def test_alloy_collects_sanitized_inference_gateway_logs() -> None:
    config = ALLOY_PATH.read_text(encoding="utf-8")

    assert 'matches    = "_SYSTEMD_UNIT=ai-soc-inference-gateway.service"' in config
    assert 'service = "ai-soc-inference-gateway"' in config
    assert "ai-soc-inference-gateway" in config
    assert "sensitive_or_investigation_payload" in config
