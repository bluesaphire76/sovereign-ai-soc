from fastapi import FastAPI

from routers.detection_control import router as detection_control_router
from routers.detection_quality import router as detection_quality_router
from routers.ai_data_control import router as ai_data_control_router
from routers.ai_providers import router as ai_providers_router
from routers.case_closure_semantic_context import router as case_closure_semantic_context_router
from routers.dashboard_metrics import router as dashboard_metrics_router
from routers.dns_events import router as dns_events_router
from routers.health import router as health_router
from routers.incident_ai_brief import router as incident_ai_brief_router
from routers.incident_timeline import router as incident_timeline_router
from routers.incident_network_evidence import router as incident_network_evidence_router
from routers.investigation_graph import router as investigation_graph_router
from routers.network_events import router as network_events_router
from routers.playbook_recommendations import router as playbook_recommendations_router
from routers.reports import router as reports_router
from routers.remediation import router as remediation_router
from routers.service_operations import router as service_operations_router
from routers.semantic_memory import router as semantic_memory_router
from routers.similar_incidents import router as similar_incidents_router
from routers.metrics import metrics_router, prometheus_metrics_middleware


def include_app_routers(app: FastAPI) -> None:
    app.middleware("http")(prometheus_metrics_middleware)
    app.include_router(metrics_router)
    app.include_router(dashboard_metrics_router)
    app.include_router(health_router)
    app.include_router(reports_router)
    app.include_router(incident_ai_brief_router)
    app.include_router(incident_timeline_router)
    app.include_router(similar_incidents_router)
    app.include_router(playbook_recommendations_router)
    app.include_router(case_closure_semantic_context_router)
    app.include_router(incident_network_evidence_router)
    app.include_router(investigation_graph_router)
    app.include_router(ai_data_control_router)
    app.include_router(ai_providers_router)
    app.include_router(detection_control_router)
    app.include_router(detection_quality_router)
    app.include_router(dns_events_router)
    app.include_router(network_events_router)
    app.include_router(remediation_router)
    app.include_router(service_operations_router)
    app.include_router(semantic_memory_router)
