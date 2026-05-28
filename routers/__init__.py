from fastapi import FastAPI

from routers.detection_control import router as detection_control_router
from routers.detection_quality import router as detection_quality_router
from routers.dns_events import router as dns_events_router
from routers.health import router as health_router
from routers.incident_ai_brief import router as incident_ai_brief_router
from routers.incident_network_evidence import router as incident_network_evidence_router
from routers.network_events import router as network_events_router
from routers.reports import router as reports_router
from routers.remediation import router as remediation_router
from routers.metrics import metrics_router, prometheus_metrics_middleware


def include_app_routers(app: FastAPI) -> None:
    app.middleware("http")(prometheus_metrics_middleware)
    app.include_router(metrics_router)
    app.include_router(health_router)
    app.include_router(reports_router)
    app.include_router(incident_ai_brief_router)
    app.include_router(incident_network_evidence_router)
    app.include_router(detection_control_router)
    app.include_router(detection_quality_router)
    app.include_router(dns_events_router)
    app.include_router(network_events_router)
    app.include_router(remediation_router)
