from fastapi import FastAPI

from routers.detection_quality import router as detection_quality_router
from routers.health import router as health_router
from routers.incident_ai_brief import router as incident_ai_brief_router
from routers.network_events import router as network_events_router
from routers.reports import router as reports_router


def include_app_routers(app: FastAPI) -> None:
    app.include_router(health_router)
    app.include_router(reports_router)
    app.include_router(incident_ai_brief_router)
    app.include_router(detection_quality_router)
    app.include_router(network_events_router)
