from fastapi import FastAPI

from routers.health import router as health_router
from routers.incident_command_room import router as incident_command_room_router
from routers.reports import router as reports_router


def include_app_routers(app: FastAPI) -> None:
    app.include_router(health_router)
    app.include_router(reports_router)
    app.include_router(incident_command_room_router)
