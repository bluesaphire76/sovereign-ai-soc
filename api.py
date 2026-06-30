from fastapi import FastAPI

from routers import include_app_routers
from security.rbac import (
    enforce_api_authentication,
    is_request_authorized,
)

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Sovereign AI SOC API",
    version="0.7.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://localhost:8443",
        "http://localhost:8443",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

include_app_routers(app)
app.middleware("http")(enforce_api_authentication)
