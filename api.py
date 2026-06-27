from fastapi import FastAPI

from wazuh_ingest_state import get_watermark_snapshot
from routers import include_app_routers
from security.rbac import (
    enforce_api_authentication,
    is_request_authorized,
)

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Sovereign AI SOC API",
    version="0.1.0",
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

@app.get("/platform/ingest/wazuh")
def wazuh_ingest_watermark():
    return get_watermark_snapshot()
