from __future__ import annotations

from fastapi import APIRouter

from wazuh_ingest_state import get_watermark_snapshot


router = APIRouter()


@router.get("/platform/ingest/wazuh")
def wazuh_ingest_watermark():
    return get_watermark_snapshot()
