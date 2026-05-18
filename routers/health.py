import logging

from fastapi import APIRouter, HTTPException

from platform_health import get_platform_health

router = APIRouter()


@router.get("/health")
def health():
    return {
        "status": "ok",
        "service": "sovereign-ai-soc-api",
    }


@router.get("/platform/health")
def platform_health():
    try:
        return get_platform_health()
    except Exception:
        logging.getLogger(__name__).error("Platform health check failed.")
        raise HTTPException(
            status_code=503,
            detail="Platform health check failed.",
        )
