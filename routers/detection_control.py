from fastapi import APIRouter

from detection_control_inventory import get_detection_control_inventory


router = APIRouter(tags=["Detection Control"])


@router.get("/settings/detection-control")
def detection_control_inventory():
    return get_detection_control_inventory()
