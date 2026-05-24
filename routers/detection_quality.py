from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from detection_quality_guidance import generate_detection_quality_guidance


router = APIRouter()


class DetectionQualityGuidanceRequest(BaseModel):
    summary: str
    recommended_action: str
    quality_score: int
    total_synthetic: int
    scenario_name: str | None = None
    force_refresh: bool = False
    weakest_scenario: dict[str, Any] | None = None
    signals: list[dict[str, Any]] = Field(default_factory=list)
    gaps: dict[str, Any] = Field(default_factory=dict)


@router.post("/detection-quality/action-guidance")
def create_detection_quality_action_guidance(
    payload: DetectionQualityGuidanceRequest,
):
    return generate_detection_quality_guidance(payload.dict())
