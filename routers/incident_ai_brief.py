from fastapi import APIRouter, HTTPException

from incident_ai_brief import build_ai_brief_preview, generate_ai_brief

router = APIRouter()


@router.get("/incidents/{incident_id}/ai-brief")
def get_incident_ai_brief_preview(incident_id: int):
    try:
        return build_ai_brief_preview(incident_id)

    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")


@router.post("/incidents/{incident_id}/ai-brief")
def generate_incident_ai_brief(incident_id: int):
    try:
        return generate_ai_brief(incident_id)

    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")
