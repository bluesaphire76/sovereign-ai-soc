from fastapi import APIRouter, HTTPException

from incident_command_room_ai import (
    build_command_room_preview,
    generate_command_room_analysis,
)

router = APIRouter()


@router.get("/incidents/{incident_id}/command-room-analysis")
def get_incident_command_room_preview(incident_id: int):
    try:
        return build_command_room_preview(incident_id)

    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")


@router.post("/incidents/{incident_id}/command-room-analysis")
def generate_incident_command_room_analysis(incident_id: int):
    try:
        return generate_command_room_analysis(incident_id)

    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")
