from __future__ import annotations

from fastapi import APIRouter, HTTPException

from remediation import create_fallback_remediation_plan, validate_remediation_plan


router = APIRouter()


@router.get("/incidents/{incident_id}/remediation-plan")
def get_incident_remediation_plan(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    plan = create_fallback_remediation_plan(incident_id)
    validation = validate_remediation_plan(plan)

    return {
        "plan": plan.model_dump(mode="json"),
        "validation": validation.model_dump(mode="json"),
        "execution_supported": False,
        "source": "fallback",
        "notes": [
            "Read-only remediation plan preview.",
            "No remediation execution is available from this endpoint.",
            "Human approval is required before any future execution layer can act.",
        ],
    }
