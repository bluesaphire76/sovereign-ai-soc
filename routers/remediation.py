from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from remediation.controlled_soar import (
    ControlledSoarExecutionRequest,
    actor_from_current_user,
    execute_approved_controlled_soar_action,
)
from remediation.audit_trail import generate_incident_remediation_audit_trail
from remediation.intelligence import generate_remediation_intelligence
from remediation.replay import generate_incident_remediation_replay
from remediation.rollback_engine import generate_incident_remediation_rollback_readiness
from remediation.simulation import generate_incident_remediation_dry_run


router = APIRouter()


@router.get("/incidents/{incident_id}/remediation-plan")
def get_incident_remediation_plan(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    try:
        result = generate_remediation_intelligence(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")

    return {
        **result,
        "execution_supported": False,
        "notes": [
            "LLM-backed remediation intelligence preview.",
            "No remediation execution is available from this endpoint.",
            "Human approval is required before any future execution layer can act.",
        ],
    }


@router.get("/incidents/{incident_id}/remediation-dry-run")
def get_incident_remediation_dry_run(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    try:
        result = generate_incident_remediation_dry_run(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")

    return result.model_dump(mode="json")


@router.get("/incidents/{incident_id}/remediation-rollback-readiness")
def get_incident_remediation_rollback_readiness(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    try:
        result = generate_incident_remediation_rollback_readiness(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")

    return result.model_dump(mode="json")


@router.get("/incidents/{incident_id}/remediation-audit-trail")
def get_incident_remediation_audit_trail(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    try:
        result = generate_incident_remediation_audit_trail(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")

    return result.model_dump(mode="json")


@router.get("/incidents/{incident_id}/remediation-replay")
def get_incident_remediation_replay(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    try:
        result = generate_incident_remediation_replay(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")

    return result.model_dump(mode="json")


@router.post("/incidents/{incident_id}/remediation-actions/{action_id}/execute-approved")
def execute_approved_incident_remediation_action(
    incident_id: int,
    action_id: str,
    payload: ControlledSoarExecutionRequest,
    request: Request,
):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    actor = actor_from_current_user(getattr(request.state, "current_user", None))

    try:
        result = execute_approved_controlled_soar_action(
            incident_id=incident_id,
            action_id=action_id,
            actor=actor,
            approval_confirmed=payload.approval_confirmed,
            approval_rationale=payload.approval_rationale,
        )
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident or remediation action not found.")

    return result.model_dump(mode="json")
