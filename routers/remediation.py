from __future__ import annotations

from fastapi import APIRouter, HTTPException

from database import SessionLocal
from models import Incident
from remediation import (
    RemediationPlanningContext,
    generate_remediation_plan,
    validate_remediation_plan,
)


router = APIRouter()


def _incident_context(incident: Incident) -> dict[str, object]:
    return {
        "id": incident.id,
        "status": incident.status,
        "wazuh_doc_id": incident.wazuh_doc_id,
        "timestamp": incident.timestamp.isoformat() if incident.timestamp else None,
        "agent": incident.agent,
        "rule": incident.rule,
        "level": incident.level,
        "mitre": incident.mitre,
        "risk_score": incident.risk_score,
        "correlated": incident.correlated,
        "correlation_score": incident.correlation_score,
        "correlation_summary": incident.correlation_summary,
        "attack_chain": incident.attack_chain,
        "correlation_type": incident.correlation_type,
        "escalation_reason": incident.escalation_reason,
        "recommended_priority": incident.recommended_priority,
    }


@router.get("/incidents/{incident_id}/remediation-plan")
def get_incident_remediation_plan(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    db = SessionLocal()

    try:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()

        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found.")

        context = RemediationPlanningContext(
            incident_id=incident.id,
            incident=_incident_context(incident),
            generated_by="incident-remediation-preview",
        )
        plan = generate_remediation_plan(context)
        validation = validate_remediation_plan(plan)

        return {
            "plan": plan.model_dump(mode="json"),
            "validation": validation.model_dump(mode="json"),
            "execution_supported": False,
            "source": "incident_context",
            "notes": [
                "Read-only incident-aware remediation plan preview.",
                "No remediation execution is available from this endpoint.",
                "Human approval is required before any future execution layer can act.",
            ],
        }

    finally:
        db.close()
