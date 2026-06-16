from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from database import SessionLocal

from remediation.controlled_soar import (
    ControlledSoarExecutionRequest,
    actor_from_current_user,
    execute_approved_controlled_soar_action,
)
from remediation.catalog import list_action_catalog
from remediation.connectors import list_connector_catalog
from remediation.audit_trail import generate_incident_remediation_audit_trail
from remediation.intelligence import generate_remediation_intelligence
from remediation.playbooks import list_playbook_templates
from remediation.proposals import (
    approve_proposal,
    cancel_proposal,
    convert_proposal,
    create_from_ai_recommendation,
    create_from_playbook,
    create_proposal,
    get_proposal,
    list_proposals,
    proposal_history,
    reject_proposal,
    serialize_proposal,
    submit_proposal,
    update_proposal,
)
from remediation.replay import generate_incident_remediation_replay
from remediation.rollback_engine import generate_incident_remediation_rollback_readiness
from remediation.simulation import (
    build_remediation_plan_from_intelligence,
    generate_incident_remediation_dry_run,
)
from remediation.validators import validate_remediation_plan


router = APIRouter()


class ProposalPayload(BaseModel):
    incident_id: int | None = None
    case_id: int | None = None
    action_type: str
    title: str
    description: str | None = None
    risk_level: str | None = None
    reason: str
    business_justification: str | None = None
    expected_impact: str | None = None
    safety_notes: str | None = None
    source_type: str | None = None
    source_reference_id: str | None = None
    recommended_by_ai: bool = False
    ai_feature_key: str | None = None
    ai_decision_id: str | None = None
    ai_data_policy_decision_id: str | None = None
    related_alert_ids: list[str | int] = Field(default_factory=list)
    related_event_ids: list[str | int] = Field(default_factory=list)
    related_timeline_event_ids: list[str | int] = Field(default_factory=list)
    related_graph_node_ids: list[str | int] = Field(default_factory=list)
    payload_json: dict = Field(default_factory=dict)


class ProposalPatchPayload(BaseModel):
    title: str | None = None
    description: str | None = None
    reason: str | None = None
    business_justification: str | None = None
    expected_impact: str | None = None
    payload_json: dict | None = None
    comment: str | None = None


class ProposalCommentPayload(BaseModel):
    comment: str | None = None


class ProposalApprovalPayload(BaseModel):
    approval_comment: str | None = None


class ProposalRejectPayload(BaseModel):
    rejection_reason: str


class AIRecommendationPayload(BaseModel):
    incident_id: int | None = None
    case_id: int | None = None
    recommendation: str | dict
    title: str | None = None
    description: str | None = None
    action_type: str | None = None
    risk_level: str | None = None
    reason: str | None = None
    business_justification: str | None = None
    expected_impact: str | None = None
    source_reference_id: str | None = None
    evidence_reference: str | None = None
    ai_feature_key: str | None = None
    ai_decision_id: str | None = None
    ai_data_policy_decision_id: str | None = None
    payload_json: dict = Field(default_factory=dict)


class PlaybookProposalPayload(BaseModel):
    incident_id: int | None = None
    case_id: int | None = None
    playbook_key: str
    action_type: str | None = None
    title: str | None = None
    reason: str | None = None
    business_justification: str | None = None
    payload_json: dict = Field(default_factory=dict)


def _current_user(request: Request) -> dict:
    return getattr(request.state, "current_user", None) or {}


def _public_plan_source(source: object) -> str:
    if source == "deterministic_fallback":
        return "fallback"
    if source:
        return str(source)
    return "unknown"


def _public_plan_payload(result: dict) -> tuple[dict, dict]:
    remediation_plan = build_remediation_plan_from_intelligence(result)
    validation = validate_remediation_plan(remediation_plan)
    intelligence_plan = result.get("plan") if isinstance(result.get("plan"), dict) else {}

    plan = {
        **intelligence_plan,
        "incident_id": remediation_plan.incident_id,
        "plan_id": remediation_plan.plan_id,
        "execution_supported": False,
    }

    return plan, validation.model_dump(mode="json")


@router.get("/remediation/catalog/actions")
def remediation_action_catalog():
    return {"items": list_action_catalog()}


@router.get("/remediation/catalog/connectors")
def remediation_connector_catalog():
    return {"items": list_connector_catalog()}


@router.get("/remediation/catalog/playbooks")
def remediation_playbook_catalog():
    return {"items": list_playbook_templates()}


@router.get("/remediation/proposals")
def remediation_proposals(status: str | None = None, limit: int = 100):
    db = SessionLocal()
    try:
        return list_proposals(db, status=status, limit=limit)
    finally:
        db.close()


@router.post("/remediation/proposals")
def create_remediation_proposal(payload: ProposalPayload, request: Request):
    db = SessionLocal()
    try:
        return create_proposal(
            db,
            payload=payload.model_dump(exclude_unset=True),
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.get("/remediation/proposals/{proposal_id}")
def remediation_proposal_detail(proposal_id: int):
    db = SessionLocal()
    try:
        return serialize_proposal(get_proposal(db, proposal_id))
    finally:
        db.close()


@router.patch("/remediation/proposals/{proposal_id}")
def patch_remediation_proposal(proposal_id: int, payload: ProposalPatchPayload, request: Request):
    db = SessionLocal()
    try:
        return update_proposal(
            db,
            proposal_id=proposal_id,
            payload=payload.model_dump(exclude_unset=True),
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/remediation/proposals/{proposal_id}/submit")
def submit_remediation_proposal(proposal_id: int, payload: ProposalCommentPayload, request: Request):
    db = SessionLocal()
    try:
        return submit_proposal(
            db,
            proposal_id=proposal_id,
            comment=payload.comment,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/remediation/proposals/{proposal_id}/approve")
def approve_remediation_proposal(proposal_id: int, payload: ProposalApprovalPayload, request: Request):
    db = SessionLocal()
    try:
        return approve_proposal(
            db,
            proposal_id=proposal_id,
            approval_comment=payload.approval_comment,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/remediation/proposals/{proposal_id}/reject")
def reject_remediation_proposal(proposal_id: int, payload: ProposalRejectPayload, request: Request):
    db = SessionLocal()
    try:
        return reject_proposal(
            db,
            proposal_id=proposal_id,
            rejection_reason=payload.rejection_reason,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/remediation/proposals/{proposal_id}/cancel")
def cancel_remediation_proposal(proposal_id: int, payload: ProposalCommentPayload, request: Request):
    db = SessionLocal()
    try:
        return cancel_proposal(
            db,
            proposal_id=proposal_id,
            comment=payload.comment,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/remediation/proposals/{proposal_id}/convert")
def convert_remediation_proposal(proposal_id: int, payload: ProposalCommentPayload, request: Request):
    db = SessionLocal()
    try:
        return convert_proposal(
            db,
            proposal_id=proposal_id,
            comment=payload.comment,
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/remediation/proposals/from-ai-recommendation")
def remediation_proposal_from_ai_recommendation(payload: AIRecommendationPayload, request: Request):
    db = SessionLocal()
    try:
        return create_from_ai_recommendation(
            db,
            payload=payload.model_dump(exclude_unset=True),
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.post("/remediation/proposals/from-playbook")
def remediation_proposal_from_playbook(payload: PlaybookProposalPayload, request: Request):
    db = SessionLocal()
    try:
        return create_from_playbook(
            db,
            payload=payload.model_dump(exclude_unset=True),
            current_user=_current_user(request),
            request=request,
        )
    finally:
        db.close()


@router.get("/remediation/proposals/{proposal_id}/history")
def remediation_proposal_history(proposal_id: int):
    db = SessionLocal()
    try:
        return proposal_history(db, proposal_id=proposal_id)
    finally:
        db.close()


@router.get("/remediation/incidents/{incident_id}/proposals")
def remediation_incident_proposals(incident_id: int, status: str | None = None, limit: int = 100):
    db = SessionLocal()
    try:
        return list_proposals(db, incident_id=incident_id, status=status, limit=limit)
    finally:
        db.close()


@router.get("/remediation/cases/{case_id}/proposals")
def remediation_case_proposals(case_id: int, status: str | None = None, limit: int = 100):
    db = SessionLocal()
    try:
        return list_proposals(db, case_id=case_id, status=status, limit=limit)
    finally:
        db.close()


@router.get("/incidents/{incident_id}/remediation-plan")
def get_incident_remediation_plan(incident_id: int):
    if incident_id <= 0:
        raise HTTPException(status_code=404, detail="Incident not found.")

    try:
        result = generate_remediation_intelligence(incident_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Incident not found.")

    plan, validation = _public_plan_payload(result)

    return {
        **result,
        "source": _public_plan_source(result.get("source")),
        "remediation_source": result.get("source"),
        "execution_supported": False,
        "plan": plan,
        "validation": validation,
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
