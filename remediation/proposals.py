from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import HTTPException, Request

from detection_control_plane import _request_client_ip, _sanitize_audit_details
from detection_rule_lifecycle import create_lifecycle_item
from models import (
    CaseAction,
    CaseAudit,
    CaseIncident,
    Incident,
    IncidentCase,
    IncidentNote,
    RemediationProposal,
    RemediationProposalEvent,
    SecurityAuditEvent,
)

from .catalog import (
    ACTION_CREATE_CASE_ACTION,
    ACTION_CREATE_DETECTION_RULE_DRAFT,
    ACTION_CREATE_EXCEPTION_DRAFT,
    ACTION_CREATE_NOISE_SUPPRESSION_DRAFT,
    ACTION_GENERATE_CONTAINMENT_CHECKLIST,
    ACTION_GENERATE_REMEDIATION_PLAN,
    ACTION_LINK_RECOMMENDED_ACTION_TO_CASE,
    ACTION_PREPARE_EXTERNAL_TICKET,
    ACTION_PREPARE_IP_BLOCK,
    ACTION_PREPARE_RULE_DISABLE,
    ACTION_PREPARE_SERVICE_RESTART,
    ACTION_PREPARE_SOAR_PLAYBOOK,
    MODE_DISABLED,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    get_action_catalog_item,
    list_action_catalog,
    normalize_action_type,
    strictest_risk,
)
from .playbooks import get_playbook_template


STATE_DRAFT = "DRAFT"
STATE_PROPOSED = "PROPOSED"
STATE_APPROVED = "APPROVED"
STATE_REJECTED = "REJECTED"
STATE_CANCELLED = "CANCELLED"
STATE_CONVERTED = "CONVERTED"

PROPOSAL_STATES = {
    STATE_DRAFT,
    STATE_PROPOSED,
    STATE_APPROVED,
    STATE_REJECTED,
    STATE_CANCELLED,
    STATE_CONVERTED,
}

ALLOWED_TRANSITIONS = {
    STATE_DRAFT: {STATE_PROPOSED, STATE_CANCELLED},
    STATE_PROPOSED: {STATE_APPROVED, STATE_REJECTED, STATE_DRAFT},
    STATE_APPROVED: {STATE_CONVERTED, STATE_CANCELLED},
    STATE_REJECTED: {STATE_DRAFT},
    STATE_CANCELLED: set(),
    STATE_CONVERTED: set(),
}

LOW_RISK_DRAFT_CONVERT_ACTIONS = {
    ACTION_CREATE_CASE_ACTION,
    ACTION_GENERATE_REMEDIATION_PLAN,
    ACTION_GENERATE_CONTAINMENT_CHECKLIST,
    ACTION_LINK_RECOMMENDED_ACTION_TO_CASE,
}

DETECTION_DRAFT_ACTIONS = {
    ACTION_CREATE_DETECTION_RULE_DRAFT,
    ACTION_CREATE_NOISE_SUPPRESSION_DRAFT,
    ACTION_CREATE_EXCEPTION_DRAFT,
}

PROPOSAL_ONLY_ACTIONS = {
    ACTION_PREPARE_SERVICE_RESTART,
    ACTION_PREPARE_RULE_DISABLE,
    ACTION_PREPARE_IP_BLOCK,
    ACTION_PREPARE_EXTERNAL_TICKET,
    ACTION_PREPARE_SOAR_PLAYBOOK,
}

ROLE_ADMIN = "ADMIN"
ROLE_ANALYST = "ANALYST"
ROLE_VIEWER = "VIEWER"
OPERATOR_ROLES = {ROLE_ADMIN, ROLE_ANALYST}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, default=str, sort_keys=True, separators=(",", ":"))


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return fallback
    return parsed


def _clean_text(value: Any) -> str:
    return str(value or "").strip()


def _current_user_id(current_user: Mapping[str, Any] | None) -> int | None:
    value = (current_user or {}).get("id")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def current_user_role(current_user: Mapping[str, Any] | None) -> str:
    return str((current_user or {}).get("role") or ROLE_VIEWER).upper().strip()


def _username(current_user: Mapping[str, Any] | None) -> str:
    return _clean_text((current_user or {}).get("username")) or "unknown"


def _safe_details(details: dict[str, Any] | None) -> dict[str, Any]:
    return _sanitize_audit_details(details or {})


def _risk_priority(risk_level: str) -> str:
    if risk_level == RISK_HIGH:
        return "HIGH"
    if risk_level == RISK_MEDIUM:
        return "MEDIUM"
    return "LOW"


def _payload(row: RemediationProposal) -> dict[str, Any]:
    parsed = _json_loads(row.payload_json, {})
    return parsed if isinstance(parsed, dict) else {}


def _related_json(row: RemediationProposal, field_name: str) -> list[Any]:
    parsed = _json_loads(getattr(row, field_name), [])
    return parsed if isinstance(parsed, list) else []


def _record_security_audit(
    db,
    *,
    event_type: str,
    outcome: str,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
    proposal: RemediationProposal | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        SecurityAuditEvent(
            event_type=event_type,
            outcome=outcome,
            actor_user_id=_current_user_id(current_user),
            actor_username=(current_user or {}).get("username"),
            actor_role=(current_user or {}).get("role"),
            target_type="REMEDIATION_PROPOSAL",
            target_id=str(proposal.id) if proposal else None,
            method=request.method if request else None,
            path=request.url.path if request else None,
            client_ip=_request_client_ip(request),
            user_agent=request.headers.get("user-agent") if request else None,
            details_json=_json_dumps(
                _safe_details(
                    {
                        "proposal_id": proposal.id if proposal else None,
                        "action_type": proposal.action_type if proposal else None,
                        "risk_level": proposal.risk_level if proposal else None,
                        "status": proposal.status if proposal else None,
                        "incident_id": proposal.incident_id if proposal else None,
                        "case_id": proposal.case_id if proposal else None,
                        "connector_key": proposal.connector_key if proposal else None,
                        **(details or {}),
                    }
                )
            ),
        )
    )
    db.flush()


def _record_event(
    db,
    *,
    proposal: RemediationProposal,
    event_type: str,
    current_user: Mapping[str, Any] | None,
    from_status: str | None,
    to_status: str | None,
    comment: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    db.add(
        RemediationProposalEvent(
            proposal_id=proposal.id,
            event_type=event_type,
            from_status=from_status,
            to_status=to_status,
            actor_user_id=_current_user_id(current_user),
            actor_username=(current_user or {}).get("username"),
            comment=comment,
            metadata_json=_json_dumps(_safe_details(metadata or {})),
        )
    )
    db.flush()


def _deny(
    db,
    *,
    current_user: Mapping[str, Any] | None,
    request: Request | None,
    proposal: RemediationProposal | None,
    reason: str,
    status_code: int = 403,
) -> None:
    _record_security_audit(
        db,
        event_type="REMEDIATION_ACTION_DENIED",
        outcome="DENIED",
        current_user=current_user,
        request=request,
        proposal=proposal,
        details={"reason": reason},
    )
    db.commit()
    raise HTTPException(status_code=status_code, detail=reason)


def _require_operator(db, *, current_user: Mapping[str, Any] | None, request: Request | None, proposal=None) -> None:
    if current_user_role(current_user) not in OPERATOR_ROLES:
        _deny(
            db,
            current_user=current_user,
            request=request,
            proposal=proposal,
            reason="ADMIN or ANALYST role required.",
        )


def _require_admin(db, *, current_user: Mapping[str, Any] | None, request: Request | None, proposal=None) -> None:
    if current_user_role(current_user) != ROLE_ADMIN:
        _deny(
            db,
            current_user=current_user,
            request=request,
            proposal=proposal,
            reason="ADMIN role required.",
        )


def _assert_transition(row: RemediationProposal, to_status: str) -> None:
    if to_status not in ALLOWED_TRANSITIONS.get(row.status, set()):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid remediation proposal transition",
                "from_status": row.status,
                "to_status": to_status,
                "allowed_transitions": sorted(ALLOWED_TRANSITIONS.get(row.status, set())),
            },
        )


def _proposal_safe_summary(*, title: str, action_type: str, execution_mode: str, connector_key: str) -> str:
    return (
        f"{title} | {action_type} via {connector_key}. "
        f"Mode={execution_mode}. No autonomous remediation or external execution is performed in Step 13."
    )


def _required_approval_role(action_type: str, risk_level: str) -> str:
    item = get_action_catalog_item(action_type)
    if item and item.requires_admin_approval:
        return ROLE_ADMIN
    if risk_level in {RISK_MEDIUM, RISK_HIGH}:
        return ROLE_ADMIN
    return ROLE_ANALYST


def _validate_payload(
    *,
    action_type: str,
    incident_id: int | None,
    case_id: int | None,
    title: str,
    reason: str,
    payload: Mapping[str, Any],
) -> None:
    if not title:
        raise HTTPException(status_code=400, detail="Proposal title is required.")
    if not reason:
        raise HTTPException(status_code=400, detail="Proposal reason is required.")

    if action_type == ACTION_CREATE_CASE_ACTION and not (case_id or incident_id):
        raise HTTPException(status_code=400, detail="CREATE_CASE_ACTION requires case_id or incident_id.")

    if action_type in DETECTION_DRAFT_ACTIONS:
        source_system = _clean_text(payload.get("source_system") or payload.get("source") or "OTHER")
        match = payload.get("match") or payload.get("match_criteria") or payload.get("content_json", {}).get("match")
        business_reason = _clean_text(payload.get("business_reason") or reason)
        owner = _clean_text(payload.get("owner"))
        if not source_system:
            raise HTTPException(status_code=400, detail="Detection draft requires source_system.")
        if not match:
            raise HTTPException(status_code=400, detail="Detection draft requires match criteria.")
        if not business_reason:
            raise HTTPException(status_code=400, detail="Detection draft requires business reason.")
        if not owner:
            raise HTTPException(status_code=400, detail="Detection draft requires owner.")

    if action_type == ACTION_PREPARE_SERVICE_RESTART:
        if not _clean_text(payload.get("service_key")):
            raise HTTPException(status_code=400, detail="PREPARE_SERVICE_RESTART requires service_key.")
        if not _clean_text(payload.get("expected_impact")):
            raise HTTPException(status_code=400, detail="PREPARE_SERVICE_RESTART requires expected impact.")

    if action_type == ACTION_PREPARE_IP_BLOCK:
        if not _clean_text(payload.get("source_ip")):
            raise HTTPException(status_code=400, detail="PREPARE_IP_BLOCK requires source_ip.")
        if not _clean_text(payload.get("evidence_reference")):
            raise HTTPException(status_code=400, detail="PREPARE_IP_BLOCK requires evidence reference.")

    if action_type == ACTION_PREPARE_SOAR_PLAYBOOK:
        if not _clean_text(payload.get("playbook_name")):
            raise HTTPException(status_code=400, detail="PREPARE_SOAR_PLAYBOOK requires playbook_name.")
        if not _clean_text(payload.get("evidence_reference")):
            raise HTTPException(status_code=400, detail="PREPARE_SOAR_PLAYBOOK requires evidence reference.")


def serialize_proposal(row: RemediationProposal) -> dict[str, Any]:
    return {
        "id": row.id,
        "proposal_key": row.proposal_key,
        "title": row.title,
        "description": row.description,
        "action_type": row.action_type,
        "status": row.status,
        "risk_level": row.risk_level,
        "execution_mode": row.execution_mode,
        "connector_key": row.connector_key,
        "source_type": row.source_type,
        "source_reference_id": row.source_reference_id,
        "incident_id": row.incident_id,
        "case_id": row.case_id,
        "related_alert_ids": _related_json(row, "related_alert_ids_json"),
        "related_event_ids": _related_json(row, "related_event_ids_json"),
        "related_timeline_event_ids": _related_json(row, "related_timeline_event_ids_json"),
        "related_graph_node_ids": _related_json(row, "related_graph_node_ids_json"),
        "recommended_by_ai": bool(row.recommended_by_ai),
        "ai_feature_key": row.ai_feature_key,
        "ai_decision_id": row.ai_decision_id,
        "ai_data_policy_decision_id": row.ai_data_policy_decision_id,
        "reason": row.reason,
        "business_justification": row.business_justification,
        "expected_impact": row.expected_impact,
        "safety_notes": row.safety_notes,
        "required_approval_role": row.required_approval_role,
        "created_by_user_id": row.created_by_user_id,
        "created_by_username": row.created_by_username,
        "submitted_by_user_id": row.submitted_by_user_id,
        "submitted_at": row.submitted_at.isoformat() if row.submitted_at else None,
        "approved_by_user_id": row.approved_by_user_id,
        "approved_by_username": row.approved_by_username,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "rejected_by_user_id": row.rejected_by_user_id,
        "rejected_by_username": row.rejected_by_username,
        "rejected_at": row.rejected_at.isoformat() if row.rejected_at else None,
        "rejection_reason": row.rejection_reason,
        "converted_by_user_id": row.converted_by_user_id,
        "converted_at": row.converted_at.isoformat() if row.converted_at else None,
        "converted_target_type": row.converted_target_type,
        "converted_target_id": row.converted_target_id,
        "payload_json": _payload(row),
        "safe_summary": row.safe_summary,
        "allowed_transitions": sorted(ALLOWED_TRANSITIONS.get(row.status, set())),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def serialize_event(row: RemediationProposalEvent) -> dict[str, Any]:
    metadata = _json_loads(row.metadata_json, {})
    return {
        "id": row.id,
        "proposal_id": row.proposal_id,
        "event_type": row.event_type,
        "from_status": row.from_status,
        "to_status": row.to_status,
        "actor_user_id": row.actor_user_id,
        "actor_username": row.actor_username,
        "comment": row.comment,
        "metadata": metadata if isinstance(metadata, dict) else {},
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def get_proposal(db, proposal_id: int) -> RemediationProposal:
    row = db.query(RemediationProposal).filter(RemediationProposal.id == proposal_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Remediation proposal not found.")
    return row


def list_proposals(
    db,
    *,
    incident_id: int | None = None,
    case_id: int | None = None,
    status: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    query = db.query(RemediationProposal)
    if incident_id is not None:
        query = query.filter(RemediationProposal.incident_id == incident_id)
    if case_id is not None:
        query = query.filter(RemediationProposal.case_id == case_id)
    if status:
        query = query.filter(RemediationProposal.status == status.upper().strip())

    rows = (
        query.order_by(RemediationProposal.updated_at.desc(), RemediationProposal.id.desc())
        .limit(max(1, min(limit, 300)))
        .all()
    )
    items = [serialize_proposal(row) for row in rows]
    states = {state: 0 for state in sorted(PROPOSAL_STATES)}
    for item in items:
        states[item["status"]] = states.get(item["status"], 0) + 1

    return {
        "items": items,
        "summary": {
            "total": len(items),
            "states": states,
            "proposal_only": sum(1 for item in items if item["execution_mode"] in {MODE_DISABLED, "PROPOSAL_ONLY"}),
            "requires_admin": sum(1 for item in items if item["required_approval_role"] == ROLE_ADMIN),
        },
        "states": sorted(PROPOSAL_STATES),
        "action_catalog": list_action_catalog(),
    }


def create_proposal(
    db,
    *,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    _require_operator(db, current_user=current_user, request=request)

    action_type = normalize_action_type(payload.get("action_type"))
    catalog = get_action_catalog_item(action_type)
    if catalog is None:
        raise HTTPException(status_code=400, detail="Unsupported remediation action type.")

    raw_payload = payload.get("payload_json") or payload.get("payload") or {}
    proposal_payload = raw_payload if isinstance(raw_payload, dict) else {}
    title = _clean_text(payload.get("title") or proposal_payload.get("title"))
    description = _clean_text(payload.get("description") or proposal_payload.get("description")) or None
    reason = _clean_text(payload.get("reason") or proposal_payload.get("reason"))
    incident_id = payload.get("incident_id")
    case_id = payload.get("case_id")
    incident_id = int(incident_id) if incident_id is not None and str(incident_id).strip() else None
    case_id = int(case_id) if case_id is not None and str(case_id).strip() else None
    risk_level = strictest_risk(catalog.risk_level, str(payload.get("risk_level") or "").upper())

    _validate_payload(
        action_type=action_type,
        incident_id=incident_id,
        case_id=case_id,
        title=title,
        reason=reason,
        payload=proposal_payload,
    )

    now = utc_now()
    row = RemediationProposal(
        proposal_key=f"rp-{uuid.uuid4().hex[:16]}",
        title=title,
        description=description,
        action_type=action_type,
        status=STATE_DRAFT,
        risk_level=risk_level,
        execution_mode=catalog.execution_mode,
        connector_key=catalog.connector_key,
        source_type=_clean_text(payload.get("source_type") or "ANALYST") or "ANALYST",
        source_reference_id=_clean_text(payload.get("source_reference_id")) or None,
        incident_id=incident_id,
        case_id=case_id,
        related_alert_ids_json=_json_dumps(payload.get("related_alert_ids") or []),
        related_event_ids_json=_json_dumps(payload.get("related_event_ids") or []),
        related_timeline_event_ids_json=_json_dumps(payload.get("related_timeline_event_ids") or []),
        related_graph_node_ids_json=_json_dumps(payload.get("related_graph_node_ids") or []),
        recommended_by_ai=bool(payload.get("recommended_by_ai", False)),
        ai_feature_key=_clean_text(payload.get("ai_feature_key")) or None,
        ai_decision_id=_clean_text(payload.get("ai_decision_id")) or None,
        ai_data_policy_decision_id=_clean_text(payload.get("ai_data_policy_decision_id")) or None,
        reason=reason,
        business_justification=_clean_text(payload.get("business_justification")) or None,
        expected_impact=_clean_text(payload.get("expected_impact") or proposal_payload.get("expected_impact")) or None,
        safety_notes=_clean_text(payload.get("safety_notes")) or (
            "Governed remediation only. No autonomous execution in Step 13."
        ),
        required_approval_role=_required_approval_role(action_type, risk_level),
        created_by_user_id=_current_user_id(current_user),
        created_by_username=(current_user or {}).get("username"),
        payload_json=_json_dumps(_sanitize_payload_for_storage(proposal_payload)),
        safe_summary=_proposal_safe_summary(
            title=title,
            action_type=action_type,
            execution_mode=catalog.execution_mode,
            connector_key=catalog.connector_key,
        ),
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_PROPOSAL_CREATED",
        current_user=current_user,
        from_status=None,
        to_status=STATE_DRAFT,
        comment=reason,
        metadata={"source_type": row.source_type},
    )
    _record_security_audit(
        db,
        event_type="REMEDIATION_PROPOSAL_CREATED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        proposal=row,
        details={"source_type": row.source_type},
    )
    db.commit()
    db.refresh(row)
    return serialize_proposal(row)


def _sanitize_payload_for_storage(payload: Mapping[str, Any]) -> dict[str, Any]:
    sanitized = _safe_details(dict(payload))
    free_text = _clean_text(sanitized.get("free_form_ai_text") or sanitized.get("raw_ai_text"))
    if free_text:
        sanitized["raw_ai_text_length"] = len(free_text)
        sanitized.pop("free_form_ai_text", None)
        sanitized.pop("raw_ai_text", None)
    return sanitized


def update_proposal(
    db,
    *,
    proposal_id: int,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_proposal(db, proposal_id)
    _require_operator(db, current_user=current_user, request=request, proposal=row)
    if row.status != STATE_DRAFT:
        raise HTTPException(status_code=400, detail="Only draft proposals can be edited.")

    from_status = row.status
    if "title" in payload:
        title = _clean_text(payload.get("title"))
        if not title:
            raise HTTPException(status_code=400, detail="Proposal title is required.")
        row.title = title
    if "description" in payload:
        row.description = _clean_text(payload.get("description")) or None
    if "reason" in payload:
        row.reason = _clean_text(payload.get("reason"))
        if not row.reason:
            raise HTTPException(status_code=400, detail="Proposal reason is required.")
    if "business_justification" in payload:
        row.business_justification = _clean_text(payload.get("business_justification")) or None
    if "expected_impact" in payload:
        row.expected_impact = _clean_text(payload.get("expected_impact")) or None
    if "payload_json" in payload and isinstance(payload.get("payload_json"), dict):
        row.payload_json = _json_dumps(_sanitize_payload_for_storage(payload["payload_json"]))

    row.updated_at = utc_now()
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_PROPOSAL_UPDATED",
        current_user=current_user,
        from_status=from_status,
        to_status=row.status,
        comment=_clean_text(payload.get("comment")) or None,
    )
    _record_security_audit(
        db,
        event_type="REMEDIATION_PROPOSAL_UPDATED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        proposal=row,
    )
    db.commit()
    db.refresh(row)
    return serialize_proposal(row)


def submit_proposal(
    db,
    *,
    proposal_id: int,
    comment: str | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_proposal(db, proposal_id)
    _require_operator(db, current_user=current_user, request=request, proposal=row)
    _assert_transition(row, STATE_PROPOSED)
    from_status = row.status
    now = utc_now()
    row.status = STATE_PROPOSED
    row.submitted_by_user_id = _current_user_id(current_user)
    row.submitted_at = now
    row.updated_at = now
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_PROPOSAL_SUBMITTED",
        current_user=current_user,
        from_status=from_status,
        to_status=row.status,
        comment=comment,
    )
    _record_security_audit(
        db,
        event_type="REMEDIATION_PROPOSAL_SUBMITTED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        proposal=row,
    )
    db.commit()
    db.refresh(row)
    return serialize_proposal(row)


def approve_proposal(
    db,
    *,
    proposal_id: int,
    approval_comment: str | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_proposal(db, proposal_id)
    _require_admin(db, current_user=current_user, request=request, proposal=row)
    _assert_transition(row, STATE_APPROVED)
    from_status = row.status
    now = utc_now()
    row.status = STATE_APPROVED
    row.approved_by_user_id = _current_user_id(current_user)
    row.approved_by_username = (current_user or {}).get("username")
    row.approved_at = now
    row.updated_at = now
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_PROPOSAL_APPROVED",
        current_user=current_user,
        from_status=from_status,
        to_status=row.status,
        comment=approval_comment,
    )
    _record_security_audit(
        db,
        event_type="REMEDIATION_PROPOSAL_APPROVED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        proposal=row,
    )
    db.commit()
    db.refresh(row)
    return serialize_proposal(row)


def reject_proposal(
    db,
    *,
    proposal_id: int,
    rejection_reason: str | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_proposal(db, proposal_id)
    _require_admin(db, current_user=current_user, request=request, proposal=row)
    reason = _clean_text(rejection_reason)
    if not reason:
        raise HTTPException(status_code=400, detail="Rejection reason is required.")
    _assert_transition(row, STATE_REJECTED)
    from_status = row.status
    now = utc_now()
    row.status = STATE_REJECTED
    row.rejected_by_user_id = _current_user_id(current_user)
    row.rejected_by_username = (current_user or {}).get("username")
    row.rejected_at = now
    row.rejection_reason = reason
    row.updated_at = now
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_PROPOSAL_REJECTED",
        current_user=current_user,
        from_status=from_status,
        to_status=row.status,
        comment=reason,
    )
    _record_security_audit(
        db,
        event_type="REMEDIATION_PROPOSAL_REJECTED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        proposal=row,
    )
    db.commit()
    db.refresh(row)
    return serialize_proposal(row)


def cancel_proposal(
    db,
    *,
    proposal_id: int,
    comment: str | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_proposal(db, proposal_id)
    _require_operator(db, current_user=current_user, request=request, proposal=row)
    _assert_transition(row, STATE_CANCELLED)
    from_status = row.status
    row.status = STATE_CANCELLED
    row.updated_at = utc_now()
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_PROPOSAL_CANCELLED",
        current_user=current_user,
        from_status=from_status,
        to_status=row.status,
        comment=comment,
    )
    _record_security_audit(
        db,
        event_type="REMEDIATION_PROPOSAL_CANCELLED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        proposal=row,
    )
    db.commit()
    db.refresh(row)
    return serialize_proposal(row)


def _resolve_case(db, row: RemediationProposal) -> IncidentCase | None:
    if row.case_id:
        return db.query(IncidentCase).filter(IncidentCase.id == row.case_id).first()
    if row.incident_id:
        relation = (
            db.query(CaseIncident)
            .filter(CaseIncident.incident_id == row.incident_id)
            .order_by(CaseIncident.id.asc())
            .first()
        )
        if relation:
            return db.query(IncidentCase).filter(IncidentCase.id == relation.case_id).first()
    return None


def _create_case_action(db, row: RemediationProposal, current_user: Mapping[str, Any] | None) -> tuple[str, str]:
    case = _resolve_case(db, row)
    if not case:
        raise HTTPException(status_code=400, detail="No linked case found for case action conversion.")
    payload = _payload(row)
    now = utc_now()
    action = CaseAction(
        case_id=case.id,
        title=_clean_text(payload.get("task_title") or row.title),
        description=(
            f"{row.description or row.reason or ''}\n\n"
            f"Remediation proposal #{row.id}: {row.safe_summary}"
        ).strip(),
        category="CONTAINMENT" if row.action_type == ACTION_GENERATE_CONTAINMENT_CHECKLIST else "OTHER",
        priority=_risk_priority(row.risk_level),
        status="OPEN",
        created_by=_username(current_user),
        created_at=now,
        updated_at=now,
    )
    db.add(action)
    db.flush()
    case.updated_at = now
    db.add(
        CaseAudit(
            case_id=case.id,
            event_type="REMEDIATION_PROPOSAL_CONVERTED",
            old_value=None,
            new_value=f"remediation_proposal:{row.id}:case_action:{action.id}",
            comment=row.reason,
            created_by=_username(current_user),
            created_at=now,
        )
    )
    db.flush()
    row.case_id = case.id
    return "case_action", str(action.id)


def _create_document_record(db, row: RemediationProposal, current_user: Mapping[str, Any] | None) -> tuple[str, str]:
    case = _resolve_case(db, row)
    now = utc_now()
    content = _document_content(row)
    if case:
        action = CaseAction(
            case_id=case.id,
            title=row.title,
            description=content,
            category="OTHER",
            priority=_risk_priority(row.risk_level),
            status="OPEN",
            created_by=_username(current_user),
            created_at=now,
            updated_at=now,
        )
        db.add(action)
        db.flush()
        case.updated_at = now
        row.case_id = case.id
        return "case_action", str(action.id)

    if not row.incident_id:
        raise HTTPException(status_code=400, detail="Document conversion requires incident_id or case_id.")

    incident = db.query(Incident).filter(Incident.id == row.incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    note = IncidentNote(
        incident_id=incident.id,
        note=content,
        created_by=_username(current_user),
        created_at=now,
    )
    db.add(note)
    db.flush()
    return "incident_note", str(note.id)


def _document_content(row: RemediationProposal) -> str:
    payload = _payload(row)
    checklist = payload.get("checklist_items")
    if isinstance(checklist, list) and checklist:
        lines = "\n".join(f"- {item}" for item in checklist)
    else:
        lines = row.description or row.reason or row.safe_summary or ""
    return (
        f"{row.title}\n\n"
        f"Action type: {row.action_type}\n"
        f"Risk: {row.risk_level}\n"
        f"Execution mode: {row.execution_mode}\n\n"
        f"{lines}\n\n"
        "Step 13 boundary: this record is documentation/checklist only and does not execute remediation."
    ).strip()


def _detection_lifecycle_payload(row: RemediationProposal, current_user: Mapping[str, Any] | None) -> dict[str, Any]:
    payload = _payload(row)
    content = payload.get("content_json")
    if not isinstance(content, dict):
        match = payload.get("match") or payload.get("match_criteria")
        content = {
            "source": _clean_text(payload.get("source_system") or payload.get("source") or "OTHER").lower(),
            "match": match,
            "scope": _clean_text(payload.get("scope") or payload.get("host") or "review_scope"),
            "description": row.description,
            "business_reason": row.business_justification or row.reason,
            "owner": _clean_text(payload.get("owner") or _username(current_user)),
        }
        if row.action_type == ACTION_CREATE_NOISE_SUPPRESSION_DRAFT:
            content["action"] = "suppress"
        if row.action_type == ACTION_CREATE_EXCEPTION_DRAFT:
            content["severity"] = _clean_text(payload.get("severity") or row.risk_level)
            if payload.get("no_expiration_justification"):
                content["no_expiration_justification"] = payload.get("no_expiration_justification")

    policy_type = {
        ACTION_CREATE_DETECTION_RULE_DRAFT: "DETECTION_RULE",
        ACTION_CREATE_NOISE_SUPPRESSION_DRAFT: "NOISE_SUPPRESSION",
        ACTION_CREATE_EXCEPTION_DRAFT: "EXCEPTION",
    }[row.action_type]

    return {
        "policy_type": policy_type,
        "rule_key": payload.get("rule_key"),
        "title": row.title,
        "description": row.description,
        "business_reason": row.business_justification or row.reason,
        "owner": payload.get("owner") or _username(current_user),
        "source_system": payload.get("source_system") or payload.get("source") or "OTHER",
        "content_json": content,
        "expires_at": payload.get("expires_at"),
        "risk_note": row.safety_notes,
    }


def _create_detection_draft(
    db,
    row: RemediationProposal,
    current_user: Mapping[str, Any] | None,
    request: Request | None,
) -> tuple[str, str]:
    result = create_lifecycle_item(
        db,
        payload=_detection_lifecycle_payload(row, current_user),
        current_user=current_user or {},
        request=request,
    )
    item = result["item"]
    return "detection_lifecycle_item", str(item["id"])


def _proposal_only_conversion(row: RemediationProposal) -> tuple[str, str]:
    payload = _payload(row)
    if row.action_type == ACTION_PREPARE_SERVICE_RESTART:
        return "service_operations_link", _clean_text(payload.get("service_key"))
    if row.action_type == ACTION_PREPARE_RULE_DISABLE:
        return "detection_control_review", _clean_text(payload.get("rule_key") or payload.get("rule_id") or row.id)
    if row.action_type == ACTION_PREPARE_IP_BLOCK:
        return "firewall_placeholder", _clean_text(payload.get("source_ip"))
    if row.action_type == ACTION_PREPARE_EXTERNAL_TICKET:
        return "ticketing_placeholder", str(row.id)
    if row.action_type == ACTION_PREPARE_SOAR_PLAYBOOK:
        return "soar_placeholder", _clean_text(payload.get("playbook_name") or row.id)
    return "proposal_only_review_record", str(row.id)


def convert_proposal(
    db,
    *,
    proposal_id: int,
    comment: str | None,
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    row = get_proposal(db, proposal_id)
    _require_operator(db, current_user=current_user, request=request, proposal=row)
    catalog = get_action_catalog_item(row.action_type)
    if catalog is None:
        raise HTTPException(status_code=400, detail="Unknown remediation action type.")

    draft_low_risk_allowed = row.status == STATE_DRAFT and row.action_type in LOW_RISK_DRAFT_CONVERT_ACTIONS
    if row.status != STATE_APPROVED and not draft_low_risk_allowed:
        raise HTTPException(status_code=400, detail="Proposal must be APPROVED before conversion.")

    if row.required_approval_role == ROLE_ADMIN or row.risk_level in {RISK_MEDIUM, RISK_HIGH}:
        _require_admin(db, current_user=current_user, request=request, proposal=row)

    if row.status == STATE_APPROVED:
        _assert_transition(row, STATE_CONVERTED)

    if row.action_type in {ACTION_CREATE_CASE_ACTION, ACTION_LINK_RECOMMENDED_ACTION_TO_CASE}:
        target_type, target_id = _create_case_action(db, row, current_user)
    elif row.action_type in {ACTION_GENERATE_REMEDIATION_PLAN, ACTION_GENERATE_CONTAINMENT_CHECKLIST}:
        target_type, target_id = _create_document_record(db, row, current_user)
    elif row.action_type in DETECTION_DRAFT_ACTIONS:
        target_type, target_id = _create_detection_draft(db, row, current_user, request)
    elif row.action_type in PROPOSAL_ONLY_ACTIONS:
        target_type, target_id = _proposal_only_conversion(row)
        if row.action_type in {ACTION_PREPARE_IP_BLOCK, ACTION_PREPARE_SOAR_PLAYBOOK, ACTION_PREPARE_EXTERNAL_TICKET}:
            _record_security_audit(
                db,
                event_type="REMEDIATION_CONNECTOR_PLACEHOLDER_USED",
                outcome="SUCCESS",
                current_user=current_user,
                request=request,
                proposal=row,
                details={"target_type": target_type, "external_execution": False},
            )
    else:
        raise HTTPException(status_code=400, detail="Conversion is not supported for this proposal type.")

    from_status = row.status
    now = utc_now()
    row.status = STATE_CONVERTED
    row.converted_by_user_id = _current_user_id(current_user)
    row.converted_at = now
    row.converted_target_type = target_type
    row.converted_target_id = target_id
    row.updated_at = now
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_PROPOSAL_CONVERTED",
        current_user=current_user,
        from_status=from_status,
        to_status=row.status,
        comment=comment,
        metadata={
            "converted_target_type": target_type,
            "converted_target_id": target_id,
            "external_execution": False,
            "target_system_mutated": False,
        },
    )
    _record_security_audit(
        db,
        event_type="REMEDIATION_PROPOSAL_CONVERTED",
        outcome="SUCCESS",
        current_user=current_user,
        request=request,
        proposal=row,
        details={
            "converted_target_type": target_type,
            "converted_target_id": target_id,
            "external_execution": False,
        },
    )
    db.commit()
    db.refresh(row)
    return {
        "proposal_id": row.id,
        "status": row.status,
        "converted_target_type": target_type,
        "converted_target_id": target_id,
        "message": _conversion_message(row, target_type, target_id),
        "proposal": serialize_proposal(row),
    }


def _conversion_message(row: RemediationProposal, target_type: str, target_id: str) -> str:
    if target_type == "case_action":
        return f"Case action created and linked to remediation proposal #{row.id}."
    if target_type == "detection_lifecycle_item":
        return f"Detection Control Plane draft #{target_id} created. It was not submitted, approved or applied."
    if target_type == "service_operations_link":
        return f"Service restart proposal linked to service {target_id}. No restart was executed."
    if target_type.endswith("_placeholder"):
        return "External connector placeholder recorded. No external API call was made."
    return "Proposal converted into an internal review record."


def proposal_history(db, *, proposal_id: int) -> dict[str, Any]:
    get_proposal(db, proposal_id)
    rows = (
        db.query(RemediationProposalEvent)
        .filter(RemediationProposalEvent.proposal_id == proposal_id)
        .order_by(RemediationProposalEvent.created_at.asc(), RemediationProposalEvent.id.asc())
        .all()
    )
    return {"proposal_id": proposal_id, "items": [serialize_event(row) for row in rows]}


def _infer_action_type_from_text(text: str) -> str:
    value = text.lower()
    if "restart" in value and ("service" in value or "worker" in value or "frontend" in value):
        return ACTION_PREPARE_SERVICE_RESTART
    if re.search(r"\b(block|deny|firewall)\b", value) and re.search(r"\bip\b|\d{1,3}(?:\.\d{1,3}){3}", value):
        return ACTION_PREPARE_IP_BLOCK
    if "noise" in value or "suppress" in value:
        return ACTION_CREATE_NOISE_SUPPRESSION_DRAFT
    if "exception" in value or "false positive" in value:
        return ACTION_CREATE_EXCEPTION_DRAFT
    if "detection" in value and "rule" in value:
        return ACTION_CREATE_DETECTION_RULE_DRAFT
    if "checklist" in value or "containment" in value:
        return ACTION_GENERATE_CONTAINMENT_CHECKLIST
    if "case" in value or "investigat" in value or "review" in value:
        return ACTION_CREATE_CASE_ACTION
    return ACTION_GENERATE_REMEDIATION_PLAN


def _extract_ipv4(text: str) -> str | None:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    return match.group(0) if match else None


def create_from_ai_recommendation(
    db,
    *,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    recommendation = payload.get("recommendation")
    if isinstance(recommendation, dict):
        text = _clean_text(
            recommendation.get("title")
            or recommendation.get("action")
            or recommendation.get("description")
        )
        description = _clean_text(recommendation.get("description") or recommendation.get("reason"))
        requested_action_type = recommendation.get("action_type") or payload.get("action_type")
        risk_level = recommendation.get("risk_level") or recommendation.get("risk")
    else:
        text = _clean_text(recommendation or payload.get("text") or payload.get("title"))
        description = _clean_text(payload.get("description"))
        requested_action_type = payload.get("action_type")
        risk_level = payload.get("risk_level")

    if not text:
        raise HTTPException(status_code=400, detail="AI recommendation text is required.")

    action_type = normalize_action_type(requested_action_type, fallback=_infer_action_type_from_text(text))
    proposal_payload = {
        "source_recommendation": text,
        "description": description,
        "evidence_reference": _clean_text(payload.get("evidence_reference") or "AI recommendation"),
    }

    if action_type == ACTION_PREPARE_IP_BLOCK:
        source_ip = _extract_ipv4(text)
        if not source_ip:
            action_type = ACTION_GENERATE_REMEDIATION_PLAN
        else:
            proposal_payload["source_ip"] = source_ip

    if action_type in DETECTION_DRAFT_ACTIONS and not payload.get("payload_json"):
        action_type = ACTION_GENERATE_REMEDIATION_PLAN

    create_payload = {
        "incident_id": payload.get("incident_id"),
        "case_id": payload.get("case_id"),
        "action_type": action_type,
        "title": _clean_text(payload.get("title") or text)[:240],
        "description": description or text,
        "risk_level": risk_level,
        "source_type": "AI_RECOMMENDATION",
        "source_reference_id": payload.get("source_reference_id"),
        "recommended_by_ai": True,
        "ai_feature_key": payload.get("ai_feature_key") or "remediation_proposal_conversion",
        "ai_decision_id": payload.get("ai_decision_id"),
        "ai_data_policy_decision_id": payload.get("ai_data_policy_decision_id"),
        "reason": _clean_text(payload.get("reason") or "Converted from analyst-selected AI recommendation."),
        "business_justification": payload.get("business_justification"),
        "expected_impact": payload.get("expected_impact"),
        "payload_json": {
            **proposal_payload,
            **(payload.get("payload_json") if isinstance(payload.get("payload_json"), dict) else {}),
        },
    }
    result = create_proposal(db, payload=create_payload, current_user=current_user, request=request)
    row = get_proposal(db, result["id"])
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_AI_RECOMMENDATION_CONVERTED",
        current_user=current_user,
        from_status=STATE_DRAFT,
        to_status=STATE_DRAFT,
        comment="AI recommendation converted to governed proposal.",
        metadata={"normalized_action_type": action_type},
    )
    db.commit()
    return serialize_proposal(get_proposal(db, result["id"]))


def create_from_playbook(
    db,
    *,
    payload: Mapping[str, Any],
    current_user: Mapping[str, Any] | None,
    request: Request | None = None,
) -> dict[str, Any]:
    template = get_playbook_template(str(payload.get("playbook_key") or ""))
    if template is None:
        raise HTTPException(status_code=404, detail="Playbook template not found.")

    action_type = normalize_action_type(
        payload.get("action_type"),
        fallback=ACTION_GENERATE_REMEDIATION_PLAN,
    )
    if action_type not in template.supported_connector_actions:
        action_type = ACTION_GENERATE_REMEDIATION_PLAN

    create_payload = {
        "incident_id": payload.get("incident_id"),
        "case_id": payload.get("case_id"),
        "action_type": action_type,
        "title": _clean_text(payload.get("title") or template.display_name),
        "description": template.description,
        "risk_level": template.risk_level,
        "source_type": "PLAYBOOK_TEMPLATE",
        "source_reference_id": template.playbook_key,
        "reason": _clean_text(payload.get("reason") or f"Created from playbook {template.display_name}."),
        "business_justification": payload.get("business_justification")
        or "Use a governed playbook template to structure analyst review.",
        "payload_json": {
            "playbook_key": template.playbook_key,
            "recommended_actions": template.recommended_actions,
            "checklist_items": template.checklist_items,
            "required_evidence": template.required_evidence,
            **(payload.get("payload_json") if isinstance(payload.get("payload_json"), dict) else {}),
        },
    }
    result = create_proposal(db, payload=create_payload, current_user=current_user, request=request)
    row = get_proposal(db, result["id"])
    _record_event(
        db,
        proposal=row,
        event_type="REMEDIATION_PLAYBOOK_PROPOSAL_CREATED",
        current_user=current_user,
        from_status=STATE_DRAFT,
        to_status=STATE_DRAFT,
        comment=f"Created from playbook {template.playbook_key}.",
        metadata={"playbook_key": template.playbook_key},
    )
    db.commit()
    return {"items": [serialize_proposal(get_proposal(db, result["id"]))]}
