import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import (
    Base,
    CaseAction,
    DetectionRuleLifecycleItem,
    IncidentCase,
    RemediationProposal,
    SecurityAuditEvent,
    ServiceOperation,
)
from remediation.catalog import (
    ACTION_CREATE_CASE_ACTION,
    ACTION_CREATE_NOISE_SUPPRESSION_DRAFT,
    ACTION_PREPARE_IP_BLOCK,
    ACTION_PREPARE_SERVICE_RESTART,
    list_action_catalog,
)
from remediation.connectors import list_connector_catalog
from remediation.proposals import (
    approve_proposal,
    convert_proposal,
    create_from_ai_recommendation,
    create_proposal,
    reject_proposal,
    submit_proposal,
)


def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def admin():
    return {"id": 1, "username": "admin", "role": "ADMIN"}


def analyst():
    return {"id": 2, "username": "analyst", "role": "ANALYST"}


def viewer():
    return {"id": 3, "username": "viewer", "role": "VIEWER"}


def case_row(db):
    row = IncidentCase(
        id=11,
        group_key="case-step13",
        title="Step 13 case",
        status="OPEN",
        severity="MEDIUM",
    )
    db.add(row)
    db.commit()
    return row


def case_action_payload(case_id=11):
    return {
        "case_id": case_id,
        "action_type": ACTION_CREATE_CASE_ACTION,
        "title": "Review successful login after brute force window",
        "description": "Validate whether any login succeeded after repeated SSH failures.",
        "reason": "AI analysis highlighted repeated failed SSH attempts.",
        "payload_json": {
            "task_title": "Review successful login after brute force window",
        },
    }


def test_action_and_connector_catalogs_expose_governed_boundaries():
    actions = {item["action_type"]: item for item in list_action_catalog()}
    connectors = {item["connector_key"]: item for item in list_connector_catalog()}

    assert ACTION_CREATE_CASE_ACTION in actions
    assert actions[ACTION_PREPARE_IP_BLOCK]["execution_supported_in_step13"] is False
    assert actions[ACTION_PREPARE_SERVICE_RESTART]["execution_mode"] == "EXECUTION_DEFERRED"
    assert connectors["firewall_placeholder"]["enabled"] is False
    assert connectors["firewall_placeholder"]["execution_supported"] is False
    assert connectors["soar_placeholder"]["proposal_supported"] is True


def test_viewer_cannot_create_proposal_and_denial_is_audited():
    db = db_session()

    try:
        case_row(db)

        with pytest.raises(HTTPException) as exc:
            create_proposal(db, payload=case_action_payload(), current_user=viewer())

        assert exc.value.status_code == 403
        audit = db.query(SecurityAuditEvent).one()
        assert audit.event_type == "REMEDIATION_ACTION_DENIED"
        assert db.query(RemediationProposal).count() == 0
    finally:
        db.close()


def test_admin_lifecycle_approves_and_converts_case_action():
    db = db_session()

    try:
        case_row(db)
        proposal = create_proposal(db, payload=case_action_payload(), current_user=admin())
        submitted = submit_proposal(
            db,
            proposal_id=proposal["id"],
            comment="Ready for review.",
            current_user=admin(),
        )
        approved = approve_proposal(
            db,
            proposal_id=proposal["id"],
            approval_comment="Internal case action only.",
            current_user=admin(),
        )
        converted = convert_proposal(
            db,
            proposal_id=proposal["id"],
            comment="Create case task.",
            current_user=admin(),
        )

        assert submitted["status"] == "PROPOSED"
        assert approved["status"] == "APPROVED"
        assert converted["status"] == "CONVERTED"
        assert converted["converted_target_type"] == "case_action"
        action = db.query(CaseAction).one()
        assert action.case_id == 11
        assert action.status == "OPEN"
        assert db.query(SecurityAuditEvent).filter(SecurityAuditEvent.event_type == "REMEDIATION_PROPOSAL_CONVERTED").count() == 1
    finally:
        db.close()


def test_analyst_cannot_approve_and_invalid_reject_requires_reason():
    db = db_session()

    try:
        case_row(db)
        proposal = create_proposal(db, payload=case_action_payload(), current_user=analyst())
        submit_proposal(db, proposal_id=proposal["id"], comment=None, current_user=analyst())

        with pytest.raises(HTTPException) as approve_exc:
            approve_proposal(
                db,
                proposal_id=proposal["id"],
                approval_comment="I approve.",
                current_user=analyst(),
            )
        assert approve_exc.value.status_code == 403

        with pytest.raises(HTTPException) as reject_exc:
            reject_proposal(
                db,
                proposal_id=proposal["id"],
                rejection_reason="",
                current_user=admin(),
            )
        assert reject_exc.value.status_code == 400
    finally:
        db.close()


def test_invalid_transition_is_rejected_server_side():
    db = db_session()

    try:
        case_row(db)
        proposal = create_proposal(db, payload=case_action_payload(), current_user=admin())

        with pytest.raises(HTTPException) as exc:
            approve_proposal(
                db,
                proposal_id=proposal["id"],
                approval_comment="Cannot approve draft directly.",
                current_user=admin(),
            )

        assert exc.value.status_code == 400
    finally:
        db.close()


def test_noise_suppression_conversion_creates_detection_draft_only():
    db = db_session()

    try:
        proposal = create_proposal(
            db,
            payload={
                "action_type": ACTION_CREATE_NOISE_SUPPRESSION_DRAFT,
                "title": "Suppress reviewed sudo baseline",
                "description": "Create a draft only for reviewed operational noise.",
                "reason": "Repeated benign sudo activity was validated by analyst.",
                "business_justification": "Reduce recurring low-value operational noise.",
                "payload_json": {
                    "source_system": "WAZUH",
                    "owner": "SOC",
                    "match": {"rule_group": "pam,sudo", "host": "atomicstar"},
                    "scope": "specific_host",
                },
            },
            current_user=admin(),
        )
        submit_proposal(db, proposal_id=proposal["id"], comment=None, current_user=admin())
        approve_proposal(db, proposal_id=proposal["id"], approval_comment="Draft only.", current_user=admin())
        converted = convert_proposal(db, proposal_id=proposal["id"], comment=None, current_user=admin())

        assert converted["converted_target_type"] == "detection_lifecycle_item"
        lifecycle_item = db.query(DetectionRuleLifecycleItem).one()
        assert lifecycle_item.state == "DRAFT"
        assert lifecycle_item.policy_type == "NOISE_SUPPRESSION"
    finally:
        db.close()


def test_service_restart_proposal_does_not_create_service_operation():
    db = db_session()

    try:
        proposal = create_proposal(
            db,
            payload={
                "action_type": ACTION_PREPARE_SERVICE_RESTART,
                "title": "Prepare worker restart",
                "description": "Document restart need after reviewed config change.",
                "reason": "Config change requires operator review.",
                "expected_impact": "Worker may pause event processing during manual restart.",
                "payload_json": {
                    "service_key": "ai_soc_worker",
                    "expected_impact": "Short worker interruption if later executed manually.",
                },
            },
            current_user=admin(),
        )
        submit_proposal(db, proposal_id=proposal["id"], comment=None, current_user=admin())
        approve_proposal(db, proposal_id=proposal["id"], approval_comment="Proposal only.", current_user=admin())
        converted = convert_proposal(db, proposal_id=proposal["id"], comment=None, current_user=admin())

        assert converted["converted_target_type"] == "service_operations_link"
        assert db.query(ServiceOperation).count() == 0
    finally:
        db.close()


def test_ai_recommendation_ip_block_requires_concrete_ip_and_never_executes():
    db = db_session()

    try:
        proposal = create_from_ai_recommendation(
            db,
            payload={
                "incident_id": 42,
                "recommendation": "Prepare IP block for 203.0.113.10 after evidence review.",
                "reason": "Analyst selected AI recommendation.",
            },
            current_user=admin(),
        )

        assert proposal["action_type"] == ACTION_PREPARE_IP_BLOCK
        assert proposal["status"] == "DRAFT"
        assert proposal["execution_mode"] == "PROPOSAL_ONLY"
        assert proposal["payload_json"]["source_ip"] == "203.0.113.10"
    finally:
        db.close()
