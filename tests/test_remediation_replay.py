from unittest.mock import patch

from remediation.replay import (
    RemediationReplayMode,
    RemediationReplayPhase,
    RemediationReplayStepStatus,
    build_remediation_replay_response,
)
from remediation.planner import create_fallback_remediation_plan


def _intelligence(source: str = "deterministic_fallback"):
    return {
        "incident_id": 42,
        "source": source,
        "governance": {
            "status": "REQUIRES_REVIEW",
            "confidence_score": 45,
            "evidence_coverage": "LOW",
            "human_review_required": True,
            "unsupported_claims": [],
            "assumptions": ["Only structured incident fields are available."],
            "limitations": ["Replay uses current remediation metadata only."],
            "policy_warnings": ["Human approval remains mandatory."],
            "safety_labels": ["AI_GENERATED", "HUMAN_REVIEW_REQUIRED", "NO_EXECUTION"],
        },
    }


def test_replay_is_read_only_and_requires_human_decision():
    plan = create_fallback_remediation_plan(42)
    response = build_remediation_replay_response(
        incident_id=42,
        intelligence=_intelligence(),
        plan=plan,
    )

    assert response.execution_supported is False
    assert response.state_mutated is False
    assert response.replay_mode == RemediationReplayMode.READ_ONLY
    assert response.human_decision_required is True
    assert "No remediation was executed." in response.notes
    assert "No rollback was executed." in response.notes


def test_replay_includes_expected_governance_phases():
    plan = create_fallback_remediation_plan(42)
    response = build_remediation_replay_response(
        incident_id=42,
        intelligence=_intelligence(),
        plan=plan,
    )

    phases = [entry.phase for entry in response.timeline]

    assert phases == [
        RemediationReplayPhase.PLAN_GENERATION,
        RemediationReplayPhase.GOVERNANCE_CHECK,
        RemediationReplayPhase.APPROVAL_GATE,
        RemediationReplayPhase.DRY_RUN,
        RemediationReplayPhase.ROLLBACK_READINESS,
        RemediationReplayPhase.AUDIT_TRAIL,
        RemediationReplayPhase.FINAL_DECISION,
    ]


def test_replay_proposed_actions_show_approval_and_no_execution_context():
    plan = create_fallback_remediation_plan(42)
    response = build_remediation_replay_response(
        incident_id=42,
        intelligence=_intelligence(),
        plan=plan,
    )

    assert response.proposed_actions
    assert all(action.approval_required for action in response.proposed_actions)
    assert {action.governance_status for action in response.proposed_actions} == {"REQUIRES_REVIEW"}


def test_replay_handles_missing_dry_run_subsystem_as_partial_warning():
    plan = create_fallback_remediation_plan(42)

    with patch("remediation.replay.generate_plan_dry_run", side_effect=RuntimeError("dry run unavailable")):
        response = build_remediation_replay_response(
            incident_id=42,
            intelligence=_intelligence(),
            plan=plan,
        )

    dry_run_entry = next(
        entry for entry in response.timeline if entry.phase == RemediationReplayPhase.DRY_RUN
    )

    assert dry_run_entry.status == RemediationReplayStepStatus.NOT_APPLICABLE
    assert any("Dry-run subsystem unavailable" in warning for warning in response.warnings)


def test_replay_timeline_ordering_is_deterministic():
    plan = create_fallback_remediation_plan(42)
    first = build_remediation_replay_response(
        incident_id=42,
        intelligence=_intelligence(),
        plan=plan,
    )
    second = build_remediation_replay_response(
        incident_id=42,
        intelligence=_intelligence(),
        plan=plan,
    )

    assert [entry.step for entry in first.timeline] == [entry.step for entry in second.timeline]
    assert [entry.phase for entry in first.timeline] == [entry.phase for entry in second.timeline]
