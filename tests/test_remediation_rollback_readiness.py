import unittest

from investigation_ai.models import EvidenceReference, InvestigationEvidenceType
from remediation.models import (
    RemediationAction,
    RemediationActionType,
    RemediationImpactAssessment,
    RemediationTarget,
    RemediationTargetCriticality,
    RemediationTargetType,
)
from remediation.planner import create_fallback_remediation_plan
from remediation.risk import assess_action_risk
from remediation.rollback import build_rollback_plan
from remediation.rollback_readiness import (
    RemediationRollbackReadinessStatus,
    assess_action_rollback_readiness,
    assess_plan_rollback_readiness,
)
from remediation.validators import validate_rollback_readiness


def evidence() -> EvidenceReference:
    return EvidenceReference(
        evidence_id="incident-1",
        evidence_type=InvestigationEvidenceType.INCIDENT,
        source_system="ai-soc",
        summary="Evidence supports rollback readiness review.",
    )


def action(
    action_type: RemediationActionType,
    *,
    include_rollback: bool = True,
) -> RemediationAction:
    target = RemediationTarget(
        target_type=RemediationTargetType.IP_ADDRESS,
        value="10.0.0.5",
        ip_address="10.0.0.5",
        criticality=RemediationTargetCriticality.LOW,
    )
    rollback = build_rollback_plan(action_type, action_id=f"rollback-{action_type.value.lower()}")
    risk = assess_action_risk(
        action_type,
        target=target,
        rollback_plan=rollback,
        confidence_score=85,
        evidence_count=1,
    )
    return RemediationAction(
        action_id=f"rollback-{action_type.value.lower()}",
        action_type=action_type,
        title="Assess rollback readiness",
        description="Assess rollback readiness without execution.",
        target=target,
        reason="Rollback readiness is required for future governance.",
        evidence=[evidence()],
        approval_requirement=risk.approval_requirement,
        risk=risk,
        expected_impact=RemediationImpactAssessment(technical_impact="Readiness-only action."),
        rollback_steps=rollback.steps if include_rollback else [],
    )


class RemediationRollbackReadinessTests(unittest.TestCase):
    def test_rollback_readiness_detects_missing_rollback(self):
        remediation_action = action(RemediationActionType.BLOCK_IP, include_rollback=False)
        readiness = assess_action_rollback_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
        )
        validation = validate_rollback_readiness(readiness)

        self.assertEqual(readiness.status, RemediationRollbackReadinessStatus.MISSING)
        self.assertFalse(readiness.rollback_available)
        self.assertTrue(readiness.blockers)
        self.assertEqual(validation.issues, [])

    def test_rollback_readiness_detects_partial_rollback(self):
        remediation_action = action(RemediationActionType.COLLECT_FORENSIC_EVIDENCE)
        readiness = assess_action_rollback_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
        )

        self.assertEqual(readiness.status, RemediationRollbackReadinessStatus.PARTIAL)
        self.assertTrue(readiness.rollback_available)
        self.assertTrue(readiness.limitations)

    def test_forbidden_action_blocks_rollback_readiness(self):
        remediation_action = action(RemediationActionType.KILL_PROCESS)
        readiness = assess_action_rollback_readiness(
            remediation_action,
            plan_id="plan-1",
            incident_id=1,
        )

        self.assertEqual(readiness.status, RemediationRollbackReadinessStatus.BLOCKED)
        self.assertFalse(readiness.rollback_available)
        self.assertTrue(readiness.blockers)

    def test_plan_rollback_readiness_is_replay_friendly(self):
        plan = create_fallback_remediation_plan(42)
        first = assess_plan_rollback_readiness(plan)
        second = assess_plan_rollback_readiness(plan)

        self.assertEqual(first.rollback_readiness_id, second.rollback_readiness_id)
        self.assertEqual(first.status, second.status)
        self.assertEqual(first.steps_count, second.steps_count)


if __name__ == "__main__":
    unittest.main()
