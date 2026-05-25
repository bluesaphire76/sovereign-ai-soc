import unittest

from investigation_ai.models import (
    EvidenceReference,
    InvestigationBrief,
    InvestigationEvidenceType,
    RecommendedAction,
    RecommendedActionCategory,
)
from remediation.models import (
    RemediationActionType,
    RemediationApprovalRequirement,
    RemediationPlanningContext,
)
from remediation.planner import create_fallback_remediation_plan, generate_remediation_plan
from remediation.validators import validate_remediation_plan


def context_with_brief():
    evidence = EvidenceReference(
        evidence_id="raw-event-1",
        evidence_type=InvestigationEvidenceType.RAW_EVENT,
        source_system="wazuh",
        source_ip="10.0.0.5",
        summary="Suspicious source IP observed in incident evidence.",
    )
    brief = InvestigationBrief(
        incident_id=42,
        session_id="investigation-42",
        summary="Structured investigation is available.",
        evidence_used=[evidence],
        recommended_actions=[
            RecommendedAction(
                action_id="recommended-containment",
                title="Block suspicious source IP",
                description="Review blocking the suspicious source IP after validation.",
                category=RecommendedActionCategory.CONTAINMENT,
                reason="Source IP appears in supporting incident evidence.",
                related_evidence_ids=["raw-event-1"],
            )
        ],
    )
    return RemediationPlanningContext(
        incident_id=42,
        investigation_session_id="investigation-42",
        incident={"id": 42, "source_ip": "10.0.0.5", "agent": "endpoint-01"},
        investigation_brief=brief,
    )


class RemediationPlannerTests(unittest.TestCase):
    def test_planner_handles_partial_incident_context(self):
        plan = generate_remediation_plan(
            RemediationPlanningContext(
                incident_id=7,
                incident={"id": 7, "agent": "endpoint-01"},
            )
        )

        self.assertEqual(plan.incident_id, 7)
        self.assertFalse(plan.execution_supported)
        self.assertTrue(plan.actions)
        self.assertEqual(validate_remediation_plan(plan).issues, [])

    def test_planner_maps_recommended_action_to_planning_action(self):
        plan = generate_remediation_plan(context_with_brief())
        action_types = {action.action_type for action in plan.actions}

        self.assertIn(RemediationActionType.BLOCK_IP, action_types)
        self.assertTrue(all(not action.execution_supported for action in plan.actions))
        self.assertTrue(all(not action.command_preview_is_executable for action in plan.actions))

    def test_fallback_plan_generation_is_stable(self):
        first = create_fallback_remediation_plan(99)
        second = create_fallback_remediation_plan(99)

        self.assertEqual(first.plan_id, second.plan_id)
        self.assertEqual(
            [action.action_type for action in first.actions],
            [action.action_type for action in second.actions],
        )
        self.assertEqual(validate_remediation_plan(first).issues, [])

    def test_high_impact_actions_are_not_executable_and_require_approval(self):
        brief = InvestigationBrief(
            incident_id=43,
            session_id="investigation-43",
            summary="Containment recommendation is available.",
            recommended_actions=[
                RecommendedAction(
                    action_id="isolate-host",
                    title="Isolate affected host",
                    description="Consider isolating the affected host.",
                    category=RecommendedActionCategory.CONTAINMENT,
                    reason="Host containment may be needed if evidence is confirmed.",
                )
            ],
        )
        plan = generate_remediation_plan(
            RemediationPlanningContext(
                incident_id=43,
                incident={"id": 43, "agent": "endpoint-43"},
                investigation_brief=brief,
            )
        )

        blocked_actions = [
            action for action in plan.actions
            if action.action_type == RemediationActionType.ISOLATE_HOST
        ]

        self.assertTrue(blocked_actions)
        self.assertEqual(
            blocked_actions[0].approval_requirement,
            RemediationApprovalRequirement.FORBIDDEN_BY_DEFAULT,
        )
        self.assertFalse(blocked_actions[0].execution_supported)


if __name__ == "__main__":
    unittest.main()
