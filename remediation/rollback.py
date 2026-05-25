from __future__ import annotations

from .models import (
    RemediationActionType,
    RollbackAvailability,
    RollbackPlan,
    RollbackStep,
)


FULL_ROLLBACK_ACTIONS = {
    RemediationActionType.BLOCK_IP,
    RemediationActionType.UNBLOCK_IP,
    RemediationActionType.ADD_FIREWALL_RULE,
    RemediationActionType.REMOVE_FIREWALL_RULE,
    RemediationActionType.CREATE_TICKET,
    RemediationActionType.NOTIFY_OWNER,
    RemediationActionType.ESCALATE_CASE,
}

PARTIAL_ROLLBACK_ACTIONS = {
    RemediationActionType.ENABLE_USER,
    RemediationActionType.RESTART_SERVICE,
    RemediationActionType.RESTORE_FILE,
    RemediationActionType.RELEASE_HOST,
    RemediationActionType.COLLECT_FORENSIC_EVIDENCE,
}

UNAVAILABLE_ROLLBACK_ACTIONS = {
    RemediationActionType.DISABLE_USER,
    RemediationActionType.STOP_SERVICE,
    RemediationActionType.QUARANTINE_FILE,
    RemediationActionType.KILL_PROCESS,
    RemediationActionType.ISOLATE_HOST,
}


def rollback_availability_for_action(action_type: RemediationActionType) -> RollbackAvailability:
    if action_type in FULL_ROLLBACK_ACTIONS:
        return RollbackAvailability.FULL
    if action_type in PARTIAL_ROLLBACK_ACTIONS:
        return RollbackAvailability.PARTIAL
    if action_type in UNAVAILABLE_ROLLBACK_ACTIONS:
        return RollbackAvailability.UNAVAILABLE
    return RollbackAvailability.PARTIAL


def build_rollback_plan(
    action_type: RemediationActionType,
    *,
    action_id: str = "remediation-action",
) -> RollbackPlan:
    availability = rollback_availability_for_action(action_type)
    rollback_id = f"rollback-{action_id}"

    if availability == RollbackAvailability.FULL:
        steps = [
            RollbackStep(
                step_id=f"{rollback_id}-restore-previous-state",
                title="Restore previous control state",
                description=(
                    "Restore the previous ticket, notification, firewall or block-list state after "
                    "human review confirms rollback is required."
                ),
                validation="Confirm the reviewed state matches the pre-change baseline.",
            )
        ]
        return RollbackPlan(
            rollback_id=rollback_id,
            availability=availability,
            steps=steps,
            validation_steps=["Validate the target state after rollback."],
            recovery_notes="Rollback is expected to be operationally straightforward if baseline state is preserved.",
        )

    if availability == RollbackAvailability.PARTIAL:
        steps = [
            RollbackStep(
                step_id=f"{rollback_id}-review-partial-restore",
                title="Review partial restoration path",
                description=(
                    "Document the pre-change state and validate whether the asset, user or evidence "
                    "collection state can be safely restored."
                ),
                validation="Confirm residual impact and document any incomplete restoration.",
            )
        ]
        return RollbackPlan(
            rollback_id=rollback_id,
            availability=availability,
            steps=steps,
            validation_steps=["Validate residual operational impact after rollback."],
            recovery_notes="Rollback may require additional owner coordination.",
            limitations=["Rollback may not restore all operational side effects."],
        )

    return RollbackPlan(
        rollback_id=rollback_id,
        availability=RollbackAvailability.UNAVAILABLE,
        steps=[],
        validation_steps=[
            "Document why rollback is unavailable before any future execution approval."
        ],
        recovery_notes="No reliable rollback path is defined for this action type in Step 8.",
        limitations=[
            "Rollback is unavailable in the planning model.",
            "Future execution must not proceed without stronger governance and manual approval.",
        ],
    )
