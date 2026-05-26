from __future__ import annotations

from .models import ExecutorAction, ExecutorDispatchResult, ExecutorDispatchStatus


class NoopExecutor:
    backend_name = "noop"

    def dispatch(self, action: ExecutorAction) -> ExecutorDispatchResult:
        return ExecutorDispatchResult(
            dispatch_id=f"executor-noop:{action.action_id}",
            action_id=action.action_id,
            plan_id=action.plan_id,
            incident_id=action.incident_id,
            status=ExecutorDispatchStatus.NOOP_RECORDED,
            mode=action.mode,
            message="NOOP executor recorded the validated action intent only. No system state was changed.",
            audit_notes=[
                "NOOP backend does not contact target systems.",
                "NOOP backend does not run commands.",
            ],
            state_mutated=False,
            production_impact=False,
            execution_supported=False,
        )
