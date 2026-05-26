from __future__ import annotations

from .models import ExecutorAction, ExecutorDispatchResult, ExecutorDispatchStatus


class MockExecutor:
    backend_name = "mock"

    def dispatch(self, action: ExecutorAction) -> ExecutorDispatchResult:
        return ExecutorDispatchResult(
            dispatch_id=f"executor-mock:{action.action_id}",
            action_id=action.action_id,
            plan_id=action.plan_id,
            incident_id=action.incident_id,
            status=ExecutorDispatchStatus.MOCK_RECORDED,
            mode=action.mode,
            message="MOCK executor simulated dispatch metadata only. No production operation was performed.",
            audit_notes=[
                "MOCK backend is deterministic test scaffolding.",
                "MOCK backend does not mutate targets or production configuration.",
            ],
            state_mutated=False,
            production_impact=False,
            execution_supported=False,
        )
