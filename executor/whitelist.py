from __future__ import annotations

from pydantic import Field

from remediation.models import RemediationApprovalRequirement, RemediationTargetType

from .models import ExecutorActionType, ExecutorBaseModel, ExecutorMode


class ExecutorWhitelistEntry(ExecutorBaseModel):
    whitelist_entry_id: str
    action_type: ExecutorActionType
    allowed_target_types: list[RemediationTargetType] = Field(default_factory=list)
    allowed_modes: list[ExecutorMode] = Field(default_factory=lambda: [ExecutorMode.NOOP])
    requires_approval: bool = True
    requires_rollback_readiness: bool = True
    description: str
    enabled: bool = True
    production_impact_allowed: bool = False


DEFAULT_EXECUTOR_WHITELIST: dict[ExecutorActionType, ExecutorWhitelistEntry] = {
    ExecutorActionType.CREATE_TICKET: ExecutorWhitelistEntry(
        whitelist_entry_id="executor-whitelist-create-ticket",
        action_type=ExecutorActionType.CREATE_TICKET,
        allowed_target_types=[RemediationTargetType.CASE, RemediationTargetType.TICKET],
        allowed_modes=[ExecutorMode.NOOP, ExecutorMode.MOCK],
        requires_approval=False,
        requires_rollback_readiness=False,
        description="Record a ticket-creation intent in NOOP or MOCK mode only.",
    ),
    ExecutorActionType.NOTIFY_OWNER: ExecutorWhitelistEntry(
        whitelist_entry_id="executor-whitelist-notify-owner",
        action_type=ExecutorActionType.NOTIFY_OWNER,
        allowed_target_types=[RemediationTargetType.USER, RemediationTargetType.CASE, RemediationTargetType.UNKNOWN],
        allowed_modes=[ExecutorMode.NOOP, ExecutorMode.MOCK],
        requires_approval=False,
        requires_rollback_readiness=False,
        description="Record an owner-notification intent in NOOP or MOCK mode only.",
    ),
    ExecutorActionType.ESCALATE_CASE: ExecutorWhitelistEntry(
        whitelist_entry_id="executor-whitelist-escalate-case",
        action_type=ExecutorActionType.ESCALATE_CASE,
        allowed_target_types=[RemediationTargetType.CASE, RemediationTargetType.UNKNOWN],
        allowed_modes=[ExecutorMode.NOOP, ExecutorMode.MOCK],
        requires_approval=True,
        requires_rollback_readiness=False,
        description="Record a case-escalation intent in NOOP or MOCK mode only.",
    ),
    ExecutorActionType.COLLECT_FORENSIC_EVIDENCE: ExecutorWhitelistEntry(
        whitelist_entry_id="executor-whitelist-collect-forensic-evidence",
        action_type=ExecutorActionType.COLLECT_FORENSIC_EVIDENCE,
        allowed_target_types=[RemediationTargetType.HOST, RemediationTargetType.UNKNOWN],
        allowed_modes=[ExecutorMode.NOOP, ExecutorMode.MOCK],
        requires_approval=True,
        requires_rollback_readiness=True,
        description="Record a forensic-collection intent in NOOP or MOCK mode only.",
    ),
    ExecutorActionType.BLOCK_IP: ExecutorWhitelistEntry(
        whitelist_entry_id="executor-whitelist-block-ip",
        action_type=ExecutorActionType.BLOCK_IP,
        allowed_target_types=[RemediationTargetType.IP_ADDRESS],
        allowed_modes=[ExecutorMode.NOOP, ExecutorMode.MOCK],
        requires_approval=True,
        requires_rollback_readiness=True,
        description="Record an IP-block intent in NOOP or MOCK mode only.",
    ),
    ExecutorActionType.UNBLOCK_IP: ExecutorWhitelistEntry(
        whitelist_entry_id="executor-whitelist-unblock-ip",
        action_type=ExecutorActionType.UNBLOCK_IP,
        allowed_target_types=[RemediationTargetType.IP_ADDRESS],
        allowed_modes=[ExecutorMode.NOOP, ExecutorMode.MOCK],
        requires_approval=True,
        requires_rollback_readiness=True,
        description="Record an IP-unblock intent in NOOP or MOCK mode only.",
    ),
}


def get_whitelist_entry(
    action_type: ExecutorActionType,
    whitelist: dict[ExecutorActionType, ExecutorWhitelistEntry] | None = None,
) -> ExecutorWhitelistEntry | None:
    active_whitelist = DEFAULT_EXECUTOR_WHITELIST if whitelist is None else whitelist
    return active_whitelist.get(action_type)


def approval_required_for_entry(entry: ExecutorWhitelistEntry) -> RemediationApprovalRequirement:
    return (
        RemediationApprovalRequirement.ANALYST_APPROVAL
        if entry.requires_approval
        else RemediationApprovalRequirement.NONE
    )
