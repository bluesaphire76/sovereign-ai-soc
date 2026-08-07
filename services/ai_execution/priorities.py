from __future__ import annotations

from enum import StrEnum


class AiExecutionPriority(StrEnum):
    INTERACTIVE = "interactive"
    USER_ANALYSIS = "user_analysis"
    PLAYBOOK = "playbook"
    REMEDIATION = "remediation"
    INCIDENT_TRIAGE = "incident_triage"
    BACKGROUND = "background"


PRIORITY_VALUES = {
    AiExecutionPriority.INTERACTIVE: 100,
    AiExecutionPriority.USER_ANALYSIS: 80,
    AiExecutionPriority.PLAYBOOK: 70,
    AiExecutionPriority.REMEDIATION: 60,
    AiExecutionPriority.INCIDENT_TRIAGE: 30,
    AiExecutionPriority.BACKGROUND: 10,
}


def priority_value(priority: AiExecutionPriority | str) -> int:
    try:
        normalized = AiExecutionPriority(str(priority))
    except ValueError:
        normalized = AiExecutionPriority.BACKGROUND
    return PRIORITY_VALUES[normalized]


def priority_for_task(
    task: str,
    *,
    user_triggered: bool,
) -> AiExecutionPriority:
    normalized = str(task or "").strip().lower()
    if normalized == "soc_assistant":
        return AiExecutionPriority.INTERACTIVE
    if normalized in {"recommended_playbooks"}:
        return AiExecutionPriority.PLAYBOOK
    if normalized in {"remediation", "remediation_explanation"}:
        return AiExecutionPriority.REMEDIATION
    if normalized in {"incident_triage", "worker_triage"}:
        return AiExecutionPriority.INCIDENT_TRIAGE
    if user_triggered:
        return AiExecutionPriority.USER_ANALYSIS
    return AiExecutionPriority.BACKGROUND
