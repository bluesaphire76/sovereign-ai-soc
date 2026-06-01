from __future__ import annotations

from enum import StrEnum


class AiTask(StrEnum):
    INCIDENT_TRIAGE = "incident_triage"
    INCIDENT_ANALYSIS = "incident_analysis"
    COMMAND_ROOM = "command_room"
    REMEDIATION = "remediation"
    REPORT = "report"
    EXECUTIVE_SUMMARY = "executive_summary"
    DETECTION_QUALITY = "detection_quality"
    ACTION_HOW_TO = "action_how_to"
    CASE_ANALYSIS = "case_analysis"
    CLASSIFICATION = "classification"
    ROUTING = "routing"


def _task_value(task: AiTask | str) -> str:
    if isinstance(task, AiTask):
        return task.value

    return str(task or "").lower().strip()


def select_profile(
    task: AiTask | str,
    severity: str | None = None,
    requested_mode: str | None = "auto",
    user_triggered: bool = False,
) -> str:
    requested = (requested_mode or "auto").lower().strip()

    if requested in {"fast", "standard"}:
        return requested

    if requested == "quality":
        return "quality" if user_triggered else "standard"

    task_name = _task_value(task)
    severity_upper = (severity or "").upper().strip()

    if task_name in {AiTask.CLASSIFICATION.value, AiTask.ROUTING.value}:
        return "fast"

    if task_name in {
        AiTask.INCIDENT_TRIAGE.value,
        AiTask.DETECTION_QUALITY.value,
        AiTask.ACTION_HOW_TO.value,
        AiTask.CASE_ANALYSIS.value,
    }:
        return "standard"

    if task_name in {
        AiTask.REPORT.value,
        AiTask.EXECUTIVE_SUMMARY.value,
        AiTask.COMMAND_ROOM.value,
        AiTask.REMEDIATION.value,
        AiTask.INCIDENT_ANALYSIS.value,
    }:
        if user_triggered and severity_upper in {"HIGH", "CRITICAL"}:
            return "quality"
        if user_triggered and task_name in {
            AiTask.REPORT.value,
            AiTask.EXECUTIVE_SUMMARY.value,
        }:
            return "quality"
        return "standard"

    if user_triggered and severity_upper in {"HIGH", "CRITICAL"}:
        return "quality"

    return "standard"
