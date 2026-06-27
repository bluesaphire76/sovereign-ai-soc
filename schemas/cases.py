from __future__ import annotations

from pydantic import BaseModel


class CaseWorkflowUpdate(BaseModel):
    owner: str | None = None
    assignee: str | None = None
    status: str | None = None
    severity: str | None = None
    sla_due_at: str | None = None
    status_reason: str | None = None
    reviewed_by: str | None = None


class CaseActionCreate(BaseModel):
    title: str
    description: str | None = None
    category: str = "INVESTIGATION"
    priority: str = "MEDIUM"
    status: str | None = None
    due_at: str | None = None
    created_by: str | None = None


class CaseActionUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    category: str | None = None
    priority: str | None = None
    status: str | None = None
    due_at: str | None = None
    updated_by: str | None = None


class CaseClosureChecklistUpdate(BaseModel):
    root_cause: str | None = None
    evidence_reviewed: str | None = None
    actions_summary: str | None = None
    closure_reason: str | None = None
    closure_decision: str | None = None
    final_severity: str | None = None
    residual_risk: str | None = None
    closure_approved: bool | None = None
    closure_approved_by: str | None = None
    reviewed_by: str | None = None
