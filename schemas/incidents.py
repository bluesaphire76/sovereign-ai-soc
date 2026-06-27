from __future__ import annotations

from pydantic import BaseModel


class IncidentStatusUpdate(BaseModel):
    status: str
    comment: str | None = None


class IncidentNoteCreate(BaseModel):
    note: str
    created_by: str | None = None
