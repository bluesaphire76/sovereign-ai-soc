from __future__ import annotations

from pydantic import BaseModel


class SyntheticTestRunCreate(BaseModel):
    scenario: str = "all"
    count: int = 1
    host: str | None = None
    created_by: str | None = None
