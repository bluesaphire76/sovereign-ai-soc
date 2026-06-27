from __future__ import annotations

from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    password: str
    display_name: str | None = None
    role: str = "ANALYST"
    is_active: bool = True


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: str | None = None
    is_active: bool | None = None


class UserPasswordUpdate(BaseModel):
    password: str
