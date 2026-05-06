"""Case management models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class CaseStatus(StrEnum):
    ACTIVE = "active"
    CLOSED = "closed"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class CaseMember(BaseModel):
    """A target participating in a case with an assigned role."""

    target_id: str
    role: str = "subject"  # subject | associate | threat_actor
    added_at: datetime = Field(default_factory=datetime.utcnow)
    added_by: str | None = None

    @field_validator("role")
    @classmethod
    def valid_role(cls, v: str) -> str:
        valid = {"subject", "associate", "threat_actor"}
        if v not in valid:
            raise ValueError(f"role must be one of {valid}")
        return v


class AnalystNote(BaseModel):
    """A timestamped analyst observation attached to a case."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str
    content: str
    author_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    tags: list[str] = Field(default_factory=list)

    @field_validator("content")
    @classmethod
    def content_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("note content must not be empty")
        return v


class Case(BaseModel):
    """An investigation grouping one or more targets under a single program."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str | None = None
    status: CaseStatus = CaseStatus.ACTIVE
    members: list[CaseMember] = Field(default_factory=list)
    notes: list[AnalystNote] = Field(default_factory=list)
    analyst_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("case name must not be empty")
        return v
