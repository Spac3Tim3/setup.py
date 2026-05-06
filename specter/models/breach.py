"""Breach record and dark web signal models."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class BreachRecord(BaseModel):
    """A detected data breach affecting a monitored identity.

    data_classes contains label strings only (e.g. 'email', 'password_hash').
    Raw credential data is never stored.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    breach_name: str
    breach_date: datetime | None = None
    data_classes: list[str] = Field(default_factory=list)
    source: str
    verified: bool = False
    is_sensitive: bool = False
    target_id: str | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("breach_name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("breach_name must not be empty")
        return v


class DarkWebSignal(BaseModel):
    """A sanitized signal detected on dark/grey web sources.

    context_summary is a plain-language description only.
    Plaintext passwords and raw credential data must never populate this model.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str  # intelx | ahmia | ransomware.live
    query: str
    result_type: str  # paste | forum_post | ransomware_victim | marketplace
    context_summary: str
    url: str | None = None
    indexed_at: datetime | None = None
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    target_id: str | None = None
    severity: str = "medium"

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, v: str) -> str:
        valid = {"low", "medium", "high", "critical"}
        if v not in valid:
            raise ValueError(f"severity must be one of {valid}")
        return v
