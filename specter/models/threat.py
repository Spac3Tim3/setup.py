"""Threat signal and actor models."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

SIGNAL_TYPES = {"stalking", "harassment", "doxxing", "impersonation", "physical_threat", "other"}
SEVERITY_LEVELS = {"low", "medium", "high", "critical"}


class ThreatSignal(BaseModel):
    """A detected threat signal targeting a protected individual."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target_id: str
    signal_type: str
    source: str
    raw_content: str
    summary: str
    severity: str
    confidence: float = 0.0
    url: str | None = None
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    actor_id: str | None = None

    @field_validator("signal_type")
    @classmethod
    def valid_signal_type(cls, v: str) -> str:
        if v not in SIGNAL_TYPES:
            raise ValueError(f"signal_type must be one of {SIGNAL_TYPES}")
        return v

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, v: str) -> str:
        if v not in SEVERITY_LEVELS:
            raise ValueError(f"severity must be one of {SEVERITY_LEVELS}")
        return v

    @field_validator("confidence")
    @classmethod
    def confidence_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class SockpuppetSignal(BaseModel):
    """Indicators that an account may be a coordinated inauthentic persona."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    suspected_real_identity: str | None = None
    platforms: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    linked_target_ids: list[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("confidence")
    @classmethod
    def confidence_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")
        return v


class ThreatActor(BaseModel):
    """A persistent actor identified as targeting one or more principals."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    alias: str
    platforms: list[str] = Field(default_factory=list)
    signals: list[ThreatSignal] = Field(default_factory=list)
    sockpuppets: list[SockpuppetSignal] = Field(default_factory=list)
    targeting: list[str] = Field(default_factory=list)  # target IDs
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    notes: str | None = None
