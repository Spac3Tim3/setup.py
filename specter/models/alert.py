"""Alert and notification threshold models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class AlertSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertChannel(StrEnum):
    IN_APP = "in_app"
    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"


class AlertThreshold(BaseModel):
    """Per-target or global alert routing configuration."""

    target_id: str | None = None  # None = global default
    min_severity: AlertSeverity = AlertSeverity.MEDIUM
    channels: list[AlertChannel] = Field(default_factory=lambda: [AlertChannel.IN_APP])
    exposure_score_delta: float = 10.0
    breach_count_threshold: int = 1

    @field_validator("breach_count_threshold")
    @classmethod
    def threshold_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("breach_count_threshold must be at least 1")
        return v


class MonitoringAlert(BaseModel):
    """A generated alert surfacing a detected change or risk for a target."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target_id: str
    severity: AlertSeverity
    title: str
    summary: str
    findings: list[str] = Field(default_factory=list)
    channels_notified: list[AlertChannel] = Field(default_factory=list)
    dismissed: bool = False
    dismissed_by: str | None = None
    dismissed_at: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    source_job_id: str | None = None

    @field_validator("title")
    @classmethod
    def title_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("alert title must not be empty")
        return v
