"""Audit log models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field


class AuditAction(StrEnum):
    PROFILE_VIEWED = "profile_viewed"
    JOB_CREATED = "job_created"
    JOB_CANCELLED = "job_cancelled"
    TARGET_CREATED = "target_created"
    TARGET_DELETED = "target_deleted"
    CASE_CREATED = "case_created"
    CASE_UPDATED = "case_updated"
    NOTE_ADDED = "note_added"
    CREDENTIAL_ADDED = "credential_added"
    CREDENTIAL_REMOVED = "credential_removed"
    ALERT_DISMISSED = "alert_dismissed"
    EXPORT_GENERATED = "export_generated"
    LOGIN = "login"
    LOGOUT = "logout"


class AuditEvent(BaseModel):
    """An immutable log entry for a single operator action."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    action: AuditAction
    operator_id: str
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict = Field(default_factory=dict)
    ip_address: str | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
