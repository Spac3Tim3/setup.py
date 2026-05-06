"""API credential and service configuration models."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field


class ServiceConfig(BaseModel):
    """Static configuration for an external data service."""

    name: str
    api_key_required: bool = True
    free_tier: bool = False
    signup_url: str | None = None
    docs_url: str | None = None
    rate_limit_per_minute: int = 60
    kali_native: bool = False
    install_cmd: str | None = None


class APICredential(BaseModel):
    """An encrypted API key stored in the local credential store."""

    service_id: str
    encrypted_key: str  # Fernet-encrypted blob
    added_at: datetime = Field(default_factory=datetime.utcnow)
    last_validated: datetime | None = None
    valid: bool | None = None
    added_by: str | None = None


class CollectorHealth(BaseModel):
    """Runtime health status for a single data collector."""

    service_id: str
    available: bool
    configured: bool
    key_valid: bool | None = None
    last_check: datetime = Field(default_factory=datetime.utcnow)
    error: str | None = None
    rate_limit_remaining: int | None = None
