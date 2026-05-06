"""Person-centric intelligence models."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class PhoneIntel(BaseModel):
    """Enriched phone number intelligence."""

    number: str
    carrier: str | None = None
    country_code: str | None = None
    region: str | None = None
    line_type: str | None = None  # mobile | landline | voip | unknown
    linked_accounts: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)

    @field_validator("number")
    @classmethod
    def number_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("phone number must not be empty")
        return v


class SocialPresence(BaseModel):
    """A detected presence on a social or online platform."""

    platform: str
    username: str
    url: str | None = None
    profile_data: dict = Field(default_factory=dict)
    verified: bool = False
    source: str = ""


class ImageIntel(BaseModel):
    """Intelligence derived from image analysis and EXIF extraction."""

    url: str | None = None
    file_path: str | None = None
    face_matches: list[dict] = Field(default_factory=list)
    gps_lat: float | None = None
    gps_lon: float | None = None
    device_make: str | None = None
    device_model: str | None = None
    timestamp: datetime | None = None
    source: str = ""


class CircleFinding(BaseModel):
    """A specific exposure finding linked back to the principal's risk."""

    member_id: str
    relationship: str
    exposure_summary: str
    risk_contribution: float = 0.0

    @field_validator("risk_contribution")
    @classmethod
    def contribution_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("risk_contribution must be between 0.0 and 1.0")
        return v


class CircleMember(BaseModel):
    """A close-circle member and their aggregated findings."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    relationship: str  # spouse | child | parent | colleague | associate
    profile: PersonProfile
    findings: list[CircleFinding] = Field(default_factory=list)
    risk_score: float = 0.0

    @field_validator("risk_score")
    @classmethod
    def score_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("risk_score must be between 0.0 and 1.0")
        return v


class IdentityConfidence(BaseModel):
    """Confidence assessment that collected signals belong to a single identity."""

    score: float  # 0.0 – 1.0
    factors: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    requires_review: bool = False

    @field_validator("score")
    @classmethod
    def score_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("score must be between 0.0 and 1.0")
        return v


class PersonProfile(BaseModel):
    """Aggregated intelligence profile for a single identity."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    full_name: str | None = None
    aliases: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    phone_intel: list[PhoneIntel] = Field(default_factory=list)
    social_presence: list[SocialPresence] = Field(default_factory=list)
    images: list[ImageIntel] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)
    employers: list[str] = Field(default_factory=list)
    circle: list[CircleMember] = Field(default_factory=list)
    confidence: IdentityConfidence | None = None
    raw_sources: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# Resolve forward reference
CircleMember.model_rebuild()
