"""Public records and shield verification models."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

RECORD_SOURCES = {
    "fl_elections",
    "fl_property",
    "myflcourtaccess",
    "sunbiz",
    "fdle_sex_offender",
    "other",
}


class PublicRecordResult(BaseModel):
    """A single public record result retrieved from a government portal."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: str
    record_type: str  # voter | property | court | business_filing | sex_offender
    subject_name: str | None = None
    address: str | None = None
    raw_data: dict = Field(default_factory=dict)
    url: str | None = None
    fetched_at: datetime = Field(default_factory=datetime.utcnow)
    target_id: str | None = None


class ShieldStatus(BaseModel):
    """Result of statutory address-protection verification for a protected individual."""

    individual_id: str
    protected: bool
    protection_class: str
    violations: list[str] = Field(default_factory=list)  # descriptions of exposed records
    gaps: list[str] = Field(default_factory=list)  # indirect / LLC exposure risks
    recommendations: list[str] = Field(default_factory=list)
    last_verified: datetime = Field(default_factory=datetime.utcnow)
    record_sources_checked: list[str] = Field(default_factory=list)


class IdentityValidation(BaseModel):
    """Cross-reference of public records against a target profile."""

    target_id: str
    matched_records: list[PublicRecordResult] = Field(default_factory=list)
    confidence_boost: float = 0.0
    conflicts: list[str] = Field(default_factory=list)
    validated_at: datetime = Field(default_factory=datetime.utcnow)

    @field_validator("confidence_boost")
    @classmethod
    def boost_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence_boost must be between 0.0 and 1.0")
        return v
