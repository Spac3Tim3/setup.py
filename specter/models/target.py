"""Target and protected individual models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from specter.models.person import PersonProfile

SEED_TYPES = Literal["email", "username", "phone", "name", "image", "platform_url"]

PROTECTION_CLASSES = Literal[
    "judge", "law_enforcement", "executive", "public_official", "domestic_violence_survivor"
]


class SeedInput(BaseModel):
    """A single seed value used to initiate or expand collection."""

    seed_type: str
    value: str
    metadata: dict = Field(default_factory=dict)

    @field_validator("seed_type")
    @classmethod
    def valid_seed_type(cls, v: str) -> str:
        valid = {"email", "username", "phone", "name", "image", "platform_url"}
        if v not in valid:
            raise ValueError(f"seed_type must be one of {valid}")
        return v

    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("seed value must not be empty")
        return v


class TargetEntity(BaseModel):
    """A monitored individual or entity."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    display_name: str
    seeds: list[SeedInput]
    profile: PersonProfile | None = None
    case_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    active: bool = True

    @field_validator("seeds")
    @classmethod
    def at_least_one_seed(cls, v: list[SeedInput]) -> list[SeedInput]:
        if not v:
            raise ValueError("target must have at least one seed")
        return v


class ProtectedIndividual(BaseModel):
    """A target subject to statutory address/record protection."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target: TargetEntity
    protection_class: str
    jurisdiction: str | None = None
    shield_active: bool = True
    shield_verified_at: datetime | None = None
    notes: str | None = None

    @field_validator("protection_class")
    @classmethod
    def valid_protection_class(cls, v: str) -> str:
        valid = {
            "judge",
            "law_enforcement",
            "executive",
            "public_official",
            "domestic_violence_survivor",
        }
        if v not in valid:
            raise ValueError(f"protection_class must be one of {valid}")
        return v
