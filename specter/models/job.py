"""Collection job lifecycle models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from specter.models.target import SeedInput


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CollectionJob(BaseModel):
    """A scheduled or on-demand collection job for a target."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    target_id: str
    seeds: list[SeedInput]
    collectors: list[str] = Field(default_factory=list)  # empty = all available
    status: JobStatus = JobStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    operator_id: str | None = None
    max_depth: int = 4
    max_seeds: int = 50
    time_limit_minutes: int = 30

    @field_validator("seeds")
    @classmethod
    def at_least_one_seed(cls, v: list[SeedInput]) -> list[SeedInput]:
        if not v:
            raise ValueError("job must have at least one seed")
        return v

    @field_validator("max_depth")
    @classmethod
    def depth_positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("max_depth must be at least 1")
        return v


class JobResult(BaseModel):
    """The output of a single collector run within a job."""

    job_id: str
    collector: str
    seed: SeedInput
    status: JobStatus
    raw_output: dict = Field(default_factory=dict)
    artifacts: list[dict] = Field(default_factory=list)
    new_seeds: list[SeedInput] = Field(default_factory=list)
    error: str | None = None
    duration_seconds: float | None = None
    completed_at: datetime = Field(default_factory=datetime.utcnow)
