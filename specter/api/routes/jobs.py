"""Job status routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from specter.api.auth import TokenData, get_current_operator
from specter.api.state import _jobs
from specter.models.job import CollectionJob

router = APIRouter(prefix="/api/jobs", tags=["jobs"])


@router.get("", summary="List all jobs")
async def list_jobs(
    operator: Annotated[TokenData, Depends(get_current_operator)],
) -> list[CollectionJob]:
    return list(_jobs.values())


@router.get("/{job_id}/status", summary="Get job status")
async def get_job_status(
    job_id: str,
    operator: Annotated[TokenData, Depends(get_current_operator)],
) -> CollectionJob:
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job
