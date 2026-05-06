"""Target management routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from specter.api.auth import Role, TokenData, get_current_operator, require_role
from specter.api.state import _targets, _jobs, _alerts, _profiles
from specter.models.job import CollectionJob, JobStatus
from specter.models.target import SeedInput, TargetEntity

router = APIRouter(prefix="/api/targets", tags=["targets"])


class TargetCreate(BaseModel):
    display_name: str
    seeds: list[SeedInput]


@router.get("", summary="List all targets")
async def list_targets(
    operator: Annotated[TokenData, Depends(get_current_operator)],
) -> list[TargetEntity]:
    return list(_targets.values())


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create a target")
async def create_target(
    body: TargetCreate,
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN, Role.ANALYST)
    )],
) -> TargetEntity:
    target = TargetEntity(display_name=body.display_name, seeds=body.seeds)
    _targets[target.id] = target
    return target


@router.get("/{target_id}", summary="Get a target by ID")
async def get_target(
    target_id: str,
    operator: Annotated[TokenData, Depends(get_current_operator)],
) -> TargetEntity:
    target = _targets.get(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: str,
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN)
    )],
):
    if target_id not in _targets:
        raise HTTPException(status_code=404, detail="Target not found")
    del _targets[target_id]


@router.post("/{target_id}/collect", summary="Trigger a collection job")
async def trigger_collection(
    target_id: str,
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN, Role.ANALYST)
    )],
) -> CollectionJob:
    target = _targets.get(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    job = CollectionJob(
        target_id=target_id,
        seeds=target.seeds,
        operator_id=operator.operator_id,
    )
    _jobs[job.id] = job
    return job


@router.get("/{target_id}/profile", summary="Get enriched profile for a target")
async def get_profile(
    target_id: str,
    operator: Annotated[TokenData, Depends(get_current_operator)],
):
    profile = _profiles.get(target_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not yet available")
    return profile


@router.get("/{target_id}/alerts", summary="Get alerts for a target")
async def get_target_alerts(
    target_id: str,
    operator: Annotated[TokenData, Depends(get_current_operator)],
) -> list[MonitoringAlert]:
    return [a for a in _alerts.values() if a.target_id == target_id]
