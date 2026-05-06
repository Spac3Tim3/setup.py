"""Audit log routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from specter.api.auth import Role, TokenData, require_role
from specter.api.routes.alerts import _audit
from specter.models.audit import AuditAction, AuditEvent

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", summary="List audit events")
async def list_audit(
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN, Role.AUDITOR)
    )],
    action: AuditAction | None = None,
    resource_id: str | None = None,
) -> list[AuditEvent]:
    return _audit.list(action=action, resource_id=resource_id)
