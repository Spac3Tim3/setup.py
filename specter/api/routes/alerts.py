"""Alert management routes."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from specter.api.auth import Role, TokenData, get_current_operator, require_role
from specter.api.state import _alerts
from specter.cases.audit import AuditLogger
from specter.models.alert import MonitoringAlert
from specter.models.audit import AuditAction

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

_audit = AuditLogger()


@router.get("", summary="List all alerts")
async def list_alerts(
    operator: Annotated[TokenData, Depends(get_current_operator)],
    dismissed: bool = False,
) -> list[MonitoringAlert]:
    return [
        a for a in _alerts.values()
        if a.dismissed == dismissed
    ]


@router.patch("/{alert_id}/dismiss", summary="Dismiss an alert")
async def dismiss_alert(
    alert_id: str,
    operator: Annotated[TokenData, Depends(
        require_role(Role.ADMIN, Role.ANALYST, Role.REVIEWER)
    )],
) -> MonitoringAlert:
    alert = _alerts.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    # Update in-place (immutable model — replace)
    _alerts[alert_id] = alert.model_copy(update={
        "dismissed": True,
        "dismissed_by": operator.operator_id,
        "dismissed_at": datetime.utcnow(),
    })
    _audit.log(
        action=AuditAction.ALERT_DISMISSED,
        operator_id=operator.operator_id,
        resource_type="alert",
        resource_id=alert_id,
    )
    return _alerts[alert_id]
