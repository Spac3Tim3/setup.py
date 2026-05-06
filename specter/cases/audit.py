"""Audit log writer with decorator support."""

from __future__ import annotations

import functools
import logging
from datetime import datetime
from typing import Any, Callable

from specter.models.audit import AuditAction, AuditEvent

logger = logging.getLogger(__name__)


class AuditLogger:
    """In-memory audit log. Persisted to SQLite by Agent 10."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def log(
        self,
        action: AuditAction,
        operator_id: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
    ) -> AuditEvent:
        """Record an operator action."""
        event = AuditEvent(
            action=action,
            operator_id=operator_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
        )
        self._events.append(event)
        logger.info("AUDIT %s operator=%s resource=%s/%s",
                    action, operator_id, resource_type, resource_id)
        return event

    def list(
        self,
        operator_id: str | None = None,
        action: AuditAction | None = None,
        resource_id: str | None = None,
    ) -> list[AuditEvent]:
        """Filter the audit log."""
        events = self._events
        if operator_id:
            events = [e for e in events if e.operator_id == operator_id]
        if action:
            events = [e for e in events if e.action == action]
        if resource_id:
            events = [e for e in events if e.resource_id == resource_id]
        return events

    def count(self) -> int:
        return len(self._events)


def audit_log(action: AuditAction, resource_type: str | None = None):
    """Decorator that automatically writes an AuditEvent around a function call.

    The decorated function must accept ``operator_id`` and ``audit_logger``
    keyword arguments (injected by the API layer).
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args, operator_id: str = "system",
                         audit_logger: AuditLogger | None = None, **kwargs):
            result = await fn(*args, operator_id=operator_id,
                              audit_logger=audit_logger, **kwargs)
            if audit_logger:
                resource_id = getattr(result, "id", None) or kwargs.get("resource_id")
                audit_logger.log(
                    action=action,
                    operator_id=operator_id,
                    resource_type=resource_type,
                    resource_id=str(resource_id) if resource_id else None,
                )
            return result
        return wrapper
    return decorator
