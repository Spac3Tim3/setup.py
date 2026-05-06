"""SIEM webhook dispatch."""

from __future__ import annotations

import logging

import httpx

from specter.models.alert import MonitoringAlert

logger = logging.getLogger(__name__)


class WebhookDispatch:
    """Posts MonitoringAlerts to a SIEM or generic webhook endpoint as JSON."""

    def __init__(self, webhook_url: str, headers: dict[str, str] | None = None) -> None:
        self._url = webhook_url
        self._headers = headers or {}

    async def send(self, alert: MonitoringAlert) -> bool:
        """POST alert payload to webhook. Returns True on success."""
        payload = {
            "source": "specter",
            "alert_id": alert.id,
            "target_id": alert.target_id,
            "severity": alert.severity,
            "title": alert.title,
            "summary": alert.summary,
            "findings": alert.findings,
            "created_at": alert.created_at.isoformat(),
            "dismissed": alert.dismissed,
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self._url,
                    json=payload,
                    headers={"Content-Type": "application/json", **self._headers},
                )
            if resp.status_code not in range(200, 300):
                logger.warning("Webhook returned %s", resp.status_code)
                return False
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Webhook dispatch failed: %s", exc)
            return False
