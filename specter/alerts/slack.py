"""Slack alert dispatch via incoming webhook."""

from __future__ import annotations

import logging

import httpx

from specter.models.alert import AlertSeverity, MonitoringAlert

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    AlertSeverity.INFO: ":information_source:",
    AlertSeverity.LOW: ":white_circle:",
    AlertSeverity.MEDIUM: ":large_yellow_circle:",
    AlertSeverity.HIGH: ":large_orange_circle:",
    AlertSeverity.CRITICAL: ":red_circle:",
}


class SlackDispatch:
    """Posts MonitoringAlerts to a Slack incoming webhook."""

    def __init__(self, webhook_url: str) -> None:
        self._url = webhook_url

    async def send(self, alert: MonitoringAlert) -> bool:
        """Format and post the alert. Returns True on success."""
        payload = self._format(alert)
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self._url, json=payload)
            if resp.status_code != 200:
                logger.warning("Slack webhook returned %s", resp.status_code)
                return False
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Slack dispatch failed: %s", exc)
            return False

    def _format(self, alert: MonitoringAlert) -> dict:
        emoji = _SEVERITY_EMOJI.get(alert.severity, ":bell:")
        findings_text = "\n".join(f"  • {f}" for f in alert.findings[:10])
        return {
            "text": f"{emoji} *Specter Alert — {alert.severity.upper()}*",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{emoji} {alert.title}"},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*Severity:* {alert.severity.upper()}\n"
                            f"*Target:* {alert.target_id}\n"
                            f"*Summary:* {alert.summary}"
                            + (f"\n*Findings:*\n{findings_text}" if findings_text else "")
                        ),
                    },
                },
            ],
        }
