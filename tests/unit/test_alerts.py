"""Agent 8 TDD contract: diff engine + alert dispatchers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from specter.alerts.diff import DiffEngine
from specter.alerts.email import EmailDispatch
from specter.alerts.slack import SlackDispatch
from specter.alerts.webhook import WebhookDispatch
from specter.models.alert import AlertChannel, AlertSeverity, AlertThreshold, MonitoringAlert
from specter.models.person import PersonProfile, PhoneIntel, SocialPresence


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_profile(**kwargs) -> PersonProfile:
    return PersonProfile(**kwargs)


def make_alert(
    target_id: str = "t1",
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    title: str = "Test alert",
    summary: str = "Test summary",
    findings: list[str] | None = None,
) -> MonitoringAlert:
    return MonitoringAlert(
        target_id=target_id,
        severity=severity,
        title=title,
        summary=summary,
        findings=findings or [],
    )


# ===========================================================================
# DiffEngine
# ===========================================================================


class TestDiffEngine:
    def _engine(self) -> DiffEngine:
        return DiffEngine()

    def test_diff_no_alert_on_unchanged_profile(self):
        baseline = make_profile(emails=["x@x.com"])
        current = make_profile(emails=["x@x.com"])
        alerts = self._engine().diff(current, baseline, target_id="t1")
        assert alerts == []

    def test_diff_detects_new_email(self):
        baseline = make_profile(emails=["x@x.com"])
        current = make_profile(emails=["x@x.com", "new@x.com"])
        alerts = self._engine().diff(current, baseline, target_id="t1")
        assert any("email" in a.title.lower() for a in alerts)

    def test_diff_detects_new_platform(self):
        baseline = make_profile(social_presence=[])
        current = make_profile(
            social_presence=[SocialPresence(platform="twitter", username="jdoe")]
        )
        alerts = self._engine().diff(current, baseline, target_id="t1")
        assert any("platform" in a.title.lower() for a in alerts)

    def test_diff_detects_new_breach(self):
        baseline = make_profile(raw_sources=[])
        current = make_profile(raw_sources=["hibp", "breach"])
        alerts = self._engine().diff(current, baseline, target_id="t1")
        assert any("breach" in a.title.lower() for a in alerts)

    def test_diff_detects_new_location(self):
        baseline = make_profile(locations=[])
        current = make_profile(locations=["Miami, FL"])
        alerts = self._engine().diff(current, baseline, target_id="t1")
        assert any("location" in a.title.lower() for a in alerts)

    def test_diff_detects_new_phone(self):
        baseline = make_profile(phone_intel=[])
        current = make_profile(phone_intel=[PhoneIntel(number="+15550001111")])
        alerts = self._engine().diff(current, baseline, target_id="t1")
        assert any("phone" in a.title.lower() for a in alerts)

    def test_alert_threshold_respects_severity_min(self):
        """Threshold min_severity=HIGH filters out LOW and MEDIUM alerts."""
        baseline = make_profile()
        current = make_profile(
            emails=["new@x.com"],
            social_presence=[SocialPresence(platform="reddit", username="jdoe")],
        )
        threshold = AlertThreshold(min_severity=AlertSeverity.HIGH)
        alerts = self._engine().diff(current, baseline, target_id="t1", threshold=threshold)
        for alert in alerts:
            assert alert.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL)

    def test_critical_alert_severity_attached_to_breach(self):
        """New breach detection creates at least one HIGH alert."""
        baseline = make_profile(raw_sources=[])
        current = make_profile(raw_sources=["hibp"])
        alerts = self._engine().diff(current, baseline, target_id="t1")
        severities = {a.severity for a in alerts}
        assert AlertSeverity.HIGH in severities

    def test_findings_populated(self):
        baseline = make_profile(emails=[])
        current = make_profile(emails=["jane@x.com"])
        alerts = self._engine().diff(current, baseline, target_id="t1")
        assert any(alerts) and alerts[0].findings


# ===========================================================================
# SlackDispatch
# ===========================================================================


class TestSlackDispatch:
    async def test_slack_dispatch_formats_correctly(self):
        """Slack payload contains title, severity, and findings block."""
        dispatch = SlackDispatch(webhook_url="https://hooks.slack.com/test")
        alert = make_alert(
            severity=AlertSeverity.HIGH,
            title="New breach detected",
            findings=["Source: hibp"],
        )
        payload = dispatch._format(alert)
        text = str(payload)
        assert "HIGH" in text
        assert "breach" in text.lower()

    async def test_slack_send_success(self):
        dispatch = SlackDispatch(webhook_url="https://hooks.slack.com/test")
        alert = make_alert()
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_resp
            )
            ok = await dispatch.send(alert)
        assert ok is True

    async def test_slack_send_failure_returns_false(self):
        dispatch = SlackDispatch(webhook_url="https://hooks.slack.com/test")
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            ok = await dispatch.send(make_alert())
        assert ok is False

    async def test_slack_non_200_returns_false(self):
        dispatch = SlackDispatch(webhook_url="https://hooks.slack.com/test")
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 400
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_resp
            )
            ok = await dispatch.send(make_alert())
        assert ok is False


# ===========================================================================
# EmailDispatch
# ===========================================================================


class TestEmailDispatch:
    def _dispatch(self) -> EmailDispatch:
        return EmailDispatch(
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="user",
            password="pass",
            from_addr="specter@example.com",
            recipients=["analyst@example.com"],
        )

    def test_email_dispatch_formats_correctly(self):
        dispatch = self._dispatch()
        alert = make_alert(severity=AlertSeverity.HIGH, title="Critical Exposure")
        msg = dispatch._format(alert)
        assert "Critical Exposure" in msg["Subject"]
        assert "HIGH" in msg["Subject"]
        assert msg["To"] == "analyst@example.com"
        assert msg["From"] == "specter@example.com"

    def test_email_format_includes_findings(self):
        dispatch = self._dispatch()
        alert = make_alert(findings=["Source: hibp", "Source: intelx"])
        msg = dispatch._format(alert)
        payload = msg.as_string()
        assert "hibp" in payload

    async def test_email_send_smtp_failure_returns_false(self):
        dispatch = self._dispatch()
        with patch("smtplib.SMTP", side_effect=Exception("Connection refused")):
            ok = await dispatch.send(make_alert())
        assert ok is False


# ===========================================================================
# WebhookDispatch
# ===========================================================================


class TestWebhookDispatch:
    async def test_webhook_send_success(self):
        dispatch = WebhookDispatch(webhook_url="https://siem.example.com/ingest")
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_resp
            )
            ok = await dispatch.send(make_alert())
        assert ok is True

    async def test_webhook_payload_contains_required_fields(self):
        dispatch = WebhookDispatch(webhook_url="https://siem.example.com/ingest")
        alert = make_alert(target_id="t42", severity=AlertSeverity.CRITICAL)
        captured_payload: dict = {}

        async def capture_post(url, json, headers):
            captured_payload.update(json)
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=capture_post
            )
            await dispatch.send(alert)

        assert captured_payload["source"] == "specter"
        assert captured_payload["target_id"] == "t42"
        assert captured_payload["severity"] == AlertSeverity.CRITICAL

    async def test_critical_alert_fires_all_channels(self):
        """Integration: critical alert should succeed on all dispatch channels."""
        alert = make_alert(severity=AlertSeverity.CRITICAL, title="CRITICAL: Address exposed")

        success = []
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                return_value=mock_resp
            )
            slack = SlackDispatch("https://hooks.slack.com/test")
            webhook = WebhookDispatch("https://siem.example.com/ingest")

            success.append(await slack.send(alert))
            success.append(await webhook.send(alert))

        assert all(success)
