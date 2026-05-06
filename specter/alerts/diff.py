"""Baseline diff engine: detects changes between PersonProfile snapshots."""

from __future__ import annotations

import logging
from uuid import uuid4

from specter.models.alert import AlertChannel, AlertSeverity, AlertThreshold, MonitoringAlert
from specter.models.person import PersonProfile

logger = logging.getLogger(__name__)

_DEFAULT_THRESHOLD = AlertThreshold()


class DiffEngine:
    """Compares a current ProfileSnapshot to a baseline and emits MonitoringAlerts."""

    def diff(
        self,
        current: PersonProfile,
        baseline: PersonProfile,
        target_id: str,
        threshold: AlertThreshold | None = None,
        job_id: str | None = None,
    ) -> list[MonitoringAlert]:
        """Return alerts for every meaningful change between baseline and current."""
        thr = threshold or _DEFAULT_THRESHOLD
        alerts: list[MonitoringAlert] = []

        # New emails
        new_emails = set(current.emails) - set(baseline.emails)
        if new_emails:
            alerts.append(self._alert(
                target_id=target_id,
                severity=AlertSeverity.LOW,
                title="New email address identified",
                summary=f"{len(new_emails)} new email address(es) discovered.",
                findings=[f"New email: {e}" for e in new_emails],
                job_id=job_id,
            ))

        # New social platforms
        current_platforms = {s.platform for s in current.social_presence}
        baseline_platforms = {s.platform for s in baseline.social_presence}
        new_platforms = current_platforms - baseline_platforms
        if new_platforms:
            alerts.append(self._alert(
                target_id=target_id,
                severity=AlertSeverity.LOW,
                title="New social platform presence detected",
                summary=f"Subject found on {len(new_platforms)} new platform(s).",
                findings=[f"New platform: {p}" for p in new_platforms],
                job_id=job_id,
            ))

        # New breach records (detected via raw_sources growth)
        current_breach_sources = {s for s in current.raw_sources if s in ("hibp", "breach", "intelx")}
        baseline_breach_sources = {s for s in baseline.raw_sources if s in ("hibp", "breach", "intelx")}
        if current_breach_sources and not baseline_breach_sources:
            alerts.append(self._alert(
                target_id=target_id,
                severity=AlertSeverity.HIGH,
                title="New breach exposure detected",
                summary="Subject identified in breach data for the first time.",
                findings=[f"Source: {s}" for s in current_breach_sources],
                job_id=job_id,
            ))

        # New phone numbers
        current_phones = {p.number for p in current.phone_intel}
        baseline_phones = {p.number for p in baseline.phone_intel}
        new_phones = current_phones - baseline_phones
        if new_phones:
            alerts.append(self._alert(
                target_id=target_id,
                severity=AlertSeverity.LOW,
                title="New phone number identified",
                summary=f"{len(new_phones)} new phone number(s) discovered.",
                findings=[f"New phone: {p}" for p in new_phones],
                job_id=job_id,
            ))

        # New locations
        new_locs = set(current.locations) - set(baseline.locations)
        if new_locs:
            alerts.append(self._alert(
                target_id=target_id,
                severity=AlertSeverity.MEDIUM,
                title="New location data identified",
                summary=f"{len(new_locs)} new location(s) detected.",
                findings=[f"New location: {loc}" for loc in new_locs],
                job_id=job_id,
            ))

        # Filter by threshold
        severity_order = list(AlertSeverity)
        min_idx = severity_order.index(thr.min_severity)
        return [
            a for a in alerts
            if severity_order.index(a.severity) >= min_idx
        ]

    @staticmethod
    def _alert(
        *,
        target_id: str,
        severity: AlertSeverity,
        title: str,
        summary: str,
        findings: list[str],
        job_id: str | None,
    ) -> MonitoringAlert:
        return MonitoringAlert(
            target_id=target_id,
            severity=severity,
            title=title,
            summary=summary,
            findings=findings,
            source_job_id=job_id,
        )
