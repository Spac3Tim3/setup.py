"""Opus-powered triage: PersonProfile → TriageResult."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from specter.models.alert import AlertSeverity
from specter.models.person import PersonProfile

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a protective intelligence triage analyst. Assess the digital exposure of the
subject based on the provided PersonProfile and produce a structured risk assessment.

Rules:
- exposure_score: integer 0-100 (0=no exposure, 100=critical)
- risk_categories: list of applicable categories from:
  [breach_exposure, dark_web_presence, social_overexposure, address_exposure,
   threat_actor_contact, impersonation_risk, family_exposure]
- critical_findings: concise, factual observations
- recommendations: actionable privacy/security steps, non-accusatory language
- alert_required: true if exposure_score >= 70 or critical_finding present
- alert_severity: one of info | low | medium | high | critical

Return ONLY valid JSON, no prose, no markdown.

Schema:
{
  "exposure_score": integer,
  "risk_categories": [string],
  "critical_findings": [string],
  "recommendations": [string],
  "alert_required": boolean,
  "alert_severity": string
}
"""


@dataclass
class TriageResult:
    """Structured risk assessment for a PersonProfile."""

    exposure_score: int  # 0–100
    risk_categories: list[str] = field(default_factory=list)
    critical_findings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    alert_required: bool = False
    alert_severity: AlertSeverity = AlertSeverity.INFO


class Triage:
    """Uses Claude Opus to produce a TriageResult for a PersonProfile."""

    def __init__(
        self,
        client: Any | None = None,
        model: str = "claude-opus-4-7",
    ) -> None:
        if client is None:
            import anthropic
            client = anthropic.AsyncAnthropic()
        self._client = client
        self._model = model

    async def assess(self, profile: PersonProfile) -> TriageResult:
        """Produce a TriageResult for a PersonProfile. Never raises."""
        prompt = self._format_prompt(profile)
        try:
            message = await self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = message.content[0].text
            data = self._parse_json(raw)
            return self._build_result(data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Triage API error: %s", exc)
            return self._heuristic_result(profile)

    # ------------------------------------------------------------------

    def _format_prompt(self, profile: PersonProfile) -> str:
        return (
            "Assess this PersonProfile for privacy and security risk:\n\n"
            + profile.model_dump_json(indent=2)
        )

    def _parse_json(self, text: str) -> dict:
        text = text.strip()
        m = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
        if m:
            text = m.group(1)
        return json.loads(text)

    def _build_result(self, data: dict) -> TriageResult:
        score = max(0, min(100, int(data.get("exposure_score", 0))))
        raw_severity = data.get("alert_severity", "info")
        try:
            severity = AlertSeverity(raw_severity)
        except ValueError:
            severity = AlertSeverity.INFO
        return TriageResult(
            exposure_score=score,
            risk_categories=data.get("risk_categories", []),
            critical_findings=data.get("critical_findings", []),
            recommendations=data.get("recommendations", []),
            alert_required=bool(data.get("alert_required", score >= 70)),
            alert_severity=severity,
        )

    def _heuristic_result(self, profile: PersonProfile) -> TriageResult:
        """Deterministic fallback when API is unavailable."""
        breach_count = sum(
            1 for s in profile.raw_sources if s in ("hibp", "breach", "intelx")
        )
        score = min(100, breach_count * 20 + len(profile.emails) * 5)
        severity = (
            AlertSeverity.HIGH if score >= 70
            else AlertSeverity.MEDIUM if score >= 40
            else AlertSeverity.LOW
        )
        return TriageResult(
            exposure_score=score,
            risk_categories=["breach_exposure"] if breach_count else [],
            critical_findings=[],
            recommendations=["Review breach exposure and enable account monitoring."],
            alert_required=score >= 70,
            alert_severity=severity,
        )
