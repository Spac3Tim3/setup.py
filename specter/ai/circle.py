"""Sonnet-powered close circle risk analysis."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from specter.models.person import CircleMember, PersonProfile

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a protective intelligence analyst assessing how a principal's close circle
creates or amplifies privacy and security risk for THAT PRINCIPAL ONLY.

Critical rules:
- Focus entirely on risk to the principal, not to circle members individually
- Do NOT name circle members in the output
- Use role-based language: "a family member", "a colleague", never a person's name
- Produce principal-centric, privacy-preserving language throughout
- Recommendations must be actionable and non-accusatory

Return ONLY valid JSON, no prose, no markdown.

Schema:
{
  "principal_risk_summary": string,
  "exposure_pathways": [string],   // how circle members create risk for principal
  "recommendations": [string],    // actionable steps for the principal
  "aggregate_risk_score": float   // 0.0-1.0
}
"""


@dataclass
class CircleRiskReport:
    """Principal-centric risk report derived from circle member analysis."""

    principal_id: str
    principal_risk_summary: str
    exposure_pathways: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    aggregate_risk_score: float = 0.0


class CircleAnalyzer:
    """Uses Claude Sonnet to analyze close-circle exposure risk for a principal."""

    def __init__(
        self,
        client: Any | None = None,
        model: str = "claude-sonnet-4-6",
    ) -> None:
        if client is None:
            import anthropic
            client = anthropic.AsyncAnthropic()
        self._client = client
        self._model = model

    async def analyze(
        self,
        principal: PersonProfile,
        circle: list[CircleMember],
    ) -> CircleRiskReport:
        """Generate a principal-centric risk report from circle member profiles."""
        if not circle:
            return CircleRiskReport(
                principal_id=principal.id,
                principal_risk_summary="No circle members to analyze.",
            )

        prompt = self._format_prompt(principal, circle)
        try:
            message = await self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = message.content[0].text
            data = self._parse_json(raw)
            return self._build_report(principal.id, data)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CircleAnalyzer API error: %s", exc)
            return CircleRiskReport(
                principal_id=principal.id,
                principal_risk_summary="Circle analysis unavailable due to API error.",
                exposure_pathways=[],
                recommendations=["Manual review of circle member exposure recommended."],
            )

    # ------------------------------------------------------------------

    def _format_prompt(self, principal: PersonProfile, circle: list[CircleMember]) -> str:
        # Strip identifying info from circle members before sending to AI
        sanitised_circle = []
        for member in circle:
            sanitised_circle.append({
                "relationship": member.relationship,
                "emails_count": len(member.profile.emails),
                "social_platforms": [s.platform for s in member.profile.social_presence],
                "locations": member.profile.locations,
                "breach_sources": member.profile.raw_sources,
                "risk_score": member.risk_score,
            })
        return (
            f"Principal exposure context: {len(principal.emails)} emails, "
            f"{len(principal.social_presence)} platforms.\n\n"
            f"Circle members (anonymised):\n{json.dumps(sanitised_circle, indent=2)}"
        )

    def _parse_json(self, text: str) -> dict:
        text = text.strip()
        m = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
        if m:
            text = m.group(1)
        return json.loads(text)

    def _build_report(self, principal_id: str, data: dict) -> CircleRiskReport:
        raw_score = float(data.get("aggregate_risk_score", 0.0))
        score = max(0.0, min(1.0, raw_score))
        return CircleRiskReport(
            principal_id=principal_id,
            principal_risk_summary=data.get("principal_risk_summary", ""),
            exposure_pathways=data.get("exposure_pathways", []),
            recommendations=data.get("recommendations", []),
            aggregate_risk_score=score,
        )
