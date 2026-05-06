"""Sonnet-powered normalizer: raw JobResults → PersonProfile."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from specter.models.job import JobResult
from specter.models.person import IdentityConfidence, PersonProfile, PhoneIntel, SocialPresence

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a precise intelligence analyst normalization engine.
Your job is to extract, merge, and deduplicate identity data from raw collector output.

Rules:
- Extract all unique identifiers (emails, usernames, phones, platforms, locations, employers)
- Merge entries representing the same person across different sources
- Deduplicate: if the same email appears from two sources, list it once
- Tag each social presence with its source
- Flag conflicts in a top-level "conflicts" array (e.g. contradicting names or locations)
- Return ONLY a valid JSON object — no prose, no markdown fences
- Never fabricate data not present in the input
- Never include raw passwords, hashes, or credential content

Return schema:
{
  "full_name": string | null,
  "aliases": [string],
  "emails": [string],
  "phones": [{"number": string, "carrier": string|null, "region": string|null}],
  "social_presence": [{"platform": string, "username": string, "url": string|null, "source": string}],
  "locations": [string],
  "employers": [string],
  "conflicts": [string]
}
"""


class Normalizer:
    """Uses Claude Sonnet to normalize raw collector output into a PersonProfile."""

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

    async def normalize(self, results: list[JobResult]) -> PersonProfile:
        """Normalize a list of JobResults into a deduplicated PersonProfile."""
        if not results:
            return PersonProfile()

        prompt = self._format_prompt(results)
        try:
            message = await self._client.messages.create(
                model=self._model,
                max_tokens=4096,
                system=_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = message.content[0].text
            data = self._parse_json(raw)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Normalizer API error: %s", exc)
            return self._fallback_profile(results)

        return self._build_profile(data, results)

    # ------------------------------------------------------------------

    def _format_prompt(self, results: list[JobResult]) -> str:
        sections: list[str] = []
        for r in results:
            sections.append(
                f"Source: {r.collector}\n"
                f"Seed: {r.seed.seed_type}={r.seed.value}\n"
                f"Artifacts: {json.dumps(r.artifacts, default=str)}"
            )
        return "Normalize this intelligence data:\n\n" + "\n---\n".join(sections)

    def _parse_json(self, text: str) -> dict:
        text = text.strip()
        # Strip markdown code fences if present
        m = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
        if m:
            text = m.group(1)
        return json.loads(text)

    def _build_profile(self, data: dict, results: list[JobResult]) -> PersonProfile:
        phone_intel = [
            PhoneIntel(
                number=p["number"],
                carrier=p.get("carrier"),
                region=p.get("region"),
            )
            for p in data.get("phones", [])
            if p.get("number")
        ]
        social = [
            SocialPresence(
                platform=s["platform"],
                username=s["username"],
                url=s.get("url"),
                source=s.get("source", ""),
            )
            for s in data.get("social_presence", [])
            if s.get("platform") and s.get("username")
        ]
        # Deduplicate emails case-insensitively
        emails = list({e.lower().strip() for e in data.get("emails", []) if e})
        conflicts = data.get("conflicts", [])
        confidence = IdentityConfidence(
            score=0.5,
            conflicts=conflicts,
            requires_review=bool(conflicts),
        )
        return PersonProfile(
            full_name=data.get("full_name"),
            aliases=data.get("aliases", []),
            emails=emails,
            phone_intel=phone_intel,
            social_presence=social,
            locations=data.get("locations", []),
            employers=data.get("employers", []),
            confidence=confidence,
            raw_sources=list({r.collector for r in results}),
        )

    def _fallback_profile(self, results: list[JobResult]) -> PersonProfile:
        """Best-effort profile built without AI, used on API failure."""
        emails: set[str] = set()
        for r in results:
            for a in r.artifacts:
                if a.get("type") == "breach" and (email := r.seed.value):
                    if r.seed.seed_type == "email":
                        emails.add(email.lower())
        return PersonProfile(
            emails=list(emails),
            raw_sources=list({r.collector for r in results}),
        )
