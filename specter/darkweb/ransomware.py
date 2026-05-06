"""ransomware.live public victim feed monitor."""

from __future__ import annotations

import logging

import httpx

from specter.models.breach import DarkWebSignal

logger = logging.getLogger(__name__)

_API_BASE = "https://api.ransomware.live/v2"


class RansomwareLiveClient:
    """Checks the public ransomware.live victim feed for domain/organisation mentions.

    This is a passive, unauthenticated public API. No API key required.
    Victim data is returned as-published by the ransomware groups themselves.
    """

    async def check_victim(
        self, domain_or_org: str, target_id: str | None = None
    ) -> list[DarkWebSignal]:
        """Search victim posts for a domain or organisation name."""
        try:
            victims = await self._fetch_recent()
            return [
                self._to_signal(v, domain_or_org, target_id)
                for v in victims
                if self._matches(v, domain_or_org)
            ]
        except Exception as exc:  # noqa: BLE001
            logger.warning("ransomware.live check failed: %s", exc)
            return []

    async def _fetch_recent(self) -> list[dict]:
        """Fetch recent victim posts from the public API."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{_API_BASE}/recentvictims",
                headers={"User-Agent": "Specter/1.0"},
            )
        if resp.status_code != 200:
            return []
        data = resp.json()
        return data if isinstance(data, list) else data.get("victims", [])

    @staticmethod
    def _matches(victim: dict, query: str) -> bool:
        """Case-insensitive substring match against victim name, domain, or country."""
        query_lower = query.lower()
        for field in ("victim", "domain", "country", "description"):
            if query_lower in str(victim.get(field, "")).lower():
                return True
        return False

    @staticmethod
    def _to_signal(victim: dict, query: str, target_id: str | None) -> DarkWebSignal:
        group = victim.get("group", "unknown group")
        name = victim.get("victim", "unknown organisation")
        # Sanitised: no raw exfiltrated data, only published victim metadata
        summary = (
            f"Organisation '{name[:80]}' listed as victim by ransomware group '{group}'. "
            "Source: ransomware.live public feed."
        )
        return DarkWebSignal(
            source="ransomware.live",
            query=query,
            result_type="ransomware_victim",
            context_summary=summary,
            url=victim.get("url"),
            indexed_at=victim.get("published"),
            target_id=target_id,
            severity="high",
        )
