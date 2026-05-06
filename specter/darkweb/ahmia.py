"""Ahmia clearnet Tor search index — no Tor client required."""

from __future__ import annotations

import logging
import re

import httpx

from specter.models.breach import DarkWebSignal

logger = logging.getLogger(__name__)

_AHMIA_SEARCH = "https://ahmia.fi/search/"


class AhmiaClient:
    """Queries Ahmia's clearnet search index for dark web references.

    Ahmia indexes .onion content and is accessible over HTTPS without Tor.
    Only metadata (URLs, titles) is collected — no raw page content retrieved.
    """

    async def search(
        self, query: str, target_id: str | None = None
    ) -> list[DarkWebSignal]:
        """Search Ahmia for the given query and return sanitised signals."""
        try:
            results = await self._fetch(query)
            return [self._to_signal(r, query, target_id) for r in results]
        except Exception as exc:  # noqa: BLE001
            logger.warning("Ahmia search failed for '%s': %s", query, exc)
            return []

    async def _fetch(self, query: str) -> list[dict]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                _AHMIA_SEARCH,
                params={"q": query},
                headers={"User-Agent": "Specter/1.0"},
            )
        if resp.status_code != 200:
            return []
        return self._parse_html(resp.text)

    @staticmethod
    def _parse_html(html: str) -> list[dict]:
        """Extract result titles and .onion URLs from Ahmia search results page."""
        results: list[dict] = []
        # Ahmia results: <li class="result"> ... <h4><a href="...">title</a></h4>
        pattern = re.compile(
            r'<h4>\s*<a\s+href="([^"]+)"[^>]*>([^<]+)</a>\s*</h4>',
            re.IGNORECASE,
        )
        for m in pattern.finditer(html):
            results.append({"url": m.group(1).strip(), "title": m.group(2).strip()})
        return results

    @staticmethod
    def _to_signal(result: dict, query: str, target_id: str | None) -> DarkWebSignal:
        title = result.get("title", "Untitled")
        url = result.get("url", "")
        # Sanitised — only title and .onion URL (metadata), not page content
        summary = f"Ahmia result: '{title[:120]}'"
        return DarkWebSignal(
            source="ahmia",
            query=query,
            result_type="forum_post",
            context_summary=summary,
            url=url if ".onion" in url else None,
            target_id=target_id,
            severity="low",
        )
