"""IntelX REST API client — passive, read-only."""

from __future__ import annotations

import logging

import httpx

from specter.models.breach import DarkWebSignal

logger = logging.getLogger(__name__)

_BASE = "https://2.intelx.io"
_MAX_RESULTS = 20


class IntelXClient:
    """Queries IntelX for breach/paste mentions of an identifier.

    Results are sanitised: context_summary contains a description only.
    Raw credential data is never stored or returned.
    """

    def __init__(self, api_key: str) -> None:
        self._key = api_key

    async def search(self, query: str, target_id: str | None = None) -> list[DarkWebSignal]:
        """Search IntelX for the given query term."""
        try:
            search_id = await self._initiate_search(query)
            if not search_id:
                return []
            records = await self._fetch_results(search_id)
            return [self._to_signal(r, query, target_id) for r in records]
        except Exception as exc:  # noqa: BLE001
            logger.warning("IntelX search failed for '%s': %s", query, exc)
            return []

    async def _initiate_search(self, query: str) -> str | None:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{_BASE}/intelligent/search",
                headers={"x-key": self._key},
                json={"term": query, "maxresults": _MAX_RESULTS, "media": 0, "sort": 4},
            )
        if resp.status_code != 200:
            logger.warning("IntelX search initiation returned %s", resp.status_code)
            return None
        return resp.json().get("id")

    async def _fetch_results(self, search_id: str) -> list[dict]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{_BASE}/intelligent/search/result",
                headers={"x-key": self._key},
                params={"id": search_id, "limit": _MAX_RESULTS},
            )
        if resp.status_code != 200:
            return []
        return resp.json().get("records", [])

    @staticmethod
    def _to_signal(record: dict, query: str, target_id: str | None) -> DarkWebSignal:
        bucket = record.get("bucket", "unknown")
        media = record.get("media", "")
        # Sanitised summary only — no raw credential content
        summary = f"Found in IntelX bucket '{bucket}' (media type: {media})"
        return DarkWebSignal(
            source="intelx",
            query=query,
            result_type="paste",
            context_summary=summary,
            indexed_at=record.get("date"),
            target_id=target_id,
            severity="medium",
        )
