"""Breach intelligence: HIBP + IntelX."""

from __future__ import annotations

import asyncio
import time

import httpx

from specter.collectors.base import BaseCollector
from specter.credentials.registry import SERVICES
from specter.credentials.store import CredentialStore
from specter.models.credential import ServiceConfig
from specter.models.job import JobResult, JobStatus
from specter.models.target import SeedInput

_INTELX_BASE = "https://2.intelx.io"


class BreachCollector(BaseCollector):
    """Queries HIBP and IntelX for breach records. Returns data-class labels only."""

    name = "breach"
    seed_types = ["email", "username", "phone"]
    produces = ["breach_records", "paste_mentions"]

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    @property
    def config(self) -> ServiceConfig:
        return SERVICES["hibp"]

    def is_available(self) -> bool:
        return bool(self._store.get("hibp") or self._store.get("intelx"))

    async def collect(self, seed: SeedInput) -> JobResult:
        job_id = f"{self.name}:{seed.value}"
        if seed.seed_type not in self.seed_types:
            return self._error_result(job_id, seed, f"Unsupported seed type: {seed.seed_type}")
        self._check_ethics(seed)

        start = time.monotonic()
        hibp_task = self._query_hibp(seed.value) if seed.seed_type == "email" else asyncio.sleep(0, result=[])
        intelx_task = self._query_intelx(seed.value)

        hibp_result, intelx_result = await asyncio.gather(
            hibp_task, intelx_task, return_exceptions=True
        )

        artifacts: list[dict] = []
        errors: list[str] = []
        for name, result in [("hibp", hibp_result), ("intelx", intelx_result)]:
            if isinstance(result, Exception):
                errors.append(f"{name}: {result}")
            elif isinstance(result, list):
                artifacts.extend(result)

        duration = time.monotonic() - start
        return JobResult(
            job_id=job_id,
            collector=self.name,
            seed=seed,
            status=JobStatus.COMPLETED,
            artifacts=artifacts,
            error="; ".join(errors) if errors else None,
            duration_seconds=duration,
        )

    async def _query_hibp(self, email: str) -> list[dict]:
        api_key = self._store.get("hibp")
        if not api_key:
            return []
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": api_key, "user-agent": "Specter/1.0"},
                params={"truncateResponse": "false"},
            )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return [
            {
                "type": "breach_record",
                "breach_name": b.get("Name"),
                "data_classes": b.get("DataClasses", []),  # labels only — no raw creds
                "breach_date": b.get("BreachDate"),
                "source": "hibp",
            }
            for b in resp.json()
        ]

    async def _query_intelx(self, query: str) -> list[dict]:
        api_key = self._store.get("intelx")
        if not api_key:
            return []
        async with httpx.AsyncClient(timeout=30) as client:
            # Step 1: initiate search
            resp = await client.post(
                f"{_INTELX_BASE}/intelligent/search",
                headers={"x-key": api_key},
                json={"term": query, "maxresults": 20, "media": 0, "sort": 4},
            )
            resp.raise_for_status()
            search_id = resp.json().get("id")
            if not search_id:
                return []

            # Step 2: fetch results (single poll)
            resp2 = await client.get(
                f"{_INTELX_BASE}/intelligent/search/result",
                headers={"x-key": api_key},
                params={"id": search_id, "limit": 20},
            )
            resp2.raise_for_status()
            records = resp2.json().get("records", [])

        return [
            {
                "type": "paste_mention",
                "context_summary": f"Bucket: {r.get('bucket', 'unknown')}, Media: {r.get('media', '')}",
                "indexed_at": r.get("date"),
                "source": "intelx",
            }
            for r in records
        ]
