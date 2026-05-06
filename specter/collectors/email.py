"""Email intelligence: Holehe, GHunt, HIBP, EmailRep."""

from __future__ import annotations

import asyncio
import json
import time

import httpx

from specter.collectors.base import BaseCollector
from specter.credentials.registry import SERVICES
from specter.credentials.store import CredentialStore
from specter.models.credential import ServiceConfig
from specter.models.job import JobResult, JobStatus
from specter.models.target import SeedInput


class EmailCollector(BaseCollector):
    """Aggregates email-based intelligence from Holehe, GHunt, HIBP, and EmailRep."""

    name = "email"
    seed_types = ["email"]
    produces = ["services", "breach_list", "google_metadata", "reputation"]

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    @property
    def config(self) -> ServiceConfig:
        return SERVICES["hibp"]

    def is_available(self) -> bool:
        import shutil
        return bool(shutil.which("holehe"))

    async def collect(self, seed: SeedInput) -> JobResult:
        job_id = f"{self.name}:{seed.value}"
        if seed.seed_type != "email":
            return self._error_result(job_id, seed, f"Unsupported seed type: {seed.seed_type}")
        self._check_ethics(seed)

        start = time.monotonic()
        artifacts: list[dict] = []
        errors: list[str] = []

        # Run sub-collectors concurrently
        holehe, hibp, emailrep = await asyncio.gather(
            self._run_holehe(seed.value),
            self._run_hibp(seed.value),
            self._run_emailrep(seed.value),
            return_exceptions=True,
        )
        for name, result in [("holehe", holehe), ("hibp", hibp), ("emailrep", emailrep)]:
            if isinstance(result, Exception):
                errors.append(f"{name}: {result}")
            else:
                artifacts.extend(result)

        duration = time.monotonic() - start
        status = JobStatus.COMPLETED if artifacts else JobStatus.FAILED
        error = "; ".join(errors) if errors and not artifacts else None

        return JobResult(
            job_id=job_id,
            collector=self.name,
            seed=seed,
            status=status,
            artifacts=artifacts,
            error=error,
            duration_seconds=duration,
        )

    async def _run_holehe(self, email: str) -> list[dict]:
        """Run holehe CLI and parse registered services."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "holehe", "--only-used", "--no-color", email,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except (asyncio.TimeoutError, FileNotFoundError) as exc:
            raise RuntimeError(str(exc)) from exc

        artifacts: list[dict] = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if line.startswith("[✓]") or line.startswith("[+]"):
                service = line.split(None, 1)[-1].strip()
                artifacts.append({"type": "registered_service", "value": service, "source": "holehe"})
        return artifacts

    async def _run_hibp(self, email: str) -> list[dict]:
        """Query HIBP for breaches. Returns data-class labels only."""
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
        if resp.status_code != 200:
            raise RuntimeError(f"HIBP HTTP {resp.status_code}")
        artifacts: list[dict] = []
        for breach in resp.json():
            artifacts.append({
                "type": "breach",
                "breach_name": breach.get("Name"),
                "data_classes": breach.get("DataClasses", []),
                "breach_date": breach.get("BreachDate"),
                "source": "hibp",
            })
        return artifacts

    async def _run_emailrep(self, email: str) -> list[dict]:
        """Query EmailRep for reputation metadata."""
        api_key = self._store.get("emailrep")
        headers = {"User-Agent": "Specter/1.0"}
        if api_key:
            headers["Key"] = api_key
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"https://emailrep.io/{email}", headers=headers)
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [{
            "type": "reputation",
            "reputation": data.get("reputation"),
            "suspicious": data.get("suspicious"),
            "references": data.get("references"),
            "profiles": data.get("details", {}).get("profiles", []),
            "source": "emailrep",
        }]
