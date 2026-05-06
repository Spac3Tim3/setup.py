"""Username intelligence: Maigret + Whatsmyname."""

from __future__ import annotations

import asyncio
import json
import time

from specter.collectors.base import BaseCollector
from specter.credentials.registry import SERVICES
from specter.models.credential import ServiceConfig
from specter.models.job import JobResult, JobStatus
from specter.models.target import SeedInput


class UsernameCollector(BaseCollector):
    """Discovers platform presence for a username via Maigret and Whatsmyname."""

    name = "username"
    seed_types = ["username"]
    produces = ["platform_presence", "profile_data"]

    @property
    def config(self) -> ServiceConfig:
        return SERVICES["maigret"]

    def is_available(self) -> bool:
        import shutil
        return bool(shutil.which("maigret"))

    async def collect(self, seed: SeedInput) -> JobResult:
        job_id = f"{self.name}:{seed.value}"
        if seed.seed_type != "username":
            return self._error_result(job_id, seed, f"Unsupported seed type: {seed.seed_type}")
        if not self.is_available():
            return self._error_result(job_id, seed, "maigret not found on PATH")
        self._check_ethics(seed)

        start = time.monotonic()
        maigret_result, wmn_result = await asyncio.gather(
            self._run_maigret(seed.value),
            self._run_whatsmyname(seed.value),
            return_exceptions=True,
        )

        artifacts: list[dict] = []
        errors: list[str] = []
        for name, result in [("maigret", maigret_result), ("whatsmyname", wmn_result)]:
            if isinstance(result, Exception):
                errors.append(f"{name}: {result}")
            else:
                artifacts.extend(result)

        duration = time.monotonic() - start
        return JobResult(
            job_id=job_id,
            collector=self.name,
            seed=seed,
            status=JobStatus.COMPLETED if artifacts else JobStatus.FAILED,
            artifacts=artifacts,
            error="; ".join(errors) if errors and not artifacts else None,
            duration_seconds=duration,
        )

    async def _run_maigret(self, username: str) -> list[dict]:
        proc = await asyncio.create_subprocess_exec(
            "maigret", username, "--json", "/dev/stdout", "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("maigret timed out")

        try:
            data = json.loads(stdout.decode())
        except json.JSONDecodeError:
            return []

        artifacts: list[dict] = []
        for platform, info in data.items():
            if isinstance(info, dict) and info.get("status") == "Claimed":
                artifacts.append({
                    "type": "platform_presence",
                    "platform": platform,
                    "url": info.get("url_user"),
                    "profile_data": info,
                    "source": "maigret",
                })
        return artifacts

    async def _run_whatsmyname(self, username: str) -> list[dict]:
        import shutil
        if not shutil.which("whatsmyname"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "whatsmyname", "-u", username, "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            return []

        try:
            sites = json.loads(stdout.decode())
        except json.JSONDecodeError:
            return []

        return [
            {"type": "platform_presence", "platform": s.get("name"), "url": s.get("uri"),
             "source": "whatsmyname"}
            for s in (sites if isinstance(sites, list) else [])
        ]
