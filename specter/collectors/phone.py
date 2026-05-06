"""Phone number intelligence via PhoneInfoga subprocess."""

from __future__ import annotations

import asyncio
import json
import time

from specter.collectors.base import BaseCollector
from specter.credentials.registry import SERVICES
from specter.models.credential import ServiceConfig
from specter.models.job import JobResult, JobStatus
from specter.models.target import SeedInput


class PhoneCollector(BaseCollector):
    """Wraps PhoneInfoga CLI to gather carrier, region, and linked account data."""

    name = "phoneinfoga"
    seed_types = ["phone"]
    produces = ["carrier", "region", "linked_accounts"]

    @property
    def config(self) -> ServiceConfig:
        return SERVICES["phoneinfoga"]

    def is_available(self) -> bool:
        import shutil
        return bool(shutil.which("phoneinfoga"))

    async def collect(self, seed: SeedInput) -> JobResult:
        job_id = f"{self.name}:{seed.value}"
        if seed.seed_type != "phone":
            return self._error_result(job_id, seed, f"Unsupported seed type: {seed.seed_type}")
        if not self.is_available():
            return self._error_result(job_id, seed, "phoneinfoga not found on PATH")
        self._check_ethics(seed)

        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                "phoneinfoga", "scan", "-n", seed.value, "--output", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        except asyncio.TimeoutError:
            return self._error_result(job_id, seed, "phoneinfoga timed out after 60s")
        except Exception as exc:  # noqa: BLE001
            return self._error_result(job_id, seed, f"subprocess error: {exc}")

        duration = time.monotonic() - start
        raw: dict = {}
        try:
            raw = json.loads(stdout.decode())
        except json.JSONDecodeError:
            raw = {"stdout": stdout.decode(), "stderr": stderr.decode()}

        artifacts = self._parse_artifacts(raw)
        return JobResult(
            job_id=job_id,
            collector=self.name,
            seed=seed,
            status=JobStatus.COMPLETED,
            raw_output=raw,
            artifacts=artifacts,
            duration_seconds=duration,
        )

    @staticmethod
    def _parse_artifacts(raw: dict) -> list[dict]:
        artifacts: list[dict] = []
        if carrier := raw.get("carrier"):
            artifacts.append({"type": "carrier", "value": carrier})
        if region := raw.get("country") or raw.get("region"):
            artifacts.append({"type": "region", "value": region})
        for acct in raw.get("found_accounts", []):
            artifacts.append({"type": "linked_account", "value": acct})
        return artifacts
