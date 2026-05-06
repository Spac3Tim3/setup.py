"""Image intelligence: FaceCheck.ID API + Exiftool EXIF extraction."""

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


class ImageCollector(BaseCollector):
    """Extracts face matches via FaceCheck.ID and EXIF/GPS via Exiftool."""

    name = "image"
    seed_types = ["image"]
    produces = ["face_matches", "gps", "device_metadata"]

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    @property
    def config(self) -> ServiceConfig:
        return SERVICES["facecheck"]

    def is_available(self) -> bool:
        import shutil
        return bool(shutil.which("exiftool"))

    async def collect(self, seed: SeedInput) -> JobResult:
        job_id = f"{self.name}:{seed.value}"
        if seed.seed_type != "image":
            return self._error_result(job_id, seed, f"Unsupported seed type: {seed.seed_type}")
        self._check_ethics(seed)

        start = time.monotonic()
        artifacts: list[dict] = []
        errors: list[str] = []

        exif_task = self._run_exiftool(seed.value)
        face_task = self._run_facecheck(seed.value)
        exif_result, face_result = await asyncio.gather(exif_task, face_task, return_exceptions=True)

        for name, result in [("exiftool", exif_result), ("facecheck", face_result)]:
            if isinstance(result, Exception):
                errors.append(f"{name}: {result}")
            else:
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

    async def _run_exiftool(self, path_or_url: str) -> list[dict]:
        import shutil
        if not shutil.which("exiftool"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "exiftool", "-json", "-GPS*", "-Make", "-Model", "-DateTimeOriginal",
            path_or_url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        try:
            data = json.loads(stdout.decode())
        except json.JSONDecodeError:
            return []

        artifacts: list[dict] = []
        for entry in data if isinstance(data, list) else [data]:
            artifact: dict = {"type": "exif", "source": "exiftool"}
            if lat := entry.get("GPSLatitude"):
                artifact["gps_lat"] = lat
            if lon := entry.get("GPSLongitude"):
                artifact["gps_lon"] = lon
            if make := entry.get("Make"):
                artifact["device_make"] = make
            if model := entry.get("Model"):
                artifact["device_model"] = model
            if ts := entry.get("DateTimeOriginal"):
                artifact["timestamp"] = ts
            if len(artifact) > 2:
                artifacts.append(artifact)
        return artifacts

    async def _run_facecheck(self, image_ref: str) -> list[dict]:
        api_key = self._store.get("facecheck")
        if not api_key:
            return []
        # FaceCheck.ID: POST search with image URL
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                "https://facecheck.id/api/search",
                headers={"Authorization": f"Bearer {api_key}"},
                json={"url": image_ref},
            )
        if resp.status_code != 200:
            return []
        matches = resp.json().get("matches", [])
        return [
            {"type": "face_match", "url": m.get("url"), "score": m.get("score"), "source": "facecheck"}
            for m in matches
        ]
