"""API key health validation for each registered service."""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Awaitable, Callable

import httpx

from specter.credentials.registry import SERVICES
from specter.credentials.store import CredentialStore
from specter.models.credential import CollectorHealth, ServiceConfig

_PingFn = Callable[[str], Awaitable[tuple[bool, str | None]]]


class HealthValidator:
    """Checks availability and key validity for every registered service.

    Kali-native tools are checked via PATH lookup. API services get a
    lightweight authenticated ping. All checks are run concurrently.
    """

    def __init__(self, store: CredentialStore) -> None:
        self._store = store

    async def check(self, service_id: str) -> CollectorHealth:
        """Health-check a single service."""
        config = SERVICES.get(service_id)
        if config is None:
            return CollectorHealth(
                service_id=service_id,
                available=False,
                configured=False,
                error=f"Unknown service: '{service_id}'",
            )
        if config.kali_native:
            return self._check_native_tool(service_id, config)
        return await self._check_api_service(service_id, config)

    async def check_all(self) -> list[CollectorHealth]:
        """Run health checks for all registered services concurrently."""
        tasks = [self.check(svc_id) for svc_id in SERVICES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[CollectorHealth] = []
        for svc_id, result in zip(SERVICES, results):
            if isinstance(result, Exception):
                out.append(
                    CollectorHealth(
                        service_id=svc_id,
                        available=False,
                        configured=False,
                        error=str(result),
                    )
                )
            else:
                out.append(result)  # type: ignore[arg-type]
        return out

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_native_tool(self, service_id: str, config: ServiceConfig) -> CollectorHealth:
        """Verify a CLI tool exists on PATH."""
        candidates = [
            service_id,
            service_id.replace("_", "-"),
            service_id.replace("_", ""),
        ]
        found = any(shutil.which(name) for name in candidates)
        return CollectorHealth(
            service_id=service_id,
            available=found,
            configured=True,
            key_valid=None,
            error=(
                None
                if found
                else f"Tool '{service_id}' not found on PATH. Install: {config.install_cmd}"
            ),
        )

    async def _check_api_service(
        self, service_id: str, config: ServiceConfig
    ) -> CollectorHealth:
        """Verify a stored key and perform a lightweight live ping."""
        api_key = self._store.get(service_id)
        if api_key is None:
            return CollectorHealth(
                service_id=service_id,
                available=False,
                configured=False,
                key_valid=False,
                error="API key not configured",
            )

        ping_fn = _SERVICE_PINGS.get(service_id)
        if ping_fn is None:
            # No live ping registered; treat presence of key as available
            return CollectorHealth(
                service_id=service_id,
                available=True,
                configured=True,
                key_valid=None,
            )

        try:
            valid, error = await ping_fn(api_key)
            return CollectorHealth(
                service_id=service_id,
                available=valid,
                configured=True,
                key_valid=valid,
                error=error,
            )
        except Exception as exc:  # noqa: BLE001
            return CollectorHealth(
                service_id=service_id,
                available=False,
                configured=True,
                key_valid=None,
                error=f"Ping failed: {exc}",
            )


# ---------------------------------------------------------------------------
# Per-service lightweight ping functions
# ---------------------------------------------------------------------------


async def _ping_hibp(api_key: str) -> tuple[bool, str | None]:
    """HIBP: list breach names (no PII, always public)."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://haveibeenpwned.com/api/v3/breachnames",
            headers={"hibp-api-key": api_key, "user-agent": "Specter-HealthCheck/1.0"},
        )
    if resp.status_code == 200:
        return True, None
    if resp.status_code == 401:
        return False, "Invalid API key"
    return False, f"Unexpected HTTP {resp.status_code}"


async def _ping_intelx(api_key: str) -> tuple[bool, str | None]:
    """IntelX: account info endpoint."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://2.intelx.io/authenticate/info",
            headers={"x-key": api_key},
        )
    if resp.status_code == 200:
        return True, None
    if resp.status_code == 401:
        return False, "Invalid API key"
    return False, f"Unexpected HTTP {resp.status_code}"


async def _ping_emailrep(api_key: str) -> tuple[bool, str | None]:
    """EmailRep: query a known-safe address; 400 is acceptable (key authenticated)."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://emailrep.io/query/test@example.com",
            headers={"Key": api_key, "User-Agent": "Specter-HealthCheck/1.0"},
        )
    if resp.status_code in (200, 400):
        return True, None
    if resp.status_code == 401:
        return False, "Invalid API key"
    return False, f"Unexpected HTTP {resp.status_code}"


async def _ping_shodan(api_key: str) -> tuple[bool, str | None]:
    """Shodan: account info."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"https://api.shodan.io/api-info?key={api_key}")
    if resp.status_code == 200:
        return True, None
    if resp.status_code == 401:
        return False, "Invalid API key"
    return False, f"Unexpected HTTP {resp.status_code}"


async def _ping_facecheck(api_key: str) -> tuple[bool, str | None]:
    """FaceCheck.ID: search endpoint; 422 is expected without an image (key OK)."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            "https://facecheck.id/api/search",
            headers={"Authorization": f"Bearer {api_key}"},
        )
    if resp.status_code in (200, 422):
        return True, None
    if resp.status_code in (401, 403):
        return False, "Invalid API key"
    return False, f"Unexpected HTTP {resp.status_code}"


_SERVICE_PINGS: dict[str, _PingFn] = {
    "hibp": _ping_hibp,
    "intelx": _ping_intelx,
    "emailrep": _ping_emailrep,
    "shodan": _ping_shodan,
    "facecheck": _ping_facecheck,
}
