"""Abstract base class for all Specter data collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod

from specter.models.credential import ServiceConfig
from specter.models.job import JobResult
from specter.models.target import SeedInput


class EthicsConstraintError(Exception):
    """Raised when a collector would violate passive-only or public-source constraints."""


class BaseCollector(ABC):
    """Contract every collector must satisfy.

    Collectors are always passive (read-only). They must never write to,
    authenticate against, or modify any external system.
    They must never store or surface raw credential data.
    """

    #: Short identifier matching the service registry key
    name: str

    #: Seed types this collector can accept
    seed_types: list[str]

    #: Artifact types this collector produces
    produces: list[str]

    # Ethics flags — hardcoded, never overridden
    passive_only: bool = True
    no_credential_extraction: bool = True
    public_sources_only: bool = True

    @abstractmethod
    async def collect(self, seed: SeedInput) -> JobResult:
        """Run collection for the given seed. Never raises — errors go into JobResult."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this collector's tool/key is present and configured."""

    @property
    @abstractmethod
    def config(self) -> ServiceConfig:
        """Return the ServiceConfig for this collector's backing service."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _check_ethics(self, seed: SeedInput) -> None:
        """Raise EthicsConstraintError if the seed would violate constraints."""
        if not self.passive_only:
            raise EthicsConstraintError(f"{self.name}: passive_only must be True")
        if not self.public_sources_only:
            raise EthicsConstraintError(f"{self.name}: public_sources_only must be True")

    def _error_result(self, job_id: str, seed: SeedInput, error: str) -> JobResult:
        from specter.models.job import JobStatus

        return JobResult(
            job_id=job_id,
            collector=self.name,
            seed=seed,
            status=JobStatus.FAILED,
            error=error,
        )
