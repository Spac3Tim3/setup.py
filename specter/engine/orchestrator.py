"""Pipeline coordinator: seed queue → collectors → new seeds → repeat."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from specter.collectors.registry import CollectorRegistry
from specter.engine.convergence import ConvergenceChecker, ConvergenceConfig
from specter.engine.seed_queue import SeedQueue
from specter.models.job import CollectionJob, JobResult, JobStatus
from specter.models.target import SeedInput

logger = logging.getLogger(__name__)


@dataclass
class OrchestratorResult:
    job_id: str
    results: list[JobResult] = field(default_factory=list)
    seeds_processed: int = 0
    convergence_reason: str = ""
    duration_seconds: float = 0.0
    status: JobStatus = JobStatus.PENDING


class Orchestrator:
    """Runs the enrichment loop end-to-end for a CollectionJob.

    Loop invariant:
      while queue not empty and not converged:
          pop seed
          run all matching available collectors concurrently
          push new seeds discovered in results
          increment depth
    """

    def __init__(
        self,
        registry: CollectorRegistry,
        convergence_config: ConvergenceConfig | None = None,
        concurrency: int = 5,
    ) -> None:
        self._registry = registry
        self._config = convergence_config or ConvergenceConfig()
        self._concurrency = concurrency

    async def run(self, job: CollectionJob) -> OrchestratorResult:
        """Execute the enrichment pipeline. Never raises — all errors are captured."""
        out = OrchestratorResult(job_id=job.id, status=JobStatus.RUNNING)
        start = time.monotonic()

        queue = SeedQueue()
        queue.push_many(job.seeds)
        convergence = ConvergenceChecker(
            ConvergenceConfig(
                max_depth=job.max_depth,
                max_seeds=job.max_seeds,
                time_limit_seconds=job.time_limit_minutes * 60,
            )
        )
        semaphore = asyncio.Semaphore(self._concurrency)
        depth = 0

        while not queue.is_empty():
            should_stop, reason = convergence.check(
                seeds_processed=queue.processed_count(),
                current_depth=depth,
            )
            if should_stop:
                out.convergence_reason = reason
                logger.info("Converged: %s", reason)
                break

            # Drain the current queue level
            batch: list[SeedInput] = []
            while not queue.is_empty():
                seed = queue.pop()
                if seed:
                    batch.append(seed)

            tasks = [self._run_seed(seed, job, semaphore) for seed in batch]
            batch_results: list[JobResult | BaseException] = await asyncio.gather(
                *tasks, return_exceptions=True
            )

            for res in batch_results:
                if isinstance(res, BaseException):
                    logger.warning("Unexpected collector exception: %s", res)
                    continue
                out.results.append(res)
                added = queue.push_many(res.new_seeds)
                if added:
                    logger.debug("Queued %d new seeds from %s", added, res.collector)

            depth += 1

        if not out.convergence_reason:
            out.convergence_reason = "queue_empty"

        out.seeds_processed = queue.processed_count()
        out.duration_seconds = time.monotonic() - start
        out.status = JobStatus.COMPLETED
        return out

    async def _run_seed(
        self,
        seed: SeedInput,
        job: CollectionJob,
        semaphore: asyncio.Semaphore,
    ) -> JobResult:
        collectors = [
            c
            for c in self._registry.available()
            if seed.seed_type in c.seed_types
            and (not job.collectors or c.name in job.collectors)
        ]
        if not collectors:
            return JobResult(
                job_id=job.id,
                collector="none",
                seed=seed,
                status=JobStatus.FAILED,
                error=f"No available collector for seed_type='{seed.seed_type}'",
            )
        # Run all matching collectors and merge; use semaphore for concurrency cap
        async with semaphore:
            results = await asyncio.gather(
                *[c.collect(seed) for c in collectors], return_exceptions=True
            )
        # Return the first successful result, accumulating new_seeds from all
        primary: JobResult | None = None
        all_new_seeds: list[SeedInput] = []
        for r in results:
            if isinstance(r, BaseException):
                continue
            all_new_seeds.extend(r.new_seeds)
            if primary is None or r.status == JobStatus.COMPLETED:
                primary = r
        if primary is None:
            return JobResult(
                job_id=job.id,
                collector="none",
                seed=seed,
                status=JobStatus.FAILED,
                error="All collectors failed",
            )
        # Attach merged new_seeds
        return primary.model_copy(update={"new_seeds": all_new_seeds})
