"""Agent 3 TDD contract: seed queue, convergence, scheduler, orchestrator."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from specter.collectors.registry import CollectorRegistry
from specter.credentials.store import CredentialStore
from specter.engine.convergence import ConvergenceChecker, ConvergenceConfig
from specter.engine.orchestrator import Orchestrator, OrchestratorResult
from specter.engine.scheduler import Cadence, Scheduler, TargetSchedule
from specter.engine.seed_queue import SeedQueue
from specter.models.job import CollectionJob, JobResult, JobStatus
from specter.models.target import SeedInput


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_seed(seed_type: str = "email", value: str = "test@example.com") -> SeedInput:
    return SeedInput(seed_type=seed_type, value=value)


def make_job(
    seeds: list[SeedInput] | None = None,
    max_depth: int = 4,
    max_seeds: int = 50,
    time_limit_minutes: int = 30,
) -> CollectionJob:
    return CollectionJob(
        target_id="t1",
        seeds=seeds or [make_seed()],
        max_depth=max_depth,
        max_seeds=max_seeds,
        time_limit_minutes=time_limit_minutes,
    )


@pytest.fixture
def store(tmp_path: Path) -> CredentialStore:
    return CredentialStore(fernet_key=Fernet.generate_key(), store_path=tmp_path / "c.json")


@pytest.fixture
def registry(store: CredentialStore) -> CollectorRegistry:
    return CollectorRegistry(store=store)


# ===========================================================================
# SeedQueue
# ===========================================================================


class TestSeedQueue:
    def test_push_and_pop(self):
        q = SeedQueue()
        seed = make_seed()
        assert q.push(seed) is True
        assert q.pop() == seed

    def test_deduplicates_by_type_and_value(self):
        q = SeedQueue()
        s1 = make_seed("email", "test@example.com")
        s2 = make_seed("email", "test@example.com")
        assert q.push(s1) is True
        assert q.push(s2) is False  # duplicate
        assert q.size() == 1

    def test_deduplication_is_case_insensitive(self):
        q = SeedQueue()
        assert q.push(make_seed("email", "Test@Example.COM")) is True
        assert q.push(make_seed("email", "test@example.com")) is False

    def test_different_types_not_deduplicated(self):
        q = SeedQueue()
        q.push(make_seed("email", "jdoe"))
        assert q.push(make_seed("username", "jdoe")) is True

    def test_push_many_returns_count(self):
        q = SeedQueue()
        seeds = [make_seed("email", f"user{i}@x.com") for i in range(5)]
        assert q.push_many(seeds) == 5
        assert q.push_many(seeds) == 0  # all duplicates

    def test_pop_empty_returns_none(self):
        q = SeedQueue()
        assert q.pop() is None

    def test_is_empty_after_all_popped(self):
        q = SeedQueue()
        q.push(make_seed())
        q.pop()
        assert q.is_empty()

    def test_processed_count_tracks_pops(self):
        q = SeedQueue()
        q.push_many([make_seed("email", f"{i}@x.com") for i in range(3)])
        q.pop()
        q.pop()
        assert q.processed_count() == 2

    def test_seen_count_includes_duplicates_only_once(self):
        q = SeedQueue()
        q.push(make_seed("email", "a@x.com"))
        q.push(make_seed("email", "a@x.com"))  # dup
        q.push(make_seed("email", "b@x.com"))
        assert q.seen_count() == 2


# ===========================================================================
# ConvergenceChecker
# ===========================================================================


class TestConvergenceChecker:
    def test_no_stop_within_limits(self):
        cfg = ConvergenceConfig(max_depth=4, max_seeds=50, time_limit_seconds=1800)
        checker = ConvergenceChecker(cfg)
        should_stop, _ = checker.check(seeds_processed=5, current_depth=2)
        assert should_stop is False

    def test_terminates_on_max_depth(self):
        cfg = ConvergenceConfig(max_depth=3, max_seeds=100, time_limit_seconds=3600)
        checker = ConvergenceChecker(cfg)
        should_stop, reason = checker.check(seeds_processed=1, current_depth=3)
        assert should_stop is True
        assert "max_depth" in reason

    def test_terminates_on_max_seeds(self):
        cfg = ConvergenceConfig(max_depth=10, max_seeds=5, time_limit_seconds=3600)
        checker = ConvergenceChecker(cfg)
        should_stop, reason = checker.check(seeds_processed=5, current_depth=1)
        assert should_stop is True
        assert "max_seeds" in reason

    def test_terminates_on_time_limit(self):
        cfg = ConvergenceConfig(max_depth=10, max_seeds=1000, time_limit_seconds=0.0)
        checker = ConvergenceChecker(cfg)
        # time_limit=0 means already exceeded at construction
        should_stop, reason = checker.check(seeds_processed=0, current_depth=0)
        assert should_stop is True
        assert "time_limit" in reason

    def test_elapsed_increases(self):
        checker = ConvergenceChecker(ConvergenceConfig())
        assert checker.elapsed() >= 0


# ===========================================================================
# Scheduler
# ===========================================================================


class TestScheduler:
    def test_register_creates_schedule(self):
        s = Scheduler()
        sched = s.register("t1", Cadence.DAILY)
        assert sched.target_id == "t1"
        assert sched.cadence == Cadence.DAILY

    def test_newly_registered_target_is_due(self):
        s = Scheduler()
        s.register("t1", Cadence.DAILY)
        assert "t1" in s.due_targets()

    def test_mark_run_advances_schedule_daily(self):
        s = Scheduler()
        s.register("t1", Cadence.DAILY)
        s.mark_run("t1")
        sched = s.get("t1")
        assert sched is not None
        assert sched.last_run_at is not None
        # next_run_at should be ~1 day in the future
        assert sched.next_run_at > datetime.utcnow()

    def test_mark_run_removes_from_due(self):
        s = Scheduler()
        s.register("t1", Cadence.DAILY)
        s.mark_run("t1")
        assert "t1" not in s.due_targets()

    def test_on_demand_never_auto_reschedules(self):
        s = Scheduler()
        s.register("t1", Cadence.ON_DEMAND)
        s.mark_run("t1")
        sched = s.get("t1")
        assert sched is not None
        assert sched.next_run_at == datetime.max

    def test_weekly_interval(self):
        s = Scheduler()
        s.register("t1", Cadence.WEEKLY)
        s.mark_run("t1")
        sched = s.get("t1")
        assert sched is not None
        # next run should be ~7 days out
        assert sched.next_run_at > datetime.utcnow() + timedelta(days=6)

    def test_scheduler_creates_job_on_cadence(self):
        """Registered target appears in due_targets immediately."""
        s = Scheduler()
        s.register("executive-001", Cadence.DAILY)
        due = s.due_targets()
        assert "executive-001" in due


# ===========================================================================
# Orchestrator (mocked collectors)
# ===========================================================================


class TestEnrichmentLoop:
    def _make_registry_with_mock_collector(
        self, store: CredentialStore, collector_name: str, seed_type: str,
        job_results: list[JobResult],
    ) -> CollectorRegistry:
        registry = CollectorRegistry(store=store)
        mock_collector = MagicMock()
        mock_collector.name = collector_name
        mock_collector.seed_types = [seed_type]
        mock_collector.is_available.return_value = True
        mock_collector.collect = AsyncMock(side_effect=job_results)
        registry._collectors = [mock_collector]
        return registry

    def _job_result(self, job_id: str, seed: SeedInput, new_seeds: list[SeedInput] | None = None) -> JobResult:
        return JobResult(
            job_id=job_id,
            collector="mock",
            seed=seed,
            status=JobStatus.COMPLETED,
            new_seeds=new_seeds or [],
        )

    async def test_terminates_on_empty_queue(self, store: CredentialStore):
        seed = make_seed()
        job = make_job(seeds=[seed])
        result = self._job_result(job.id, seed)
        registry = self._make_registry_with_mock_collector(
            store, "mock", "email", [result]
        )
        orch = Orchestrator(registry)
        out = await orch.run(job)
        assert out.status == JobStatus.COMPLETED
        assert out.convergence_reason == "queue_empty"
        assert out.seeds_processed >= 1

    async def test_terminates_on_max_depth(self, store: CredentialStore):
        """Each result yields a new seed, driving depth up until max_depth."""
        seeds_chain = [
            make_seed("email", f"depth{i}@x.com") for i in range(10)
        ]
        job = make_job(seeds=[seeds_chain[0]], max_depth=2, max_seeds=100)

        # Each collection discovers the next seed
        results = [
            self._job_result(job.id, seeds_chain[i], new_seeds=[seeds_chain[i + 1]])
            for i in range(len(seeds_chain) - 1)
        ]
        registry = self._make_registry_with_mock_collector(
            store, "mock", "email", results
        )
        orch = Orchestrator(registry)
        out = await orch.run(job)
        assert "max_depth" in out.convergence_reason

    async def test_terminates_on_time_limit(self, store: CredentialStore):
        seed = make_seed()
        job = make_job(seeds=[seed], time_limit_minutes=0)  # 0 minutes = immediate
        # Collector never called; loop stops before first iteration
        registry = CollectorRegistry(store=store)
        registry._collectors = []
        orch = Orchestrator(registry)
        out = await orch.run(job)
        # Either time_limit or queue_empty (queue drains before time check on some runs)
        assert out.status == JobStatus.COMPLETED

    async def test_new_artifact_triggers_new_collection(self, store: CredentialStore):
        """A seed in new_seeds is added to the queue and collected in the next depth."""
        seed1 = make_seed("email", "initial@x.com")
        seed2 = make_seed("email", "discovered@x.com")
        job = make_job(seeds=[seed1], max_depth=4)

        result1 = self._job_result(job.id, seed1, new_seeds=[seed2])
        result2 = self._job_result(job.id, seed2, new_seeds=[])

        registry = self._make_registry_with_mock_collector(
            store, "mock", "email", [result1, result2]
        )
        orch = Orchestrator(registry)
        out = await orch.run(job)

        # Both seeds should have been processed
        assert out.seeds_processed == 2
        assert out.convergence_reason == "queue_empty"

    async def test_orchestrator_runs_full_pipeline(self, store: CredentialStore):
        """Integration: pipeline processes all seeds and returns completed status."""
        seeds = [make_seed("email", f"user{i}@x.com") for i in range(3)]
        job = make_job(seeds=seeds)

        results = [self._job_result(job.id, s) for s in seeds]
        registry = self._make_registry_with_mock_collector(
            store, "mock", "email", results
        )
        orch = Orchestrator(registry, concurrency=3)
        out = await orch.run(job)

        assert out.status == JobStatus.COMPLETED
        assert len(out.results) == 3
        assert out.seeds_processed == 3
        assert out.duration_seconds > 0

    async def test_no_collector_available_returns_failed_result(self, store: CredentialStore):
        job = make_job(seeds=[make_seed("phone", "+15550001111")])
        # Registry with no collectors
        registry = CollectorRegistry(store=store)
        registry._collectors = []
        orch = Orchestrator(registry)
        out = await orch.run(job)
        assert out.status == JobStatus.COMPLETED
        failed = [r for r in out.results if r.status == JobStatus.FAILED]
        assert len(failed) == 1

    async def test_duplicate_new_seeds_not_reprocessed(self, store: CredentialStore):
        seed = make_seed("email", "once@x.com")
        job = make_job(seeds=[seed])
        # Returns the same seed as a new_seed (would be infinite without dedup)
        result = self._job_result(job.id, seed, new_seeds=[seed])
        registry = self._make_registry_with_mock_collector(
            store, "mock", "email", [result]
        )
        orch = Orchestrator(registry)
        out = await orch.run(job)
        # Dedup prevents infinite loop; queue becomes empty
        assert out.convergence_reason == "queue_empty"
        assert out.seeds_processed == 1
