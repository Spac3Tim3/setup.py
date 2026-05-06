"""Per-target cadence scheduler."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum


class Cadence(StrEnum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_DEMAND = "on_demand"


_INTERVALS: dict[Cadence, timedelta] = {
    Cadence.DAILY: timedelta(days=1),
    Cadence.WEEKLY: timedelta(weeks=1),
    Cadence.MONTHLY: timedelta(days=30),
}


class TargetSchedule:
    """Scheduling state for a single target."""

    def __init__(self, target_id: str, cadence: Cadence = Cadence.DAILY) -> None:
        self.target_id = target_id
        self.cadence = cadence
        self.last_run_at: datetime | None = None
        # Due immediately on first registration
        self.next_run_at: datetime = datetime.utcnow()

    def is_due(self) -> bool:
        """Return True if the target is due for collection."""
        return datetime.utcnow() >= self.next_run_at

    def mark_run(self) -> None:
        """Record that a run just completed and advance next_run_at."""
        self.last_run_at = datetime.utcnow()
        interval = _INTERVALS.get(self.cadence)
        if interval:
            self.next_run_at = datetime.utcnow() + interval
        else:
            # ON_DEMAND: never automatically re-schedule
            self.next_run_at = datetime.max


class Scheduler:
    """In-memory cadence registry. SQLite persistence is layered on top by Agent 10."""

    def __init__(self) -> None:
        self._schedules: dict[str, TargetSchedule] = {}

    def register(
        self, target_id: str, cadence: Cadence = Cadence.DAILY
    ) -> TargetSchedule:
        """Register or update a target's cadence."""
        schedule = TargetSchedule(target_id=target_id, cadence=cadence)
        self._schedules[target_id] = schedule
        return schedule

    def due_targets(self) -> list[str]:
        """Return IDs of targets whose next run is now due."""
        return [tid for tid, s in self._schedules.items() if s.is_due()]

    def mark_run(self, target_id: str) -> None:
        """Advance the schedule after a successful run."""
        if sched := self._schedules.get(target_id):
            sched.mark_run()

    def get(self, target_id: str) -> TargetSchedule | None:
        return self._schedules.get(target_id)

    def all(self) -> list[TargetSchedule]:
        return list(self._schedules.values())
