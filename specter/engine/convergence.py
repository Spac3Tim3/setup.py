"""Convergence / termination criteria for the enrichment loop."""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class ConvergenceConfig:
    """Tunable termination parameters for a collection run."""

    max_depth: int = 4
    max_seeds: int = 50
    time_limit_seconds: float = 1800.0  # 30 minutes


class ConvergenceChecker:
    """Stateful checker that evaluates termination conditions each loop iteration."""

    def __init__(self, config: ConvergenceConfig) -> None:
        self._config = config
        self._start = time.monotonic()

    def check(self, seeds_processed: int, current_depth: int) -> tuple[bool, str]:
        """Return (should_stop, reason). Caller halts when should_stop is True."""
        elapsed = self.elapsed()
        if elapsed >= self._config.time_limit_seconds:
            return True, f"time_limit_exceeded ({elapsed:.0f}s >= {self._config.time_limit_seconds:.0f}s)"
        if seeds_processed >= self._config.max_seeds:
            return True, f"max_seeds_reached ({seeds_processed} >= {self._config.max_seeds})"
        if current_depth >= self._config.max_depth:
            return True, f"max_depth_reached ({current_depth} >= {self._config.max_depth})"
        return False, ""

    def elapsed(self) -> float:
        """Seconds since this checker was created."""
        return time.monotonic() - self._start
