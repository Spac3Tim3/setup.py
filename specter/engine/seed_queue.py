"""Deduplicating FIFO seed queue for the enrichment loop."""

from __future__ import annotations

from collections import deque

from specter.models.target import SeedInput


class SeedQueue:
    """FIFO queue of SeedInput deduplicated by (seed_type, normalised_value).

    A seed is considered duplicate if its (type, lowercased-stripped value)
    has been seen before, whether or not it has been processed yet.
    """

    def __init__(self) -> None:
        self._queue: deque[SeedInput] = deque()
        self._seen: set[tuple[str, str]] = set()
        self._processed_count: int = 0

    # ------------------------------------------------------------------

    def _key(self, seed: SeedInput) -> tuple[str, str]:
        return (seed.seed_type, seed.value.lower().strip())

    def push(self, seed: SeedInput) -> bool:
        """Enqueue seed if not already seen. Returns True if added."""
        key = self._key(seed)
        if key in self._seen:
            return False
        self._seen.add(key)
        self._queue.append(seed)
        return True

    def push_many(self, seeds: list[SeedInput]) -> int:
        """Enqueue multiple seeds; return count of newly added."""
        return sum(1 for s in seeds if self.push(s))

    def pop(self) -> SeedInput | None:
        """Dequeue and return the next seed, or None if empty."""
        if not self._queue:
            return None
        self._processed_count += 1
        return self._queue.popleft()

    def is_empty(self) -> bool:
        return not self._queue

    def size(self) -> int:
        """Number of seeds currently waiting to be processed."""
        return len(self._queue)

    def seen_count(self) -> int:
        """Total unique seeds ever pushed (queued + processed)."""
        return len(self._seen)

    def processed_count(self) -> int:
        """Number of seeds already popped for processing."""
        return self._processed_count
