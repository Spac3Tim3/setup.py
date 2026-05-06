"""Collector auto-discovery registry."""

from __future__ import annotations

from specter.collectors.base import BaseCollector
from specter.credentials.store import CredentialStore


class CollectorRegistry:
    """Discovers and holds all registered collectors.

    Collectors that require a CredentialStore are injected at construction.
    """

    def __init__(self, store: CredentialStore) -> None:
        self._store = store
        self._collectors: list[BaseCollector] = []
        self._register_all()

    def _register_all(self) -> None:
        from specter.collectors.breach import BreachCollector
        from specter.collectors.email import EmailCollector
        from specter.collectors.image import ImageCollector
        from specter.collectors.phone import PhoneCollector
        from specter.collectors.social import SocialCollector
        from specter.collectors.username import UsernameCollector

        self._collectors = [
            PhoneCollector(),
            EmailCollector(store=self._store),
            UsernameCollector(),
            ImageCollector(store=self._store),
            BreachCollector(store=self._store),
            SocialCollector(),
        ]

    def all(self) -> list[BaseCollector]:
        """Return every registered collector."""
        return list(self._collectors)

    def available(self) -> list[BaseCollector]:
        """Return collectors that are currently available (tool + key present)."""
        return [c for c in self._collectors if c.is_available()]

    def for_seed_type(self, seed_type: str) -> list[BaseCollector]:
        """Return available collectors that can process the given seed type."""
        return [c for c in self.available() if seed_type in c.seed_types]

    def get(self, name: str) -> BaseCollector | None:
        """Look up a collector by name."""
        return next((c for c in self._collectors if c.name == name), None)
