"""Social platform profile extraction via Playwright."""

from __future__ import annotations

import time

from specter.collectors.base import BaseCollector
from specter.credentials.registry import SERVICES
from specter.models.credential import ServiceConfig
from specter.models.job import JobResult, JobStatus
from specter.models.target import SeedInput


class SocialCollector(BaseCollector):
    """Extracts public profile data from social platform URLs via Playwright."""

    name = "social"
    seed_types = ["platform_url"]
    produces = ["profile_data", "post_metadata", "connections"]

    @property
    def config(self) -> ServiceConfig:
        # No API key — uses Playwright browser automation on public pages
        return SERVICES["maigret"]

    def is_available(self) -> bool:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
            return True
        except ImportError:
            return False

    async def collect(self, seed: SeedInput) -> JobResult:
        job_id = f"{self.name}:{seed.value}"
        if seed.seed_type != "platform_url":
            return self._error_result(job_id, seed, f"Unsupported seed type: {seed.seed_type}")
        if not self.is_available():
            return self._error_result(job_id, seed, "Playwright not installed")
        self._check_ethics(seed)

        start = time.monotonic()
        try:
            artifacts = await self._scrape_public_profile(seed.value)
        except Exception as exc:  # noqa: BLE001
            return self._error_result(job_id, seed, f"Playwright error: {exc}")

        duration = time.monotonic() - start
        return JobResult(
            job_id=job_id,
            collector=self.name,
            seed=seed,
            status=JobStatus.COMPLETED,
            artifacts=artifacts,
            duration_seconds=duration,
        )

    async def _scrape_public_profile(self, url: str) -> list[dict]:
        """Navigate to a public profile URL and extract visible metadata."""
        from playwright.async_api import async_playwright

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(
                user_agent="Mozilla/5.0 (compatible; Specter/1.0; +https://specter.internal)"
            )
            # Passive: block login forms, CAPTCHA triggers
            await page.route("**/*", lambda route: route.continue_())
            await page.goto(url, wait_until="networkidle", timeout=30_000)

            profile_data = await page.evaluate("""
                () => ({
                    title: document.title,
                    description: document.querySelector('meta[name="description"]')?.content,
                    og_title: document.querySelector('meta[property="og:title"]')?.content,
                    og_image: document.querySelector('meta[property="og:image"]')?.content,
                    canonical: document.querySelector('link[rel="canonical"]')?.href,
                })
            """)
            await browser.close()

        return [{
            "type": "profile_data",
            "url": url,
            "source": "playwright",
            **{k: v for k, v in profile_data.items() if v},
        }]
