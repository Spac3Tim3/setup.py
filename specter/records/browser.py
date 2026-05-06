"""Playwright browser automation base for portal scraping."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class BrowserSession:
    """Thin async context manager around a headless Playwright browser.

    All pages are opened in read-only mode — form submissions are restricted
    to GET or permitted public search forms. Never authenticates or stores cookies.
    """

    def __init__(self, timeout_ms: int = 30_000) -> None:
        self._timeout = timeout_ms
        self._browser: Any = None
        self._pw: Any = None

    async def __aenter__(self) -> "BrowserSession":
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().__aenter__()
        self._browser = await self._pw.chromium.launch(headless=True)
        return self

    async def __aexit__(self, *args) -> None:
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.__aexit__(*args)

    async def get_text(self, url: str, wait_selector: str | None = None) -> str:
        """Navigate to URL and return page text content."""
        page = await self._browser.new_page(
            user_agent="Mozilla/5.0 (compatible; Specter/1.0)"
        )
        await page.goto(url, wait_until="networkidle", timeout=self._timeout)
        if wait_selector:
            await page.wait_for_selector(wait_selector, timeout=self._timeout)
        text = await page.inner_text("body")
        await page.close()
        return text

    async def submit_form(
        self,
        url: str,
        fields: dict[str, str],
        submit_selector: str,
        result_selector: str | None = None,
    ) -> str:
        """Fill and submit a public search form. Returns result page HTML."""
        page = await self._browser.new_page(
            user_agent="Mozilla/5.0 (compatible; Specter/1.0)"
        )
        await page.goto(url, wait_until="networkidle", timeout=self._timeout)
        for selector, value in fields.items():
            await page.fill(selector, value)
        await page.click(submit_selector)
        if result_selector:
            await page.wait_for_selector(result_selector, timeout=self._timeout)
        else:
            await page.wait_for_load_state("networkidle")
        content = await page.content()
        await page.close()
        return content
