"""Agent 7 TDD contract: dark web monitors — all mocked, no live calls."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from specter.darkweb.ahmia import AhmiaClient
from specter.darkweb.intelx import IntelXClient
from specter.darkweb.ransomware import RansomwareLiveClient
from specter.models.breach import DarkWebSignal


# ---------------------------------------------------------------------------
# IntelX
# ---------------------------------------------------------------------------


class TestIntelXClient:
    async def test_intelx_query_returns_signals(self):
        client = IntelXClient(api_key="test-key")
        fake_records = [
            {"bucket": "pastes", "media": "1", "date": "2024-01-15T00:00:00Z"},
            {"bucket": "darkweb", "media": "7", "date": "2024-02-20T00:00:00Z"},
        ]
        with patch.object(client, "_initiate_search", new_callable=AsyncMock) as mock_init:
            mock_init.return_value = "search-id-123"
            with patch.object(client, "_fetch_results", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = fake_records
                signals = await client.search("target@example.com", target_id="t1")

        assert len(signals) == 2
        assert all(isinstance(s, DarkWebSignal) for s in signals)
        assert all(s.source == "intelx" for s in signals)

    async def test_dark_web_signal_sanitized_no_passwords(self):
        """IntelX signal must never contain raw credential data."""
        client = IntelXClient(api_key="test-key")
        with patch.object(client, "_initiate_search", new_callable=AsyncMock) as mock_init:
            mock_init.return_value = "sid"
            with patch.object(client, "_fetch_results", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = [
                    {"bucket": "pastes", "media": "1", "date": "2024-01-01T00:00:00Z",
                     "content": "password123 jane@example.com"}
                ]
                signals = await client.search("jane@example.com")

        for signal in signals:
            # Raw content must not propagate to context_summary
            assert "password123" not in signal.context_summary

    async def test_intelx_no_results_returns_empty(self):
        client = IntelXClient(api_key="test-key")
        with patch.object(client, "_initiate_search", new_callable=AsyncMock) as mock_init:
            mock_init.return_value = None  # no search ID = no results
            signals = await client.search("nobody@example.com")
        assert signals == []

    async def test_intelx_api_error_returns_empty(self):
        client = IntelXClient(api_key="test-key")
        with patch.object(client, "_initiate_search", new_callable=AsyncMock) as mock_init:
            mock_init.side_effect = Exception("Connection refused")
            signals = await client.search("query")
        assert signals == []

    async def test_intelx_severity_default_medium(self):
        client = IntelXClient(api_key="test-key")
        with patch.object(client, "_initiate_search", return_value="sid"):
            with patch.object(client, "_fetch_results",
                              return_value=[{"bucket": "pastes", "media": "1"}]):
                signals = await client.search("x@x.com")
        assert signals[0].severity == "medium"


# ---------------------------------------------------------------------------
# Ahmia
# ---------------------------------------------------------------------------


class TestAhmiaClient:
    async def test_ahmia_search_parses_results(self):
        fake_html = """
        <h4><a href="http://abc123.onion/page">Dark Forum Post</a></h4>
        <h4><a href="http://xyz789.onion/thread">Another Result</a></h4>
        """
        client = AhmiaClient()
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = fake_html
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_resp
            )
            signals = await client.search("target@example.com", target_id="t1")

        assert len(signals) == 2
        assert all(s.source == "ahmia" for s in signals)
        assert all(".onion" in (s.url or "") for s in signals)

    async def test_ahmia_no_results_returns_empty(self):
        client = AhmiaClient()
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "<html><body>No results found</body></html>"
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_resp
            )
            signals = await client.search("unique-query-xyz")
        assert signals == []

    async def test_ahmia_http_error_returns_empty(self):
        client = AhmiaClient()
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 503
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_resp
            )
            signals = await client.search("query")
        assert signals == []

    async def test_ahmia_exception_returns_empty(self):
        client = AhmiaClient()
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=Exception("Timeout")
            )
            signals = await client.search("query")
        assert signals == []

    async def test_ahmia_context_summary_sanitized(self):
        """Summary must be a short metadata description, not raw page content."""
        fake_html = '<h4><a href="http://a.onion">Credential Dump</a></h4>'
        client = AhmiaClient()
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = fake_html
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_resp
            )
            signals = await client.search("x@example.com")
        assert signals[0].context_summary
        assert len(signals[0].context_summary) < 300  # concise summary


# ---------------------------------------------------------------------------
# RansomwareLive
# ---------------------------------------------------------------------------


class TestRansomwareLiveClient:
    async def test_ransomware_live_victim_check_match(self):
        fake_victims = [
            {"victim": "Acme Corporation", "group": "LockBit",
             "published": "2024-03-01", "domain": "acme.com"},
            {"victim": "Beta Industries", "group": "BlackCat",
             "published": "2024-03-05", "domain": "beta.com"},
        ]
        client = RansomwareLiveClient()
        with patch.object(client, "_fetch_recent", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = fake_victims
            signals = await client.check_victim("acme", target_id="t1")

        assert len(signals) == 1
        assert signals[0].source == "ransomware.live"
        assert signals[0].severity == "high"

    async def test_ransomware_live_no_match_returns_empty(self):
        fake_victims = [
            {"victim": "Unrelated Corp", "group": "SomeGroup",
             "published": "2024-01-01", "domain": "unrelated.com"}
        ]
        client = RansomwareLiveClient()
        with patch.object(client, "_fetch_recent", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = fake_victims
            signals = await client.check_victim("targetcompany.com")
        assert signals == []

    async def test_ransomware_live_signal_sanitized(self):
        """Signal context must not contain raw exfiltrated data."""
        victim = {"victim": "TestCorp", "group": "AlphaGroup",
                  "published": "2024-01-01", "domain": "test.com",
                  "exfil_data": "ssn:123-45-6789 password:secret"}
        client = RansomwareLiveClient()
        signal = client._to_signal(victim, "test.com", None)
        assert "ssn:" not in signal.context_summary
        assert "secret" not in signal.context_summary
        assert "password:" not in signal.context_summary

    async def test_ransomware_live_api_error_returns_empty(self):
        client = RansomwareLiveClient()
        with patch.object(client, "_fetch_recent", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.side_effect = Exception("API down")
            signals = await client.check_victim("query")
        assert signals == []

    async def test_new_signal_triggers_alert_readiness(self):
        """Signals with severity 'high' should be alert-worthy."""
        victim = {"victim": "Protected Org", "group": "Cl0p",
                  "published": "2024-04-01", "domain": "protected.com"}
        client = RansomwareLiveClient()
        signal = client._to_signal(victim, "protected.com", "t1")
        assert signal.severity == "high"
        assert signal.target_id == "t1"
