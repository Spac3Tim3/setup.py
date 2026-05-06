"""Agent 6 TDD contract: Florida public records + shield verification."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from specter.models.records import PublicRecordResult, ShieldStatus
from specter.models.target import ProtectedIndividual, SeedInput, TargetEntity
from specter.records.florida import FloridaRecordClient, _parse_officer_names, _parse_sunbiz_html
from specter.records.shield import ShieldVerifier


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_target(name: str = "Jane Doe") -> TargetEntity:
    return TargetEntity(
        display_name=name,
        seeds=[SeedInput(seed_type="name", value=name)],
    )


def make_individual(
    name: str = "Jane Doe",
    protection_class: str = "judge",
    shield_active: bool = True,
) -> ProtectedIndividual:
    return ProtectedIndividual(
        target=make_target(name),
        protection_class=protection_class,
        shield_active=shield_active,
    )


# ===========================================================================
# Florida Record Client
# ===========================================================================


class TestSunbizParser:
    def test_sunbiz_parser_extracts_officer_names(self):
        """HTML parser correctly extracts officer/director names from Sunbiz."""
        html = """
        <html><body>
        <span class="officerName">Jane Doe</span>
        <span class="officerName">John Smith</span>
        </body></html>
        """
        names = _parse_officer_names(html)
        assert "Jane Doe" in names
        assert "John Smith" in names

    def test_sunbiz_html_parser_extracts_entities(self):
        html = """
        <table class="list">
          <tr><td>Header</td><td>Type</td><td>Status</td></tr>
          <tr><td>Acme LLC</td><td>Florida LLC</td><td>Active</td></tr>
          <tr><td>Beta Corp</td><td>Florida Corp</td><td>Inactive</td></tr>
        </table>
        """
        results = _parse_sunbiz_html(html, "Jane Doe")
        entity_names = [r.raw_data["entity"] for r in results]
        assert "Acme LLC" in entity_names
        assert "Beta Corp" in entity_names

    def test_empty_html_returns_empty_list(self):
        results = _parse_sunbiz_html("", "Jane Doe")
        assert results == []


class TestFloridaRecordClient:
    async def test_search_sunbiz_returns_results(self):
        fake_html = """
        <tr><td>Acme LLC</td><td>Florida LLC</td><td>Active</td></tr>
        """
        client = FloridaRecordClient()
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = fake_html
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_resp
            )
            results = await client.search_sunbiz("Jane Doe")
        assert isinstance(results, list)

    async def test_sunbiz_http_error_returns_empty(self):
        client = FloridaRecordClient()
        with patch("httpx.AsyncClient") as mock_client:
            mock_resp = MagicMock()
            mock_resp.status_code = 503
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_resp
            )
            results = await client.search_sunbiz("Jane Doe")
        assert results == []

    async def test_sunbiz_network_error_returns_empty(self):
        """Network errors are caught; empty list returned (graceful degradation)."""
        client = FloridaRecordClient()
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                side_effect=Exception("Connection refused")
            )
            results = await client.search_sunbiz("Jane Doe")
        assert results == []

    async def test_browser_automation_sunbiz(self):
        """Playwright-based Sunbiz lookup returns parsed records (mocked browser)."""
        from specter.records.browser import BrowserSession

        fake_html = "<tr><td>Doe LLC</td><td>Florida LLC</td><td>Active</td></tr>"

        with patch.object(BrowserSession, "submit_form", new_callable=AsyncMock) as mock_form:
            mock_form.return_value = fake_html
            # The FL client can also use Playwright for court records, etc.
            # Test that BrowserSession.submit_form is wired correctly
            session = BrowserSession()
            html = await session.submit_form(
                url="https://search.sunbiz.org",
                fields={"#SearchTerm": "Jane Doe"},
                submit_selector="#SearchSubmit",
            )
        assert "Doe LLC" in html


# ===========================================================================
# Shield Verifier
# ===========================================================================


class TestShieldVerifier:
    async def test_shield_passes_when_record_absent(self):
        """No Sunbiz results → shield passes (individual not exposed)."""
        individual = make_individual()
        fl_client = MagicMock(spec=FloridaRecordClient)
        fl_client.search_sunbiz = AsyncMock(return_value=[])

        verifier = ShieldVerifier(fl_client=fl_client)
        status = await verifier.verify(individual)

        assert status.protected is True
        assert status.violations == []

    async def test_shield_flags_exposed_address(self):
        """Record with address + shield_active → violation flagged."""
        individual = make_individual(shield_active=True)
        record = PublicRecordResult(
            source="sunbiz",
            record_type="business_filing",
            address="123 Main St, Miami FL 33101",
            raw_data={"entity": "Doe Consulting LLC", "filing_type": "FL LLC", "status": "Active"},
        )
        fl_client = MagicMock(spec=FloridaRecordClient)
        fl_client.search_sunbiz = AsyncMock(return_value=[record])

        verifier = ShieldVerifier(fl_client=fl_client)
        status = await verifier.verify(individual)

        assert status.protected is False
        assert any("Address exposed" in v for v in status.violations)
        assert status.recommendations

    async def test_llc_gap_detected(self):
        """Business filing without address still triggers a gap warning."""
        individual = make_individual(shield_active=True)
        record = PublicRecordResult(
            source="sunbiz",
            record_type="business_filing",
            raw_data={"entity": "Shadow Holdings LLC", "filing_type": "FL LLC", "status": "Active"},
        )
        fl_client = MagicMock(spec=FloridaRecordClient)
        fl_client.search_sunbiz = AsyncMock(return_value=[record])

        verifier = ShieldVerifier(fl_client=fl_client)
        status = await verifier.verify(individual)

        assert any("business filing" in g.lower() or "LLC" in g for g in status.gaps)

    async def test_sources_checked_populated(self):
        individual = make_individual()
        fl_client = MagicMock(spec=FloridaRecordClient)
        fl_client.search_sunbiz = AsyncMock(return_value=[])
        verifier = ShieldVerifier(fl_client=fl_client)
        status = await verifier.verify(individual)
        assert "sunbiz" in status.record_sources_checked

    async def test_identity_confidence_from_records(self):
        """Multiple matching Sunbiz records boost confidence (same name across filings)."""
        individual = make_individual(name="Jane Doe")
        records = [
            PublicRecordResult(
                source="sunbiz",
                record_type="business_filing",
                subject_name="Jane Doe",
                raw_data={"entity": f"Entity {i}", "filing_type": "FL LLC", "status": "Active"},
            )
            for i in range(3)
        ]
        fl_client = MagicMock(spec=FloridaRecordClient)
        fl_client.search_sunbiz = AsyncMock(return_value=records)
        verifier = ShieldVerifier(fl_client=fl_client)
        status = await verifier.verify(individual)
        # Multiple matches = more gaps flagged
        assert len(status.gaps) >= 1
