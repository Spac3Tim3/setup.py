"""Florida public record lookups: Sunbiz, FDLE, FL Elections, FL Property."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from specter.models.records import PublicRecordResult

logger = logging.getLogger(__name__)

_SUNBIZ_BASE = "https://search.sunbiz.org"
_FDLE_BASE = "https://offender.fdle.state.fl.us"
_ELECTIONS_BASE = "https://registration.elections.myflorida.com"


def _parse_sunbiz_html(html: str, query_name: str) -> list[PublicRecordResult]:
    """Extract officer/director name rows from Sunbiz search results."""
    results: list[PublicRecordResult] = []
    # Sunbiz returns a table; parse rows with a simple regex for resilience
    row_pattern = re.compile(
        r'<tr[^>]*>\s*<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>',
        re.IGNORECASE | re.DOTALL,
    )
    for match in row_pattern.finditer(html):
        entity, filing_type, status = (
            match.group(1).strip(),
            match.group(2).strip(),
            match.group(3).strip(),
        )
        if entity.lower() in ("entity name", "name", ""):
            continue  # skip header row
        results.append(
            PublicRecordResult(
                source="sunbiz",
                record_type="business_filing",
                subject_name=query_name,
                raw_data={"entity": entity, "filing_type": filing_type, "status": status},
                url=f"{_SUNBIZ_BASE}/Inquiry/corporationsearch/GetListOfEntities",
            )
        )
    return results


def _parse_officer_names(html: str) -> list[str]:
    """Extract officer/director names from a Sunbiz entity detail page."""
    pattern = re.compile(
        r'<span[^>]*class="[^"]*officer[^"]*"[^>]*>([^<]+)</span>',
        re.IGNORECASE,
    )
    names = [m.group(1).strip() for m in pattern.finditer(html) if m.group(1).strip()]
    # Fallback: look for any label-value pairs near "OFFICER"
    if not names:
        officer_section = re.search(
            r'(?:OFFICER|DIRECTOR|REGISTERED AGENT)[\s\S]{0,200}?([A-Z][A-Z ,\.]+)',
            html,
            re.IGNORECASE,
        )
        if officer_section:
            names = [officer_section.group(1).strip()]
    return names


class FloridaRecordClient:
    """Passive read-only client for Florida public record portals."""

    async def search_sunbiz(self, name: str) -> list[PublicRecordResult]:
        """Search Sunbiz officer/director registry for a name."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{_SUNBIZ_BASE}/Inquiry/corporationsearch/GetListOfEntities",
                    params={
                        "SearchTerm": name,
                        "SearchType": "OfficerDirectorName",
                        "ListOfEntities": "Officers",
                    },
                    headers={"User-Agent": "Specter/1.0"},
                )
            if resp.status_code != 200:
                return []
            return _parse_sunbiz_html(resp.text, name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sunbiz search failed: %s", exc)
            return []

    async def get_sunbiz_entity(self, entity_id: str) -> PublicRecordResult | None:
        """Fetch detail page for a Sunbiz entity and extract officer names."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    f"{_SUNBIZ_BASE}/Inquiry/corporationsearch/SearchResultDetail",
                    params={"inquirytype": "EntityName", "directionType": "Initial",
                            "searchNameOrder": entity_id},
                    headers={"User-Agent": "Specter/1.0"},
                )
            if resp.status_code != 200:
                return None
            officers = _parse_officer_names(resp.text)
            return PublicRecordResult(
                source="sunbiz",
                record_type="business_filing",
                raw_data={"entity_id": entity_id, "officers": officers},
                url=f"{_SUNBIZ_BASE}/Inquiry/corporationsearch/SearchResultDetail",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Sunbiz entity fetch failed: %s", exc)
            return None

    async def search_fdle_sex_offender(
        self, first_name: str, last_name: str
    ) -> list[PublicRecordResult]:
        """Query the FDLE sex offender registry by name."""
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{_FDLE_BASE}/offender/Search.jsp",
                    data={"firstName": first_name, "lastName": last_name},
                    headers={"User-Agent": "Specter/1.0"},
                )
            if resp.status_code != 200:
                return []
            return self._parse_fdle(resp.text)
        except Exception as exc:  # noqa: BLE001
            logger.warning("FDLE search failed: %s", exc)
            return []

    @staticmethod
    def _parse_fdle(html: str) -> list[PublicRecordResult]:
        name_pattern = re.compile(
            r'class=["\']offenderName["\'][^>]*>([^<]+)<', re.IGNORECASE
        )
        results: list[PublicRecordResult] = []
        for m in name_pattern.finditer(html):
            results.append(
                PublicRecordResult(
                    source="fdle_sex_offender",
                    record_type="sex_offender",
                    subject_name=m.group(1).strip(),
                    raw_data={},
                )
            )
        return results
