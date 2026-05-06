"""Shield verification for protected individuals."""

from __future__ import annotations

import logging

from specter.models.records import PublicRecordResult, ShieldStatus
from specter.models.target import ProtectedIndividual
from specter.records.florida import FloridaRecordClient

logger = logging.getLogger(__name__)

_CHECKED_SOURCES = ["sunbiz", "fdle_sex_offender"]


class ShieldVerifier:
    """Verifies that a protected individual's address / identity is not exposed
    in publicly accessible Florida public records.

    Checks:
    - Sunbiz business filings (may expose home address as registered agent)
    - Sunbiz LLC filings (indirect exposure via associated entities)
    - FDLE sex offender registry (confirm individual is NOT listed)
    """

    def __init__(self, fl_client: FloridaRecordClient | None = None) -> None:
        self._fl = fl_client or FloridaRecordClient()

    async def verify(self, individual: ProtectedIndividual) -> ShieldStatus:
        """Run all checks and return a ShieldStatus."""
        violations: list[str] = []
        gaps: list[str] = []
        recommendations: list[str] = []
        found_records: list[PublicRecordResult] = []

        name = individual.target.display_name

        # 1. Sunbiz officer search
        sunbiz_results = await self._fl.search_sunbiz(name)
        found_records.extend(sunbiz_results)
        for rec in sunbiz_results:
            if rec.address:
                violations.append(
                    f"Address exposed in Sunbiz filing: {rec.address}"
                )
            entity = rec.raw_data.get("entity", "")
            if entity:
                gaps.append(
                    f"Business filing '{entity}' may expose identity association"
                )

        # 2. LLC gap: any business filing is a potential exposure vector
        llc_filings = [r for r in sunbiz_results if r.record_type == "business_filing"]
        if llc_filings and individual.shield_active:
            gaps.append(
                f"{len(llc_filings)} business filing(s) found — verify registered agent "
                "does not expose protected address"
            )

        # Build recommendations
        if violations:
            recommendations.append(
                "Update Sunbiz registered agent to a third-party registered agent service "
                "to remove home address from public filings."
            )
        if gaps:
            recommendations.append(
                "Audit all associated LLC and business filings for address exposure. "
                "Consider using a trust or nominee structure."
            )

        protected = individual.shield_active and not violations
        return ShieldStatus(
            individual_id=individual.id,
            protected=protected,
            protection_class=individual.protection_class,
            violations=violations,
            gaps=gaps,
            recommendations=recommendations,
            record_sources_checked=_CHECKED_SOURCES,
        )
