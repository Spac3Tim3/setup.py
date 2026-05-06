"""Agent 4 TDD contract: normalizer, triage, confidence, circle."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from specter.ai.circle import CircleAnalyzer, CircleRiskReport
from specter.ai.confidence import IdentityConfidenceScorer
from specter.ai.normalizer import Normalizer
from specter.ai.triage import Triage, TriageResult
from specter.models.alert import AlertSeverity
from specter.models.job import JobResult, JobStatus
from specter.models.person import CircleMember, IdentityConfidence, PersonProfile, SocialPresence
from specter.models.target import SeedInput


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_seed(seed_type: str = "email", value: str = "test@example.com") -> SeedInput:
    return SeedInput(seed_type=seed_type, value=value)


def make_profile(**kwargs) -> PersonProfile:
    return PersonProfile(**kwargs)


def make_job_result(
    collector: str = "email",
    seed: SeedInput | None = None,
    artifacts: list[dict] | None = None,
) -> JobResult:
    return JobResult(
        job_id="j1",
        collector=collector,
        seed=seed or make_seed(),
        status=JobStatus.COMPLETED,
        artifacts=artifacts or [],
    )


def mock_anthropic_response(content: str):
    """Return a mock that looks like an anthropic AsyncAnthropic client."""
    mock_client = MagicMock()
    mock_msg = MagicMock()
    mock_msg.content = [MagicMock(text=content)]
    mock_client.messages.create = AsyncMock(return_value=mock_msg)
    return mock_client


# ===========================================================================
# Normalizer
# ===========================================================================


class TestNormalizer:
    async def test_returns_empty_profile_for_empty_results(self):
        n = Normalizer(client=MagicMock())
        profile = await n.normalize([])
        assert isinstance(profile, PersonProfile)

    async def test_merges_duplicate_emails(self):
        """Two results with the same email should produce one email in profile."""
        response_json = json.dumps({
            "full_name": "Jane Doe",
            "aliases": [],
            "emails": ["jane@example.com", "Jane@Example.COM"],  # duplicates
            "phones": [],
            "social_presence": [],
            "locations": [],
            "employers": [],
            "conflicts": [],
        })
        client = mock_anthropic_response(response_json)
        n = Normalizer(client=client)

        results = [
            make_job_result("email", artifacts=[{"type": "breach", "source": "hibp"}]),
            make_job_result("holehe", artifacts=[{"type": "registered_service", "value": "twitter"}]),
        ]
        profile = await n.normalize(results)
        assert profile.emails.count("jane@example.com") == 1

    async def test_deduplicates_platforms(self):
        """Same platform from two sources should appear once in social_presence."""
        response_json = json.dumps({
            "full_name": None,
            "aliases": [],
            "emails": ["x@example.com"],
            "phones": [],
            "social_presence": [
                {"platform": "twitter", "username": "jdoe", "url": None, "source": "maigret"},
            ],
            "locations": [],
            "employers": [],
            "conflicts": [],
        })
        client = mock_anthropic_response(response_json)
        n = Normalizer(client=client)
        results = [
            make_job_result("maigret"),
            make_job_result("holehe"),
        ]
        profile = await n.normalize(results)
        twitter_entries = [s for s in profile.social_presence if s.platform == "twitter"]
        assert len(twitter_entries) == 1

    async def test_fallback_on_api_error(self):
        """API failure returns a fallback profile without raising."""
        client = MagicMock()
        client.messages.create = AsyncMock(side_effect=Exception("API unavailable"))
        n = Normalizer(client=client)
        profile = await n.normalize([make_job_result()])
        assert isinstance(profile, PersonProfile)

    async def test_conflict_flagged_in_confidence(self):
        response_json = json.dumps({
            "full_name": None,
            "aliases": [],
            "emails": ["x@example.com"],
            "phones": [],
            "social_presence": [],
            "locations": [],
            "employers": [],
            "conflicts": ["Name mismatch: Jane vs John"],
        })
        client = mock_anthropic_response(response_json)
        n = Normalizer(client=client)
        profile = await n.normalize([make_job_result()])
        assert profile.confidence is not None
        assert profile.confidence.requires_review is True
        assert profile.confidence.conflicts


# ===========================================================================
# Triage
# ===========================================================================


class TestTriage:
    async def test_scores_high_breach_count(self):
        """Profile with breach sources should receive elevated exposure score."""
        response_json = json.dumps({
            "exposure_score": 85,
            "risk_categories": ["breach_exposure"],
            "critical_findings": ["Found in 5 breach datasets"],
            "recommendations": ["Enable multi-factor authentication"],
            "alert_required": True,
            "alert_severity": "high",
        })
        client = mock_anthropic_response(response_json)
        t = Triage(client=client)
        profile = make_profile(
            emails=["target@example.com"],
            raw_sources=["hibp", "intelx", "breach"],
        )
        result = await t.assess(profile)
        assert result.exposure_score >= 70
        assert result.alert_required is True
        assert result.alert_severity == AlertSeverity.HIGH

    async def test_generates_recommendations(self):
        response_json = json.dumps({
            "exposure_score": 55,
            "risk_categories": ["social_overexposure"],
            "critical_findings": [],
            "recommendations": [
                "Review public social media privacy settings",
                "Audit third-party app permissions",
            ],
            "alert_required": False,
            "alert_severity": "medium",
        })
        client = mock_anthropic_response(response_json)
        t = Triage(client=client)
        result = await t.assess(make_profile())
        assert len(result.recommendations) >= 1

    async def test_exposure_score_clamped_to_range(self):
        response_json = json.dumps({
            "exposure_score": 150,  # out of range
            "risk_categories": [],
            "critical_findings": [],
            "recommendations": [],
            "alert_required": True,
            "alert_severity": "critical",
        })
        client = mock_anthropic_response(response_json)
        t = Triage(client=client)
        result = await t.assess(make_profile())
        assert result.exposure_score <= 100

    async def test_fallback_heuristic_on_api_error(self):
        client = MagicMock()
        client.messages.create = AsyncMock(side_effect=Exception("Network error"))
        t = Triage(client=client)
        profile = make_profile(
            emails=["t@x.com"],
            raw_sources=["hibp", "breach"],
        )
        result = await t.assess(profile)
        assert isinstance(result, TriageResult)
        assert 0 <= result.exposure_score <= 100

    async def test_invalid_severity_defaults_to_info(self):
        response_json = json.dumps({
            "exposure_score": 30,
            "risk_categories": [],
            "critical_findings": [],
            "recommendations": [],
            "alert_required": False,
            "alert_severity": "ultra_high",  # invalid
        })
        client = mock_anthropic_response(response_json)
        t = Triage(client=client)
        result = await t.assess(make_profile())
        assert result.alert_severity == AlertSeverity.INFO


# ===========================================================================
# IdentityConfidenceScorer
# ===========================================================================


class TestIdentityConfidenceScorer:
    def _scorer(self) -> IdentityConfidenceScorer:
        return IdentityConfidenceScorer()

    def test_high_confidence_on_multi_factor_match(self):
        scorer = self._scorer()
        baseline = make_profile(
            emails=["jane@example.com"],
            social_presence=[SocialPresence(platform="twitter", username="jdoe")],
            phone_intel=[],
        )
        candidate = make_profile(
            emails=["jane@example.com"],
            social_presence=[SocialPresence(platform="twitter", username="jdoe")],
        )
        result = scorer.score(candidate, baseline)
        assert result.score >= 0.4
        assert "username+email match" in result.factors

    def test_low_confidence_on_single_username_match(self):
        scorer = self._scorer()
        baseline = make_profile(
            social_presence=[SocialPresence(platform="reddit", username="shadow99")]
        )
        candidate = make_profile(
            social_presence=[SocialPresence(platform="reddit", username="shadow99")]
        )
        result = scorer.score(candidate, baseline)
        # Only single platform match (+0.10), no email overlap
        assert result.score <= 0.2
        assert "single platform match" in result.factors

    def test_conflict_reduces_score(self):
        scorer = self._scorer()
        baseline = make_profile(full_name="Jane Doe", locations=["Miami, FL"])
        candidate = make_profile(full_name="John Smith", locations=["Seattle, WA"])
        result = scorer.score(candidate, baseline)
        assert "conflicting name signals" in result.conflicts
        assert result.requires_review is True

    def test_single_profile_confidence(self):
        scorer = self._scorer()
        profile = make_profile(
            emails=["x@example.com"],
            social_presence=[SocialPresence(platform="twitter", username="jdoe")],
        )
        result = scorer.score_single(profile)
        assert result.score > 0
        assert "username+email present" in result.factors

    def test_empty_profile_low_confidence(self):
        scorer = self._scorer()
        result = scorer.score_single(make_profile())
        assert result.score == 0.0
        assert result.requires_review is True


# ===========================================================================
# CircleAnalyzer
# ===========================================================================


class TestCircleAnalyzer:
    async def test_empty_circle_returns_summary(self):
        client = MagicMock()
        ca = CircleAnalyzer(client=client)
        principal = make_profile()
        report = await ca.analyze(principal, [])
        assert isinstance(report, CircleRiskReport)
        assert report.principal_id == principal.id

    async def test_circle_report_omits_family_names(self):
        """The report must not contain names of circle members."""
        # Member with a recognizable name in their profile
        member_profile = make_profile(full_name="Alice Smith", emails=["alice@example.com"])
        member = CircleMember(relationship="spouse", profile=member_profile, risk_score=0.6)

        response_json = json.dumps({
            "principal_risk_summary": "A family member's data exposure creates risk for the principal.",
            "exposure_pathways": ["A family member has exposed home address via public records."],
            "recommendations": ["Audit family member's public records exposure."],
            "aggregate_risk_score": 0.6,
        })
        client = mock_anthropic_response(response_json)
        ca = CircleAnalyzer(client=client)
        principal = make_profile()
        report = await ca.analyze(principal, [member])

        # Check that the actual name does not appear anywhere in the report
        report_text = (
            report.principal_risk_summary
            + " ".join(report.exposure_pathways)
            + " ".join(report.recommendations)
        )
        assert "Alice" not in report_text
        assert "Smith" not in report_text
        assert "alice@example.com" not in report_text

    async def test_circle_report_maps_risk_to_principal(self):
        """Exposure pathways must reference principal risk, not member details."""
        response_json = json.dumps({
            "principal_risk_summary": "Circle member exposure creates indirect risk for the principal.",
            "exposure_pathways": ["A colleague's breach exposure could reveal the principal's workplace."],
            "recommendations": ["Review workplace association exposure."],
            "aggregate_risk_score": 0.45,
        })
        client = mock_anthropic_response(response_json)
        ca = CircleAnalyzer(client=client)
        principal = make_profile()
        member_profile = make_profile(raw_sources=["hibp"])
        member = CircleMember(relationship="colleague", profile=member_profile, risk_score=0.5)
        report = await ca.analyze(principal, [member])

        assert report.aggregate_risk_score == pytest.approx(0.45)
        assert report.principal_id == principal.id
        # Should reference principal impact
        assert "principal" in report.principal_risk_summary.lower()

    async def test_api_error_returns_graceful_report(self):
        client = MagicMock()
        client.messages.create = AsyncMock(side_effect=Exception("Timeout"))
        ca = CircleAnalyzer(client=client)
        member = CircleMember(relationship="spouse", profile=make_profile(), risk_score=0.3)
        report = await ca.analyze(make_profile(), [member])
        assert isinstance(report, CircleRiskReport)
        assert report.recommendations  # fallback recommendation present
