"""Integration tests for security pipeline."""
import pytest
from continental.contracts.pipeline import SecurityPipeline
from continental.models import ScanConfig, ScanTarget, Severity


@pytest.fixture
def test_config():
    """Configuration for testing."""
    target = ScanTarget(
        name="TestApp",
        base_url="http://localhost:8080",
        rate_limit=5
    )

    return ScanConfig(
        target=target,
        scanners=["sqli", "xss"],
        enable_ai_analysis=False,  # Disable for faster tests
        enable_fuzzing=False,
        max_duration_seconds=600,
        severity_threshold=Severity.MEDIUM
    )


def test_pipeline_initialization(test_config):
    """Test pipeline initializes correctly."""
    pipeline = SecurityPipeline(test_config)

    assert pipeline.config == test_config
    assert len(pipeline.scanners) == 2


def test_pipeline_deduplicates_findings(test_config):
    """Test pipeline removes duplicate findings."""
    from continental.models import Finding, VulnerabilityCategory, Remediation

    pipeline = SecurityPipeline(test_config)

    # Create duplicate findings
    findings = [
        Finding(
            title="SQL Injection",
            description="Test",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.SQL_INJECTION,
            cvss_score=7.5,
            affected_url="http://test.com/page",
            affected_parameter="id",
            remediation=Remediation(summary="Fix", detailed_steps=[]),
            discovered_by="scanner1"
        ),
        Finding(
            title="SQL Injection",
            description="Test",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.SQL_INJECTION,
            cvss_score=7.5,
            affected_url="http://test.com/page",
            affected_parameter="id",
            remediation=Remediation(summary="Fix", detailed_steps=[]),
            discovered_by="scanner2"
        ),
    ]

    unique = pipeline._deduplicate_findings(findings)
    assert len(unique) == 1


def test_pipeline_filters_by_severity(test_config):
    """Test pipeline respects severity threshold."""
    from continental.models import Finding, VulnerabilityCategory, Remediation

    pipeline = SecurityPipeline(test_config)

    findings = [
        Finding(
            title="Critical",
            description="Test",
            severity=Severity.CRITICAL,
            category=VulnerabilityCategory.SQL_INJECTION,
            cvss_score=9.0,
            affected_url="http://test.com",
            remediation=Remediation(summary="Fix", detailed_steps=[]),
            discovered_by="scanner"
        ),
        Finding(
            title="Low",
            description="Test",
            severity=Severity.LOW,
            category=VulnerabilityCategory.XSS,
            cvss_score=3.0,
            affected_url="http://test.com",
            remediation=Remediation(summary="Fix", detailed_steps=[]),
            discovered_by="scanner"
        ),
    ]

    filtered = pipeline._filter_by_severity(findings, Severity.MEDIUM)
    assert len(filtered) == 1  # Only CRITICAL should pass MEDIUM threshold
    assert filtered[0].severity == Severity.CRITICAL
