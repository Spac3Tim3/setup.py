"""Tests for base scanner functionality."""
import pytest
import time
from src.scanners.base import BaseScanner, RateLimiter
from src.models import ScanTarget, Finding, Severity, VulnerabilityCategory, Remediation


class MockScanner(BaseScanner):
    """Mock scanner for testing."""

    @property
    def name(self) -> str:
        return "MockScanner"

    @property
    def description(self) -> str:
        return "A mock scanner for testing"

    def scan(self):
        finding = Finding(
            title="Test Finding",
            description="Test",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.XSS,
            cvss_score=7.5,
            affected_url=str(self.target.base_url),
            remediation=Remediation(summary="Fix", detailed_steps=[]),
            discovered_by=self.name
        )
        self.add_finding(finding)
        return self.findings


def test_rate_limiter():
    """Test rate limiter enforces request limits."""
    limiter = RateLimiter(requests_per_second=10)

    start = time.time()
    for _ in range(10):
        limiter.wait_if_needed()
    elapsed = time.time() - start

    # 10 requests at 10 req/s should take ~1 second
    assert elapsed >= 0.9
    assert elapsed <= 1.5  # Allow some overhead


def test_scanner_initialization():
    """Test scanner initializes correctly."""
    target = ScanTarget(name="test", base_url="http://localhost:8080")
    scanner = MockScanner(target)

    assert scanner.name == "MockScanner"
    assert scanner.target == target
    assert len(scanner.findings) == 0


def test_scanner_adds_findings():
    """Test scanner can add findings."""
    target = ScanTarget(name="test", base_url="http://localhost:8080")
    scanner = MockScanner(target)

    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].discovered_by == "MockScanner"
    assert findings[0].severity == Severity.HIGH
