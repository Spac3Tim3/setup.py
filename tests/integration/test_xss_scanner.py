"""Integration tests for XSS scanner."""
import pytest
from continental.operators.xss_scanner import XSSScanner
from continental.models import ScanTarget, Severity, VulnerabilityCategory


@pytest.fixture
def test_target():
    """Test target for scanning."""
    return ScanTarget(
        name="TestTarget",
        base_url="http://localhost:8080",
        rate_limit=5
    )


def test_xss_scanner_initialization(test_target):
    """Test scanner initializes correctly."""
    scanner = XSSScanner(test_target)

    assert scanner.name == "XSSScanner"
    assert scanner.description
    assert scanner.target == test_target


def test_xss_scanner_has_payloads(test_target):
    """Test scanner has XSS payloads."""
    scanner = XSSScanner(test_target)

    assert len(scanner.PAYLOADS) > 0
    assert any("script" in p.lower() for p in scanner.PAYLOADS)
    assert any("alert" in p.lower() for p in scanner.PAYLOADS)
