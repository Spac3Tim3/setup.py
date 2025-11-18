"""Integration tests for SQL injection scanner."""
import pytest
from src.scanners.sqli_scanner import SQLiScanner
from src.models import ScanTarget, Severity


@pytest.fixture
def test_target():
    """Test target for scanning."""
    return ScanTarget(
        name="TestTarget",
        base_url="http://localhost:8080",
        rate_limit=5
    )


def test_sqli_scanner_initialization(test_target):
    """Test scanner initializes correctly."""
    scanner = SQLiScanner(test_target)

    assert scanner.name == "SQLiScanner"
    assert scanner.target == test_target
    assert len(scanner.findings) == 0


def test_sqli_scanner_has_payloads(test_target):
    """Test scanner has SQL injection payloads."""
    scanner = SQLiScanner(test_target)

    assert len(scanner.PAYLOADS) > 0
    assert any("OR" in p for p in scanner.PAYLOADS)
    assert any("--" in p or "#" in p for p in scanner.PAYLOADS)


def test_sqli_scanner_has_error_patterns(test_target):
    """Test scanner has error detection patterns."""
    scanner = SQLiScanner(test_target)

    assert len(scanner.ERROR_PATTERNS) > 0
    assert any("MySQL" in p for p in scanner.ERROR_PATTERNS)
    assert any("PostgreSQL" in p for p in scanner.ERROR_PATTERNS)
