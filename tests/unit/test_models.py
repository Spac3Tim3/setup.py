"""Tests for core data models."""
import pytest
from datetime import datetime
from continental.models import (
    Finding, Severity, VulnerabilityCategory,
    ScanReport, ScanTarget, ScanConfig,
    Remediation, ProofOfConcept, HTTPRequest, HTTPResponse
)


def test_finding_creation():
    """Test creating a basic finding."""
    finding = Finding(
        title="SQL Injection in login form",
        description="The login form is vulnerable to SQL injection",
        severity=Severity.CRITICAL,
        category=VulnerabilityCategory.SQL_INJECTION,
        cvss_score=9.8,
        affected_url="http://localhost:8080/login",
        affected_parameter="username",
        remediation=Remediation(
            summary="Use parameterized queries",
            detailed_steps=["Replace string concatenation with prepared statements"],
            references=["https://owasp.org/www-community/attacks/SQL_Injection"]
        ),
        discovered_by="test_scanner"
    )

    assert finding.title == "SQL Injection in login form"
    assert finding.severity == Severity.CRITICAL
    assert finding.cvss_score == 9.8
    assert finding.id.startswith("VULN-")
    assert not finding.verified


def test_scan_report_statistics():
    """Test scan report statistics calculation."""
    report = ScanReport(
        target=ScanTarget(name="test", base_url="http://localhost:8080"),
        config=ScanConfig(
            target=ScanTarget(name="test", base_url="http://localhost:8080")
        )
    )

    # Add findings
    report.findings = [
        Finding(
            title="Critical vuln",
            description="Test",
            severity=Severity.CRITICAL,
            category=VulnerabilityCategory.SQL_INJECTION,
            cvss_score=9.0,
            affected_url="http://test.com",
            remediation=Remediation(summary="Fix it", detailed_steps=[]),
            discovered_by="scanner"
        ),
        Finding(
            title="High vuln",
            description="Test",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.XSS,
            cvss_score=7.5,
            affected_url="http://test.com",
            remediation=Remediation(summary="Fix it", detailed_steps=[]),
            discovered_by="scanner"
        ),
        Finding(
            title="Medium vuln",
            description="Test",
            severity=Severity.MEDIUM,
            category=VulnerabilityCategory.BROKEN_AUTH,
            cvss_score=5.0,
            affected_url="http://test.com",
            remediation=Remediation(summary="Fix it", detailed_steps=[]),
            discovered_by="scanner"
        ),
    ]

    report.update_statistics()

    assert report.total_findings == 3
    assert report.critical_count == 1
    assert report.high_count == 1
    assert report.medium_count == 1
    assert report.low_count == 0


def test_proof_of_concept_structure():
    """Test PoC includes all necessary information."""
    poc = ProofOfConcept(
        description="Exploit SQL injection to bypass authentication",
        steps=[
            "Navigate to login page",
            "Enter username: admin' OR '1'='1",
            "Enter any password",
            "Click login"
        ],
        request=HTTPRequest(
            method="POST",
            url="http://localhost:8080/login",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body="username=admin'+OR+'1'='1&password=anything"
        ),
        response=HTTPResponse(
            status_code=200,
            headers={"Set-Cookie": "session=abc123"},
            body="Welcome admin!",
            response_time_ms=145.2
        ),
        payload="admin' OR '1'='1",
        impact_demonstration="Successfully bypassed authentication and logged in as admin"
    )

    assert len(poc.steps) == 4
    assert poc.request.method == "POST"
    assert poc.response.status_code == 200
    assert "admin" in poc.impact_demonstration
