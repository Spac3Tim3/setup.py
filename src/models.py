"""Core data models for vulnerability findings and reports."""
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityCategory(str, Enum):
    """OWASP Top 10 and common vulnerability categories."""
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    BROKEN_AUTH = "Broken Authentication"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    XXE = "XML External Entities"
    BROKEN_ACCESS = "Broken Access Control"
    SECURITY_MISCONFIG = "Security Misconfiguration"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    KNOWN_VULNS = "Using Components with Known Vulnerabilities"
    INSUFFICIENT_LOGGING = "Insufficient Logging & Monitoring"
    SSRF = "Server-Side Request Forgery"
    IDOR = "Insecure Direct Object Reference"
    COMMAND_INJECTION = "Command Injection"
    FILE_UPLOAD = "Unrestricted File Upload"
    LFI = "Local File Inclusion"
    RFI = "Remote File Inclusion"


class HTTPRequest(BaseModel):
    """HTTP request details."""
    method: str
    url: str
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None


class HTTPResponse(BaseModel):
    """HTTP response details."""
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    response_time_ms: float


class ProofOfConcept(BaseModel):
    """Proof of concept for exploiting a vulnerability."""
    description: str
    steps: List[str]
    request: HTTPRequest
    response: HTTPResponse
    payload: str
    impact_demonstration: str


class Remediation(BaseModel):
    """Remediation advice for fixing a vulnerability."""
    summary: str
    detailed_steps: List[str]
    code_examples: Optional[Dict[str, str]] = None
    references: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    """A security vulnerability finding."""
    id: str = Field(default_factory=lambda: f"VULN-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    title: str
    description: str
    severity: Severity
    category: VulnerabilityCategory
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None

    # Location
    affected_url: str
    affected_parameter: Optional[str] = None
    affected_component: Optional[str] = None

    # Evidence
    proof_of_concept: Optional[ProofOfConcept] = None
    additional_evidence: List[str] = Field(default_factory=list)

    # Fix
    remediation: Remediation

    # Metadata
    discovered_by: str  # scanner name
    discovered_at: datetime = Field(default_factory=datetime.now)
    verified: bool = False
    false_positive: bool = False

    # CWE and CVE mappings
    cwe_ids: List[int] = Field(default_factory=list)
    cve_ids: List[str] = Field(default_factory=list)


class ScanTarget(BaseModel):
    """Target application to scan."""
    name: str
    base_url: HttpUrl
    authentication: Optional[Dict[str, Any]] = None
    rate_limit: int = Field(default=10, description="Requests per second")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    excluded_paths: List[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    """Configuration for a security scan."""
    target: ScanTarget
    scanners: List[str] = Field(default=["zap", "nuclei", "custom"])
    enable_ai_analysis: bool = True
    enable_fuzzing: bool = True
    max_duration_seconds: int = 3600
    severity_threshold: Severity = Severity.MEDIUM


class ScanReport(BaseModel):
    """Complete scan report."""
    scan_id: str = Field(default_factory=lambda: f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}")
    target: ScanTarget
    config: ScanConfig

    # Findings
    findings: List[Finding] = Field(default_factory=list)

    # Statistics
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    # Timing
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    # Status
    status: str = "in_progress"  # in_progress, completed, failed
    error_message: Optional[str] = None

    def update_statistics(self):
        """Recalculate statistics from findings."""
        self.total_findings = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        self.info_count = sum(1 for f in self.findings if f.severity == Severity.INFO)
