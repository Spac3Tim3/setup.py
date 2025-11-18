# AI Bug Bounty Hunter - Detailed Usage Guide

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Running Scans](#running-scans)
- [Understanding Reports](#understanding-reports)
- [Bug Bounty Submission](#bug-bounty-submission)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## Installation

### System Requirements

- Python 3.11 or higher
- 4GB RAM minimum
- Docker and Docker Compose (for vulnerable test apps)
- Internet connection for AI analysis

### Step-by-Step Installation

1. **Clone the repository** (or start from this base):
```bash
cd ai-bug-bounty-hunter
```

2. **Create virtual environment** (recommended):
```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

4. **Configure environment**:
```bash
cp .env.example .env
```

Edit `.env` and add your Anthropic API key:
```bash
ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

5. **Verify installation**:
```bash
python -m pytest tests/unit/ -v
```

## Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-xxxxx

# Optional
MAX_SCAN_DURATION=3600
REQUESTS_PER_SECOND=10
ENABLE_AI_ANALYSIS=true
ENABLE_FUZZING=true
```

### Scan Configuration

Configure scans programmatically:

```python
from src.models import ScanConfig, ScanTarget, Severity

config = ScanConfig(
    target=ScanTarget(
        name="My Application",
        base_url="https://app.example.com",
        rate_limit=10,              # Requests per second
        timeout=30,                 # Seconds
        excluded_paths=["/admin"]   # Paths to skip
    ),
    scanners=["sqli", "xss"],       # Which scanners to run
    enable_ai_analysis=True,        # Use AI enhancement
    enable_fuzzing=False,           # Advanced fuzzing
    max_duration_seconds=3600,      # Maximum scan time
    severity_threshold=Severity.MEDIUM  # Minimum severity to report
)
```

## Running Scans

### Basic Scan

```bash
python -m src.cli scan \
  --target http://localhost:8080 \
  --scanners sqli,xss \
  --output reports/
```

### Advanced Scan Options

```bash
python -m src.cli scan \
  --target https://your-app.com \
  --scanners sqli,xss \
  --output reports/ \
  --format both \
  --severity-threshold HIGH
```

Options:
- `--target`: URL to scan (required)
- `--scanners`: Comma-separated scanner list (default: sqli,xss)
- `--output`: Output directory (default: reports/)
- `--format`: markdown, json, or both (default: markdown)
- `--severity-threshold`: CRITICAL, HIGH, MEDIUM, LOW (default: MEDIUM)

### Testing Against Vulnerable Applications

Start the vulnerable test applications:

```bash
# Start all vulnerable apps
./docker/setup-vulnerable-targets.sh

# Scan WebGoat
python -m src.cli scan \
  --target http://localhost:8080 \
  --scanners sqli,xss \
  --output reports/webgoat/

# Scan DVWA
python -m src.cli scan \
  --target http://localhost:8081 \
  --scanners sqli,xss \
  --output reports/dvwa/

# Scan Juice Shop
python -m src.cli scan \
  --target http://localhost:3000 \
  --scanners sqli,xss \
  --output reports/juiceshop/
```

### Programmatic Usage

```python
from src.models import ScanConfig, ScanTarget, Severity
from src.orchestrator.pipeline import SecurityPipeline
from src.reporters.bug_bounty_reporter import BugBountyReporter

# Configure
config = ScanConfig(
    target=ScanTarget(
        name="My App",
        base_url="https://app.example.com"
    ),
    scanners=["sqli", "xss"],
    enable_ai_analysis=True,
    severity_threshold=Severity.HIGH
)

# Run scan
pipeline = SecurityPipeline(config)
report = pipeline.execute()

# Generate reports
reporter = BugBountyReporter(report)
reporter.generate_markdown_report("scan_report.md")
reporter.generate_json_report("scan_report.json")
individual_reports = reporter.generate_individual_reports("findings/")

# Print summary
print(f"Found {report.total_findings} vulnerabilities")
print(f"Critical: {report.critical_count}")
print(f"High: {report.high_count}")
```

## Understanding Reports

### Markdown Report Structure

The main `scan_report.md` contains:

1. **Header**: Scan metadata (ID, target, date, duration)
2. **Executive Summary**: Finding counts by severity
3. **Detailed Findings**: Organized by severity level

Each finding includes:
- Title and unique ID
- Severity and CVSS score
- Affected URL and parameters
- Description
- Proof of Concept (PoC)
- Remediation steps
- Code examples
- References (OWASP, CWE)

### JSON Report Structure

The `scan_report.json` contains structured data:

```json
{
  "scan_id": "SCAN-20250118120000",
  "target": {...},
  "findings": [
    {
      "id": "VULN-20250118120001",
      "title": "SQL Injection in username parameter",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "affected_url": "http://example.com/login",
      "proof_of_concept": {...},
      "remediation": {...}
    }
  ],
  "total_findings": 5,
  "critical_count": 1,
  "high_count": 2
}
```

### Individual Finding Reports

Located in `reports/findings/`, each high/critical vulnerability gets its own professional report:

- **Filename**: `bug_report_1_VULN-xxxxx.md`
- **Format**: Ready for bug bounty submission
- **Contents**: Complete vulnerability details with PoC

## Bug Bounty Submission

### Step 1: Run Targeted Scan

```bash
python -m src.cli scan \
  --target https://target-app.com \
  --scanners sqli,xss \
  --output bounty_reports/ \
  --format both \
  --severity-threshold HIGH
```

### Step 2: Review Findings

Check `bounty_reports/findings/` for individual reports.

### Step 3: Verify Findings

**Always manually verify** before submission:

```python
# Verify specific finding
from src.scanners.sqli_scanner import SQLiScanner
from src.models import ScanTarget

target = ScanTarget(name="Target", base_url="https://target-app.com")
scanner = SQLiScanner(target)

# Manual verification steps here
```

### Step 4: Submit to Platform

1. Copy content from individual report
2. Add screenshots/videos if applicable
3. Submit through bug bounty platform:
   - HackerOne
   - Bugcrowd
   - Synack
   - Intigriti

### Step 5: Track Submissions

Keep records:
- Original scan reports
- Platform submission IDs
- Communication logs
- Payout information

## Advanced Usage

### Custom Scanners

Create your own scanner:

```python
from src.scanners.base import BaseScanner
from src.models import Finding, Severity, VulnerabilityCategory, Remediation

class CustomScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "CustomScanner"

    @property
    def description(self) -> str:
        return "My custom security scanner"

    def scan(self):
        # Your scanning logic here
        finding = Finding(
            title="Custom Vulnerability",
            description="Description here",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.SECURITY_MISCONFIG,
            cvss_score=7.0,
            affected_url=str(self.target.base_url),
            remediation=Remediation(
                summary="Fix the issue",
                detailed_steps=["Step 1", "Step 2"]
            ),
            discovered_by=self.name
        )
        self.add_finding(finding)
        return self.findings
```

### Rate Limiting

Control request rate to avoid overwhelming targets:

```python
target = ScanTarget(
    name="Production",
    base_url="https://app.example.com",
    rate_limit=5,  # 5 requests per second
    timeout=30
)
```

### Filtering Results

```python
# Filter by severity
high_critical = [
    f for f in report.findings
    if f.severity in [Severity.HIGH, Severity.CRITICAL]
]

# Filter by category
sqli_findings = [
    f for f in report.findings
    if f.category == VulnerabilityCategory.SQL_INJECTION
]
```

## Troubleshooting

### Common Issues

**1. No vulnerabilities found**

- Verify target is accessible
- Check authentication requirements
- Review excluded paths
- Increase scan timeout

**2. Rate limiting errors**

```python
# Reduce rate limit
target = ScanTarget(
    name="Target",
    base_url="http://example.com",
    rate_limit=2  # Slower rate
)
```

**3. AI analysis fails**

- Verify `ANTHROPIC_API_KEY` is set correctly
- Check API quota/limits
- Review error logs
- Disable AI temporarily: `enable_ai_analysis=False`

**4. Tests failing**

```bash
# Run tests with verbose output
pytest -v -s

# Run specific test
pytest tests/unit/test_models.py::test_finding_creation -v
```

**5. Docker containers not starting**

```bash
# Check Docker is running
docker ps

# View container logs
docker logs webgoat
docker logs dvwa

# Restart containers
docker-compose -f docker/docker-compose.vulnerable-targets.yml down
./docker/setup-vulnerable-targets.sh
```

### Debug Mode

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Now run your scan
```

### Performance Optimization

```python
config = ScanConfig(
    target=target,
    scanners=["sqli"],  # Run one scanner at a time
    enable_ai_analysis=False,  # Disable for speed
    severity_threshold=Severity.HIGH  # Only high/critical
)
```

## Best Practices

### 1. Authorization

- ✅ Get written permission
- ✅ Test only in-scope targets
- ✅ Follow bug bounty program rules
- ❌ Never scan without authorization

### 2. Responsible Testing

- Use staging environments
- Respect rate limits
- Avoid DoS conditions
- Clean up test data

### 3. Documentation

- Take screenshots
- Record all steps
- Save all evidence
- Document timeline

### 4. Verification

- Manually verify findings
- Test in isolated environment
- Confirm impact
- Validate remediation

## Examples

See test files for working examples:
- `tests/unit/test_models.py` - Data model usage
- `tests/integration/test_pipeline.py` - Pipeline usage
- `tests/integration/test_sqli_scanner.py` - Scanner usage

---

**Happy hunting! 🎯**
