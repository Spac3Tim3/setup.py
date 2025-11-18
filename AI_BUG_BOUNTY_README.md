# AI Bug Bounty Hunter

**Automated security testing platform that discovers vulnerabilities and generates professional bug bounty reports.**

## Features

- 🔍 **Automated Scanning**: SQL injection, XSS, and more
- 🤖 **AI-Powered Analysis**: Claude enhances findings with intelligent insights
- 📊 **Professional Reports**: Bug bounty-ready markdown and JSON reports
- ⚡ **CI/CD Integration**: GitHub Actions workflow included
- 🎯 **Tested Against**: WebGoat, DVWA, Juice Shop

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (for testing against vulnerable apps)
- Anthropic API key (for AI-powered analysis)

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### Start Vulnerable Test Applications (Optional)

```bash
./docker/setup-vulnerable-targets.sh
```

This starts:
- **WebGoat**: http://localhost:8080
- **DVWA**: http://localhost:8081
- **Juice Shop**: http://localhost:3000
- **ZAP**: http://localhost:8090

### Run Your First Scan

```bash
python -m src.cli scan \
  --target http://localhost:8080 \
  --scanners sqli,xss \
  --output reports/ \
  --format both
```

### View Results

Reports are generated in `reports/`:
- `scan_report.md` - Comprehensive markdown report
- `scan_report.json` - Structured JSON data
- `findings/` - Individual bug bounty reports

## Usage

### Command Line

```bash
# Full scan with AI analysis
python -m src.cli scan \
  --target https://your-app.com \
  --scanners sqli,xss \
  --output reports/ \
  --format both \
  --severity-threshold HIGH

# Check if findings exceed thresholds
python -m src.cli check-findings \
  --report reports/scan_report.json \
  --max-critical 0 \
  --max-high 5
```

### Python API

```python
from src.models import ScanConfig, ScanTarget
from src.orchestrator.pipeline import SecurityPipeline
from src.reporters.bug_bounty_reporter import BugBountyReporter

# Configure scan
config = ScanConfig(
    target=ScanTarget(
        name="My App",
        base_url="https://your-app.com"
    ),
    scanners=["sqli", "xss"],
    enable_ai_analysis=True
)

# Execute scan
pipeline = SecurityPipeline(config)
report = pipeline.execute()

# Generate reports
reporter = BugBountyReporter(report)
reporter.generate_markdown_report("report.md")
reporter.generate_individual_reports("findings/")
```

## Project Structure

```
ai-bug-bounty-hunter/
├── src/
│   ├── scanners/          # Vulnerability scanners
│   │   ├── base.py        # Base scanner interface
│   │   ├── sqli_scanner.py
│   │   └── xss_scanner.py
│   ├── analyzers/         # AI analysis
│   │   └── ai_analyzer.py
│   ├── orchestrator/      # Pipeline coordination
│   │   └── pipeline.py
│   ├── reporters/         # Report generation
│   │   └── bug_bounty_reporter.py
│   ├── models.py          # Data models
│   └── cli.py             # Command-line interface
├── tests/
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   └── e2e/               # End-to-end tests
├── docker/                # Docker configurations
│   ├── docker-compose.vulnerable-targets.yml
│   └── setup-vulnerable-targets.sh
└── .github/workflows/     # CI/CD workflows
    └── security-scan.yml
```

## Scanners

| Scanner | Detects | Status |
|---------|---------|--------|
| SQLiScanner | SQL Injection | ✅ Ready |
| XSSScanner | Cross-Site Scripting | ✅ Ready |

## Testing

```bash
# Run all tests
pytest

# Run specific test suite
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/e2e/ -v

# Run with coverage
pytest --cov=src --cov-report=html
```

## GitHub Actions Integration

The included workflow (`.github/workflows/security-scan.yml`) automatically:

1. Runs tests on every push
2. Generates detailed reports
3. Uploads artifacts for review

### Setup

Add these secrets to your repository:
- `ANTHROPIC_API_KEY` - Your Anthropic API key

## Bug Bounty Submission

Individual finding reports in `reports/findings/` are formatted for direct submission to bug bounty programs like:

- HackerOne
- Bugcrowd
- Synack
- Intigriti

Each report includes:
- Detailed vulnerability description
- Step-by-step reproduction
- Proof of concept
- Impact assessment
- Remediation guidance
- CVSS scoring

## Configuration

### Environment Variables

```bash
# API Keys
ANTHROPIC_API_KEY=your_key_here

# Scanning Configuration
MAX_SCAN_DURATION=3600
REQUESTS_PER_SECOND=10
ENABLE_AI_ANALYSIS=true
```

### Custom Scanner Configuration

```python
config = ScanConfig(
    target=ScanTarget(
        name="Production App",
        base_url="https://app.example.com",
        rate_limit=5,  # Requests per second
        timeout=30,    # Request timeout
        excluded_paths=["/admin", "/internal"]
    ),
    scanners=["sqli", "xss"],
    enable_ai_analysis=True,
    max_duration_seconds=3600,
    severity_threshold=Severity.MEDIUM
)
```

## Best Practices

### Responsible Disclosure

- ✅ Always get written authorization
- ✅ Follow program scope
- ✅ Respect rate limits
- ✅ Don't test in production (use staging)

### Validation

- ✅ Manually verify all findings
- ✅ Test PoCs in isolated environment
- ✅ Document every step
- ✅ Capture screenshots/videos

## Contributing

Contributions welcome! Feel free to:
- Add new scanners
- Improve detection accuracy
- Enhance reporting
- Add documentation

## License

MIT License - see LICENSE file

## Security

**Important**: This tool is for authorized testing only. Always obtain proper authorization before scanning any application.

## Support

For issues and questions:
- Open an issue on GitHub
- Check existing documentation
- Review test cases for examples

---

**Built with ❤️ for the security community**
