<div align="center">

# 🏛️ THE CONTINENTAL

**Professional Security Intelligence Platform**

*"In this business, precision is everything."*

[![License: MIT](https://img.shields.io/badge/License-MIT-gold.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-darkred.svg)](https://python.org)
[![Continental Standard](https://img.shields.io/badge/Continental-Standard-2B2B2B.svg)](#)

[Installation](#installation) • [Quick Start](#quick-start) • [Rules](#the-rules) • [Documentation](#documentation)

</div>

---

```
╔═══════════════════════════════════════════════════════════╗
║                    THE CONTINENTAL                        ║
║            Professional Security Services                 ║
║                                                           ║
║         "No Business on Production Grounds"               ║
╚═══════════════════════════════════════════════════════════╝
```

## Welcome to The Continental

The Continental is a professional security intelligence platform where security professionals conduct business. Like the establishment it's named after, we operate under strict rules and maintain the highest standards of professionalism.

### What is The Continental?

An AI-powered security testing platform that:
- 🎯 Identifies security markers (vulnerabilities)
- 🤖 Employs AI intelligence for analysis
- 📋 Generates professional dossiers (reports)
- ⚔️ Deploys specialized operators (scanners)
- 🏛️ Operates under The Rules at all times

## The Rules

1. **No business on production grounds** - Test in authorized environments only
2. **Professional conduct at all times** - Responsible disclosure required
3. **Respect the ledger** - Honor all findings and remediation contracts
4. **The price must be paid** - All vulnerabilities must be addressed
5. **Courtesy. Professional courtesy** - Maintain professionalism in all interactions

## Installation

### Prerequisites

- Python 3.11+
- Docker & Docker Compose (optional, for testing)
- Anthropic API key (for AI intelligence)

### Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Configure your operator credentials
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

## Quick Start

### Initiate Your First Contract

```bash
# Basic contract
python -m continental.concierge contract \
  --target http://localhost:8080 \
  --operators sqli,xss \
  --output ledger/

# Professional contract with operator identification
python -m continental.concierge contract \
  --target https://staging.example.com \
  --operators sqli,xss \
  --operator-name "Your Name" \
  --price-threshold HIGH \
  --output contracts/staging/
```

### View Available Services

```bash
# Display the operations board
python -m continental.concierge board

# Review The Rules
python -m continental.concierge rules

# Verify contract status
python -m continental.concierge verify \
  --ledger contracts/contract_ledger.json \
  --max-critical 0 \
  --max-high 5
```

## Continental Services

### Available Operators

| Operator | Specialty | Status |
|----------|-----------|--------|
| ⚔️ SQLi Specialist | SQL Injection Detection | ✅ Active |
| ⚔️ XSS Specialist | Cross-Site Scripting | ✅ Active |
| 🤖 AI Intelligence | Enhanced Analysis | ✅ Active |

### Marker Classification

Vulnerabilities are classified by "price" (severity):

- 🔴 **Critical**: ⚜⚜⚜⚜⚜ (5 gold coins) - Immediate action required
- 🟠 **High**: ⚜⚜⚜ (3 gold coins) - Priority remediation
- 🟡 **Medium**: ⚜ (1 gold coin) - Standard attention
- 🟢 **Low**: Standard tracking

## Dossier Structure

After contract completion, you'll receive:

```
ledger/
├── continental_dossier.md       # Complete intelligence report
├── contract_ledger.json          # Structured data
└── markers/                      # Individual marker reports
    ├── marker_001_CRITICAL.md
    ├── marker_002_HIGH.md
    └── ...
```

Each marker report includes:
- 🎯 Target identification
- 📋 Proof of concept
- 💰 Price assessment (CVSS)
- 🔧 Remediation contract
- 📚 Reference materials

## Professional Usage

### Contract Workflow

```python
from continental.models import ScanConfig, ScanTarget, Severity
from continental.contracts.pipeline import SecurityPipeline
from continental.dossiers.bug_bounty_reporter import BugBountyReporter

# Initiate contract
config = ScanConfig(
    target=ScanTarget(
        name="Corporate Application",
        base_url="https://app.example.com"
    ),
    scanners=["sqli", "xss"],
    enable_ai_analysis=True,
    severity_threshold=Severity.HIGH
)

# Deploy operators
pipeline = SecurityPipeline(config)
contract_results = pipeline.execute()

# Generate dossier
dossier = BugBountyReporter(contract_results)
dossier.generate_markdown_report("continental_intelligence.md")
dossier.generate_individual_reports("markers/")
```

### High Table Enterprise

For enterprise deployments, The Continental offers:

- 🏛️ Dedicated concierge (support)
- 🎯 Custom operator development
- 📊 Real-time intelligence dashboards
- ⚔️ Priority contract execution
- 🔒 Enhanced confidentiality protocols

## Project Structure

```
continental-platform/
├── continental/              # Main package
│   ├── operators/           # Security specialists (scanners)
│   │   ├── base.py         # Operator framework
│   │   ├── sqli_scanner.py # SQL injection specialist
│   │   └── xss_scanner.py  # XSS specialist
│   ├── intelligence/        # AI analysis suite
│   │   └── ai_analyzer.py  # Claude integration
│   ├── contracts/           # Contract orchestration
│   │   └── pipeline.py     # Multi-operator coordination
│   ├── dossiers/            # Intelligence reporting
│   │   └── bug_bounty_reporter.py
│   ├── models.py            # Data structures
│   └── concierge.py         # Command interface
├── tests/                   # Verification suite
├── docker/                  # Test environments
└── rules/                   # Configuration
```

## Testing Environment

Deploy vulnerable test applications (for authorized testing):

```bash
# Start The Continental's practice range
./docker/setup-vulnerable-targets.sh

# Applications available:
# - WebGoat:     http://localhost:8080
# - DVWA:        http://localhost:8081
# - Juice Shop:  http://localhost:3000
```

## Running Tests

```bash
# Execute verification suite
pytest

# With coverage report
pytest --cov=continental --cov-report=html

# Specific test categories
pytest tests/unit/ -v
pytest tests/integration/ -v
```

## Configuration

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-xxxxx

# Optional
MAX_SCAN_DURATION=3600
REQUESTS_PER_SECOND=10
ENABLE_AI_ANALYSIS=true
```

### Operator Configuration

```python
config = ScanConfig(
    target=ScanTarget(
        name="Secure Application",
        base_url="https://app.example.com",
        rate_limit=5,              # Respect the establishment
        timeout=30,
        excluded_paths=["/admin"]  # No unauthorized areas
    ),
    scanners=["sqli", "xss"],
    enable_ai_analysis=True,
    severity_threshold=Severity.MEDIUM
)
```

## Bug Bounty Integration

Individual marker reports in `ledger/markers/` are formatted for direct submission to:

- HackerOne
- Bugcrowd
- Synack
- Intigriti

Each includes:
- Complete vulnerability details
- Step-by-step proof of concept
- CVSS scoring
- Remediation guidance
- Professional formatting

## Easter Eggs

```bash
# Pay respects
python -m continental.concierge respect --for winston

# Check on what matters
python -m continental.concierge respect --for dog

# Display operations board
python -m continental.concierge board
```

## Contributing

The Continental welcomes professional contributions:

- 🔧 New operator development
- 📊 Enhanced intelligence features
- 📋 Improved dossier formats
- 🧪 Additional test coverage

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - See [LICENSE](LICENSE)

## Security & Responsibility

**⚠️ CRITICAL NOTICE ⚠️**

This tool is for **authorized security testing only**. The Continental operates under strict rules:

- ✅ Obtain written authorization
- ✅ Test only in designated environments
- ✅ Follow responsible disclosure
- ✅ Respect all boundaries
- ❌ No unauthorized access
- ❌ No production testing without approval

> *"The Continental exists to serve our unique clientele. Those who break The Rules face consequences."*

## Support

- 📋 [Documentation](USAGE.md)
- 🐛 [Issue Tracker](https://github.com/continental-security/platform/issues)
- 💬 [Discussions](https://github.com/continental-security/platform/discussions)

---

<div align="center">

**The Continental**

*Where security professionals conduct business.*

```
⚜  Professional  •  Precise  •  Uncompromising  ⚜
```

</div>
