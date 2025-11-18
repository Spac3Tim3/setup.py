"""
The Continental - Professional Security Intelligence Platform
Command-line interface for contract management and operations.

"Courtesy. Professional courtesy."
"""
import click
import json
import sys
from pathlib import Path

from continental.models import ScanConfig, ScanTarget, Severity
from continental.contracts.pipeline import SecurityPipeline
from continental.dossiers.bug_bounty_reporter import BugBountyReporter

CONTINENTAL_BANNER = """
╔═══════════════════════════════════════════════════════════╗
║                    THE CONTINENTAL                        ║
║            Professional Security Services                 ║
║                                                           ║
║         "No Business on Production Grounds"               ║
╚═══════════════════════════════════════════════════════════╝
"""

GOLD_COIN = "⚜"


@click.group()
def continental():
    """The Continental - Professional security intelligence platform."""
    click.echo(click.style(CONTINENTAL_BANNER, fg='yellow', bold=True))


@continental.command()
@click.option('--target', required=True, help='Contract target URL')
@click.option('--operators', default='sqli,xss', help='Comma-separated operator list')
@click.option('--output', default='ledger/', help='Dossier output directory')
@click.option('--format', default='dossier', help='Report format (dossier, json, both)')
@click.option('--price-threshold', default='MEDIUM', help='Minimum marker price (CRITICAL, HIGH, MEDIUM, LOW)')
@click.option('--operator-name', default='Anonymous', help='Your operator name')
def contract(target, operators, output, format, price_threshold, operator_name):
    """Initiate a new security contract."""
    click.echo(f"\n{click.style(GOLD_COIN, fg='yellow')} Contract accepted, {operator_name}")
    click.echo(click.style(f"Target: {target}", dim=True))
    click.echo(click.style("\n⚠  Remember: No business on production grounds", fg='yellow'))
    click.echo(click.style("⚠  Professional conduct required at all times\n", fg='yellow'))

    click.echo(click.style("INITIATING CONTRACT", bold=True))
    click.echo("━" * 60)

    # Create config
    config = ScanConfig(
        target=ScanTarget(name="Contract Target", base_url=target),
        scanners=operators.split(','),
        enable_ai_analysis=True,
        severity_threshold=Severity[price_threshold.upper()]
    )

    # Run pipeline
    click.echo("\nDeploying operators...")
    pipeline = SecurityPipeline(config)
    report = pipeline.execute()

    # Generate dossiers
    reporter = BugBountyReporter(report)

    if format in ['dossier', 'both']:
        md_path = Path(output) / 'continental_dossier.md'
        reporter.generate_markdown_report(str(md_path))
        click.echo(f"📋 Dossier generated: {md_path}")

    if format in ['json', 'both']:
        json_path = Path(output) / 'contract_ledger.json'
        reporter.generate_json_report(str(json_path))
        click.echo(f"📊 Ledger updated: {json_path}")

    # Individual marker reports
    marker_reports = reporter.generate_individual_reports(str(Path(output) / 'markers'))
    click.echo(f"🎯 {len(marker_reports)} markers documented\n")

    # Display summary
    click.echo(click.style("CONTRACT SUMMARY", bold=True))
    click.echo("━" * 60)
    click.echo(f"Markers Identified: {report.total_findings}")
    click.echo(f"  🔴 Critical:  {report.critical_count} markers ({GOLD_COIN * 5} each)")
    click.echo(f"  🟠 High:      {report.high_count} markers ({GOLD_COIN * 3} each)")
    click.echo(f"  🟡 Medium:    {report.medium_count} markers ({GOLD_COIN} each)")
    click.echo(f"  🟢 Low:       {report.low_count} markers")

    total_price = (report.critical_count * 5 +
                   report.high_count * 3 +
                   report.medium_count * 1)
    click.echo(f"\nTotal Price: {GOLD_COIN * min(total_price, 15)} ({total_price} gold coins)")
    click.echo("━" * 60)

    if report.critical_count > 0:
        click.echo(click.style("\n⚠  HIGH TABLE ATTENTION REQUIRED", fg='red', bold=True))
        click.echo(click.style(f"   {report.critical_count} critical markers demand immediate action\n", fg='red'))

    click.echo(click.style('\nThe Continental thanks you for your business.', dim=True))


@continental.command()
@click.option('--ledger', required=True, help='Path to contract ledger (JSON)')
@click.option('--max-critical', default=0, type=int, help='Maximum allowed critical markers')
@click.option('--max-high', default=5, type=int, help='Maximum allowed high markers')
def verify(ledger, max_critical, max_high):
    """Verify contract completion status."""
    click.echo(click.style("\nVERIFYING CONTRACT STATUS", bold=True))
    click.echo("━" * 60)

    with open(ledger) as f:
        data = json.load(f)

    critical = data['critical_count']
    high = data['high_count']

    click.echo(f"Critical markers: {critical} (maximum allowed: {max_critical})")
    click.echo(f"High markers:     {high} (maximum allowed: {max_high})")

    if critical > max_critical or high > max_high:
        click.echo(click.style("\n❌ CONTRACT TERMS VIOLATED", fg='red', bold=True))
        click.echo(click.style("   Marker threshold exceeded. Remediation required.", fg='red'))
        click.echo("━" * 60)
        sys.exit(1)
    else:
        click.echo(click.style("\n✓ CONTRACT TERMS SATISFIED", fg='green', bold=True))
        click.echo(click.style("  All markers within acceptable parameters.", fg='green'))
        click.echo("━" * 60)


@continental.command()
def markers():
    """List all identified markers (findings)."""
    click.echo(click.style("\nCONTINENTAL MARKER REGISTRY", bold=True))
    click.echo("━" * 60)
    click.echo("Use 'continental contract' to identify new markers")
    click.echo("Use 'continental verify' to check marker status")


@continental.command()
def rules():
    """Display The Continental rules."""
    rules_text = """
╔═══════════════════════════════════════════════════════════╗
║                    THE RULES                              ║
╚═══════════════════════════════════════════════════════════╝

1. NO BUSINESS ON PRODUCTION GROUNDS
   → Test only in authorized staging environments
   → Obtain written permission before any engagement

2. PROFESSIONAL CONDUCT AT ALL TIMES
   → Respect rate limits and system boundaries
   → Follow responsible disclosure practices
   → Honor all confidentiality agreements

3. RESPECT THE LEDGER
   → Document all findings accurately
   → Verify markers before reporting
   → Maintain complete audit trails

4. THE PRICE MUST BE PAID
   → All critical markers require immediate remediation
   → High markers must be addressed within SLA
   → Track all contract obligations

5. COURTESY. PROFESSIONAL COURTESY.
   → Communicate clearly and respectfully
   → Provide actionable remediation guidance
   → Support the security community

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"In this business, precision is everything."
    """
    click.echo(click.style(rules_text, fg='yellow'))


@continental.command()
@click.option('--for', 'respect_for', default='winston', help='Show respect')
def respect(respect_for):
    """Pay respects. Easter egg command."""
    if respect_for.lower() == 'winston':
        click.echo(click.style("\n🎩 Winston sends his regards.", fg='yellow'))
        click.echo(click.style("   'The Continental' - Where professionals conduct business.\n", dim=True))
    elif respect_for.lower() == 'dog':
        click.echo(click.style("\n🐕 The dog is safe. All is well.", fg='green'))
    else:
        click.echo(click.style(f"\n{GOLD_COIN} Professional courtesy acknowledged.", fg='yellow'))


@continental.command()
def board():
    """Display the Continental operations board."""
    board_display = """
╔═══════════════════════════════════════════════════════════╗
║              CONTINENTAL OPERATIONS BOARD                  ║
╚═══════════════════════════════════════════════════════════╝

ACTIVE OPERATORS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 ⚔  SQLi Specialist        [READY]
 ⚔  XSS Specialist         [READY]
 ⚔  AI Intelligence        [READY]

SERVICES AVAILABLE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 • Contract Initiation     continental contract --target <url>
 • Marker Verification     continental verify --ledger <path>
 • Rules Review            continental rules
 • Status Board            continental board

"Welcome to The Continental."
    """
    click.echo(click.style(board_display, fg='yellow'))


if __name__ == '__main__':
    continental()
