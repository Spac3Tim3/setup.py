"""Command-line interface for security scanner."""
import click
import json
import sys
from pathlib import Path

from src.models import ScanConfig, ScanTarget, Severity
from src.orchestrator.pipeline import SecurityPipeline
from src.reporters.bug_bounty_reporter import BugBountyReporter


@click.group()
def cli():
    """AI-powered bug bounty hunter CLI."""
    pass


@cli.command()
@click.option('--target', required=True, help='Target URL to scan')
@click.option('--scanners', default='sqli,xss', help='Comma-separated list of scanners')
@click.option('--output', default='reports/', help='Output directory')
@click.option('--format', default='markdown', help='Report format (markdown, json, both)')
@click.option('--severity-threshold', default='MEDIUM', help='Minimum severity to report')
def scan(target, scanners, output, format, severity_threshold):
    """Execute security scan."""
    click.echo(f"🔍 Starting security scan of {target}")

    # Create config
    config = ScanConfig(
        target=ScanTarget(name="Target", base_url=target),
        scanners=scanners.split(','),
        enable_ai_analysis=True,
        severity_threshold=Severity[severity_threshold.upper()]
    )

    # Run pipeline
    pipeline = SecurityPipeline(config)
    report = pipeline.execute()

    # Generate reports
    reporter = BugBountyReporter(report)

    if format in ['markdown', 'both']:
        md_path = Path(output) / 'scan_report.md'
        reporter.generate_markdown_report(str(md_path))
        click.echo(f"📄 Markdown report: {md_path}")

    if format in ['json', 'both']:
        json_path = Path(output) / 'scan_report.json'
        reporter.generate_json_report(str(json_path))
        click.echo(f"📊 JSON report: {json_path}")

    # Individual reports
    individual_reports = reporter.generate_individual_reports(str(Path(output) / 'findings'))
    click.echo(f"📋 Generated {len(individual_reports)} individual reports")

    # Summary
    click.echo(f"\n{'='*50}")
    click.echo(f"Scan complete! Found {report.total_findings} vulnerabilities:")
    click.echo(f"  🔴 Critical: {report.critical_count}")
    click.echo(f"  🟠 High: {report.high_count}")
    click.echo(f"  🟡 Medium: {report.medium_count}")
    click.echo(f"  🟢 Low: {report.low_count}")
    click.echo(f"{'='*50}\n")


@cli.command()
@click.option('--report', required=True, help='Path to scan report JSON')
@click.option('--max-critical', default=0, type=int, help='Maximum allowed critical findings')
@click.option('--max-high', default=5, type=int, help='Maximum allowed high findings')
def check_findings(report, max_critical, max_high):
    """Check if findings exceed thresholds."""
    with open(report) as f:
        data = json.load(f)

    critical = data['critical_count']
    high = data['high_count']

    click.echo(f"Critical: {critical} (max: {max_critical})")
    click.echo(f"High: {high} (max: {max_high})")

    if critical > max_critical or high > max_high:
        click.echo("❌ Finding thresholds exceeded!")
        sys.exit(1)
    else:
        click.echo("✅ Finding thresholds OK")


if __name__ == '__main__':
    cli()
