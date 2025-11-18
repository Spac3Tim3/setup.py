"""Generate professional bug bounty reports."""
import json
from datetime import datetime
from typing import List, Optional
from pathlib import Path
import logging

from src.models import ScanReport, Finding, Severity

logger = logging.getLogger(__name__)


class BugBountyReporter:
    """Generates professional reports suitable for bug bounty submissions."""

    def __init__(self, report: ScanReport):
        self.report = report

    def generate_markdown_report(self, output_path: str):
        """Generate a comprehensive markdown report."""
        md_content = self._generate_markdown()

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(md_content)

        logger.info(f"Generated markdown report: {output_path}")

    def generate_json_report(self, output_path: str):
        """Generate a JSON report for programmatic processing."""
        report_dict = self.report.model_dump(mode='json')

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)

        logger.info(f"Generated JSON report: {output_path}")

    def generate_individual_reports(self, output_dir: str) -> List[str]:
        """Generate individual bug bounty reports for each finding."""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        report_paths = []

        # Only create reports for HIGH and CRITICAL findings
        critical_findings = [
            f for f in self.report.findings
            if f.severity in [Severity.CRITICAL, Severity.HIGH]
        ]

        for i, finding in enumerate(critical_findings, 1):
            filename = f"bug_report_{i}_{finding.id}.md"
            filepath = output_path / filename

            with open(filepath, 'w') as f:
                f.write(self._generate_individual_finding_report(finding))

            report_paths.append(str(filepath))
            logger.info(f"Generated individual report: {filepath}")

        return report_paths

    def _generate_markdown(self) -> str:
        """Generate complete markdown report."""
        md = []

        # Title and summary
        md.append(f"# Security Scan Report: {self.report.target.name}\n")
        md.append(f"**Scan ID:** `{self.report.scan_id}`  ")
        md.append(f"**Target:** {self.report.target.base_url}  ")
        md.append(f"**Date:** {self.report.started_at.strftime('%Y-%m-%d %H:%M:%S')}  ")
        md.append(f"**Duration:** {self.report.duration_seconds:.1f}s  ")
        md.append(f"**Status:** {self.report.status}\n")

        # Executive summary
        md.append("## Executive Summary\n")
        md.append(f"**Total Findings:** {self.report.total_findings}  \n")
        md.append(f"- Critical: {self.report.critical_count}  \n")
        md.append(f"- High: {self.report.high_count}  \n")
        md.append(f"- Medium: {self.report.medium_count}  \n")
        md.append(f"- Low: {self.report.low_count}  \n")
        md.append(f"- Info: {self.report.info_count}\n")

        # Findings by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            severity_findings = [
                f for f in self.report.findings
                if f.severity == severity
            ]

            if severity_findings:
                md.append(f"\n## {severity.value} Severity Findings\n")

                for finding in severity_findings:
                    md.append(f"### {finding.title}\n")
                    md.append(f"**ID:** `{finding.id}`  ")
                    md.append(f"**Category:** {finding.category.value}  ")
                    md.append(f"**CVSS Score:** {finding.cvss_score}  ")
                    md.append(f"**Affected URL:** `{finding.affected_url}`  ")
                    if finding.affected_parameter:
                        md.append(f"**Affected Parameter:** `{finding.affected_parameter}`  ")
                    md.append("\n")

                    md.append("#### Description\n")
                    md.append(f"{finding.description}\n")

                    if finding.proof_of_concept:
                        md.append("#### Proof of Concept\n")
                        md.append(f"{finding.proof_of_concept.description}\n")
                        md.append("**Steps to Reproduce:**\n")
                        for step in finding.proof_of_concept.steps:
                            md.append(f"1. {step}\n")
                        md.append(f"\n**Payload:** `{finding.proof_of_concept.payload}`\n")

                    md.append("#### Remediation\n")
                    md.append(f"{finding.remediation.summary}\n")
                    md.append("**Steps:**\n")
                    for step in finding.remediation.detailed_steps:
                        md.append(f"1. {step}\n")

                    if finding.remediation.code_examples:
                        md.append("\n**Code Examples:**\n")
                        for lang, code in finding.remediation.code_examples.items():
                            md.append(f"\n```{lang}\n{code}\n```\n")

                    if finding.remediation.references:
                        md.append("\n**References:**\n")
                        for ref in finding.remediation.references:
                            md.append(f"- {ref}\n")

                    md.append("\n---\n")

        return "\n".join(md)

    def _generate_individual_finding_report(self, finding: Finding) -> str:
        """Generate a standalone report for a single finding."""
        md = []

        # Title
        emoji = "🔴" if finding.severity == Severity.CRITICAL else "🟠"
        md.append(f"# {emoji} {finding.title}\n")

        # Metadata
        md.append("## Vulnerability Details\n")
        md.append(f"**Severity:** {finding.severity.value}  ")
        md.append(f"**Category:** {finding.category.value}  ")
        md.append(f"**CVSS Score:** {finding.cvss_score}/10.0  ")
        if finding.cvss_vector:
            md.append(f"**CVSS Vector:** `{finding.cvss_vector}`  ")
        md.append(f"**Discovery Date:** {finding.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}  ")
        md.append(f"**Vulnerability ID:** `{finding.id}`\n")

        # CWE/CVE
        if finding.cwe_ids:
            md.append(f"\n**CWE IDs:** {', '.join(f'CWE-{cwe}' for cwe in finding.cwe_ids)}  ")
        if finding.cve_ids:
            md.append(f"**CVE IDs:** {', '.join(finding.cve_ids)}  ")

        # Affected component
        md.append("\n## Affected Component\n")
        md.append(f"**URL:** `{finding.affected_url}`  ")
        if finding.affected_parameter:
            md.append(f"**Parameter:** `{finding.affected_parameter}`  ")
        if finding.affected_component:
            md.append(f"**Component:** `{finding.affected_component}`  ")

        # Description
        md.append("\n## Description\n")
        md.append(f"{finding.description}\n")

        # Proof of Concept
        if finding.proof_of_concept:
            poc = finding.proof_of_concept
            md.append("\n## Proof of Concept\n")
            md.append(f"{poc.description}\n")

            md.append("\n### Steps to Reproduce\n")
            for i, step in enumerate(poc.steps, 1):
                md.append(f"{i}. {step}\n")

            md.append("\n### Request\n")
            md.append(f"```http\n")
            md.append(f"{poc.request.method} {poc.request.url}\n")
            for header, value in poc.request.headers.items():
                md.append(f"{header}: {value}\n")
            if poc.request.body:
                md.append(f"\n{poc.request.body}\n")
            md.append(f"```\n")

            md.append("\n### Response\n")
            md.append(f"```http\n")
            md.append(f"HTTP/1.1 {poc.response.status_code}\n")
            md.append(f"\n{poc.response.body}\n")
            md.append(f"```\n")

            md.append(f"\n**Impact Demonstration:** {poc.impact_demonstration}\n")

        # Remediation
        md.append("\n## Recommended Fix\n")
        md.append(f"### Summary\n")
        md.append(f"{finding.remediation.summary}\n")

        md.append("\n### Detailed Steps\n")
        for i, step in enumerate(finding.remediation.detailed_steps, 1):
            md.append(f"{i}. {step}\n")

        if finding.remediation.code_examples:
            md.append("\n### Code Examples\n")
            for lang, code in finding.remediation.code_examples.items():
                md.append(f"\n**{lang.title()}:**\n")
                md.append(f"```{lang}\n{code}\n```\n")

        # References
        if finding.remediation.references:
            md.append("\n## References\n")
            for ref in finding.remediation.references:
                md.append(f"- {ref}\n")

        return "\n".join(md)
