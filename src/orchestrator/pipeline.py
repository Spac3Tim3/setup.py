"""Security scanning pipeline orchestrator."""
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import time

from src.models import (
    ScanConfig, ScanReport, ScanTarget, Finding, Severity
)
from src.scanners.sqli_scanner import SQLiScanner
from src.scanners.xss_scanner import XSSScanner
from src.analyzers.ai_analyzer import AIAnalyzer

logger = logging.getLogger(__name__)


class SecurityPipeline:
    """Orchestrates security scanning across multiple scanners."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.report = ScanReport(
            target=config.target,
            config=config
        )

        # Initialize scanners
        self.scanners = self._initialize_scanners()

        # Initialize AI analyzer if enabled
        self.ai_analyzer = None
        if config.enable_ai_analysis:
            try:
                self.ai_analyzer = AIAnalyzer()
            except Exception as e:
                logger.warning(f"Failed to initialize AI analyzer: {e}")

        logger.info(f"Initialized pipeline with {len(self.scanners)} scanners")

    def _initialize_scanners(self) -> List:
        """Initialize requested scanners."""
        scanner_map = {
            "sqli": SQLiScanner,
            "xss": XSSScanner,
        }

        scanners = []
        for scanner_name in self.config.scanners:
            scanner_class = scanner_map.get(scanner_name)
            if scanner_class:
                scanner = scanner_class(self.config.target)
                scanners.append(scanner)
                logger.info(f"Initialized {scanner.name}")
            else:
                logger.warning(f"Unknown scanner: {scanner_name}")

        return scanners

    def execute(self) -> ScanReport:
        """
        Execute the full security scanning pipeline.

        Returns:
            Complete scan report with all findings
        """
        logger.info(f"Starting security scan of {self.config.target.name}")
        self.report.started_at = datetime.now()

        try:
            # Run all scanners
            all_findings = []
            for scanner in self.scanners:
                logger.info(f"Running {scanner.name}...")
                try:
                    findings = scanner.scan()
                    all_findings.extend(findings)
                    logger.info(f"{scanner.name} found {len(findings)} issues")
                except Exception as e:
                    logger.error(f"{scanner.name} failed: {e}")
                    continue

            # Deduplicate findings
            logger.info("Deduplicating findings...")
            self.report.findings = self._deduplicate_findings(all_findings)

            # Filter by severity threshold
            self.report.findings = self._filter_by_severity(
                self.report.findings,
                self.config.severity_threshold
            )

            # Enhance with AI analysis if enabled
            if self.ai_analyzer and self.config.enable_ai_analysis:
                logger.info("Enhancing findings with AI analysis...")
                self._enhance_with_ai()

            # Update statistics
            self.report.update_statistics()

            self.report.status = "completed"
            logger.info(f"Scan completed. Found {self.report.total_findings} issues")

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.report.status = "failed"
            self.report.error_message = str(e)

        finally:
            self.report.completed_at = datetime.now()
            if self.report.started_at:
                self.report.duration_seconds = (
                    self.report.completed_at - self.report.started_at
                ).total_seconds()

        return self.report

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings based on URL and vulnerability type."""
        seen = set()
        unique_findings = []

        for finding in findings:
            # Create fingerprint
            fingerprint = (
                finding.category,
                finding.affected_url,
                finding.affected_parameter
            )

            if fingerprint not in seen:
                seen.add(fingerprint)
                unique_findings.append(finding)

        logger.info(f"Deduplicated {len(findings)} -> {len(unique_findings)} findings")
        return unique_findings

    def _filter_by_severity(
        self,
        findings: List[Finding],
        threshold: Severity
    ) -> List[Finding]:
        """Filter findings by severity threshold."""
        severity_order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1
        }

        threshold_value = severity_order[threshold]
        filtered = [
            f for f in findings
            if severity_order[f.severity] >= threshold_value
        ]

        logger.info(f"Filtered findings: {len(findings)} -> {len(filtered)}")
        return filtered

    def _enhance_with_ai(self):
        """Enhance findings with AI-generated insights."""
        for finding in self.report.findings[:10]:  # Limit to avoid costs
            try:
                # Generate better remediation if needed
                if not finding.remediation.code_examples:
                    enhanced_remediation = self.ai_analyzer.generate_remediation_advice(
                        vulnerability_type=finding.category.value,
                        affected_component=finding.affected_parameter or "application",
                        context={
                            "url": finding.affected_url,
                            "parameter": finding.affected_parameter
                        }
                    )
                    finding.remediation = enhanced_remediation

            except Exception as e:
                logger.warning(f"Failed to enhance finding with AI: {e}")
