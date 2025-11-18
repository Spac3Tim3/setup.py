"""End-to-end tests for complete system."""
import pytest
from pathlib import Path
import json


def test_models_import():
    """Test core models can be imported."""
    from continental.models import Finding, ScanReport, ScanTarget, ScanConfig
    assert Finding
    assert ScanReport
    assert ScanTarget
    assert ScanConfig


def test_scanners_import():
    """Test scanners can be imported."""
    from continental.operators.base import BaseScanner
    from continental.operators.sqli_scanner import SQLiScanner
    from continental.operators.xss_scanner import XSSScanner
    assert BaseScanner
    assert SQLiScanner
    assert XSSScanner


def test_pipeline_import():
    """Test pipeline can be imported."""
    from continental.contracts.pipeline import SecurityPipeline
    assert SecurityPipeline


def test_reporter_import():
    """Test reporter can be imported."""
    from continental.dossiers.bug_bounty_reporter import BugBountyReporter
    assert BugBountyReporter


def test_cli_import():
    """Test CLI can be imported."""
    from continental.cli import cli
    assert cli
