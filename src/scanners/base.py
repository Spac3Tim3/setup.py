"""Base scanner interface that all scanners must implement."""
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
import logging

from src.models import Finding, ScanTarget, Severity

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for HTTP requests."""

    def __init__(self, requests_per_second: int = 10):
        self.requests_per_second = requests_per_second
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0

    def wait_if_needed(self):
        """Wait if necessary to respect rate limit."""
        now = time.time()
        time_since_last = now - self.last_request_time

        if time_since_last < self.min_interval:
            sleep_time = self.min_interval - time_since_last
            time.sleep(sleep_time)

        self.last_request_time = time.time()


class BaseScanner(ABC):
    """Abstract base class for all security scanners."""

    def __init__(self, target: ScanTarget, config: Optional[Dict[str, Any]] = None):
        self.target = target
        self.config = config or {}
        self.findings: List[Finding] = []

        # Setup rate limiter
        self.rate_limiter = RateLimiter(target.rate_limit)

        # Setup HTTP session with retries
        self.session = self._create_session()

        logger.info(f"Initialized {self.name} for target: {target.name}")

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic."""
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def make_request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> requests.Response:
        """Make HTTP request with rate limiting."""
        self.rate_limiter.wait_if_needed()

        # Set timeout if not provided
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.target.timeout

        try:
            response = self.session.request(method, url, **kwargs)
            logger.debug(f"{method} {url} -> {response.status_code}")
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {method} {url} - {e}")
            raise

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name for identification."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this scanner does."""
        pass

    @abstractmethod
    def scan(self) -> List[Finding]:
        """
        Execute the scan and return findings.

        Returns:
            List of Finding objects discovered during scan.
        """
        pass

    def add_finding(self, finding: Finding):
        """Add a finding to the results."""
        finding.discovered_by = self.name
        self.findings.append(finding)
        logger.info(f"Found {finding.severity.value}: {finding.title}")

    def get_findings(self) -> List[Finding]:
        """Get all findings from this scanner."""
        return self.findings

    def verify_finding(self, finding: Finding) -> bool:
        """
        Verify a finding by attempting to reproduce it.

        Args:
            finding: The finding to verify.

        Returns:
            True if finding is verified, False otherwise.
        """
        # Default implementation - subclasses should override
        return False
