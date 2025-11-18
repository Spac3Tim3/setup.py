"""Cross-Site Scripting (XSS) vulnerability scanner."""
import re
from typing import List
from urllib.parse import urlencode
import logging

from src.scanners.base import BaseScanner
from src.models import (
    Finding, Severity, VulnerabilityCategory, Remediation,
    ProofOfConcept, HTTPRequest, HTTPResponse
)

logger = logging.getLogger(__name__)


class XSSScanner(BaseScanner):
    """Scanner for Cross-Site Scripting vulnerabilities."""

    # XSS payloads with unique identifiers
    PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<select onfocus=alert('XSS') autofocus>",
        "<textarea onfocus=alert('XSS') autofocus>",
        "<keygen onfocus=alert('XSS') autofocus>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "'-alert('XSS')-'",
        "\"-alert('XSS')-\"",
        "</script><script>alert('XSS')</script>",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<IMG SRC=javascript:alert('XSS')>",
        "<IMG SRC=\"javascript:alert('XSS');\">",
    ]

    @property
    def name(self) -> str:
        return "XSSScanner"

    @property
    def description(self) -> str:
        return "Detects Cross-Site Scripting (XSS) vulnerabilities"

    def scan(self) -> List[Finding]:
        """Execute XSS scan."""
        logger.info(f"Starting XSS scan on {self.target.base_url}")

        # Test reflected XSS in GET parameters
        self._test_reflected_xss_get()

        # Test reflected XSS in POST parameters
        self._test_reflected_xss_post()

        logger.info(f"XSS scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def _test_reflected_xss_get(self):
        """Test for reflected XSS in GET parameters."""
        test_endpoints = [
            "/search",
            "/query",
            "/q",
            "/s",
            "/find",
        ]

        for endpoint in test_endpoints:
            url = f"{self.target.base_url}{endpoint}"
            params = {"q": "test", "search": "test", "query": "test"}

            for param_name in params.keys():
                for payload in self.PAYLOADS:
                    test_params = {param_name: payload}
                    test_url = f"{url}?{urlencode(test_params)}"

                    try:
                        response = self.make_request("GET", test_url)

                        if self._is_vulnerable(payload, response.text):
                            self._create_xss_finding(
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                method="GET",
                                response=response,
                                xss_type="reflected"
                            )
                            break

                    except Exception as e:
                        logger.debug(f"Error testing {test_url}: {e}")

    def _test_reflected_xss_post(self):
        """Test for reflected XSS in POST parameters."""
        test_endpoints = [
            "/search",
            "/comment",
            "/post",
            "/feedback",
        ]

        for endpoint in test_endpoints:
            url = f"{self.target.base_url}{endpoint}"

            for payload in self.PAYLOADS:
                data = {
                    "comment": payload,
                    "message": payload,
                    "text": payload,
                }

                try:
                    response = self.make_request("POST", url, data=data)

                    if self._is_vulnerable(payload, response.text):
                        self._create_xss_finding(
                            url=url,
                            parameter="multiple",
                            payload=payload,
                            method="POST",
                            response=response,
                            xss_type="reflected",
                            post_data=data
                        )
                        break

                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")

    def _is_vulnerable(self, payload: str, response_text: str) -> bool:
        """Check if payload is reflected unescaped in response."""
        # Check if payload appears unescaped in response
        if payload in response_text:
            return True

        # Check for common XSS patterns
        xss_patterns = [
            r"<script[^>]*>.*alert.*</script>",
            r"onerror\s*=\s*['\"]?alert",
            r"onload\s*=\s*['\"]?alert",
            r"javascript:\s*alert",
        ]

        for pattern in xss_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _create_xss_finding(
        self,
        url: str,
        parameter: str,
        payload: str,
        method: str,
        response,
        xss_type: str,
        post_data: dict = None
    ):
        """Create an XSS finding."""
        finding = Finding(
            title=f"Cross-Site Scripting ({xss_type.title()}) in {parameter}",
            description=(
                f"The application is vulnerable to {xss_type} Cross-Site Scripting (XSS) "
                f"through the '{parameter}' parameter. An attacker can inject malicious "
                f"JavaScript code that will be executed in the victim's browser, potentially "
                f"leading to session hijacking, credential theft, or malware distribution."
            ),
            severity=Severity.HIGH,
            category=VulnerabilityCategory.XSS,
            cvss_score=7.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            affected_url=url,
            affected_parameter=parameter,
            proof_of_concept=ProofOfConcept(
                description="Injected JavaScript payload is reflected in response",
                steps=[
                    f"Send {method} request to {url}",
                    f"Set {parameter} parameter to: {payload}",
                    "Observe payload reflected without sanitization",
                    "JavaScript would execute in victim's browser"
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
                    body=response.text[:500],
                    response_time_ms=response.elapsed.total_seconds() * 1000
                ),
                payload=payload,
                impact_demonstration="JavaScript payload reflected in HTML response"
            ),
            remediation=Remediation(
                summary="Sanitize and encode all user input before rendering in HTML",
                detailed_steps=[
                    "Implement context-aware output encoding (HTML, JavaScript, CSS, URL)",
                    "Use Content Security Policy (CSP) headers to restrict script execution",
                    "Validate and sanitize input on the server side",
                    "Use modern frameworks with automatic XSS protection (React, Angular, Vue)",
                    "Set HTTPOnly and Secure flags on sensitive cookies",
                    "Implement proper input validation with allowlists"
                ],
                code_examples={
                    "python": """
# Vulnerable code:
return f"<div>Search results for: {user_input}</div>"

# Fixed code (using proper escaping):
from html import escape
return f"<div>Search results for: {escape(user_input)}</div>"

# Or use templating engine with auto-escaping:
# Jinja2, Django templates automatically escape by default
                    """,
                    "javascript": """
// Vulnerable code:
element.innerHTML = userInput;

// Fixed code:
element.textContent = userInput;  // Safe for text
// Or use DOMPurify for HTML:
element.innerHTML = DOMPurify.sanitize(userInput);
                    """
                },
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    "https://cwe.mitre.org/data/definitions/79.html"
                ]
            ),
            cwe_ids=[79],  # CWE-79: Cross-site Scripting
            verified=True
        )

        self.add_finding(finding)
