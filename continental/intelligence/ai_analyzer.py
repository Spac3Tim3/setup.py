"""AI-powered vulnerability analysis using Claude."""
import os
import json
import logging
from typing import List, Dict, Any, Optional
from anthropic import Anthropic

from continental.models import Finding, Severity, VulnerabilityCategory, Remediation

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """Uses Claude to analyze applications and generate test cases."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

        self.client = Anthropic(api_key=self.api_key)
        self.model = "claude-sonnet-4-20250514"

    def generate_test_payloads(
        self,
        endpoint: str,
        method: str,
        parameters: List[str],
        vulnerability_type: str
    ) -> List[str]:
        """
        Generate intelligent test payloads for a specific vulnerability type.

        Args:
            endpoint: The API endpoint to test
            method: HTTP method (GET, POST, etc.)
            parameters: List of parameter names
            vulnerability_type: Type of vulnerability to test for

        Returns:
            List of test payloads
        """
        prompt = f"""You are a security testing expert. Generate test payloads to detect {vulnerability_type} vulnerabilities.

Endpoint: {endpoint}
HTTP Method: {method}
Parameters: {', '.join(parameters)}

Generate 10-15 diverse test payloads that could expose {vulnerability_type} vulnerabilities.
Include edge cases, boundary conditions, and known attack patterns.

Return ONLY a JSON array of strings, no other text:
["payload1", "payload2", ...]
"""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()

            # Parse JSON response
            if response_text.startswith("```"):
                # Remove markdown code blocks
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]

            payloads = json.loads(response_text)
            logger.info(f"Generated {len(payloads)} test payloads for {vulnerability_type}")
            return payloads

        except Exception as e:
            logger.error(f"Failed to generate payloads: {e}")
            return []

    def analyze_response_for_vulnerability(
        self,
        request_info: Dict[str, Any],
        response_info: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze HTTP response to determine if it indicates a vulnerability.

        Args:
            request_info: Information about the request (method, URL, payload, etc.)
            response_info: Information about the response (status, headers, body)

        Returns:
            Dictionary with vulnerability details or None if not vulnerable
        """
        prompt = f"""Analyze this HTTP request/response pair for security vulnerabilities.

REQUEST:
{json.dumps(request_info, indent=2)}

RESPONSE:
{json.dumps(response_info, indent=2)}

Determine if the response indicates a security vulnerability. Consider:
- Error messages revealing system information
- Unexpected behavior suggesting code execution
- Data exposure
- Authentication/authorization bypasses
- Injection attack success indicators

Respond with JSON only:
{{
    "vulnerable": true/false,
    "confidence": 0.0-1.0,
    "vulnerability_type": "SQL Injection|XSS|etc.",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "reasoning": "explanation",
    "indicators": ["list", "of", "specific", "indicators"]
}}
"""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()

            # Clean up markdown if present
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]

            analysis = json.loads(response_text)

            if analysis.get("vulnerable") and analysis.get("confidence", 0) > 0.7:
                return analysis

            return None

        except Exception as e:
            logger.error(f"Failed to analyze response: {e}")
            return None

    def generate_remediation_advice(
        self,
        vulnerability_type: str,
        affected_component: str,
        context: Dict[str, Any]
    ) -> Remediation:
        """
        Generate detailed remediation advice for a vulnerability.

        Args:
            vulnerability_type: Type of vulnerability
            affected_component: Component or parameter affected
            context: Additional context about the vulnerability

        Returns:
            Remediation object with detailed fix guidance
        """
        prompt = f"""Generate detailed remediation advice for this security vulnerability.

Vulnerability Type: {vulnerability_type}
Affected Component: {affected_component}
Context: {json.dumps(context, indent=2)}

Provide:
1. A concise summary (1-2 sentences)
2. Detailed step-by-step remediation instructions (5-7 steps)
3. Code examples in Python and one other relevant language
4. References to authoritative sources (OWASP, CWE, etc.)

Respond with JSON only:
{{
    "summary": "brief summary",
    "detailed_steps": ["step 1", "step 2", ...],
    "code_examples": {{"python": "...", "javascript": "..."}},
    "references": ["url1", "url2", ...]
}}
"""

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()

            # Clean up markdown
            if response_text.startswith("```"):
                response_text = response_text.split("```")[1]
                if response_text.startswith("json"):
                    response_text = response_text[4:]

            data = json.loads(response_text)

            return Remediation(
                summary=data["summary"],
                detailed_steps=data["detailed_steps"],
                code_examples=data.get("code_examples", {}),
                references=data.get("references", [])
            )

        except Exception as e:
            logger.error(f"Failed to generate remediation: {e}")
            # Return basic remediation as fallback
            return Remediation(
                summary=f"Fix {vulnerability_type} vulnerability in {affected_component}",
                detailed_steps=[
                    "Review the affected code",
                    "Implement proper input validation",
                    "Apply security best practices",
                    "Test the fix thoroughly"
                ],
                references=["https://owasp.org"]
            )
