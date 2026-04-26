"""
header_auditor.py — Security header checker (OWASP A05:2021 Security Misconfiguration).

Checks for missing security headers and headers that leak server information.
"""
import requests
from .scanner_base import ScannerBase


class HeaderAuditor(ScannerBase):
    """
    OWASP A05:2021 — Security Misconfiguration

    Checks for:
    - Missing protective headers (HSTS, CSP, X-Content-Type-Options, etc.)
    - Headers that expose server/technology information
    """

    # Headers that SHOULD be present
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "owasp": "A05:2021",
            "cwe": "CWE-319",
            "recommendation": (
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
            "severity": "HIGH",
        },
        "X-Content-Type-Options": {
            "owasp": "A05:2021",
            "cwe": "CWE-693",
            "recommendation": "Add: X-Content-Type-Options: nosniff",
            "severity": "MEDIUM",
        },
        "X-Frame-Options": {
            "owasp": "A05:2021",
            "cwe": "CWE-1021",
            "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
            "severity": "MEDIUM",
        },
        "Content-Security-Policy": {
            "owasp": "A05:2021",
            "cwe": "CWE-693",
            "recommendation": (
                "Implement a Content-Security-Policy. Start with: "
                "Content-Security-Policy: default-src 'self'"
            ),
            "severity": "MEDIUM",
        },
        "Referrer-Policy": {
            "owasp": "A05:2021",
            "cwe": "CWE-116",
            "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
            "severity": "LOW",
        },
        "Permissions-Policy": {
            "owasp": "A05:2021",
            "cwe": "CWE-693",
            "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            "severity": "LOW",
        },
    }

    # Headers that SHOULD NOT be present (leak info)
    DANGEROUS_HEADERS = {
        "Server": {
            "description": "Reveals web server software and version",
            "severity": "LOW",
        },
        "X-Powered-By": {
            "description": "Reveals server-side framework or language",
            "severity": "LOW",
        },
        "X-AspNet-Version": {
            "description": "Reveals .NET framework version",
            "severity": "LOW",
        },
        "X-AspNetMvc-Version": {
            "description": "Reveals ASP.NET MVC version",
            "severity": "LOW",
        },
    }

    def scan(self):
        """Check security headers on the target URL."""
        self._log(f"Checking security headers on {self.target}")

        try:
            resp = self.session.get(self.target, timeout=self.timeout)
        except requests.RequestException as e:
            return self.findings

        headers = {k.title(): v for k, v in resp.headers.items()}

        # Check for missing protective headers
        for header_name, meta in self.REQUIRED_HEADERS.items():
            if header_name not in headers:
                self._log(f"Missing: {header_name}")
                self.findings.append(self._finding(
                    title=f"Missing Security Header: {header_name}",
                    severity=meta["severity"],
                    description=(
                        f"The response does not include the '{header_name}' header. "
                        f"This header provides important browser-level protections."
                    ),
                    evidence=f"GET {self.target} → Response missing: {header_name}",
                    recommendation=meta["recommendation"],
                    owasp_id=meta["owasp"],
                    url=self.target,
                    cwe_id=meta["cwe"],
                ))

        # Check for headers that leak information
        for header_name, meta in self.DANGEROUS_HEADERS.items():
            if header_name in headers:
                value = headers[header_name]
                self._log(f"Leaking: {header_name}: {value}")
                self.findings.append(self._finding(
                    title=f"Information Disclosure via '{header_name}' Header",
                    severity=meta["severity"],
                    description=(
                        f"The response includes '{header_name}: {value}'. "
                        f"{meta['description']}. This helps attackers fingerprint the "
                        f"technology stack and target known vulnerabilities."
                    ),
                    evidence=f"{header_name}: {value}",
                    recommendation=f"Remove or anonymize the '{header_name}' header in server configuration.",
                    owasp_id="A05:2021",
                    url=self.target,
                    cwe_id="CWE-200",
                ))

        # Check for weak CSP if present
        if "Content-Security-Policy" in headers:
            csp = headers["Content-Security-Policy"]
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                self.findings.append(self._finding(
                    title="Weak Content-Security-Policy: unsafe directives present",
                    severity="MEDIUM",
                    description=(
                        "The Content-Security-Policy contains 'unsafe-inline' or 'unsafe-eval', "
                        "which significantly reduces CSP effectiveness against XSS attacks."
                    ),
                    evidence=f"Content-Security-Policy: {csp}",
                    recommendation="Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes instead.",
                    owasp_id="A05:2021",
                    url=self.target,
                    cwe_id="CWE-693",
                ))

        return self.findings
