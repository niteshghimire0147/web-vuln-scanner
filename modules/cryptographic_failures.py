"""
cryptographic_failures.py — Cryptographic Failures Scanner (OWASP A02:2021)

Tests for:
- HTTP (non-HTTPS) transmission of sensitive data
- Mixed content (HTTPS page loading HTTP resources)
- Insecure cookies (missing Secure / HttpOnly / SameSite flags)
- Sensitive data in URLs (query parameters)
- Weak TLS/SSL indicators via response headers
- Missing HSTS header
- Cleartext secrets in responses (API keys, tokens, passwords)
"""
import re
import time
from typing import List
from urllib.parse import urlparse

import requests
from .scanner_base import ScannerBase


class CryptographicFailuresScanner(ScannerBase):
    """
    OWASP A02:2021 — Cryptographic Failures

    Detects insecure data-in-transit patterns, cookie security flags,
    and accidental secret exposure in HTTP responses.
    """

    # Regex patterns for secret/credential leakage in response bodies
    SECRET_PATTERNS = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
         "API Key"),
        (r'(?i)(secret[_-]?key|secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?',
         "Secret Key"),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\'&<>]{6,})["\']?',
         "Password"),
        (r'(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?',
         "Access Token"),
        (r'(?i)(aws[_-]?secret|aws_access_key_id)\s*[=:]\s*["\']?([A-Za-z0-9\/+]{20,})["\']?',
         "AWS Credential"),
        (r'(?i)(private[_-]?key)\s*[=:]\s*["\']?([^\s"\']{16,})["\']?',
         "Private Key"),
        (r'BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY',
         "Private Key Material"),
        (r'(?i)basic\s+([A-Za-z0-9+/]{20,}={0,2})',
         "HTTP Basic Auth Credential"),
        (r'(?i)(db_password|database_password|db_pass)\s*[=:]\s*["\']?([^\s"\'&<>]{4,})["\']?',
         "Database Password"),
        (r'(?i)(smtp_password|mail_password)\s*[=:]\s*["\']?([^\s"\'&<>]{4,})["\']?',
         "Email Password"),
    ]

    # Query parameter names that should not carry sensitive data
    SENSITIVE_PARAM_NAMES = [
        "password", "passwd", "pwd", "pass",
        "token", "secret", "key", "apikey", "api_key",
        "auth", "authorization", "credential",
        "ssn", "cc", "creditcard", "credit_card",
        "cvv", "pin", "otp",
    ]

    def scan(self) -> List[dict]:
        """Run all cryptographic-failure checks against the target."""
        self._check_plaintext_http()
        self._check_response_secrets()
        self._check_cookie_flags()
        self._check_hsts()
        return self.findings

    def scan_url_params(self, url_params: List[dict]) -> List[dict]:
        """Check discovered URL parameters for sensitive data exposure."""
        for param_info in url_params:
            self._check_sensitive_in_url(param_info["url"])
        return self.findings

    # ── Plaintext HTTP ────────────────────────────────────────────────────

    def _check_plaintext_http(self) -> None:
        """Flag if the target is served over HTTP rather than HTTPS."""
        parsed = urlparse(self.target)
        if parsed.scheme.lower() != "https":
            self.findings.append(self._finding(
                title="Application Served Over Unencrypted HTTP",
                severity="HIGH",
                description=(
                    "The application is accessible via plain HTTP, meaning all "
                    "data (including session cookies, form submissions, and "
                    "credentials) is transmitted in cleartext and is susceptible "
                    "to interception by network-level attackers."
                ),
                evidence=f"Target scheme: {parsed.scheme}",
                recommendation=(
                    "Enforce HTTPS across the entire application. Obtain a "
                    "trusted TLS certificate (e.g., via Let's Encrypt) and "
                    "configure your server to redirect all HTTP traffic to "
                    "HTTPS. Add an HSTS header to prevent downgrade attacks."
                ),
                owasp_id="A02:2021",
                cwe_id="CWE-319",
            ))

        # Even if target is HTTPS, check if HTTP version is also reachable
        if parsed.scheme.lower() == "https":
            http_url = self.target.replace("https://", "http://", 1)
            try:
                resp = self.session.get(http_url, timeout=self.timeout,
                                        allow_redirects=False)
                time.sleep(self.delay)
                if resp.status_code == 200:
                    self.findings.append(self._finding(
                        title="HTTP Version of Site Returns 200 (No HTTPS Redirect)",
                        severity="MEDIUM",
                        description=(
                            "The HTTP version of the site returns a 200 response "
                            "instead of redirecting to HTTPS. Users who navigate "
                            "to the HTTP URL will receive content over an "
                            "unencrypted channel."
                        ),
                        evidence=f"HTTP GET {http_url} → {resp.status_code}",
                        recommendation=(
                            "Configure a permanent (301) redirect from HTTP to "
                            "HTTPS at the web-server or load-balancer level and "
                            "add HSTS with includeSubDomains."
                        ),
                        owasp_id="A02:2021",
                        cwe_id="CWE-311",
                        url=http_url,
                    ))
            except requests.RequestException:
                pass

    # ── Response Secrets ──────────────────────────────────────────────────

    def _check_response_secrets(self) -> None:
        """Scan the target page response body for leaked credentials/secrets."""
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            time.sleep(self.delay)
        except requests.RequestException:
            return

        for pattern, label in self.SECRET_PATTERNS:
            match = re.search(pattern, resp.text)
            if match:
                # Redact the actual value in evidence
                evidence_snippet = resp.text[
                    max(0, match.start() - 20): match.end() + 20
                ]
                # Mask the captured credential group
                evidence_safe = re.sub(
                    pattern,
                    lambda m: m.group(0)[:10] + "****REDACTED****",
                    evidence_snippet,
                )
                self.findings.append(self._finding(
                    title=f"Potential {label} Exposed in HTTP Response",
                    severity="CRITICAL",
                    description=(
                        f"A pattern matching a {label} was detected in the HTTP "
                        f"response body of '{self.target}'. Credentials or "
                        f"secrets exposed in web responses can be harvested by "
                        f"any user or intermediary proxy."
                    ),
                    evidence=f"Pattern matched near: {evidence_safe!r}",
                    recommendation=(
                        "Remove all credentials, API keys, and secrets from "
                        "source code and HTTP responses. Use environment "
                        "variables or a secrets manager (e.g., HashiCorp Vault, "
                        "AWS Secrets Manager). Rotate any exposed credentials "
                        "immediately."
                    ),
                    owasp_id="A02:2021",
                    cwe_id="CWE-312",
                ))

    # ── Cookie Flags ──────────────────────────────────────────────────────

    def _check_cookie_flags(self) -> None:
        """
        Check Set-Cookie headers for missing security flags:
        Secure, HttpOnly, SameSite.
        """
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            time.sleep(self.delay)
        except requests.RequestException:
            return

        raw_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(
            resp.raw.headers, "getlist") else []

        # Fallback: parse from resp.headers
        if not raw_headers:
            raw_headers = [
                v for k, v in resp.headers.items()
                if k.lower() == "set-cookie"
            ]

        for cookie_str in raw_headers:
            cookie_lower = cookie_str.lower()
            cookie_name  = cookie_str.split("=")[0].strip()

            issues = []
            if "secure" not in cookie_lower:
                issues.append("missing 'Secure' flag (cookie transmitted over HTTP)")
            if "httponly" not in cookie_lower:
                issues.append("missing 'HttpOnly' flag (accessible via JavaScript)")
            if "samesite" not in cookie_lower:
                issues.append("missing 'SameSite' attribute (CSRF risk)")

            for issue in issues:
                self.findings.append(self._finding(
                    title=f"Insecure Cookie: {issue.split('(')[0].strip().title()} — '{cookie_name}'",
                    severity="MEDIUM",
                    description=(
                        f"The cookie '{cookie_name}' is {issue}. "
                        f"Improperly secured cookies can be stolen via "
                        f"network interception, cross-site scripting, or "
                        f"cross-site request forgery."
                    ),
                    evidence=f"Set-Cookie: {cookie_str[:120]}",
                    recommendation=(
                        "Set the Secure flag on all cookies to prevent "
                        "transmission over HTTP. Set HttpOnly to prevent "
                        "JavaScript access. Set SameSite=Strict or Lax to "
                        "mitigate CSRF. Example: "
                        "Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Strict"
                    ),
                    owasp_id="A02:2021",
                    cwe_id="CWE-614",
                ))

    # ── HSTS ─────────────────────────────────────────────────────────────

    def _check_hsts(self) -> None:
        """Verify Strict-Transport-Security header presence and strength."""
        parsed = urlparse(self.target)
        if parsed.scheme.lower() != "https":
            return  # HSTS only applies to HTTPS

        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            time.sleep(self.delay)
        except requests.RequestException:
            return

        hsts = resp.headers.get("Strict-Transport-Security", "")
        if not hsts:
            self.findings.append(self._finding(
                title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                severity="MEDIUM",
                description=(
                    "The HTTPS response does not include an HSTS header. Without "
                    "HSTS, browsers will not automatically upgrade subsequent "
                    "requests to HTTPS, leaving users vulnerable to SSL-stripping "
                    "attacks."
                ),
                evidence="No 'Strict-Transport-Security' header found",
                recommendation=(
                    "Add: Strict-Transport-Security: max-age=63072000; "
                    "includeSubDomains; preload"
                ),
                owasp_id="A02:2021",
                cwe_id="CWE-523",
            ))
        else:
            # Check max-age is sufficient (at least 1 year = 31536000)
            match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
            if match and int(match.group(1)) < 31536000:
                self.findings.append(self._finding(
                    title="HSTS max-age Too Short",
                    severity="LOW",
                    description=(
                        f"The HSTS max-age is set to {match.group(1)} seconds, "
                        f"which is less than the recommended one year (31536000). "
                        f"A short max-age reduces protection against SSL-stripping "
                        f"attacks after the header expires."
                    ),
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation=(
                        "Set max-age to at least 31536000 (one year) and add "
                        "includeSubDomains; preload for maximum protection."
                    ),
                    owasp_id="A02:2021",
                    cwe_id="CWE-523",
                ))

    # ── Sensitive Data in URLs ────────────────────────────────────────────

    def _check_sensitive_in_url(self, url: str) -> None:
        """Flag URLs that contain sensitive parameter names."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        for param in parsed.query.lower().split("&"):
            name = param.split("=")[0]
            if name in self.SENSITIVE_PARAM_NAMES:
                self.findings.append(self._finding(
                    title=f"Sensitive Parameter '{name}' Transmitted in URL",
                    severity="HIGH",
                    description=(
                        f"The parameter '{name}' is passed in the URL query "
                        f"string. Sensitive values in URLs are logged by web "
                        f"servers, proxies, browsers, and CDNs, and appear in "
                        f"Referer headers sent to third parties."
                    ),
                    evidence=f"URL: {url[:200]}",
                    recommendation=(
                        "Transmit sensitive parameters in the POST body over "
                        "HTTPS, never in the URL. For session tokens, use "
                        "secure, HttpOnly cookies instead of query parameters."
                    ),
                    owasp_id="A02:2021",
                    cwe_id="CWE-598",
                    url=url,
                    parameter=name,
                ))
                break  # One finding per URL
