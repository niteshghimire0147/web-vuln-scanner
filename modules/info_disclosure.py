"""
info_disclosure.py — Information disclosure scanner (OWASP A05:2021).

Checks for exposed sensitive files, debug endpoints, and verbose error messages.
"""
import hashlib
import re
import requests
from .scanner_base import ScannerBase


# Sensitive paths to probe
SENSITIVE_PATHS = [
    # Environment and config
    ("/.env", "Environment file with credentials/secrets", "CRITICAL"),
    ("/.env.local", "Local environment file", "CRITICAL"),
    ("/.env.backup", "Environment backup file", "CRITICAL"),
    ("/config.php", "PHP configuration file", "HIGH"),
    ("/config.yaml", "Application config file", "HIGH"),
    ("/config.yml", "Application config file", "HIGH"),
    ("/settings.py", "Django settings file", "HIGH"),
    ("/wp-config.php", "WordPress configuration", "CRITICAL"),
    ("/web.config", "IIS configuration", "HIGH"),
    # Git repository
    ("/.git/config", "Exposed Git configuration", "HIGH"),
    ("/.git/HEAD", "Exposed Git HEAD file", "HIGH"),
    ("/.gitignore", "Git ignore file (reveals project structure)", "LOW"),
    # Backup files
    ("/backup.zip", "Application backup archive", "CRITICAL"),
    ("/backup.tar.gz", "Application backup archive", "CRITICAL"),
    ("/db.sql", "Database SQL dump", "CRITICAL"),
    ("/database.sql", "Database SQL dump", "CRITICAL"),
    # Admin and debug endpoints
    ("/admin", "Admin panel", "INFORMATIONAL"),
    ("/phpinfo.php", "PHP info page exposing configuration", "HIGH"),
    ("/server-status", "Apache server status page", "MEDIUM"),
    ("/server-info", "Apache server info page", "MEDIUM"),
    ("/.DS_Store", "macOS directory metadata", "LOW"),
    ("/robots.txt", "Robots.txt (may reveal hidden paths)", "INFORMATIONAL"),
    ("/sitemap.xml", "Sitemap (reveals content structure)", "INFORMATIONAL"),
    # Debug/error endpoints
    ("/debug", "Debug endpoint", "MEDIUM"),
    ("/console", "Debug console", "HIGH"),
    ("/actuator", "Spring Boot actuator endpoints", "HIGH"),
    ("/actuator/env", "Spring Boot environment exposure", "CRITICAL"),
    ("/actuator/health", "Spring Boot health endpoint", "INFORMATIONAL"),
]


_CONTENT_VALIDATORS = {
    "/.env":              re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.MULTILINE),
    "/.env.local":        re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.MULTILINE),
    "/.env.backup":       re.compile(r"^[A-Z_][A-Z0-9_]*\s*=", re.MULTILINE),
    "/.git/config":       re.compile(r"\[core\]", re.IGNORECASE),
    "/.git/HEAD":         re.compile(r"^ref:\s+refs/heads/", re.MULTILINE),
    "/db.sql":            re.compile(r"INSERT\s+INTO|CREATE\s+TABLE", re.IGNORECASE),
    "/database.sql":      re.compile(r"INSERT\s+INTO|CREATE\s+TABLE", re.IGNORECASE),
    "/phpinfo.php":       re.compile(r"PHP Version", re.IGNORECASE),
    "/wp-config.php":     re.compile(r"DB_NAME|DB_PASSWORD", re.IGNORECASE),
    "/settings.py":       re.compile(r"SECRET_KEY|DATABASES", re.IGNORECASE),
    "/actuator/env":      re.compile(r'"activeProfiles"|"propertySources"', re.IGNORECASE),
}

_BINARY_CONTENT_TYPES = {
    "/backup.zip":    ("application/zip", "application/octet-stream", "application/x-zip"),
    "/backup.tar.gz": ("application/gzip", "application/x-gzip", "application/octet-stream"),
}


def _body_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class InfoDisclosureScanner(ScannerBase):
    """
    OWASP A05:2021 — Security Misconfiguration

    Probes for exposed sensitive files and debug endpoints.
    Uses baseline fingerprinting to eliminate false positives on SPAs
    that return HTTP 200 for every URL.
    """

    def scan(self):
        """Probe for sensitive files and debug endpoints."""
        self._log("Probing for information disclosure paths")

        baseline_hash, baseline_size = self._baseline_fingerprint()
        self._log(f"Baseline fingerprint: {baseline_hash[:12]}… ({baseline_size} bytes)")

        for path, description, severity in SENSITIVE_PATHS:
            url = self.target + path
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)

                if resp.status_code == 200:
                    body = resp.text

                    # Skip if response is identical to the SPA catch-all 404 page
                    if self._matches_baseline(body, baseline_hash, baseline_size):
                        self._log(f"Skipped (baseline match): {path}")
                        continue

                    # Validate content actually matches what the file type should contain
                    if not self._validate_content(path, resp):
                        self._log(f"Skipped (content mismatch): {path}")
                        continue

                    self._log(f"Confirmed: {path} ({resp.status_code}, {len(body)} bytes)")
                    self.findings.append(self._finding(
                        title=f"Sensitive File Exposed: {path}",
                        severity=severity,
                        description=(
                            f"{description} is publicly accessible at {url}. "
                            f"This may expose credentials, configuration, or application internals."
                        ),
                        evidence=f"GET {url} → HTTP {resp.status_code} ({len(body)} bytes) — content validated",
                        recommendation=(
                            f"Remove or restrict access to {path}. "
                            "Ensure sensitive files are not deployed to production. "
                            "Configure web server to deny access to these paths."
                        ),
                        owasp_id="A05:2021",
                        url=url,
                        cwe_id="CWE-538",
                    ))

                elif resp.status_code == 403:
                    # Exists but forbidden — lower severity, only flag HIGH+ paths
                    if severity in ("CRITICAL", "HIGH"):
                        self.findings.append(self._finding(
                            title=f"Sensitive Path Exists (Access Restricted): {path}",
                            severity="LOW",
                            description=(
                                f"{description} exists at {url} but access is restricted (HTTP 403). "
                                f"Confirm it contains no sensitive data and access controls are correct."
                            ),
                            evidence=f"GET {url} → HTTP 403 Forbidden",
                            recommendation=f"Verify {path} is not accessible and contains no sensitive data.",
                            owasp_id="A05:2021",
                            url=url,
                            cwe_id="CWE-538",
                        ))

            except requests.RequestException:
                continue

        self._check_verbose_errors()
        return self.findings

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _baseline_fingerprint(self) -> tuple[str, int]:
        """
        Fetch a URL guaranteed not to exist and record its body hash + size.
        This fingerprints the SPA catch-all / custom 404 page so we can
        skip any sensitive-path response that looks identical.
        """
        probe_url = f"{self.target}/this-path-does-not-exist-8f3a2b1c"
        try:
            resp = self.session.get(probe_url, timeout=self.timeout, allow_redirects=True)
            return _body_hash(resp.text), len(resp.text)
        except requests.RequestException:
            return "", 0

    def _matches_baseline(self, body: str, baseline_hash: str, baseline_size: int) -> bool:
        """Return True if this response is effectively the same as the baseline 404 page."""
        if not baseline_hash:
            return False
        if _body_hash(body) == baseline_hash:
            return True
        # Also catch near-identical responses (within 2% size) that differ only by timestamp/nonce
        if baseline_size > 0 and abs(len(body) - baseline_size) / baseline_size < 0.02:
            return True
        return False

    def _validate_content(self, path: str, resp: requests.Response) -> bool:
        """
        Confirm the response actually contains content consistent with
        the claimed file type. Eliminates cases where a 200 body is
        generic HTML (SPA fallback, login redirect, etc.).
        """
        body = resp.text
        content_type = resp.headers.get("Content-Type", "").lower()

        # Binary archive: check Content-Type, not body text
        if path in _BINARY_CONTENT_TYPES:
            allowed = _BINARY_CONTENT_TYPES[path]
            return any(ct in content_type for ct in allowed)

        # Files with known content patterns
        if path in _CONTENT_VALIDATORS:
            return bool(_CONTENT_VALIDATORS[path].search(body))

        # Generic fallback: reject if the body looks like an HTML page
        # (catches SPA redirects to index.html for paths without a validator)
        body_lower = body.lstrip()
        if body_lower.startswith("<!DOCTYPE") or body_lower.startswith("<html"):
            # Allow phpinfo (is HTML but validated above), reject everything else
            return False

        return True

    def _check_verbose_errors(self):
        """Send malformed requests to check if stack traces are returned."""
        test_urls = [
            self.target + "/' ",
            self.target + "/%00",
            self.target + "/nonexistent-page-xyz123",
        ]
        error_signatures = [
            ("Traceback (most recent call last)", "Python stack trace", "MEDIUM"),
            ("at sun.reflect.", "Java stack trace", "MEDIUM"),
            ("System.Exception", ".NET exception", "MEDIUM"),
            ("Fatal error:", "PHP fatal error", "MEDIUM"),
            ("Warning: ", "PHP warning", "LOW"),
            ("mysql_", "MySQL function name in error", "HIGH"),
            ("ORA-", "Oracle error code", "HIGH"),
        ]

        for url in test_urls:
            try:
                resp = self.session.get(url, timeout=self.timeout)
                for sig, desc, severity in error_signatures:
                    if sig in resp.text:
                        self.findings.append(self._finding(
                            title=f"Verbose Error Message: {desc}",
                            severity=severity,
                            description=(
                                f"The application returns verbose error messages containing {desc}. "
                                f"This reveals internal implementation details to attackers."
                            ),
                            evidence=f"GET {url} → Response contains: '{sig}'",
                            recommendation=(
                                "Disable debug mode in production. Return generic error messages to users. "
                                "Log detailed errors server-side only."
                            ),
                            owasp_id="A05:2021",
                            url=url,
                            cwe_id="CWE-209",
                        ))
                        break
            except requests.RequestException:
                continue
