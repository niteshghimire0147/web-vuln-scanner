"""
broken_access_control.py — Broken Access Control Scanner (OWASP A01:2021)

Tests for:
- Insecure Direct Object Reference (IDOR) via ID parameter fuzzing
- Path traversal / directory traversal (CWE-22)
- Forced browsing to admin/restricted areas
- Missing authorization headers on sensitive endpoints
- HTTP method override abuse (VERB tampering)
"""
import hashlib
import re
import time
from typing import List
from urllib.parse import urlparse, urlencode, parse_qs, urljoin

import requests
from .scanner_base import ScannerBase


def _body_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class BrokenAccessControlScanner(ScannerBase):
    """
    OWASP A01:2021 — Broken Access Control

    Covers IDOR, path traversal, forced browsing, and HTTP method tampering.
    All checks require only standard GET/POST requests — no exploit payloads
    that would modify server state.
    """

    # ── Sensitive Admin / Restricted Paths ────────────────────────────────
    ADMIN_PATHS = [
        "/admin", "/admin/", "/admin/login", "/admin/dashboard",
        "/administrator", "/administrator/", "/wp-admin", "/wp-admin/",
        "/cp", "/controlpanel", "/panel", "/dashboard",
        "/manager", "/management", "/backend",
        "/api/admin", "/api/v1/admin", "/api/v2/admin",
        "/api/users", "/api/v1/users", "/api/v2/users",
        "/api/config", "/api/settings",
        "/user/list", "/users/all",
        "/phpmyadmin", "/phpmyadmin/", "/pma",
        "/server-status", "/server-info",           # Apache status pages
        "/.git/HEAD", "/.git/config",               # Exposed VCS
        "/.env", "/.env.local", "/.env.production",
        "/config.php", "/config.yml", "/config.yaml",
        "/web.config", "/application.properties",
        "/actuator", "/actuator/env", "/actuator/health",  # Spring Boot
        "/health", "/metrics", "/info", "/status",          # Generic
        "/swagger-ui.html", "/swagger-ui/", "/api-docs",
        "/v2/api-docs", "/v3/api-docs",
        "/graphql", "/graphiql", "/playground",
        "/console", "/h2-console",                  # DB consoles
        "/debug", "/trace", "/heap-dump",
        "/.htaccess", "/.htpasswd",
    ]

    # ── Path Traversal Payloads (read-only, purely detection) ─────────────
    PATH_TRAVERSAL_PAYLOADS = [
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "..%252Fetc%252Fpasswd",
        "%2e%2e%2fetc%2fpasswd",
        "....//etc/passwd",
        "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
        "/etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/windows/system32/drivers/etc/hosts",
    ]

    # Signatures indicating successful traversal
    TRAVERSAL_SIGNATURES = [
        "root:x:",          # /etc/passwd
        "daemon:x:",
        "[extensions]",     # win hosts
        "localhost",
        "DOCUMENT_ROOT",    # /proc/self/environ
        "HTTP_HOST",
    ]

    # Parameters typically used to reference files or IDs
    FILE_PARAMS = ["file", "path", "page", "include", "doc", "document",
                   "load", "template", "view", "name", "filename", "dir"]
    ID_PARAMS   = ["id", "user_id", "userId", "uid", "account", "record",
                   "object", "item", "pid", "cid", "eid", "order_id"]

    # ── HTTP Method Override Headers ───────────────────────────────────────
    METHOD_OVERRIDE_HEADERS = [
        {"X-HTTP-Method-Override": "DELETE"},
        {"X-HTTP-Method-Override": "PUT"},
        {"X-Method-Override":      "DELETE"},
        {"_method":                "DELETE"},
    ]

    def scan(self) -> List[dict]:
        """
        Top-level scan entry point. Runs all BAC checks.
        Returns list of standardised finding dicts.
        """
        self._check_forced_browsing()
        self._check_path_traversal_base()
        return self.findings

    def scan_url_params(self, url_params: List[dict]) -> List[dict]:
        """Called by main.py after crawling — test discovered URL parameters."""
        for param_info in url_params:
            parsed = urlparse(param_info.get("url", ""))
            qs = parse_qs(parsed.query)

            # IDOR: numeric ID parameters
            for param, values in qs.items():
                if param.lower() in self.ID_PARAMS and values:
                    self._check_idor(param_info["url"], param, values[0])

            # Path traversal on file-like parameters
            for param, values in qs.items():
                if param.lower() in self.FILE_PARAMS and values:
                    self._check_path_traversal_param(param_info["url"], param)

        return self.findings

    # ── Baseline fingerprinting (SPA / catch-all 404 detection) ──────────

    def _baseline_fingerprint(self) -> tuple:
        """
        Fetch a URL that is guaranteed not to exist and record its body hash
        and size. SPAs return HTTP 200 with the same index.html for every
        unknown route — this fingerprint lets us detect and skip those.
        """
        probe = f"{self.target.rstrip('/')}/this-path-does-not-exist-ac2f9b7e"
        try:
            resp = self.session.get(probe, timeout=self.timeout, allow_redirects=True)
            return _body_hash(resp.text), len(resp.text)
        except requests.RequestException:
            return "", 0

    def _matches_baseline(self, body: str, baseline_hash: str, baseline_size: int) -> bool:
        """Return True when the response is effectively the same as the baseline 404."""
        if not baseline_hash:
            return False
        if _body_hash(body) == baseline_hash:
            return True
        # Catch SPA pages that differ only by a timestamp/nonce (within 2% of size)
        if baseline_size > 0 and abs(len(body) - baseline_size) / baseline_size < 0.02:
            return True
        return False

    # ── Forced Browsing ───────────────────────────────────────────────────

    def _check_forced_browsing(self) -> None:
        """Probe well-known sensitive paths for unexpected 200 responses."""
        self._log("Forced browsing: probing sensitive admin/config paths")

        # Fingerprint the site's 404/catch-all page first so we can skip
        # SPAs that return HTTP 200 for every unknown route.
        baseline_hash, baseline_size = self._baseline_fingerprint()

        for path in self.ADMIN_PATHS:
            url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            if resp.status_code != 200:
                continue

            # Ignore trivially small bodies (likely empty 200s)
            if len(resp.content) < 100:
                continue

            # Skip responses that are identical (or near-identical) to the
            # baseline 404 — this eliminates SPA catch-all false positives.
            if self._matches_baseline(resp.text, baseline_hash, baseline_size):
                self._log(f"Skipped (matches SPA baseline): {path}")
                continue

            body_lower = resp.text.lower()
            if any(k in body_lower for k in ("login", "sign in",
                                              "unauthorized", "403")):
                severity = "MEDIUM"
                title    = f"Restricted Path Accessible (Login Required): {path}"
            else:
                severity = "HIGH"
                title    = f"Sensitive Path Exposed (No Auth): {path}"

            self.findings.append(self._finding(
                title=title,
                severity=severity,
                description=(
                    f"The path '{path}' returned HTTP 200 without a redirect "
                    f"to authentication. Sensitive administrative interfaces, "
                    f"configuration files, or debug endpoints should not be "
                    f"reachable by unauthenticated users."
                ),
                evidence=f"HTTP {resp.status_code} — {len(resp.content)} bytes",
                recommendation=(
                    "Restrict access using server-level authentication "
                    "(e.g., HTTP Basic Auth, IP allowlisting, or a dedicated "
                    "auth middleware). Remove debug/test endpoints from "
                    "production deployments entirely."
                ),
                owasp_id="A01:2021",
                cwe_id="CWE-284",
                url=url,
            ))

    # ── IDOR ──────────────────────────────────────────────────────────────

    def _check_idor(self, url: str, param: str, original_value: str) -> None:
        """
        Enumerate adjacent object IDs and compare response sizes.
        A significant size difference with a non-404 response suggests IDOR.
        """
        try:
            orig_id  = int(original_value)
        except ValueError:
            return

        try:
            base_resp = self.session.get(url, timeout=self.timeout)
            time.sleep(self.delay)
        except requests.RequestException:
            return

        if base_resp.status_code == 404:
            return

        base_len = len(base_resp.content)

        for delta in (1, -1, orig_id + 100, 0):
            if delta == orig_id:
                continue
            test_url = re.sub(
                rf"([?&]{re.escape(param)}=)\d+",
                lambda m: m.group(1) + str(delta),
                url
            )
            try:
                test_resp = self.session.get(test_url, timeout=self.timeout)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            if test_resp.status_code in (200, 201) and len(test_resp.content) > 100:
                diff = abs(len(test_resp.content) - base_len)
                # If other IDs return similar-sized valid responses, flag as
                # potential IDOR — the application is not enforcing ownership
                if diff < base_len * 0.5:
                    self.findings.append(self._finding(
                        title=f"Potential IDOR on Parameter '{param}'",
                        severity="HIGH",
                        description=(
                            f"The parameter '{param}' in '{url}' appears to "
                            f"accept arbitrary object IDs. Modifying the value "
                            f"from '{orig_id}' to '{delta}' returned HTTP "
                            f"{test_resp.status_code} with a similarly sized "
                            f"response, suggesting the server is not enforcing "
                            f"object-level ownership checks."
                        ),
                        evidence=(
                            f"Original ID={orig_id} → {base_len}B; "
                            f"Test ID={delta} → {len(test_resp.content)}B "
                            f"(HTTP {test_resp.status_code})"
                        ),
                        recommendation=(
                            "Implement server-side authorization on every "
                            "object lookup: verify that the authenticated user "
                            "owns or has explicit permission to access the "
                            "requested resource. Use indirect reference maps "
                            "or UUIDs instead of sequential integers."
                        ),
                        owasp_id="A01:2021",
                        cwe_id="CWE-639",
                        url=test_url,
                        parameter=param,
                        payload=str(delta),
                    ))
                    break  # One finding per parameter

    # ── Path Traversal ────────────────────────────────────────────────────

    def _check_path_traversal_base(self) -> None:
        """Test the base URL's query params (if any) for path traversal."""
        parsed = urlparse(self.target)
        qs = parse_qs(parsed.query)
        for param in qs:
            if param.lower() in self.FILE_PARAMS:
                self._check_path_traversal_param(self.target, param)

    def _check_path_traversal_param(self, url: str, param: str) -> None:
        """Inject traversal sequences into a specific parameter."""
        parsed    = urlparse(url)
        qs_dict   = parse_qs(parsed.query)

        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            qs_dict[param] = [payload]
            test_url = parsed._replace(query=urlencode(qs_dict, doseq=True)).geturl()
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            body = resp.text.lower()
            for sig in self.TRAVERSAL_SIGNATURES:
                if sig.lower() in body:
                    self.findings.append(self._finding(
                        title="Path Traversal (Directory Traversal) Detected",
                        severity="CRITICAL",
                        description=(
                            f"The parameter '{param}' at '{url}' is vulnerable "
                            f"to path traversal. Injecting the payload "
                            f"'{payload}' caused the application to read a "
                            f"sensitive system file (signature '{sig}' found "
                            f"in response)."
                        ),
                        evidence=f"Payload: {payload!r} → signature '{sig}' in response",
                        recommendation=(
                            "Never construct file system paths directly from "
                            "user-supplied input. Resolve the canonical path "
                            "and verify it is within the intended base "
                            "directory (e.g., os.path.realpath). Use an "
                            "allowlist of permitted filenames."
                        ),
                        owasp_id="A01:2021",
                        cwe_id="CWE-22",
                        url=test_url,
                        parameter=param,
                        payload=payload,
                    ))
                    return  # One finding per param

    # ── HTTP Verb Tampering ───────────────────────────────────────────────

    def _check_verb_tampering(self, url: str) -> None:
        """
        Test whether method-override headers allow bypassing access controls.
        Only checks for unexpected successful responses — not destructive.
        """
        try:
            get_resp = self.session.get(url, timeout=self.timeout)
            time.sleep(self.delay)
        except requests.RequestException:
            return

        if get_resp.status_code not in (403, 405):
            return  # Only interesting on restricted resources

        for extra_headers in self.METHOD_OVERRIDE_HEADERS:
            try:
                resp = self.session.get(url, headers=extra_headers,
                                         timeout=self.timeout)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            if resp.status_code == 200 and len(resp.content) > 50:
                self.findings.append(self._finding(
                    title="HTTP Method Override Bypasses Access Control",
                    severity="HIGH",
                    description=(
                        f"Sending a GET request to '{url}' with the header "
                        f"'{list(extra_headers.keys())[0]}' returned HTTP 200 "
                        f"even though a plain GET was blocked ({get_resp.status_code}). "
                        f"The server appears to process method-override headers "
                        f"before evaluating access-control rules."
                    ),
                    evidence=(
                        f"Plain GET → {get_resp.status_code}; "
                        f"GET + {extra_headers} → {resp.status_code}"
                    ),
                    recommendation=(
                        "Strip or ignore method-override headers in your "
                        "reverse-proxy or framework configuration unless they "
                        "are explicitly required. Apply authorization checks "
                        "based on the *effective* HTTP method, not the "
                        "transport method."
                    ),
                    owasp_id="A01:2021",
                    cwe_id="CWE-284",
                    url=url,
                ))
                break
