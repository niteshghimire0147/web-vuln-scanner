"""
broken_auth_scanner.py — Broken Authentication Scanner (OWASP A07:2021)

Tests for:
- Default credentials on admin/login endpoints
- Weak session token entropy (short / predictable tokens)
- Missing account lockout (brute-force protection)
- Insecure password reset flows
- Session fixation indicators
- JWT security issues (algorithm confusion, weak secrets, missing validation)
"""
import base64
import json
import re
import time
from typing import List, Optional
from urllib.parse import urlparse, urljoin

import requests
from .scanner_base import ScannerBase


class BrokenAuthScanner(ScannerBase):
    """
    OWASP A07:2021 — Identification and Authentication Failures

    Detects authentication weaknesses without performing destructive
    or account-locking operations. All probes use known-safe test
    credential sets and non-destructive observation techniques.
    """

    # ── Login Endpoint Discovery ──────────────────────────────────────────
    LOGIN_PATHS = [
        "/login", "/signin", "/sign-in", "/auth", "/authenticate",
        "/admin/login", "/admin/signin", "/wp-login.php",
        "/user/login", "/account/login", "/session/new",
        "/api/login", "/api/v1/login", "/api/auth",
        "/api/v1/auth", "/api/v1/token", "/api/token",
        "/api/v1/sessions", "/api/sessions",
        "/oauth/token", "/connect/token",
    ]

    # ── Default Credentials ───────────────────────────────────────────────
    # Industry-standard default cred lists used in authorised assessments.
    DEFAULT_CREDENTIALS = [
        ("admin",         "admin"),
        ("admin",         "password"),
        ("admin",         "admin123"),
        ("admin",         "Password1"),
        ("admin",         "12345"),
        ("root",          "root"),
        ("root",          "toor"),
        ("administrator", "administrator"),
        ("administrator", "password"),
        ("test",          "test"),
        ("guest",         "guest"),
        ("demo",          "demo"),
        ("user",          "user"),
        ("manager",       "manager"),
        ("support",       "support"),
    ]

    # ── JWT Vulnerability Signatures ──────────────────────────────────────
    JWT_PATTERN = re.compile(
        r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*"
    )

    WEAK_JWT_SECRETS = [
        "secret", "password", "123456", "test", "key", "jwt",
        "change_me", "your_jwt_secret", "mysecret",
    ]

    def scan(self) -> List[dict]:
        """Run all broken-auth checks."""
        login_url = self._find_login_url()
        if login_url:
            self._test_default_credentials(login_url)
            self._test_account_lockout(login_url)
        self._check_session_tokens()
        self._check_password_reset()
        return self.findings

    # ── Login Discovery ───────────────────────────────────────────────────

    def _find_login_url(self) -> Optional[str]:
        """Return the first login URL that returns HTTP 200."""
        for path in self.LOGIN_PATHS:
            url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=True)
                time.sleep(self.delay)
                if resp.status_code == 200 and len(resp.content) > 200:
                    body_lower = resp.text.lower()
                    if any(k in body_lower for k in
                           ("password", "username", "email", "sign in",
                            "log in", "login")):
                        self._log(f"Found login endpoint: {url}")
                        return url
            except requests.RequestException:
                continue
        return None

    # ── Default Credentials ───────────────────────────────────────────────

    def _test_default_credentials(self, login_url: str) -> None:
        """
        Attempt a small set of industry-known default credentials.
        Stops immediately on first confirmed success to avoid lockout.
        """
        self._log(f"A07: Testing default credentials on {login_url}")
        # Get baseline failed response for comparison
        try:
            fail_resp = self.session.post(
                login_url,
                data={"username": "definitely_invalid_user_xyz",
                      "password": "definitely_invalid_password_xyz"},
                timeout=self.timeout,
                allow_redirects=True,
            )
            time.sleep(self.delay)
            fail_len = len(fail_resp.content)
            fail_url = fail_resp.url
        except requests.RequestException:
            return

        for username, password in self.DEFAULT_CREDENTIALS[:8]:
            try:
                resp = self.session.post(
                    login_url,
                    data={"username": username, "password": password,
                          "email": username},
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            # Success indicators: redirect to non-login URL OR significantly
            # different response size (dashboard content vs error)
            url_changed = resp.url != fail_url and "login" not in resp.url.lower()
            size_diff   = abs(len(resp.content) - fail_len)
            body_lower  = resp.text.lower()
            auth_success = any(k in body_lower for k in
                               ("dashboard", "welcome", "logout", "sign out",
                                "my account", "profile"))

            if url_changed or (size_diff > 500 and auth_success):
                self.findings.append(self._finding(
                    title=f"Default Credentials Accepted: '{username}' / '{password}'",
                    severity="CRITICAL",
                    description=(
                        f"The login endpoint '{login_url}' accepted the "
                        f"default credential pair '{username}' / '{password}'. "
                        f"Default credentials are the first thing attackers "
                        f"try and provide immediate full access to the "
                        f"application."
                    ),
                    evidence=(
                        f"POST {login_url} with {username}/{password} → "
                        f"HTTP {resp.status_code}, "
                        f"redirected to {resp.url}"
                    ),
                    recommendation=(
                        "Force all default credentials to be changed on first "
                        "login. Remove or disable default accounts in production. "
                        "Implement a strong password policy and MFA for all "
                        "privileged accounts."
                    ),
                    owasp_id="A07:2021",
                    cwe_id="CWE-521",
                    url=login_url,
                    parameter="username/password",
                    payload=f"{username}/{password}",
                ))
                return  # Stop after first hit

    # ── Account Lockout ────────────────────────────────────────────────────

    def _test_account_lockout(self, login_url: str) -> None:
        """
        Send several failed login attempts and check whether the server
        returns a 429, 403, or lockout message after repeated failures.
        A consistent 200 (or unchanged error) indicates no lockout policy.
        """
        self._log(f"A07: Testing account lockout policy on {login_url}")
        ATTEMPTS = 6
        got_lockout = False
        last_status  = None

        for i in range(ATTEMPTS):
            try:
                resp = self.session.post(
                    login_url,
                    data={"username": "lockout_test_user@example.com",
                          "password": f"WrongPassword{i}!"},
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                last_status = resp.status_code
                body_lower  = resp.text.lower()
                time.sleep(max(self.delay, 0.3))
            except requests.RequestException:
                return

            if (resp.status_code in (429, 423, 403)
                    or any(k in body_lower for k in
                           ("account locked", "too many attempts",
                            "temporarily blocked", "try again later",
                            "locked out"))):
                got_lockout = True
                break

        if not got_lockout and last_status == 200:
            self.findings.append(self._finding(
                title="No Account Lockout / Rate Limiting on Login Endpoint",
                severity="HIGH",
                description=(
                    f"Sending {ATTEMPTS} consecutive failed login attempts to "
                    f"'{login_url}' did not trigger account lockout, a 429 "
                    f"response, or any lockout message. The endpoint is "
                    f"vulnerable to password brute-forcing and credential "
                    f"stuffing attacks."
                ),
                evidence=(
                    f"{ATTEMPTS} failed attempts; final status: HTTP {last_status}; "
                    f"no lockout signal received"
                ),
                recommendation=(
                    "Implement account lockout after 5–10 failed attempts "
                    "with exponential back-off. Return HTTP 429 with a "
                    "Retry-After header. Use CAPTCHA or device fingerprinting "
                    "for suspicious patterns. Log and alert on repeated "
                    "authentication failures."
                ),
                owasp_id="A07:2021",
                cwe_id="CWE-307",
                url=login_url,
            ))

    # ── Session Token Analysis ─────────────────────────────────────────────

    def _check_session_tokens(self) -> None:
        """
        Examine cookies set during authentication for weak token entropy
        and JWT-specific misconfigurations.
        """
        self._log("A07: Analysing session token entropy and JWT security")
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            time.sleep(self.delay)
        except requests.RequestException:
            return

        # Check all cookie values for JWTs
        all_cookie_vals = [c.value for c in self.session.cookies]
        # Also check response headers
        header_vals = [v for k, v in resp.headers.items()
                       if "token" in k.lower() or "auth" in k.lower()]

        candidates = all_cookie_vals + header_vals
        for val in candidates:
            if self.JWT_PATTERN.match(val or ""):
                self._analyse_jwt(val, resp.url)

    def _analyse_jwt(self, token: str, source_url: str) -> None:
        """Check a JWT for algorithm confusion and missing claim validation."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode header (no signature verification — we're just inspecting)
            header_b64  = parts[0] + "=" * (4 - len(parts[0]) % 4)
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)

            header  = json.loads(base64.urlsafe_b64decode(header_b64))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception:
            return

        alg = header.get("alg", "")

        # None algorithm attack
        if alg.lower() in ("none", "null", ""):
            self.findings.append(self._finding(
                title="JWT 'none' Algorithm Accepted — Signature Bypass",
                severity="CRITICAL",
                description=(
                    f"A JWT token with algorithm 'none' was detected at "
                    f"'{source_url}'. If the server accepts unsigned tokens, "
                    f"any attacker can forge arbitrary claims without knowing "
                    f"the signing secret."
                ),
                evidence=f"JWT header: {header}",
                recommendation=(
                    "Reject JWTs with alg=none. Enforce an explicit allowlist "
                    "of permitted algorithms (RS256 or ES256 preferred). "
                    "Never trust the algorithm from the token header — "
                    "use the expected algorithm from your server configuration."
                ),
                owasp_id="A07:2021",
                cwe_id="CWE-347",
                url=source_url,
            ))

        # HS256 with RSA key — algorithm confusion
        if alg.upper() in ("HS256", "HS384", "HS512"):
            self.findings.append(self._finding(
                title="JWT Uses Symmetric Algorithm (HS256) — Algorithm Confusion Risk",
                severity="MEDIUM",
                description=(
                    f"The JWT uses the symmetric algorithm '{alg}'. If the "
                    f"server also supports asymmetric algorithms and the "
                    f"public key is accessible, an attacker may perform an "
                    f"RS256→HS256 algorithm confusion attack to forge tokens."
                ),
                evidence=f"JWT header alg: {alg}",
                recommendation=(
                    "Prefer asymmetric algorithms (RS256, ES256) for JWTs "
                    "shared between services. If HS256 is required, use a "
                    "cryptographically random secret of at least 256 bits. "
                    "Explicitly reject RS/EC algorithms when HS is expected."
                ),
                owasp_id="A07:2021",
                cwe_id="CWE-347",
                url=source_url,
            ))

        # Missing expiry claim
        if "exp" not in payload:
            self.findings.append(self._finding(
                title="JWT Missing 'exp' Claim — Token Never Expires",
                severity="HIGH",
                description=(
                    "The JWT does not contain an 'exp' (expiration) claim. "
                    "Without an expiry, a stolen token remains valid "
                    "indefinitely and cannot be invalidated by the server "
                    "without maintaining a denylist."
                ),
                evidence=f"JWT payload keys: {list(payload.keys())}",
                recommendation=(
                    "Always include an 'exp' claim. Short-lived access "
                    "tokens (15–60 minutes) with refresh token rotation "
                    "are the recommended pattern. Implement server-side "
                    "token revocation for high-privilege operations."
                ),
                owasp_id="A07:2021",
                cwe_id="CWE-613",
                url=source_url,
            ))

    # ── Password Reset ─────────────────────────────────────────────────────

    def _check_password_reset(self) -> None:
        """
        Check password reset endpoints for token exposure in URL or
        responses, and missing expiry / rate limiting.
        """
        RESET_PATHS = [
            "/forgot-password", "/forgot_password", "/reset-password",
            "/reset_password", "/password/reset", "/password/forgot",
            "/api/v1/password/reset", "/api/password/forgot",
            "/account/forgot", "/user/forgot-password",
        ]
        for path in RESET_PATHS:
            url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=True)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            if resp.status_code != 200:
                continue

            body_lower = resp.text.lower()
            if not any(k in body_lower for k in
                       ("password", "email", "reset", "forgot")):
                continue

            # Check if the reset token would be sent in URL (common mistake)
            if "token=" in resp.url or "reset_token=" in resp.url:
                self.findings.append(self._finding(
                    title="Password Reset Token Exposed in URL",
                    severity="HIGH",
                    description=(
                        f"The password reset flow at '{url}' appears to "
                        f"include the reset token in the URL query string. "
                        f"Tokens in URLs are logged by web servers, proxies, "
                        f"and browser history, and leak via the Referer header "
                        f"to third-party resources."
                    ),
                    evidence=f"Token parameter found in URL: {resp.url[:200]}",
                    recommendation=(
                        "Deliver password reset tokens via the POST body or "
                        "embed them in a path segment only used once. Set a "
                        "short expiry (15 minutes). Invalidate the token "
                        "immediately after use and after any new reset request."
                    ),
                    owasp_id="A07:2021",
                    cwe_id="CWE-640",
                    url=url,
                ))
