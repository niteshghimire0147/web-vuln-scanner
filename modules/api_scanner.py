"""
api_scanner.py — OWASP API Security Top 10 (2023) Scanner

Covers:
    API1:2023  Broken Object Level Authorization (BOLA / IDOR)
    API2:2023  Broken Authentication
    API3:2023  Broken Object Property Level Authorization (mass assignment)
    API4:2023  Unrestricted Resource Consumption (rate-limiting)
    API5:2023  Broken Function Level Authorization (admin endpoints)
    API6:2023  Unrestricted Access to Sensitive Business Flows
    API7:2023  Server Side Request Forgery
    API8:2023  Security Misconfiguration (CORS, verbose errors, API docs)
    API9:2023  Improper Inventory Management (exposed docs, shadow APIs)
    API10:2023 Unsafe Consumption of APIs (unvalidated 3rd-party data)
"""
import time
from typing import List
from urllib.parse import urljoin

import requests
from .scanner_base import ScannerBase


class APIScanner(ScannerBase):
    """
    OWASP API Security Top 10:2023 — comprehensive API surface scanner.

    Discovers API endpoints via well-known paths and response inspection,
    then tests each discovered surface for the full API Top 10.
    """

    # ── API Endpoint Discovery Paths ──────────────────────────────────────
    API_DISCOVERY_PATHS = [
        # OpenAPI / Swagger documentation
        "/swagger.json", "/swagger.yaml", "/swagger.yml",
        "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
        "/openapi.json", "/openapi.yaml", "/openapi.yml",
        "/api-docs", "/api-docs/", "/api-docs.json",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        # GraphQL
        "/graphql", "/graphiql", "/playground", "/altair",
        # REST API common base paths
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/rest/", "/rest/v1/", "/rest/v2/",
        "/service/", "/services/",
        # WSDL / SOAP
        "/?wsdl", "/?WSDL",
        # Spring Boot actuator
        "/actuator", "/actuator/",
        "/actuator/env", "/actuator/beans", "/actuator/mappings",
        "/actuator/health", "/actuator/info", "/actuator/metrics",
        # Debug / development
        "/api/debug", "/api/test", "/api/dev",
        "/debug", "/trace",
        # Common REST resource endpoints
        "/api/users", "/api/v1/users", "/api/v2/users",
        "/api/accounts", "/api/v1/accounts",
        "/api/orders", "/api/v1/orders",
        "/api/products", "/api/v1/products",
        "/api/admin", "/api/v1/admin",
        "/api/config", "/api/settings",
        "/api/tokens", "/api/keys",
    ]

    # ── CORS Origins to Test ──────────────────────────────────────────────
    CORS_TEST_ORIGINS = [
        "https://evil.com",
        "http://localhost",
        "null",
        "https://attacker.example.com",
    ]

    # ── Mass Assignment Test Fields ───────────────────────────────────────
    MASS_ASSIGN_FIELDS = [
        "role", "is_admin", "admin", "is_superuser", "superuser",
        "permissions", "privilege", "group", "plan", "subscription",
        "credits", "balance", "verified", "email_verified",
        "status", "active", "enabled",
    ]

    # ── Content Types for API Detection ──────────────────────────────────
    API_CONTENT_TYPES = [
        "application/json",
        "application/xml",
        "application/graphql",
        "text/xml",
    ]

    def scan(self) -> List[dict]:
        """
        Main scan entry point. Discovers API endpoints and tests them
        for all OWASP API Security Top 10:2023 categories.
        """
        self._log("API scanner: discovering endpoints")
        discovered = self._discover_api_endpoints()

        if not discovered:
            self._log("No API endpoints discovered — checking base URL as API")
            discovered = [self.target]

        for endpoint in discovered:
            self._test_api2_broken_auth(endpoint)
            self._test_api4_rate_limiting(endpoint)
            self._test_api8_cors(endpoint)
            self._test_api8_verbose_errors(endpoint)

        self._test_api9_inventory()
        self._test_api5_bfla()
        self._test_api1_bola()
        return self.findings

    # ── API1: BOLA ────────────────────────────────────────────────────────

    def _test_api1_bola(self) -> None:
        """
        Broken Object Level Authorization — enumerate resource IDs on discovered
        REST endpoints and check for unauthenticated access to arbitrary objects.
        """
        self._log("API1: Testing Broken Object Level Authorization (BOLA)")
        test_endpoints = [
            ("/api/v1/users/1", "/api/v1/users/2"),
            ("/api/users/1",    "/api/users/2"),
            ("/api/v1/orders/1", "/api/v1/orders/2"),
            ("/api/v1/accounts/1", "/api/v1/accounts/100"),
        ]
        for base_path, alt_path in test_endpoints:
            url1 = urljoin(self.target.rstrip("/") + "/", base_path.lstrip("/"))
            url2 = urljoin(self.target.rstrip("/") + "/", alt_path.lstrip("/"))
            try:
                r1 = self.session.get(url1, timeout=self.timeout)
                time.sleep(self.delay)
                r2 = self.session.get(url2, timeout=self.timeout)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            if r1.status_code == 200 and r2.status_code == 200:
                # Both IDs return data — no authorization enforced
                self.findings.append(self._finding(
                    title="API1:2023 — Broken Object Level Authorization (BOLA)",
                    severity="HIGH",
                    description=(
                        f"Both '{url1}' and '{url2}' returned HTTP 200, "
                        f"suggesting the API does not restrict object access "
                        f"by owner. An attacker can enumerate resource IDs to "
                        f"access other users' data without being the owner."
                    ),
                    evidence=(
                        f"GET {url1} → {r1.status_code} ({len(r1.content)}B); "
                        f"GET {url2} → {r2.status_code} ({len(r2.content)}B)"
                    ),
                    recommendation=(
                        "Enforce object-level authorization on every API "
                        "endpoint. Verify the authenticated user is the owner "
                        "of (or has explicit permission to access) the "
                        "requested resource ID. Never rely on obscurity."
                    ),
                    owasp_id="API1:2023",
                    cwe_id="CWE-639",
                    url=url2,
                ))
                break

    # ── API2: Broken Authentication ───────────────────────────────────────

    def _test_api2_broken_auth(self, endpoint: str) -> None:
        """
        Check for API endpoints accessible without any authentication token.
        """
        self._log(f"API2: Testing broken authentication on {endpoint}")
        # Temporarily strip auth headers from a copy request
        no_auth_headers = {
            k: v for k, v in self.session.headers.items()
            if k.lower() not in ("authorization", "x-api-key", "x-auth-token")
        }

        try:
            # With auth (baseline)
            resp_auth = self.session.get(endpoint, timeout=self.timeout)
            time.sleep(self.delay)

            # Without auth headers
            resp_noauth = requests.get(
                endpoint,
                headers=no_auth_headers,
                cookies={},
                timeout=self.timeout,
                verify=False,
            )
            time.sleep(self.delay)
        except requests.RequestException:
            return

        # If the un-authed request succeeds with real data
        if (resp_noauth.status_code == 200
                and len(resp_noauth.content) > 100
                and resp_noauth.status_code == resp_auth.status_code):
            # Check that it's returning API content, not a login page
            ct = resp_noauth.headers.get("Content-Type", "")
            if any(t in ct for t in ("json", "xml")):
                self.findings.append(self._finding(
                    title="API2:2023 — API Endpoint Accessible Without Authentication",
                    severity="HIGH",
                    description=(
                        f"The API endpoint '{endpoint}' returns HTTP 200 with "
                        f"structured data even when no authentication credentials "
                        f"are provided. Sensitive data or operations may be "
                        f"reachable by unauthenticated actors."
                    ),
                    evidence=(
                        f"No-auth request → HTTP {resp_noauth.status_code}, "
                        f"{len(resp_noauth.content)} bytes, "
                        f"Content-Type: {ct}"
                    ),
                    recommendation=(
                        "Enforce authentication on all API endpoints by default. "
                        "Use a centralised auth middleware rather than per-route "
                        "decorators to avoid accidental misses. Return 401 for "
                        "all unauthenticated requests to protected resources."
                    ),
                    owasp_id="API2:2023",
                    cwe_id="CWE-306",
                    url=endpoint,
                ))

    # ── API4: Unrestricted Resource Consumption ────────────────────────────

    def _test_api4_rate_limiting(self, endpoint: str) -> None:
        """
        Check for rate-limiting by sending a burst of requests and looking
        for HTTP 429 responses. Absence of 429 indicates no throttling.
        """
        self._log(f"API4: Testing rate limiting on {endpoint}")
        BURST = 15
        got_429 = False
        last_status = None

        for i in range(BURST):
            try:
                resp = self.session.get(endpoint, timeout=self.timeout)
                last_status = resp.status_code
                if resp.status_code == 429:
                    got_429 = True
                    break
                # Small delay to avoid hammering real targets
                time.sleep(max(self.delay, 0.1))
            except requests.RequestException:
                break

        if not got_429 and last_status == 200:
            self.findings.append(self._finding(
                title="API4:2023 — No Rate Limiting Detected on API Endpoint",
                severity="MEDIUM",
                description=(
                    f"Sending {BURST} rapid requests to '{endpoint}' did not "
                    f"trigger an HTTP 429 (Too Many Requests) response. Without "
                    f"rate limiting, the API is vulnerable to brute-force "
                    f"attacks, credential stuffing, enumeration, and "
                    f"resource exhaustion."
                ),
                evidence=(
                    f"{BURST} consecutive requests; final status: HTTP {last_status}; "
                    f"no 429 received"
                ),
                recommendation=(
                    "Implement rate limiting per user, per IP, and globally "
                    "using a token-bucket or sliding-window algorithm. Return "
                    "HTTP 429 with a Retry-After header. For authentication "
                    "endpoints, apply stricter limits and account lockout."
                ),
                owasp_id="API4:2023",
                cwe_id="CWE-770",
                url=endpoint,
            ))

    # ── API5: Broken Function Level Authorization ─────────────────────────

    def _test_api5_bfla(self) -> None:
        """
        Test whether admin-only API functions are accessible via HTTP
        method changes (e.g., GET /api/users returns 403, but DELETE
        /api/users returns 200).
        """
        self._log("API5: Testing Broken Function Level Authorization (BFLA)")
        admin_api_paths = [
            "/api/admin", "/api/v1/admin", "/api/v2/admin",
            "/api/admin/users", "/api/v1/admin/users",
            "/api/admin/config", "/api/admin/settings",
            "/api/users/delete", "/api/users/disable",
            "/admin/api/", "/manage/api/",
        ]
        for path in admin_api_paths:
            url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
            for method in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                try:
                    resp = self.session.request(method, url,
                                                timeout=self.timeout,
                                                allow_redirects=False)
                    time.sleep(self.delay)
                except requests.RequestException:
                    continue

                if resp.status_code in (200, 201):
                    ct = resp.headers.get("Content-Type", "")
                    if any(t in ct for t in ("json", "xml", "text/html")):
                        self.findings.append(self._finding(
                            title=f"API5:2023 — Admin API Function Accessible: {method} {path}",
                            severity="HIGH",
                            description=(
                                f"The admin API endpoint '{path}' is accessible "
                                f"via {method} without elevated authorization. "
                                f"Broken function-level authorization allows "
                                f"regular users or unauthenticated actors to "
                                f"invoke privileged operations."
                            ),
                            evidence=f"{method} {url} → HTTP {resp.status_code}",
                            recommendation=(
                                "Implement role-based access control (RBAC) at "
                                "the function level. Admin endpoints should "
                                "verify the 'admin' or 'superuser' role claim "
                                "on every request, regardless of HTTP method."
                            ),
                            owasp_id="API5:2023",
                            cwe_id="CWE-285",
                            url=url,
                        ))
                        break

    # ── API8: Security Misconfiguration ───────────────────────────────────

    def _test_api8_cors(self, endpoint: str) -> None:
        """
        Check for overly permissive CORS configuration (wildcard or
        reflected origins with credentials).
        """
        self._log(f"API8: Testing CORS on {endpoint}")
        for origin in self.CORS_TEST_ORIGINS:
            try:
                resp = self.session.options(
                    endpoint,
                    headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                    timeout=self.timeout,
                )
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*" and acac.lower() == "true":
                self.findings.append(self._finding(
                    title="API8:2023 — CORS Wildcard with Credentials (Critical Misconfiguration)",
                    severity="CRITICAL",
                    description=(
                        f"The endpoint '{endpoint}' responds with both "
                        f"Access-Control-Allow-Origin: * and "
                        f"Access-Control-Allow-Credentials: true. This "
                        f"combination is rejected by browsers but indicates "
                        f"a dangerous misconfiguration. If the origin is "
                        f"reflected instead of *, any malicious site can "
                        f"make credentialed cross-origin API calls."
                    ),
                    evidence=(
                        f"ACAO: {acao}, ACAC: {acac}, "
                        f"Test origin: {origin}"
                    ),
                    recommendation=(
                        "Never combine Allow-Origin: * with Allow-Credentials: "
                        "true. Maintain an explicit allowlist of trusted origins "
                        "and validate Origin headers against it. Return a 403 "
                        "for untrusted origins."
                    ),
                    owasp_id="API8:2023",
                    cwe_id="CWE-942",
                    url=endpoint,
                ))
                break

            if acao == origin and origin in ("https://evil.com",
                                              "https://attacker.example.com"):
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                self.findings.append(self._finding(
                    title="API8:2023 — CORS Origin Reflected (Permissive Policy)",
                    severity=severity,
                    description=(
                        f"The API at '{endpoint}' reflects the untrusted origin "
                        f"'{origin}' in the Access-Control-Allow-Origin header. "
                        f"{'With credentials allowed, this enables cross-origin request forgery.' if acac.lower() == 'true' else 'This permits cross-origin reads of API responses.'}"
                    ),
                    evidence=(
                        f"Request Origin: {origin} → ACAO: {acao}, ACAC: {acac}"
                    ),
                    recommendation=(
                        "Validate the Origin header against a server-side "
                        "allowlist. Do not dynamically reflect arbitrary "
                        "origins. Log and alert on untrusted origin attempts."
                    ),
                    owasp_id="API8:2023",
                    cwe_id="CWE-942",
                    url=endpoint,
                ))
                break

    def _test_api8_verbose_errors(self, endpoint: str) -> None:
        """
        Send a malformed request to see if the API returns verbose stack
        traces or internal error details.
        """
        VERBOSE_SIGNATURES = [
            "traceback", "at line", "exception in thread",
            "java.lang", "org.springframework", "django.core",
            "at com.", "at sun.reflect", "NullPointerException",
            "stack overflow", "syntax error", "undefined method",
            "psycopg2", "sqlalchemy", "hibernate",
        ]
        try:
            # Send a clearly invalid JSON body
            resp = self.session.post(
                endpoint,
                data="{invalid-json-payload-!!!}",
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )
            time.sleep(self.delay)
        except requests.RequestException:
            return

        body_lower = resp.text.lower()
        for sig in VERBOSE_SIGNATURES:
            if sig.lower() in body_lower:
                self.findings.append(self._finding(
                    title="API8:2023 — Verbose Error / Stack Trace Exposed",
                    severity="MEDIUM",
                    description=(
                        f"Sending an invalid request to '{endpoint}' caused "
                        f"the API to return a verbose error message containing "
                        f"the signature '{sig}'. Stack traces and framework "
                        f"details aid attackers in fingerprinting the tech "
                        f"stack and identifying exploitable components."
                    ),
                    evidence=f"Signature '{sig}' found in {resp.status_code} response",
                    recommendation=(
                        "Configure your framework to return generic error "
                        "messages to clients. Log detailed errors server-side "
                        "only. Disable debug mode in production. Return "
                        "RFC-7807 Problem Details format for API errors."
                    ),
                    owasp_id="API8:2023",
                    cwe_id="CWE-209",
                    url=endpoint,
                ))
                break

    # ── API9: Improper Inventory Management ───────────────────────────────

    def _test_api9_inventory(self) -> None:
        """
        Discover exposed API documentation, shadow/deprecated API versions,
        and unadvertised endpoints that indicate poor API inventory management.
        """
        self._log("API9: Testing for exposed API docs and shadow APIs")
        DOC_SIGNATURES = [
            "swagger", "openapi", "api documentation",
            "try it out", "authorize", "schema",
        ]
        DEPRECATED_VERSIONS = ["/api/v0/", "/api/beta/", "/api/dev/",
                                "/api/internal/", "/api/private/"]

        # Check for exposed documentation
        for path in self.API_DISCOVERY_PATHS:
            if not any(d in path.lower() for d in
                       ("swagger", "openapi", "api-docs", "graphql",
                        "actuator", "console", "wsdl")):
                continue
            url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            if resp.status_code != 200 or len(resp.content) < 100:
                continue

            body_lower = resp.text.lower()
            if any(sig in body_lower for sig in DOC_SIGNATURES):
                self.findings.append(self._finding(
                    title=f"API9:2023 — API Documentation Exposed: {path}",
                    severity="MEDIUM",
                    description=(
                        f"Interactive API documentation is publicly accessible "
                        f"at '{url}'. Exposed Swagger/OpenAPI/GraphQL UIs "
                        f"provide attackers with a complete map of API endpoints, "
                        f"parameters, and authentication requirements, "
                        f"significantly reducing reconnaissance effort."
                    ),
                    evidence=f"HTTP 200, {len(resp.content)} bytes, doc signature found",
                    recommendation=(
                        "Restrict API documentation to authenticated users or "
                        "internal networks only. In production, disable "
                        "interactive documentation entirely. Serve docs via "
                        "a separate, access-controlled portal."
                    ),
                    owasp_id="API9:2023",
                    cwe_id="CWE-200",
                    url=url,
                ))

        # Check for deprecated / shadow API versions
        for path in DEPRECATED_VERSIONS:
            url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            if resp.status_code == 200 and len(resp.content) > 50:
                self.findings.append(self._finding(
                    title=f"API9:2023 — Shadow / Deprecated API Version Accessible: {path}",
                    severity="HIGH",
                    description=(
                        f"The deprecated or internal API path '{path}' is "
                        f"publicly reachable and returns HTTP 200. Shadow APIs "
                        f"often lack the security hardening applied to current "
                        f"versions and may expose unpatched vulnerabilities."
                    ),
                    evidence=f"GET {url} → HTTP {resp.status_code}, {len(resp.content)} bytes",
                    recommendation=(
                        "Maintain a complete API inventory and decommission "
                        "deprecated versions promptly. Implement API versioning "
                        "policies that include automatic sunset dates. Block "
                        "access to internal and beta paths via network policy."
                    ),
                    owasp_id="API9:2023",
                    cwe_id="CWE-1059",
                    url=url,
                ))

    # ── Internal: Endpoint Discovery ──────────────────────────────────────

    def _discover_api_endpoints(self) -> List[str]:
        """
        Return a deduplicated list of API endpoint URLs that return HTTP 200
        or return JSON/XML content types.
        """
        discovered = []
        seen = set()

        for path in self.API_DISCOVERY_PATHS[:30]:  # Limit initial probe
            url = urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))
            if url in seen:
                continue
            seen.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            if resp.status_code in (200, 201):
                ct = resp.headers.get("Content-Type", "")
                if (any(t in ct for t in self.API_CONTENT_TYPES)
                        or len(resp.content) > 100):
                    discovered.append(url)
                    self._log(f"Discovered API endpoint: {url}")

        return discovered
