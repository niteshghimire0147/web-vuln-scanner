"""
ssrf_scanner.py — Server-Side Request Forgery Scanner (OWASP A10:2021)

Tests for SSRF vulnerabilities by injecting internal/loopback addresses
into URL-like parameters and observing response differences.

All probes target safe, non-destructive destinations:
- Loopback (127.0.0.1) and link-local (169.254.x.x)
- Well-known cloud metadata endpoints (read-only)
- IPv6 loopback
"""
import time
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode

import requests
from .scanner_base import ScannerBase


class SSRFScanner(ScannerBase):
    """
    OWASP A10:2021 — Server-Side Request Forgery (SSRF)

    Detects parameter values that may trigger the server to issue internal
    HTTP requests, potentially exposing cloud metadata, internal services,
    or enabling port scanning.
    """

    # Parameters commonly used to hold URLs or hostnames
    URL_PARAMS = [
        "url", "uri", "link", "src", "href", "source",
        "redirect", "return", "next", "to", "target",
        "path", "fetch", "load", "proxy", "request",
        "callback", "webhook", "endpoint", "host",
        "image", "img", "logo", "avatar", "file",
        "feed", "rss", "xml", "data",
    ]

    # Safe SSRF probe targets — all either loopback or well-known cloud metadata
    SSRF_PROBES = [
        # Loopback probes — server should not echo these back as live content
        "http://127.0.0.1/",
        "http://127.0.0.1:22/",        # SSH port
        "http://127.0.0.1:8080/",
        "http://localhost/",
        "http://[::1]/",               # IPv6 loopback
        # Cloud metadata endpoints (read-only, industry standard SSRF test targets)
        "http://169.254.169.254/latest/meta-data/",           # AWS IMDSv1
        "http://169.254.169.254/computeMetadata/v1/",         # GCP
        "http://169.254.169.254/metadata/instance",           # Azure
        "http://metadata.google.internal/computeMetadata/v1/",
        # DNS rebinding indicator
        "http://0.0.0.0/",
    ]

    # Response body signatures that confirm the server reached an internal resource
    SSRF_SIGNATURES = [
        # AWS metadata
        "ami-id", "instance-id", "local-ipv4", "security-credentials",
        "iam/", "meta-data/",
        # GCP metadata
        "computeMetadata", "instance/", "project/",
        # Azure metadata
        "subscriptionId", "resourceGroupName",
        # Linux internals (if loopback returns host's page)
        "root:x:", "daemon:x:",
        # SSH banner
        "SSH-2.0",
        # Common internal service responses
        "redis_version", "rdb_version",  # Redis INFO
        "mongod", "MongoDB",
        # Internal error pages that differ from 404
        "connection refused", "ECONNREFUSED",
    ]

    # Headers that SSRF probes may accept
    SSRF_HEADERS = [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Remote-Addr",
        "X-Custom-IP-Authorization",
    ]

    def scan(self) -> List[dict]:
        """Scan the base target URL for SSRF-prone parameters."""
        parsed = urlparse(self.target)
        qs = parse_qs(parsed.query)
        for param, values in qs.items():
            if param.lower() in self.URL_PARAMS:
                self._probe_param(self.target, param, values[0])
        self._check_header_ssrf()
        return self.findings

    def scan_url_params(self, url_params: List[dict]) -> List[dict]:
        """Test all crawled URL parameters."""
        seen = set()
        for param_info in url_params:
            url = param_info.get("url", "")
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            for param, values in qs.items():
                key = (parsed.netloc, parsed.path, param)
                if param.lower() in self.URL_PARAMS and key not in seen:
                    seen.add(key)
                    self._probe_param(url, param, values[0])
        return self.findings

    # ── Internal helpers ──────────────────────────────────────────────────

    @property
    def _probes(self) -> list:
        return self.custom_payloads if self.custom_payloads else self.SSRF_PROBES

    def _probe_param(self, url: str, param: str, original_value: str) -> None:
        """
        Replace a parameter value with SSRF probe URLs and check the response.
        """
        parsed   = urlparse(url)
        qs_dict  = parse_qs(parsed.query)

        # Baseline response for comparison
        try:
            base_resp = self.session.get(url, timeout=self.timeout)
            base_len  = len(base_resp.content)
            time.sleep(self.delay)
        except requests.RequestException:
            return

        for probe in self._probes:
            qs_dict[param] = [probe]
            test_url = parsed._replace(
                query=urlencode(qs_dict, doseq=True)
            ).geturl()

            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            body = resp.text

            # Hard confirmation — known internal resource signature in body
            for sig in self.SSRF_SIGNATURES:
                if sig.lower() in body.lower():
                    self.findings.append(self._finding(
                        title=f"Server-Side Request Forgery (SSRF) — Parameter '{param}'",
                        severity="CRITICAL",
                        description=(
                            f"The parameter '{param}' at '{url}' is vulnerable "
                            f"to SSRF. Injecting '{probe}' caused the server to "
                            f"issue an internal HTTP request and return content "
                            f"matching the internal resource signature '{sig}'. "
                            f"An attacker could use this to access cloud metadata "
                            f"endpoints, internal services, or conduct port scans "
                            f"from the server's network context."
                        ),
                        evidence=(
                            f"Probe: {probe!r} → HTTP {resp.status_code}, "
                            f"signature '{sig}' found in {len(body)}-byte response"
                        ),
                        recommendation=(
                            "Validate all user-supplied URLs against a strict "
                            "allowlist of permitted schemes and hosts. Block "
                            "requests to RFC-1918 / loopback / link-local "
                            "addresses at the network layer. Use a dedicated "
                            "egress proxy that enforces allowlisting. On cloud "
                            "platforms, require IMDSv2 (AWS) or equivalent."
                        ),
                        owasp_id="A10:2021",
                        cwe_id="CWE-918",
                        url=test_url,
                        parameter=param,
                        payload=probe,
                    ))
                    return

            # Soft signal — response size differs significantly from baseline
            diff = abs(len(resp.content) - base_len)
            if (resp.status_code not in (400, 404, 500)
                    and diff > 200
                    and resp.status_code < 400
                    and "cloud" not in probe  # Already covered above
               ):
                self.findings.append(self._finding(
                    title=f"Potential SSRF — Anomalous Response for Parameter '{param}'",
                    severity="MEDIUM",
                    description=(
                        f"Injecting the internal URL '{probe}' into parameter "
                        f"'{param}' produced an anomalous HTTP {resp.status_code} "
                        f"response ({len(resp.content)} bytes vs baseline "
                        f"{base_len} bytes). This may indicate the server is "
                        f"fetching the supplied URL, though no internal content "
                        f"signature was confirmed."
                    ),
                    evidence=(
                        f"Probe: {probe!r} → HTTP {resp.status_code}, "
                        f"size delta: {diff} bytes"
                    ),
                    recommendation=(
                        "Validate and allowlist permitted URL destinations. "
                        "Resolve DNS before validation and block private/reserved "
                        "IP ranges. Disable HTTP redirects when fetching "
                        "user-supplied URLs."
                    ),
                    owasp_id="A10:2021",
                    cwe_id="CWE-918",
                    url=test_url,
                    parameter=param,
                    payload=probe,
                ))
                break

    def _check_header_ssrf(self) -> None:
        """
        Test whether server-side logic uses proxy/IP headers to trigger
        back-end requests (Host header injection vector for SSRF).
        """
        try:
            self.session.get(self.target, timeout=self.timeout)
            time.sleep(self.delay)
        except requests.RequestException:
            return

        for header in self.SSRF_HEADERS:
            try:
                resp = self.session.get(
                    self.target,
                    headers={header: "169.254.169.254"},
                    timeout=self.timeout,
                )
                time.sleep(self.delay)
            except requests.RequestException:
                continue

            for sig in self.SSRF_SIGNATURES:
                if sig.lower() in resp.text.lower():
                    self.findings.append(self._finding(
                        title=f"SSRF via Header Injection ('{header}')",
                        severity="CRITICAL",
                        description=(
                            f"Sending the header '{header}: 169.254.169.254' "
                            f"caused the server to issue a request to the cloud "
                            f"metadata endpoint. The application appears to use "
                            f"this header to construct back-end request targets "
                            f"without validation."
                        ),
                        evidence=f"Header: {header}: 169.254.169.254 → sig '{sig}' in response",
                        recommendation=(
                            "Do not use client-supplied proxy/IP headers to "
                            "construct back-end HTTP requests. If these headers "
                            "are needed for IP attribution, validate values "
                            "against a trusted reverse-proxy allowlist."
                        ),
                        owasp_id="A10:2021",
                        cwe_id="CWE-918",
                    ))
                    break
