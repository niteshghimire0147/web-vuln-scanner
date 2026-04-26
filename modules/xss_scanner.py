"""
xss_scanner.py — Reflected XSS scanner (OWASP A03:2021 Injection).

Tests for reflected cross-site scripting in form inputs and URL parameters.
"""
import re
from typing import List
from urllib.parse import urlparse, parse_qs

import requests
from .scanner_base import ScannerBase


# Unique marker embedded in payloads — if it appears in the response, XSS is likely
XSS_MARKER = "xsstest7f3a"

XSS_PAYLOADS = [
    f'<script>alert("{XSS_MARKER}")</script>',
    f'"><script>alert("{XSS_MARKER}")</script>',
    f"'><script>alert('{XSS_MARKER}')</script>",
    f'<img src=x onerror=alert("{XSS_MARKER}")>',
    f'"><img src=x onerror=alert("{XSS_MARKER}")>',
    f'javascript:alert("{XSS_MARKER}")',
    f'<svg onload=alert("{XSS_MARKER}")>',
    f'"><svg onload=alert("{XSS_MARKER}")>',
]


class XSSScanner(ScannerBase):
    """
    OWASP A03:2021 — Injection (Reflected Cross-Site Scripting)

    Checks for reflected XSS in:
    - HTML form inputs (POST and GET)
    - URL query parameters
    """

    def scan(self) -> List[dict]:
        return self.findings

    def scan_forms(self, forms: List[dict]) -> List[dict]:
        """Test all discovered forms for reflected XSS."""
        for form in forms:
            for payload in XSS_PAYLOADS[:4]:  # Test first 4 payloads per form
                result = self._test_form(form, payload)
                if result:
                    self.findings.append(result)
                    break  # One finding per form
        return self.findings

    def scan_url_params(self, url_params: List[dict]) -> List[dict]:
        """Test URL query parameters for reflected XSS."""
        for param_info in url_params:
            for payload in XSS_PAYLOADS[:3]:
                result = self._test_url_param(param_info, payload)
                if result:
                    self.findings.append(result)
                    break
        return self.findings

    def _test_form(self, form: dict, payload: str):
        """Test a single form with one XSS payload."""
        inputs = [i for i in form.get("inputs", []) if i.get("name") and
                  i.get("type", "text") not in ("hidden", "submit", "button", "checkbox", "radio")]
        if not inputs:
            return None

        data = {inp["name"]: payload for inp in inputs}
        method = form.get("method", "get").upper()

        try:
            if method == "POST":
                resp = self.session.post(form["action"], data=data, timeout=self.timeout)
            else:
                resp = self.session.get(form["action"], params=data, timeout=self.timeout)
        except requests.RequestException:
            return None

        # Check if our payload appears unescaped in the response
        if XSS_MARKER in resp.text:
            # Verify it's truly reflected (not just present in the page for another reason)
            # Check if the full payload or the marker appears in a script/attr context
            if re.search(r'<script[^>]*>', resp.text, re.IGNORECASE) and XSS_MARKER in resp.text:
                severity = "HIGH"
                evidence = "Payload reflected in script context"
            else:
                severity = "MEDIUM"
                evidence = f"Payload marker '{XSS_MARKER}' reflected in response body"

            param_names = ", ".join(i["name"] for i in inputs)
            return self._finding(
                title="Reflected XSS in Form",
                severity=severity,
                description=(
                    f"A reflected cross-site scripting vulnerability was found in form field(s): "
                    f"{param_names}. User-supplied input is returned in the HTTP response without "
                    f"proper encoding, allowing script injection."
                ),
                evidence=f"Payload: {payload!r} → {evidence}",
                recommendation=(
                    "HTML-encode all user-supplied output. Implement Content-Security-Policy. "
                    "Use a framework with auto-escaping (e.g. Jinja2, React). "
                    "Set HttpOnly flag on session cookies."
                ),
                owasp_id="A03:2021",
                url=form["action"],
                cwe_id="CWE-79",
                parameter=param_names,
                payload=payload,
            )
        return None

    def _test_url_param(self, param_info: dict, payload: str):
        """Test a single URL parameter for reflected XSS."""
        url = param_info["url"]
        param = param_info["param_name"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = payload

        try:
            resp = self.session.get(
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                params=test_params,
                timeout=self.timeout,
            )
        except requests.RequestException:
            return None

        if XSS_MARKER in resp.text:
            return self._finding(
                title=f"Reflected XSS in URL Parameter '{param}'",
                severity="HIGH",
                description=f"XSS payload reflected in response via URL parameter '{param}'.",
                evidence=f"Payload: {payload!r} → marker '{XSS_MARKER}' in response",
                recommendation="HTML-encode all output. Implement CSP.",
                owasp_id="A03:2021",
                url=url,
                cwe_id="CWE-79",
                parameter=param,
                payload=payload,
            )
        return None
