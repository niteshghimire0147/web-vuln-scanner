"""
sql_injection.py — SQL Injection scanner (OWASP A03:2021 Injection).

Tests for error-based and time-based blind SQL injection in:
- HTML form fields (POST)
- URL query parameters (GET)
"""
import time
from typing import List
from urllib.parse import urlparse, parse_qs

import requests
from .scanner_base import ScannerBase


class SQLiScanner(ScannerBase):
    """
    OWASP A03:2021 — Injection (SQL Injection)

    Techniques:
    - Error-based: Inject SQL syntax and look for database error messages in response
    - Time-based blind: Inject SLEEP()/WAITFOR DELAY and measure response time
    """

    # Database error signatures for error-based detection
    ERROR_SIGNATURES = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "microsoft ole db provider for sql server",
        "odbc microsoft access driver",
        "ora-01756",  # Oracle
        "ora-00933",  # Oracle
        "pg::syntaxerror",  # PostgreSQL
        "psql error",
        "sqlite_error",
        "sqlite error",
        "syntax error in query expression",
        "data type mismatch in criteria expression",
        "[microsoft][odbc",
        "[mysql][odbc",
        "supplied argument is not a valid mysql",
        "division by zero",
        "invalid use of null",
        "mysql_fetch",
        "num_rows",
    ]

    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "\" OR \"1\"=\"1",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "'; SELECT SLEEP(0)--",
        "1 AND 1=1",
        "1 AND 1=2",
    ]

    # Time-based payloads (look for response time > threshold)
    TIME_PAYLOADS = [
        "' OR SLEEP(5)-- -",
        "1'; WAITFOR DELAY '0:0:5'--",
        "'; SELECT pg_sleep(5)--",
        "1 UNION SELECT SLEEP(5)--",
    ]

    TIME_THRESHOLD = 4.0  # seconds

    def scan(self) -> List[dict]:
        """
        Run SQLi checks. Call this after setting self.forms and self.url_params
        via the orchestrator.
        """
        return self.findings

    def scan_forms(self, forms: List[dict]) -> List[dict]:
        """Test all discovered forms for SQL injection."""
        for form in forms:
            if form.get("method", "GET").upper() == "POST":
                findings = self._test_form_post(form)
            else:
                findings = self._test_form_get(form)
            self.findings.extend(findings)
        return self.findings

    def scan_url_params(self, url_params: List[dict]) -> List[dict]:
        """Test URL query parameters for SQL injection."""
        for param_info in url_params:
            findings = self._test_url_param(param_info)
            self.findings.extend(findings)
        return self.findings

    def _test_form_post(self, form: dict) -> List[dict]:
        """Test a POST form for SQLi."""
        results = []
        inputs = [i for i in form.get("inputs", []) if i.get("name")]
        if not inputs:
            return results

        for payload in self.ERROR_PAYLOADS:
            data = {inp["name"]: payload for inp in inputs}
            # Keep non-target fields with original values
            for inp in inputs:
                if inp["name"] not in data:
                    data[inp["name"]] = inp.get("value", "test")
            try:
                resp = self.session.post(
                    form["action"], data=data, timeout=self.timeout, allow_redirects=True
                )
                body_lower = resp.text.lower()
                for sig in self.ERROR_SIGNATURES:
                    if sig in body_lower:
                        param_names = ", ".join(i["name"] for i in inputs)
                        results.append(self._finding(
                            title="SQL Injection (Error-Based) in Form",
                            severity="CRITICAL",
                            description=(
                                f"A SQL error was returned when injecting into form fields: {param_names}. "
                                f"Error-based SQL injection allows attackers to extract database content."
                            ),
                            evidence=f"Payload: {payload!r} → Response contained: '{sig}'",
                            recommendation=(
                                "Use parameterized queries / prepared statements. "
                                "Never concatenate user input into SQL strings."
                            ),
                            owasp_id="A03:2021",
                            url=form["action"],
                            cwe_id="CWE-89",
                            parameter=param_names,
                            payload=payload,
                        ))
                        return results  # One finding per form is enough
            except requests.RequestException:
                continue

        # Time-based test
        for payload in self.TIME_PAYLOADS:
            data = {inp["name"]: payload for inp in inputs}
            try:
                start = time.time()
                self.session.post(form["action"], data=data,
                                  timeout=self.TIME_THRESHOLD + 3, allow_redirects=True)
                elapsed = time.time() - start
                if elapsed >= self.TIME_THRESHOLD:
                    param_names = ", ".join(i["name"] for i in inputs)
                    results.append(self._finding(
                        title="SQL Injection (Time-Based Blind) in Form",
                        severity="CRITICAL",
                        description=(
                            f"Response was delayed by {elapsed:.1f}s after injecting a time-delay payload "
                            f"into form fields: {param_names}. Indicates blind SQL injection."
                        ),
                        evidence=f"Payload: {payload!r} → Response time: {elapsed:.1f}s",
                        recommendation=(
                            "Use parameterized queries / prepared statements for all database queries."
                        ),
                        owasp_id="A03:2021",
                        url=form["action"],
                        cwe_id="CWE-89",
                        parameter=param_names,
                        payload=payload,
                    ))
                    return results
            except requests.Timeout:
                # Timeout itself may indicate SLEEP worked
                param_names = ", ".join(i["name"] for i in inputs)
                results.append(self._finding(
                    title="Possible SQL Injection (Time-Based — Request Timed Out)",
                    severity="HIGH",
                    description="Request timed out after injecting a time-delay payload.",
                    evidence=f"Payload: {payload!r} → Connection timeout",
                    recommendation="Use parameterized queries.",
                    owasp_id="A03:2021",
                    url=form["action"],
                    cwe_id="CWE-89",
                    parameter=param_names,
                    payload=payload,
                ))
                return results
            except requests.RequestException:
                continue

        return results

    def _test_form_get(self, form: dict) -> List[dict]:
        """Test a GET form by appending params to URL."""
        results = []
        inputs = [i for i in form.get("inputs", []) if i.get("name")]
        if not inputs:
            return results

        for payload in self.ERROR_PAYLOADS[:5]:  # Fewer payloads for GET
            params = {inp["name"]: payload for inp in inputs}
            try:
                resp = self.session.get(
                    form["action"], params=params, timeout=self.timeout
                )
                body_lower = resp.text.lower()
                for sig in self.ERROR_SIGNATURES:
                    if sig in body_lower:
                        results.append(self._finding(
                            title="SQL Injection (Error-Based) in GET Form",
                            severity="CRITICAL",
                            description="SQL error returned from GET form submission.",
                            evidence=f"Payload: {payload!r} → Response: '{sig}'",
                            recommendation="Use parameterized queries.",
                            owasp_id="A03:2021",
                            url=form["action"],
                            cwe_id="CWE-89",
                            payload=payload,
                        ))
                        return results
            except requests.RequestException:
                continue
        return results

    def _test_url_param(self, param_info: dict) -> List[dict]:
        """Test a URL parameter for SQLi."""
        results = []
        url = param_info["url"]
        param = param_info["param_name"]
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for payload in self.ERROR_PAYLOADS[:6]:
            test_params = dict(params)
            test_params[param] = [payload]
            try:
                resp = self.session.get(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    params={k: v[0] for k, v in test_params.items()},
                    timeout=self.timeout,
                )
                for sig in self.ERROR_SIGNATURES:
                    if sig in resp.text.lower():
                        results.append(self._finding(
                            title=f"SQL Injection (Error-Based) in URL Parameter '{param}'",
                            severity="CRITICAL",
                            description=f"SQL error returned when injecting into URL parameter '{param}'.",
                            evidence=f"Payload: {payload!r} → Response: '{sig}'",
                            recommendation="Use parameterized queries.",
                            owasp_id="A03:2021",
                            url=url,
                            cwe_id="CWE-89",
                            parameter=param,
                            payload=payload,
                        ))
                        return results
            except requests.RequestException:
                continue
        return results
