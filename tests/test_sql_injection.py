"""
Tests for modules/sql_injection.py using mock HTTP responses.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import responses as resp_mock
import requests
from modules.sql_injection import SQLiScanner

TARGET = "http://testapp.local"
FORM_URL = "http://testapp.local/login"
PARAM_URL = "http://testapp.local/search?q=test"


def make_scanner():
    return SQLiScanner(session=requests.Session(), target_url=TARGET, verbose=False)


def _make_post_form(action=FORM_URL, inputs=None):
    if inputs is None:
        inputs = [{"name": "username", "type": "text"}, {"name": "password", "type": "password"}]
    return {"action": action, "method": "POST", "inputs": inputs}


def _make_get_form(action=FORM_URL, inputs=None):
    if inputs is None:
        inputs = [{"name": "search", "type": "text"}]
    return {"action": action, "method": "GET", "inputs": inputs}


# ── POST form — error-based ────────────────────────────────────────────────────

@resp_mock.activate
def test_post_form_sqli_mysql_error():
    """MySQL error in response triggers CRITICAL SQLi finding."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body="you have an error in your sql syntax near ''",
                  status=500)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert len(findings) == 1
    assert findings[0]["severity"] == "CRITICAL"
    assert "SQL Injection" in findings[0]["title"]
    assert findings[0]["owasp_id"] == "A03:2021"
    assert findings[0]["cwe_id"] == "CWE-89"


@resp_mock.activate
def test_post_form_sqli_oracle_error():
    """Oracle ORA- error signature triggers finding."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body="ORA-01756: quoted string not properly terminated",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert len(findings) >= 1
    assert findings[0]["severity"] == "CRITICAL"


@resp_mock.activate
def test_post_form_clean_response_no_finding():
    """Normal HTML response with no SQL errors yields no findings."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body="<html><body>Login failed</body></html>",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert findings == []


@resp_mock.activate
def test_post_form_no_inputs_skipped():
    """Forms with no named inputs are skipped."""
    resp_mock.add(resp_mock.POST, FORM_URL, body="", status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([{"action": FORM_URL, "method": "POST", "inputs": []}])
    assert findings == []


# ── GET form — error-based ─────────────────────────────────────────────────────

@resp_mock.activate
def test_get_form_sqli_mssql_error():
    """MSSQL error signature in GET form response triggers finding."""
    resp_mock.add(resp_mock.GET, FORM_URL,
                  body="Unclosed quotation mark after the character string",
                  status=500)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_get_form()])
    assert len(findings) >= 1
    assert findings[0]["severity"] == "CRITICAL"


# ── URL parameters ─────────────────────────────────────────────────────────────

@resp_mock.activate
def test_url_param_sqli_sqlite_error():
    """SQLite error in URL param response triggers finding."""
    resp_mock.add(resp_mock.GET, "http://testapp.local/search",
                  body="sqlite_error: unrecognized token",
                  status=500)
    scanner = make_scanner()
    findings = scanner.scan_url_params([{"url": PARAM_URL, "param_name": "q"}])
    assert len(findings) >= 1
    assert "q" in findings[0]["parameter"]


@resp_mock.activate
def test_url_param_clean_no_finding():
    """Clean URL param response yields no findings."""
    resp_mock.add(resp_mock.GET, "http://testapp.local/search",
                  body="<html>No results</html>",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_url_params([{"url": PARAM_URL, "param_name": "q"}])
    assert findings == []


# ── Finding schema ─────────────────────────────────────────────────────────────

@resp_mock.activate
def test_finding_has_required_keys():
    """SQLi findings must include all standardized keys."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body="you have an error in your sql syntax",
                  status=500)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert findings
    required = {"title", "severity", "description", "evidence",
                "recommendation", "owasp_id", "url", "payload"}
    for f in findings:
        missing = required - set(f.keys())
        assert not missing, f"Missing keys: {missing}"


@resp_mock.activate
def test_one_finding_per_form():
    """Scanner stops after first SQLi hit per form (no duplicate findings)."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body="you have an error in your sql syntax near '' at line 1",
                  status=500)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert len(findings) == 1


# ── Network errors are swallowed ───────────────────────────────────────────────

@resp_mock.activate
def test_connection_error_does_not_raise():
    """RequestException during scan should be swallowed, not propagated."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body=requests.exceptions.ConnectionError("refused"))
    scanner = make_scanner()
    # Should not raise
    findings = scanner.scan_forms([_make_post_form()])
    assert isinstance(findings, list)
