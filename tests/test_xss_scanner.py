"""
Tests for modules/xss_scanner.py using mock HTTP responses.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import responses as resp_mock
import requests
from modules.xss_scanner import XSSScanner, XSS_MARKER

TARGET = "http://testapp.local"
FORM_URL = "http://testapp.local/search"
PARAM_URL = "http://testapp.local/page?q=hello"


def make_scanner():
    return XSSScanner(session=requests.Session(), target_url=TARGET, verbose=False)


def _make_post_form(inputs=None):
    if inputs is None:
        inputs = [{"name": "query", "type": "text"}]
    return {"action": FORM_URL, "method": "POST", "inputs": inputs}


def _make_get_form(inputs=None):
    if inputs is None:
        inputs = [{"name": "q", "type": "text"}]
    return {"action": FORM_URL, "method": "GET", "inputs": inputs}


# ── Reflected XSS — forms ──────────────────────────────────────────────────────

@resp_mock.activate
def test_post_form_xss_marker_reflected():
    """XSS marker in POST response triggers HIGH finding."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body=f'<html><body>Result: {XSS_MARKER}</body></html>',
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert len(findings) == 1
    assert findings[0]["severity"] in ("HIGH", "MEDIUM")
    assert "XSS" in findings[0]["title"]
    assert findings[0]["owasp_id"] == "A03:2021"
    assert findings[0]["cwe_id"] == "CWE-79"


@resp_mock.activate
def test_post_form_xss_in_script_context_is_high():
    """XSS marker inside a script tag should be HIGH severity."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body=f'<script>var x="{XSS_MARKER}"</script>',
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


@resp_mock.activate
def test_post_form_no_reflection_no_finding():
    """Response that doesn't reflect the marker yields no finding."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body="<html><body>No results found.</body></html>",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert findings == []


@resp_mock.activate
def test_get_form_xss_reflected():
    """GET form with reflected marker triggers finding."""
    resp_mock.add(resp_mock.GET, FORM_URL,
                  body=f"<html>You searched: {XSS_MARKER}</html>",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_get_form()])
    assert len(findings) >= 1


@resp_mock.activate
def test_form_hidden_inputs_skipped():
    """Hidden/submit inputs should not be tested."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body=f"{XSS_MARKER}",
                  status=200)
    scanner = make_scanner()
    hidden_form = _make_post_form(inputs=[
        {"name": "_csrf", "type": "hidden"},
        {"name": "submit", "type": "submit"},
    ])
    findings = scanner.scan_forms([hidden_form])
    # Hidden/submit are excluded so no testable inputs → no findings
    assert findings == []


@resp_mock.activate
def test_one_finding_per_form():
    """Scanner stops after first XSS hit per form."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body=f"<html>{XSS_MARKER}</html>",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert len(findings) == 1


# ── Reflected XSS — URL params ─────────────────────────────────────────────────

@resp_mock.activate
def test_url_param_xss_reflected():
    """XSS marker reflected via URL param triggers finding."""
    resp_mock.add(resp_mock.GET, "http://testapp.local/page",
                  body=f"<html>Page: {XSS_MARKER}</html>",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_url_params([{"url": PARAM_URL, "param_name": "q"}])
    assert len(findings) >= 1
    assert "q" in findings[0]["parameter"]
    assert findings[0]["severity"] == "HIGH"


@resp_mock.activate
def test_url_param_no_reflection():
    """URL param that does not reflect marker yields no finding."""
    resp_mock.add(resp_mock.GET, "http://testapp.local/page",
                  body="<html>Welcome</html>",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_url_params([{"url": PARAM_URL, "param_name": "q"}])
    assert findings == []


# ── Finding schema ─────────────────────────────────────────────────────────────

@resp_mock.activate
def test_finding_has_required_keys():
    """XSS findings must include all standardized keys."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body=f"<b>{XSS_MARKER}</b>",
                  status=200)
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert findings
    required = {"title", "severity", "description", "evidence",
                "recommendation", "owasp_id", "url", "payload"}
    for f in findings:
        missing = required - set(f.keys())
        assert not missing, f"Missing keys: {missing}"


# ── Network errors ─────────────────────────────────────────────────────────────

@resp_mock.activate
def test_connection_error_does_not_raise():
    """RequestException is swallowed; scan returns empty list."""
    resp_mock.add(resp_mock.POST, FORM_URL,
                  body=requests.exceptions.ConnectionError("refused"))
    scanner = make_scanner()
    findings = scanner.scan_forms([_make_post_form()])
    assert isinstance(findings, list)
