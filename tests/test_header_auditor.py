"""
Tests for modules/header_auditor.py using mock HTTP responses.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import responses as resp_mock
import requests
from modules.header_auditor import HeaderAuditor


TARGET = "http://testapp.local"


def make_scanner(extra_headers=None):
    session = requests.Session()
    return HeaderAuditor(session=session, target_url=TARGET, verbose=False)


@resp_mock.activate
def test_missing_all_security_headers():
    """When no security headers are present, should find multiple issues."""
    resp_mock.add(resp_mock.GET, TARGET, body="<html></html>",
                  headers={"Content-Type": "text/html"}, status=200)
    scanner = make_scanner()
    findings = scanner.scan()
    titles = [f["title"] for f in findings]
    assert any("Strict-Transport-Security" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)


@resp_mock.activate
def test_server_header_leakage():
    """Server header revealing software version should be flagged."""
    resp_mock.add(resp_mock.GET, TARGET, body="<html></html>",
                  headers={
                      "Content-Type": "text/html",
                      "Server": "Apache/2.4.51 (Ubuntu)",
                  }, status=200)
    scanner = make_scanner()
    findings = scanner.scan()
    server_findings = [f for f in findings if "Server" in f["title"]]
    assert len(server_findings) >= 1
    assert server_findings[0]["severity"] == "LOW"


@resp_mock.activate
def test_weak_csp_flagged():
    """CSP with unsafe-inline should be flagged."""
    resp_mock.add(resp_mock.GET, TARGET, body="<html></html>",
                  headers={
                      "Content-Type": "text/html",
                      "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
                      "Strict-Transport-Security": "max-age=31536000",
                      "X-Content-Type-Options": "nosniff",
                      "X-Frame-Options": "DENY",
                      "Referrer-Policy": "strict-origin",
                      "Permissions-Policy": "geolocation=()",
                  }, status=200)
    scanner = make_scanner()
    findings = scanner.scan()
    csp_findings = [f for f in findings if "unsafe" in f["title"].lower() or "weak" in f["title"].lower()]
    assert len(csp_findings) >= 1


@resp_mock.activate
def test_all_headers_present_no_critical_findings():
    """When all security headers are properly set, no HIGH+ findings."""
    resp_mock.add(resp_mock.GET, TARGET, body="<html></html>",
                  headers={
                      "Content-Type": "text/html",
                      "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                      "X-Content-Type-Options": "nosniff",
                      "X-Frame-Options": "DENY",
                      "Content-Security-Policy": "default-src 'self'",
                      "Referrer-Policy": "strict-origin-when-cross-origin",
                      "Permissions-Policy": "geolocation=()",
                  }, status=200)
    scanner = make_scanner()
    findings = scanner.scan()
    high_or_crit = [f for f in findings if f["severity"] in ("HIGH", "CRITICAL")]
    assert len(high_or_crit) == 0


@resp_mock.activate
def test_finding_schema_valid():
    """Every finding must have required keys."""
    resp_mock.add(resp_mock.GET, TARGET, body="<html></html>",
                  headers={"Content-Type": "text/html"}, status=200)
    scanner = make_scanner()
    findings = scanner.scan()
    required_keys = {"title", "severity", "description", "evidence",
                     "recommendation", "owasp_id", "url"}
    for f in findings:
        missing = required_keys - set(f.keys())
        assert not missing, f"Finding missing keys: {missing}"
