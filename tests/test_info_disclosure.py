"""
Tests for modules/info_disclosure.py — baseline fingerprinting and content validation.
"""
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import responses as resp_mock
import requests
from modules.info_disclosure import InfoDisclosureScanner

TARGET = "http://testapp.local"
PROBE  = TARGET + "/this-path-does-not-exist-8f3a2b1c"
ANY    = re.compile(r"http://testapp\.local/.*")


def make_scanner():
    return InfoDisclosureScanner(session=requests.Session(), target_url=TARGET, verbose=False)


def _add_catchall_404():
    """Register a catch-all that returns 404 for every unregistered URL."""
    resp_mock.add(resp_mock.GET, ANY, body="", status=404)


# ── Baseline fingerprinting ────────────────────────────────────────────────────

@resp_mock.activate
def test_spa_catchall_suppressed():
    """SPA returning identical HTML for every URL must produce no file findings."""
    spa_html = "<html><body><div id='app'></div></body></html>"
    resp_mock.add(resp_mock.GET, ANY, body=spa_html, status=200)

    scanner = make_scanner()
    findings = scanner.scan()
    file_findings = [f for f in findings if "Sensitive File Exposed" in f["title"]]
    assert file_findings == [], f"Got: {[f['title'] for f in file_findings]}"


@resp_mock.activate
def test_real_env_file_detected():
    """A genuine .env file with KEY=VALUE content must be flagged CRITICAL."""
    baseline_body = "<html>404 Not Found</html>"
    env_body = "DATABASE_URL=postgres://user:pass@localhost/db\nSECRET_KEY=abc123\n"

    resp_mock.add(resp_mock.GET, PROBE, body=baseline_body, status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/.env", body=env_body, status=200)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    env_findings = [f for f in findings if "/.env" in f["title"]
                    and "Access Restricted" not in f["title"]]
    assert len(env_findings) == 1
    assert env_findings[0]["severity"] == "CRITICAL"
    assert "content validated" in env_findings[0]["evidence"]


@resp_mock.activate
def test_real_git_config_detected():
    """A real .git/config with [core] must be flagged HIGH."""
    baseline_body = "<html>Not found</html>"
    git_body = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"

    resp_mock.add(resp_mock.GET, PROBE, body=baseline_body, status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/.git/config", body=git_body, status=200)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    git_findings = [f for f in findings if "/.git/config" in f["title"]
                    and "Access Restricted" not in f["title"]]
    assert len(git_findings) == 1
    assert git_findings[0]["severity"] == "HIGH"


@resp_mock.activate
def test_sql_dump_detected():
    """A real SQL dump must be flagged CRITICAL."""
    baseline_body = "<html>Page not found</html>"
    sql_body = "-- MySQL dump\nCREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);\n"

    resp_mock.add(resp_mock.GET, PROBE, body=baseline_body, status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/db.sql", body=sql_body, status=200)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    sql_findings = [f for f in findings if "/db.sql" in f["title"]
                    and "Access Restricted" not in f["title"]]
    assert len(sql_findings) == 1
    assert sql_findings[0]["severity"] == "CRITICAL"


@resp_mock.activate
def test_env_body_without_key_value_suppressed():
    """Response on /.env that doesn't contain KEY=VALUE must be suppressed."""
    baseline_body = "<html>404</html>"
    fake_env = "<html><body>Welcome to my site</body></html>"

    resp_mock.add(resp_mock.GET, PROBE, body=baseline_body, status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/.env", body=fake_env, status=200)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    env_findings = [f for f in findings if "Sensitive File Exposed" in f["title"]
                    and "/.env" in f["title"]]
    assert env_findings == []


# ── Binary file content-type validation ───────────────────────────────────────

@resp_mock.activate
def test_html_content_type_for_zip_suppressed():
    """HTML body on /backup.zip (text/html Content-Type) must be skipped."""
    baseline_body = "<html>404</html>"
    different_html = "<html><body>Something completely different here</body></html>"

    resp_mock.add(resp_mock.GET, PROBE, body=baseline_body, status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/backup.zip",
                  body=different_html,
                  headers={"Content-Type": "text/html"}, status=200)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    zip_findings = [f for f in findings if "/backup.zip" in f["title"]
                    and "Sensitive File Exposed" in f["title"]]
    assert zip_findings == []


@resp_mock.activate
def test_zip_content_type_detected():
    """application/zip Content-Type on /backup.zip must be flagged CRITICAL."""
    baseline_body = "<html>404</html>"

    resp_mock.add(resp_mock.GET, PROBE, body=baseline_body, status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/backup.zip",
                  body=b"PK\x03\x04binary",
                  headers={"Content-Type": "application/zip"}, status=200)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    zip_findings = [f for f in findings if "/backup.zip" in f["title"]
                    and "Sensitive File Exposed" in f["title"]]
    assert len(zip_findings) == 1
    assert zip_findings[0]["severity"] == "CRITICAL"


# ── Near-identical size suppression ───────────────────────────────────────────

@resp_mock.activate
def test_near_identical_size_suppressed():
    """Response within 2% of baseline size is treated as a baseline match."""
    baseline_body = "A" * 1000
    # Same size, different chars — within 2% threshold, no KEY=VALUE content
    near_match = "B" * 1000

    resp_mock.add(resp_mock.GET, PROBE, body=baseline_body, status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/.env", body=near_match, status=200)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    env_findings = [f for f in findings if "Sensitive File Exposed" in f["title"]
                    and "/.env" in f["title"]]
    assert env_findings == []


# ── 403 handling ──────────────────────────────────────────────────────────────

@resp_mock.activate
def test_403_on_critical_path_flagged_low():
    """HTTP 403 on a CRITICAL path must produce a LOW severity finding."""
    resp_mock.add(resp_mock.GET, PROBE, body="<html>404</html>", status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/.env", body="Forbidden", status=403)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    forbidden = [f for f in findings if "Access Restricted" in f["title"] and "/.env" in f["title"]]
    assert len(forbidden) == 1
    assert forbidden[0]["severity"] == "LOW"


@resp_mock.activate
def test_403_on_low_severity_path_not_flagged():
    """HTTP 403 on a LOW-severity path (/.gitignore) must NOT produce a finding."""
    resp_mock.add(resp_mock.GET, PROBE, body="<html>404</html>", status=200)
    resp_mock.add(resp_mock.GET, TARGET + "/.gitignore", body="Forbidden", status=403)
    _add_catchall_404()

    scanner = make_scanner()
    findings = scanner.scan()
    git_forbidden = [f for f in findings if "/.gitignore" in f["title"]]
    assert git_forbidden == []


# ── Verbose error detection ────────────────────────────────────────────────────

@resp_mock.activate
def test_python_traceback_detected():
    """Python traceback in error response must be flagged MEDIUM."""
    tb_body = "Traceback (most recent call last):\n  File app.py, line 42, in view\nKeyError: 'x'"

    resp_mock.add(resp_mock.GET, PROBE, body="<html>404</html>", status=200)
    # All probes including the verbose-error test URLs return the traceback
    resp_mock.add(resp_mock.GET, ANY, body=tb_body, status=500)

    scanner = make_scanner()
    findings = scanner.scan()
    tb_findings = [f for f in findings if "Python stack trace" in f["title"]]
    assert len(tb_findings) >= 1
    assert tb_findings[0]["severity"] == "MEDIUM"
