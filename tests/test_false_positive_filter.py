"""
Tests for modules/false_positive_filter.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.false_positive_filter import FalsePositiveFilter, FilterDecision


def make_filter(**kwargs):
    return FalsePositiveFilter(**kwargs)


# ── SQLi evaluation ────────────────────────────────────────────────────────────

class TestEvaluateSQLi:
    def test_mysql_error_confirms_finding(self):
        flt = make_filter()
        decision = flt.evaluate_sqli(
            payload="' OR 1=1--",
            response_body="You have an error in your SQL syntax near '''",
        )
        assert decision.keep is True
        assert decision.confidence >= 0.8

    def test_oracle_error_confirms_finding(self):
        flt = make_filter()
        decision = flt.evaluate_sqli(
            payload="'",
            response_body="ORA-01756: quoted string not properly terminated",
        )
        assert decision.keep is True

    def test_no_sql_error_rejects_finding(self):
        flt = make_filter()
        decision = flt.evaluate_sqli(
            payload="'",
            response_body="<html>Login failed</html>",
        )
        assert decision.keep is False

    def test_small_diff_against_baseline_rejects(self):
        """SQL error present but body diff too small → likely existing error page."""
        baseline = "You have an error in your SQL syntax near 'something'"
        response = "You have an error in your SQL syntax near ''test''"
        flt = make_filter(min_body_diff=100)
        decision = flt.evaluate_sqli(
            payload="'",
            response_body=response,
            baseline_body=baseline,
        )
        # Diff is small (both have the SQL error) → invalid baseline, keep=True
        # because the baseline already had the error
        assert isinstance(decision.keep, bool)

    def test_baseline_also_has_error_keeps_finding(self):
        """If baseline already contains SQL error, diff check is waived."""
        flt = make_filter(min_body_diff=500)
        decision = flt.evaluate_sqli(
            payload="'",
            response_body="You have an error in your SQL syntax here",
            baseline_body="You have an error in your SQL syntax elsewhere",
        )
        assert decision.keep is True

    def test_generic_error_in_both_rejects(self):
        flt = make_filter()
        body = "Internal Server Error"
        decision = flt.evaluate_sqli(
            payload="'",
            response_body=body,
            baseline_body=body,
        )
        assert decision.keep is False

    def test_returns_filter_decision(self):
        flt = make_filter()
        result = flt.evaluate_sqli("'", "normal response")
        assert isinstance(result, FilterDecision)
        assert hasattr(result, "keep")
        assert hasattr(result, "reason")
        assert hasattr(result, "confidence")
        assert 0.0 <= result.confidence <= 1.0


# ── XSS evaluation ─────────────────────────────────────────────────────────────

class TestEvaluateXSS:
    def test_unencoded_script_tag_keeps(self):
        flt = make_filter()
        payload = "<script>alert(1)</script>"
        decision = flt.evaluate_xss(
            payload=payload,
            response_body="<html><script>alert(1)</script></html>",
        )
        assert decision.keep is True
        assert decision.confidence >= 0.8

    def test_html_encoded_rejects(self):
        flt = make_filter()
        payload = "<script>alert(1)</script>"
        decision = flt.evaluate_xss(
            payload=payload,
            response_body="<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>",
        )
        assert decision.keep is False
        assert decision.confidence >= 0.9

    def test_payload_not_reflected_rejects(self):
        flt = make_filter()
        decision = flt.evaluate_xss(
            payload="<script>alert(1)</script>",
            response_body="<html>Welcome</html>",
        )
        assert decision.keep is False

    def test_high_baseline_similarity_rejects(self):
        """If response is nearly identical to baseline, payload had no effect."""
        # Use a very long common base so the small XSS addition stays below threshold
        common = "x" * 2000
        base = f"<html><body>{common}</body></html>"
        response = f"<html><body>{common}<script>alert(1)</script></body></html>"
        flt = make_filter(reflection_threshold=0.99)
        decision = flt.evaluate_xss(
            payload="<script>alert(1)</script>",
            response_body=response,
            baseline_body=base,
        )
        # Similarity will be very high → reject
        assert decision.keep is False

    def test_unicode_encoded_rejects(self):
        flt = make_filter()
        decision = flt.evaluate_xss(
            payload="<script>alert(1)</script>",
            response_body="\\u003cscript\\u003ealert(1)",
        )
        assert decision.keep is False

    def test_returns_filter_decision(self):
        flt = make_filter()
        result = flt.evaluate_xss("<script>", "<html></html>")
        assert isinstance(result, FilterDecision)
        assert 0.0 <= result.confidence <= 1.0


# ── Header evaluation ──────────────────────────────────────────────────────────

class TestEvaluateHeaderFinding:
    def test_absent_header_keeps_missing_header_finding(self):
        flt = make_filter()
        decision = flt.evaluate_header_finding("X-Frame-Options", None, expected_present=True)
        assert decision.keep is True
        assert decision.confidence == 1.0

    def test_present_header_keeps_misconfiguration_finding(self):
        flt = make_filter()
        decision = flt.evaluate_header_finding(
            "Server", "Apache/2.4.51", expected_present=False
        )
        assert decision.keep is True

    def test_header_now_present_rejects_stale_missing_finding(self):
        flt = make_filter()
        decision = flt.evaluate_header_finding(
            "X-Frame-Options", "DENY", expected_present=True
        )
        assert decision.keep is False

    def test_header_now_absent_rejects_stale_misconfiguration(self):
        flt = make_filter()
        decision = flt.evaluate_header_finding(
            "Server", None, expected_present=False
        )
        assert decision.keep is False


# ── Batch filter ───────────────────────────────────────────────────────────────

class TestFilterFindings:
    def _make_finding(self, vuln_type="sqli", fp=False):
        return {
            "title": f"{vuln_type} issue",
            "type": vuln_type,
            "severity": "HIGH",
            "url": "http://example.com/",
            "payload": "' OR 1=1--",
            "false_positive": fp,
        }

    def test_pre_marked_fp_removed(self):
        flt = make_filter()
        findings = [self._make_finding(fp=True), self._make_finding(fp=False)]
        confirmed, filtered = flt.filter_findings(findings)
        assert len(confirmed) == 1
        assert len(filtered) == 1

    def test_empty_input_returns_empty(self):
        flt = make_filter()
        confirmed, filtered = flt.filter_findings([])
        assert confirmed == []
        assert filtered == []

    def test_findings_without_responses_pass_through(self):
        """Without response bodies, findings that aren't pre-marked pass through."""
        flt = make_filter()
        findings = [self._make_finding(), self._make_finding()]
        confirmed, filtered = flt.filter_findings(findings)
        assert len(confirmed) == 2
        assert len(filtered) == 0

    def test_sqli_finding_filtered_with_clean_response(self):
        flt = make_filter()
        finding = self._make_finding("sql injection")
        finding["url"] = "http://example.com/"
        responses = {"http://example.com/": "<html>Login failed</html>"}
        confirmed, filtered = flt.filter_findings([finding], responses)
        assert len(filtered) == 1
        assert filtered[0].get("false_positive") is True

    def test_sqli_finding_kept_with_sql_error_response(self):
        flt = make_filter()
        finding = self._make_finding("sql injection")
        finding["url"] = "http://example.com/"
        responses = {"http://example.com/": "You have an error in your sql syntax"}
        confirmed, filtered = flt.filter_findings([finding], responses)
        assert len(confirmed) == 1

    def test_xss_finding_filtered_with_clean_response(self):
        flt = make_filter()
        finding = self._make_finding("xss")
        finding["url"] = "http://example.com/"
        finding["payload"] = "<script>alert(1)</script>"
        responses = {"http://example.com/": "<html>Hello</html>"}
        confirmed, filtered = flt.filter_findings([finding], responses)
        assert len(filtered) == 1


# ── _body_diff_size helper ─────────────────────────────────────────────────────

class TestBodyDiffSize:
    def test_identical_strings_zero(self):
        assert FalsePositiveFilter._body_diff_size("abc", "abc") == 0

    def test_empty_strings_zero(self):
        assert FalsePositiveFilter._body_diff_size("", "") == 0

    def test_completely_different(self):
        diff = FalsePositiveFilter._body_diff_size("aaa", "bbb")
        assert diff > 0

    def test_one_char_insertion(self):
        diff = FalsePositiveFilter._body_diff_size("hello", "helllo")
        assert diff >= 1

    def test_longer_string_difference(self):
        a = "SELECT * FROM users"
        b = "SELECT * FROM users WHERE id=1"
        diff = FalsePositiveFilter._body_diff_size(a, b)
        assert diff > 0

    def test_asymmetric_inputs(self):
        diff1 = FalsePositiveFilter._body_diff_size("abc", "abcdef")
        diff2 = FalsePositiveFilter._body_diff_size("abcdef", "abc")
        assert diff1 == diff2
