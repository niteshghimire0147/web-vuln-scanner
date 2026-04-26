"""
modules/false_positive_filter.py — False-positive reduction for web vulnerability findings.

Problem: SQLi and XSS scanners can fire on application behaviours that aren't
actually exploitable — error messages that happen to contain SQL keywords,
form inputs that reflect arbitrary content by design, etc.

This module provides lightweight heuristic filtering applied after scanning
to reduce noise before findings reach the report.

Techniques:
  - Response body diff analysis (too-small diff = likely coincidental)
  - SQL error keyword presence validation (confirm actual DB error vs. app message)
  - XSS reflection confirmation (payload must appear unencoded in response)
  - Baseline response comparison (compare to non-payload request)
"""
from __future__ import annotations

import difflib
import html
import re
from dataclasses import dataclass
from typing import List, Optional

# ── SQL error fingerprints (must be present in response to confirm SQLi) ─────

_SQLI_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning:\s*mysql_", re.I),
    re.compile(r"ora-\d{5}", re.I),                            # Oracle
    re.compile(r"pg_query\(\)", re.I),                         # PostgreSQL
    re.compile(r"sqlite3\.operationalerror", re.I),            # SQLite
    re.compile(r"microsoft\s+(?:sql\s+server|ole\s+db)", re.I),
    re.compile(r"unclosed quotation mark", re.I),              # MSSQL
    re.compile(r"jdbc\s+exception", re.I),
    re.compile(r"db2\s+sql\s+error", re.I),
    re.compile(r"supplied argument is not a valid mysql", re.I),
]

# Generic "error occurred" messages that are NOT SQL errors
_GENERIC_ERROR_PATTERNS: list[re.Pattern] = [
    re.compile(r"internal server error", re.I),
    re.compile(r"an error has occurred", re.I),
    re.compile(r"something went wrong", re.I),
    re.compile(r"application error", re.I),
]

# ── XSS confirmation: these HTML-encoded forms mean the app is safe ──────────
_XSS_SAFE_ENCODINGS = [
    "&lt;script&gt;",
    "&lt;Script&gt;",
    "&#x3C;script",
    "\\u003cscript",
    "%3Cscript",
]


@dataclass
class FilterDecision:
    keep: bool              # True = genuine finding; False = likely FP
    reason: str             # Explanation for the decision
    confidence: float       # 0.0–1.0 (1.0 = very confident in decision)


class FalsePositiveFilter:
    """
    Heuristic false-positive filter for web vulnerability findings.

    Usage:
        flt = FalsePositiveFilter(min_body_diff=50, reflection_threshold=0.8)

        # For SQLi findings:
        decision = flt.evaluate_sqli(
            payload="' OR 1=1--",
            response_body=response.text,
            baseline_body=baseline.text,
        )
        if decision.keep:
            findings.append(finding)

        # For XSS findings:
        decision = flt.evaluate_xss(
            payload="<script>alert(1)</script>",
            response_body=response.text,
        )
    """

    def __init__(
        self,
        min_body_diff: int = 50,
        reflection_threshold: float = 0.8,
    ) -> None:
        self.min_body_diff = min_body_diff
        self.reflection_threshold = reflection_threshold

    # ── SQLi ──────────────────────────────────────────────────────────────────

    def evaluate_sqli(
        self,
        payload: str,
        response_body: str,
        baseline_body: Optional[str] = None,
    ) -> FilterDecision:
        """
        Evaluate whether a SQLi candidate response is a genuine finding.

        Rules:
        1. Response must contain a recognisable SQL error signature.
        2. If a baseline body is provided, the diff must exceed min_body_diff.
        3. Baseline responses that already contain SQL errors are invalid baselines.
        """
        # Rule 1: Require actual SQL error signature
        for pattern in _SQLI_ERROR_PATTERNS:
            if pattern.search(response_body):
                # Rule 2: Body diff check (skip if no baseline)
                if baseline_body is not None:
                    diff_size = self._body_diff_size(baseline_body, response_body)
                    if diff_size < self.min_body_diff:
                        # Check if baseline already had the error (invalid baseline)
                        baseline_has_error = any(p.search(baseline_body) for p in _SQLI_ERROR_PATTERNS)
                        if not baseline_has_error:
                            return FilterDecision(
                                keep=False,
                                reason=(
                                    f"SQL error pattern found but body diff is only {diff_size} bytes "
                                    f"(threshold: {self.min_body_diff}) — likely existing error page"
                                ),
                                confidence=0.7,
                            )

                return FilterDecision(
                    keep=True,
                    reason=f"Confirmed: SQL error pattern '{pattern.pattern[:40]}' in response",
                    confidence=0.9,
                )

        # No SQL error fingerprint found
        # Check if it's just a generic error — still worth keeping with lower confidence
        for pattern in _GENERIC_ERROR_PATTERNS:
            if pattern.search(response_body):
                if baseline_body and pattern.search(baseline_body):
                    return FilterDecision(
                        keep=False,
                        reason="Generic error present in both payload and baseline responses — not SQLi-specific",
                        confidence=0.8,
                    )

        # No error at all — check for time-based detection (body diff only)
        if baseline_body is not None:
            diff = self._body_diff_size(baseline_body, response_body)
            if diff < self.min_body_diff:
                return FilterDecision(
                    keep=False,
                    reason=(
                        f"No SQL error signature and body diff only {diff} bytes — likely false positive"
                    ),
                    confidence=0.85,
                )

        return FilterDecision(
            keep=False,
            reason="No SQL error signature detected in response",
            confidence=0.75,
        )

    # ── XSS ──────────────────────────────────────────────────────────────────

    def evaluate_xss(
        self,
        payload: str,
        response_body: str,
        baseline_body: Optional[str] = None,
    ) -> FilterDecision:
        """
        Evaluate whether an XSS candidate response is a genuine finding.

        Rules:
        1. Payload must appear unencoded in response (not HTML-escaped).
        2. Response similarity to baseline must be below reflection_threshold
           (too similar = payload had no effect on the page).
        3. Encoded versions of the payload (HTML entities, percent-encoding)
           indicate the application is properly escaping — not vulnerable.
        """
        # Rule 1: Check if payload appears encoded (safe encoding = not vulnerable)
        script_marker = "<script" if "<script" in payload.lower() else payload[:20]
        for safe_form in _XSS_SAFE_ENCODINGS:
            if safe_form.lower() in response_body.lower():
                return FilterDecision(
                    keep=False,
                    reason=f"Payload appears HTML-encoded in response ({safe_form[:20]}) — application escaping correctly",
                    confidence=0.95,
                )

        # Check if payload appears verbatim (unencoded) — this IS the vulnerability
        if script_marker.lower() in response_body.lower():
            # Rule 2: Baseline similarity check
            if baseline_body is not None:
                similarity = self._similarity(baseline_body, response_body)
                if similarity > self.reflection_threshold:
                    return FilterDecision(
                        keep=False,
                        reason=(
                            f"Payload reflected but response too similar to baseline "
                            f"(similarity {similarity:.0%} > {self.reflection_threshold:.0%}) — "
                            f"payload likely in non-executable context"
                        ),
                        confidence=0.65,
                    )

            return FilterDecision(
                keep=True,
                reason=f"Payload '{payload[:40]}' reflected unencoded in response",
                confidence=0.9,
            )

        # Payload not reflected at all
        return FilterDecision(
            keep=False,
            reason="Payload not reflected in response body",
            confidence=0.9,
        )

    # ── Header findings ───────────────────────────────────────────────────────

    def evaluate_header_finding(
        self,
        header_name: str,
        header_value: Optional[str],
        expected_present: bool,
    ) -> FilterDecision:
        """
        Validate security header findings.

        For missing-header findings: confirm the header truly isn't present.
        For misconfigured headers: confirm the value is genuinely weak.
        """
        if expected_present and not header_value:
            return FilterDecision(
                keep=True,
                reason=f"Header '{header_name}' confirmed absent",
                confidence=1.0,
            )
        if not expected_present and header_value:
            return FilterDecision(
                keep=True,
                reason=f"Header '{header_name}' present with value: {header_value[:60]}",
                confidence=1.0,
            )
        return FilterDecision(
            keep=False,
            reason=f"Header finding no longer reproducible (header={header_value})",
            confidence=0.9,
        )

    # ── Batch filter ──────────────────────────────────────────────────────────

    def filter_findings(
        self,
        findings: List[dict],
        responses: Optional[dict] = None,
    ) -> tuple[List[dict], List[dict]]:
        """
        Filter a list of finding dicts, returning (confirmed, filtered_out).

        If *responses* is provided it should map finding["url"] → response body.
        Without responses, findings that already carry false_positive=True are removed.
        """
        confirmed: List[dict] = []
        filtered_out: List[dict] = []

        for finding in findings:
            if finding.get("false_positive"):
                filtered_out.append(finding)
                continue

            if responses:
                url  = finding.get("url", "")
                body = responses.get(url, "")
                vuln_type = finding.get("type", finding.get("title", "")).lower()

                if "sqli" in vuln_type or "sql injection" in vuln_type:
                    decision = self.evaluate_sqli(
                        payload=finding.get("payload", ""),
                        response_body=body,
                    )
                    if not decision.keep:
                        finding["false_positive"] = True
                        finding["fp_reason"] = decision.reason
                        filtered_out.append(finding)
                        continue
                elif "xss" in vuln_type:
                    decision = self.evaluate_xss(
                        payload=finding.get("payload", ""),
                        response_body=body,
                    )
                    if not decision.keep:
                        finding["false_positive"] = True
                        finding["fp_reason"] = decision.reason
                        filtered_out.append(finding)
                        continue

            confirmed.append(finding)

        return confirmed, filtered_out

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _body_diff_size(a: str, b: str) -> int:
        """Return the number of characters that differ between two response bodies."""
        matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
        return sum(
            max(b2 - b1, d2 - d1)
            for tag, b1, b2, d1, d2 in matcher.get_opcodes()
            if tag != "equal"
        )

    @staticmethod
    def _similarity(a: str, b: str) -> float:
        """Return Gestalt sequence similarity ratio between two strings."""
        if not a and not b:
            return 1.0
        return difflib.SequenceMatcher(None, a[:2000], b[:2000]).ratio()
