"""
core/attack_chain.py — Attack Chain Correlation Engine

Correlates individual vulnerability findings into multi-step attack
chains that represent higher-level business risk.

Design:
  - Rules are defined as ChainRule objects in CHAIN_RULES.
  - Each rule specifies required vulnerability-type keywords and
    optional exclusion keywords.
  - New rules can be appended to CHAIN_RULES without modifying
    any other code — the engine iterates the registry at runtime.
  - Each matched chain is enriched with the contributing findings
    and a CVSS-based aggregate risk rating.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


# ── Rule definition ────────────────────────────────────────────────────────────

@dataclass
class ChainRule:
    """
    Defines one attack-chain correlation rule.

    Attributes:
        name:           Human-readable chain name.
        description:    Narrative description of the combined risk.
        risk:           Aggregate risk level (Critical / High / Medium).
        must_match:     ALL of these keyword sets must be satisfied.
                        Each element is a set of alternative keywords —
                        at least ONE keyword in the set must appear in
                        a finding's 'type' or 'title' (case-insensitive).
        may_not_match:  If any of these keywords appear in any finding,
                        this rule does NOT fire (veto condition).
        min_findings:   Minimum number of distinct contributing findings.
        owasp_refs:     Relevant OWASP identifiers.
        mitre_refs:     Relevant MITRE ATT&CK technique IDs.
        recommendation: Remediation guidance for the chain.
        extra_check:    Optional callable(findings_list) → bool for
                        complex matching logic that cannot be expressed
                        as simple keyword matching.
    """
    name:           str
    description:    str
    risk:           str                        = "High"
    must_match:     list[set[str]]             = field(default_factory=list)
    may_not_match:  set[str]                   = field(default_factory=set)
    min_findings:   int                        = 2
    owasp_refs:     list[str]                  = field(default_factory=list)
    mitre_refs:     list[str]                  = field(default_factory=list)
    recommendation: str                        = ""
    extra_check:    Optional[Callable]         = field(default=None, repr=False)


# ── Rule registry (extensible — append to add new rules) ──────────────────────

CHAIN_RULES: list[ChainRule] = [

    ChainRule(
        name="Session Hijacking via XSS",
        description=(
            "A reflected or stored XSS vulnerability exists alongside "
            "cookies that lack the HttpOnly flag. An attacker can inject "
            "JavaScript that reads the session cookie and exfiltrates it "
            "to an attacker-controlled server, achieving full account takeover."
        ),
        risk="Critical",
        must_match=[
            {"xss", "cross-site scripting"},
            {"httponly", "cookie", "session"},
        ],
        owasp_refs=["A03:2021", "A02:2021"],
        mitre_refs=["T1539"],
        recommendation=(
            "Set HttpOnly and Secure flags on all session cookies. "
            "Implement a Content-Security-Policy that restricts script sources. "
            "Encode all user-supplied output contextually."
        ),
    ),

    ChainRule(
        name="Sensitive Data Exposure via IDOR",
        description=(
            "Insecure Direct Object Reference combined with missing or broken "
            "authentication allows an attacker to enumerate resource identifiers "
            "and access other users' sensitive data without authorisation."
        ),
        risk="Critical",
        must_match=[
            {"idor", "broken object", "object level"},
            {"auth", "authentication", "missing auth", "no auth", "unauthenticated"},
        ],
        owasp_refs=["A01:2021", "A07:2021"],
        mitre_refs=["T1530"],
        recommendation=(
            "Enforce object-level authorisation on every API and page endpoint. "
            "Verify the authenticated user owns the requested resource before "
            "returning any data. Use non-sequential, opaque resource identifiers."
        ),
    ),

    ChainRule(
        name="Cloud Credential Exposure via SSRF",
        description=(
            "Server-Side Request Forgery reaching a cloud metadata endpoint "
            "(e.g., AWS IMDSv1, GCP, Azure) enables an attacker to retrieve "
            "IAM credentials or access tokens, granting direct cloud API access."
        ),
        risk="Critical",
        must_match=[
            {"ssrf", "server-side request forgery", "server side request"},
            {"metadata", "cloud", "169.254", "imds", "credential"},
        ],
        owasp_refs=["A10:2021"],
        mitre_refs=["T1552.005"],
        recommendation=(
            "Block server-side requests to RFC-1918 and link-local ranges at "
            "the network layer. Require IMDSv2 (token-based) on AWS. Validate "
            "and allowlist all user-supplied URLs."
        ),
    ),

    ChainRule(
        name="Authentication Bypass via SQL Injection",
        description=(
            "A SQL injection vulnerability in a login or authentication endpoint "
            "allows an attacker to bypass password validation entirely, achieving "
            "unauthenticated administrative access."
        ),
        risk="Critical",
        must_match=[
            {"sql injection", "sqli", "sql"},
            {"login", "auth", "sign in", "password", "credential"},
        ],
        owasp_refs=["A03:2021", "A07:2021"],
        mitre_refs=["T1190", "T1078"],
        recommendation=(
            "Use parameterised queries or prepared statements exclusively. "
            "Implement account lockout and MFA on all authentication endpoints. "
            "Apply input validation as a defence-in-depth measure."
        ),
    ),

    ChainRule(
        name="Full Account Takeover via Broken Auth + Weak Session",
        description=(
            "Broken authentication (e.g., missing lockout, default credentials) "
            "combined with weak session tokens (short entropy or no expiry) "
            "creates a multi-vector path to complete account takeover."
        ),
        risk="Critical",
        must_match=[
            {"broken auth", "default cred", "no lockout", "authentication failure"},
            {"jwt", "session", "token", "cookie", "no expiry", "exp"},
        ],
        owasp_refs=["A07:2021"],
        mitre_refs=["T1110", "T1539"],
        recommendation=(
            "Enforce account lockout, MFA, and strong password policies. "
            "Use short-lived JWTs with mandatory exp claims and implement "
            "refresh token rotation. Invalidate sessions on logout."
        ),
    ),

    ChainRule(
        name="AI Prompt Injection Leading to Data Exfiltration",
        description=(
            "A prompt injection vulnerability in an LLM-powered endpoint, "
            "combined with the AI having access to sensitive data sources, "
            "allows an attacker to exfiltrate confidential information via "
            "crafted prompts that override system instructions."
        ),
        risk="Critical",
        must_match=[
            {"prompt injection", "llm", "ai", "llm01"},
            {"sensitive", "disclosure", "data", "exfiltrat", "llm06"},
        ],
        owasp_refs=["LLM01:2025", "LLM06:2025"],
        mitre_refs=["T1530"],
        recommendation=(
            "Treat all user input as untrusted in LLM pipelines. "
            "Implement an output validation layer. Apply data minimisation "
            "to RAG context. Use a guard model to detect policy violations."
        ),
    ),

    ChainRule(
        name="Stored XSS Leading to Malware Distribution",
        description=(
            "A stored XSS vulnerability in content visible to many users "
            "combined with missing Content-Security-Policy allows an attacker "
            "to inject malicious scripts that execute for every visitor, "
            "enabling credential harvesting or drive-by malware distribution."
        ),
        risk="High",
        must_match=[
            {"xss", "cross-site scripting"},
            {"csp", "content-security-policy", "content security policy"},
        ],
        owasp_refs=["A03:2021", "A05:2021"],
        mitre_refs=["T1059.007"],
        recommendation=(
            "Deploy a strict Content-Security-Policy header. "
            "HTML-encode all user-supplied content at output. "
            "Implement server-side output filtering."
        ),
    ),

    ChainRule(
        name="Path Traversal to Remote Code Execution",
        description=(
            "A path traversal vulnerability combined with a writable upload "
            "endpoint or log-poisoning vector may allow an attacker to "
            "read server configuration files and subsequently achieve "
            "remote code execution."
        ),
        risk="Critical",
        must_match=[
            {"path traversal", "directory traversal", "lfi"},
            {"upload", "file write", "log", "include", "rce"},
        ],
        owasp_refs=["A01:2021"],
        mitre_refs=["T1190"],
        recommendation=(
            "Resolve canonical paths and enforce base-directory constraints. "
            "Never construct file paths from user input. "
            "Disable dangerous PHP include functions. "
            "Restrict upload directories to be non-executable."
        ),
    ),

    ChainRule(
        name="API Key Leakage Leading to Service Compromise",
        description=(
            "An exposed API key or credential in an HTTP response, combined "
            "with an API endpoint lacking authentication, allows an attacker "
            "to directly invoke privileged API operations."
        ),
        risk="High",
        must_match=[
            {"api key", "credential", "secret", "token exposed"},
            {"api", "endpoint", "unauthenticated", "no auth"},
        ],
        owasp_refs=["A02:2021", "API2:2023"],
        mitre_refs=["T1552"],
        recommendation=(
            "Rotate all exposed credentials immediately. "
            "Store secrets in a vault (e.g., HashiCorp Vault, AWS Secrets Manager). "
            "Require authentication on all API endpoints."
        ),
    ),

    ChainRule(
        name="Insecure Cryptography + Data Transmission Risk",
        description=(
            "Sensitive data is transmitted over HTTP (no encryption) while "
            "session cookies lack the Secure flag, allowing a network-level "
            "attacker to intercept both credentials and session tokens in cleartext."
        ),
        risk="High",
        must_match=[
            {"http", "plaintext", "no https", "missing hsts", "no encryption"},
            {"secure flag", "cookie", "session"},
        ],
        owasp_refs=["A02:2021"],
        mitre_refs=["T1040"],
        recommendation=(
            "Enforce HTTPS with HSTS. Set the Secure flag on all cookies. "
            "Redirect all HTTP traffic to HTTPS at the load-balancer level."
        ),
    ),
]


# ── Engine ─────────────────────────────────────────────────────────────────────

class AttackChainEngine:
    """
    Correlates individual findings into multi-step attack chains
    by evaluating findings against the registered CHAIN_RULES.

    New correlation rules can be added at runtime via register_rule().
    """

    def __init__(self, rules: Optional[list[ChainRule]] = None) -> None:
        self._rules: list[ChainRule] = list(rules or CHAIN_RULES)

    def register_rule(self, rule: ChainRule) -> None:
        """Register a new correlation rule at runtime."""
        self._rules.append(rule)

    def correlate(self, findings: list[dict]) -> list[dict]:
        """
        Evaluate all findings against the rule registry.

        Args:
            findings: List of normalised finding dicts from ResultCollector.

        Returns:
            List of attack chain dicts:
            {
                "chain":            str,
                "description":      str,
                "risk":             str,
                "related_findings": [finding, ...],
                "owasp_refs":       [str, ...],
                "mitre_refs":       [str, ...],
                "recommendation":   str,
            }
        """
        chains = []

        # Pre-compute lowercase text fields for each finding
        finding_texts = [
            self._finding_text(f) for f in findings
        ]

        for rule in self._rules:
            matched_findings = self._evaluate_rule(rule, findings, finding_texts)

            if len(matched_findings) >= rule.min_findings:
                # Run optional extra check
                if rule.extra_check and not rule.extra_check(matched_findings):
                    continue

                chains.append({
                    "chain":            rule.name,
                    "description":      rule.description,
                    "risk":             rule.risk,
                    "related_findings": matched_findings,
                    "owasp_refs":       rule.owasp_refs,
                    "mitre_refs":       rule.mitre_refs,
                    "recommendation":   rule.recommendation,
                })

        return chains

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _finding_text(finding: dict) -> str:
        """Concatenate all text fields of a finding for keyword matching."""
        return " ".join([
            finding.get("type",        ""),
            finding.get("title",       ""),
            finding.get("description", ""),
            finding.get("evidence",    ""),
            finding.get("owasp_id",    ""),
            finding.get("cwe_id",      ""),
        ]).lower()

    def _evaluate_rule(
        self,
        rule: ChainRule,
        findings: list[dict],
        texts: list[str],
    ) -> list[dict]:
        """
        Determine which findings contribute to satisfying the given rule.

        Returns the contributing findings if all must_match sets are
        satisfied and no may_not_match keyword is present.
        """
        all_text = " ".join(texts)

        # Veto check: if any excluded keyword is present, skip the rule
        for veto_kw in rule.may_not_match:
            if veto_kw.lower() in all_text:
                return []

        # Each must_match set must have at least one keyword present
        for kw_set in rule.must_match:
            if not any(kw.lower() in all_text for kw in kw_set):
                return []

        # Collect the specific findings that contributed
        contributing = []
        for finding, text in zip(findings, texts):
            for kw_set in rule.must_match:
                if any(kw.lower() in text for kw in kw_set):
                    if finding not in contributing:
                        contributing.append(finding)

        return contributing
