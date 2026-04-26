"""
core/cvss.py — Real CVSS v3.1 Base Score Calculator

Implements the full NIST NVD CVSS v3.1 formula:
https://www.first.org/cvss/v3.1/specification-document

No scores are hardcoded. All values are derived from the metric weights
and the published formulae for ISC, Exploitability, and Base Score.
"""
import math
from dataclasses import dataclass


# ── Metric weight tables (CVSS v3.1 Specification §7.1) ──────────────────────

AV_WEIGHTS = {
    "N": 0.85,   # Network
    "A": 0.62,   # Adjacent
    "L": 0.55,   # Local
    "P": 0.20,   # Physical
}

AC_WEIGHTS = {
    "L": 0.77,   # Low
    "H": 0.44,   # High
}

# PR weights differ when Scope=Changed (S=C)
PR_WEIGHTS_UNCHANGED = {
    "N": 0.85,   # None
    "L": 0.62,   # Low
    "H": 0.27,   # High
}
PR_WEIGHTS_CHANGED = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.50,
}

UI_WEIGHTS = {
    "N": 0.85,   # None
    "R": 0.62,   # Required
}

CIA_WEIGHTS = {
    "N": 0.00,   # None
    "L": 0.22,   # Low
    "H": 0.56,   # High
}

SEVERITY_THRESHOLDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "None"),
]


# ── Metric input dataclass ────────────────────────────────────────────────────

@dataclass
class CVSSMetrics:
    """
    CVSS v3.1 base metric set.

    All values use the single-letter codes from the specification:
      AV: N | A | L | P
      AC: L | H
      PR: N | L | H
      UI: N | R
      S:  U | C   (Scope: Unchanged | Changed)
      C:  N | L | H
      I:  N | L | H
      A:  N | L | H
    """
    AV: str = "N"   # Attack Vector
    AC: str = "L"   # Attack Complexity
    PR: str = "N"   # Privileges Required
    UI: str = "N"   # User Interaction
    S:  str = "U"   # Scope
    C:  str = "N"   # Confidentiality Impact
    I:  str = "N"   # Integrity Impact
    A:  str = "N"   # Availability Impact

    def validate(self) -> None:
        """Raise ValueError if any metric code is invalid."""
        checks = [
            ("AV", self.AV, AV_WEIGHTS),
            ("AC", self.AC, AC_WEIGHTS),
            ("PR", self.PR, PR_WEIGHTS_UNCHANGED),
            ("UI", self.UI, UI_WEIGHTS),
            ("S",  self.S,  {"U": True, "C": True}),
            ("C",  self.C,  CIA_WEIGHTS),
            ("I",  self.I,  CIA_WEIGHTS),
            ("A",  self.A,  CIA_WEIGHTS),
        ]
        for name, val, valid in checks:
            if val not in valid:
                raise ValueError(
                    f"Invalid CVSS metric {name}={val!r}. "
                    f"Valid options: {list(valid.keys())}"
                )


# ── Roundup function (CVSS specification §7.4) ────────────────────────────────

def _roundup(value: float) -> float:
    """
    CVSS Roundup: ceiling to 1 decimal place.
    Equivalent to: smallest value ≥ input with exactly 1 decimal digit.
    """
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10


# ── Main scoring function ─────────────────────────────────────────────────────

def calculate(metrics: CVSSMetrics) -> dict:
    """
    Compute the CVSS v3.1 Base Score from the given metric set.

    Returns:
        {
            "cvss_score":        float,  # 0.0 – 10.0
            "severity":          str,    # None | Low | Medium | High | Critical
            "impact_score":      float,
            "exploitability":    float,
            "vector_string":     str,    # CVSS:3.1/AV:X/AC:X/...
            "metrics":           dict,   # input metrics echoed back
        }
    """
    metrics.validate()

    scope_changed = metrics.S == "C"

    # Numeric metric values
    av = AV_WEIGHTS[metrics.AV]
    ac = AC_WEIGHTS[metrics.AC]
    pr = (PR_WEIGHTS_CHANGED if scope_changed else PR_WEIGHTS_UNCHANGED)[metrics.PR]
    ui = UI_WEIGHTS[metrics.UI]
    c  = CIA_WEIGHTS[metrics.C]
    i  = CIA_WEIGHTS[metrics.I]
    a  = CIA_WEIGHTS[metrics.A]

    # ISC_Base = 1 - (1-C)(1-I)(1-A)
    isc_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

    # Impact Sub-Score
    if scope_changed:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
    else:
        isc = 6.42 * isc_base

    # Exploitability Sub-Score
    exploitability = 8.22 * av * ac * pr * ui

    # Base Score
    if isc <= 0:
        base_score = 0.0
    elif scope_changed:
        base_score = _roundup(min(1.08 * (isc + exploitability), 10.0))
    else:
        base_score = _roundup(min(isc + exploitability, 10.0))

    # Severity label
    severity = "None"
    for threshold, label in SEVERITY_THRESHOLDS:
        if base_score >= threshold:
            severity = label
            break

    # CVSS vector string
    vector = (
        f"CVSS:3.1/AV:{metrics.AV}/AC:{metrics.AC}/PR:{metrics.PR}"
        f"/UI:{metrics.UI}/S:{metrics.S}/C:{metrics.C}/I:{metrics.I}/A:{metrics.A}"
    )

    return {
        "cvss_score":     base_score,
        "severity":       severity,
        "impact_score":   round(isc, 2),
        "exploitability": round(exploitability, 2),
        "vector_string":  vector,
        "metrics": {
            "AV": metrics.AV, "AC": metrics.AC, "PR": metrics.PR,
            "UI": metrics.UI, "S": metrics.S,
            "C": metrics.C, "I": metrics.I, "A": metrics.A,
        },
    }


# ── Convenience presets for common vulnerability types ────────────────────────
# These are starting points only — adjust per finding as needed.

PRESETS: dict[str, CVSSMetrics] = {
    "sqli_critical": CVSSMetrics(
        AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"
    ),
    "sqli_auth_required": CVSSMetrics(
        AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="N"
    ),
    "xss_reflected": CVSSMetrics(
        AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"
    ),
    "xss_stored": CVSSMetrics(
        AV="N", AC="L", PR="L", UI="R", S="C", C="L", I="L", A="N"
    ),
    "idor": CVSSMetrics(
        AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="L", A="N"
    ),
    "ssrf_cloud_metadata": CVSSMetrics(
        AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"
    ),
    "broken_auth": CVSSMetrics(
        AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="N"
    ),
    "missing_hsts": CVSSMetrics(
        AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="L", A="N"
    ),
    "info_disclosure": CVSSMetrics(
        AV="N", AC="L", PR="N", UI="N", S="U", C="L", I="N", A="N"
    ),
    "api_bola": CVSSMetrics(
        AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="L", A="N"
    ),
    "prompt_injection": CVSSMetrics(
        AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="N"
    ),
}


def score_from_preset(preset_key: str) -> dict:
    """Calculate a CVSS score using a named preset."""
    if preset_key not in PRESETS:
        raise KeyError(
            f"Unknown preset '{preset_key}'. "
            f"Available: {list(PRESETS.keys())}"
        )
    return calculate(PRESETS[preset_key])


def score_finding(finding: dict) -> dict:
    """
    Auto-assign a CVSS score to a finding dict based on its 'type' field.
    Adds 'cvss' key to the finding in-place and returns it.
    """
    vuln_type = finding.get("type", "").lower()

    # Map finding types to CVSS preset keys
    type_to_preset = {
        "sql injection":             "sqli_critical",
        "sqli":                      "sqli_critical",
        "sql":                       "sqli_critical",
        "xss":                       "xss_reflected",
        "cross-site scripting":      "xss_reflected",
        "idor":                      "idor",
        "broken object":             "idor",
        "ssrf":                      "ssrf_cloud_metadata",
        "server-side request":       "ssrf_cloud_metadata",
        "broken auth":               "broken_auth",
        "authentication":            "broken_auth",
        "jwt":                       "broken_auth",
        "hsts":                      "missing_hsts",
        "header":                    "missing_hsts",
        "information disclosure":    "info_disclosure",
        "api":                       "api_bola",
        "bola":                      "api_bola",
        "prompt injection":          "prompt_injection",
        "llm":                       "prompt_injection",
    }

    preset_key = "info_disclosure"  # default
    for key, preset in type_to_preset.items():
        if key in vuln_type:
            preset_key = preset
            break

    finding["cvss"] = score_from_preset(preset_key)
    return finding
