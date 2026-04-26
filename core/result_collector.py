"""
core/result_collector.py — Thread-safe finding aggregator and normaliser.

All scanner modules push their raw findings into ResultCollector, which
normalises the structure, deduplicates, applies CVSS scoring, and
provides filtered views for downstream consumers (report, attack chain).
"""
import hashlib
import threading
from datetime import datetime
from core.cvss import score_finding


# ── Canonical finding structure ───────────────────────────────────────────────

REQUIRED_KEYS = {
    "type", "endpoint", "severity", "payload", "evidence", "confidence"
}

SEVERITY_ORDER = {
    "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1, "INFO": 1
}


def _normalise(raw: dict) -> dict:
    """
    Ensure a finding dict has all required keys and consistent casing.
    Missing keys are filled with sensible defaults.
    """
    finding = {
        "type":        raw.get("type")        or raw.get("title", "Unknown"),
        "endpoint":    raw.get("endpoint")    or raw.get("url", ""),
        "severity":    (raw.get("severity", "INFORMATIONAL")).upper(),
        "payload":     raw.get("payload",    ""),
        "evidence":    raw.get("evidence",   ""),
        "confidence":  raw.get("confidence", "Medium"),
        "description": raw.get("description", ""),
        "recommendation": raw.get("recommendation", ""),
        "owasp_id":    raw.get("owasp_id",   ""),
        "cwe_id":      raw.get("cwe_id",     ""),
        "parameter":   raw.get("parameter",  ""),
        "module":      raw.get("module",     ""),
        "timestamp":   raw.get("timestamp",
                               datetime.utcnow().isoformat() + "Z"),
    }
    # Normalise severity aliases
    if finding["severity"] in ("INFO", "INFORMATIONAL"):
        finding["severity"] = "INFORMATIONAL"

    return finding


def _fingerprint(finding: dict) -> str:
    """
    Stable content hash used for deduplication.
    Two findings are duplicates if they share type + endpoint + parameter.
    """
    key = (
        finding.get("type", "").lower().strip()
        + "|" + finding.get("endpoint", "").strip()
        + "|" + finding.get("parameter", "").strip()
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ── Collector ─────────────────────────────────────────────────────────────────

class ResultCollector:
    """
    Centralised, thread-safe store for all scan findings.

    Findings are normalised, deduplicated by content fingerprint,
    CVSS-scored, and indexed by severity and module for fast retrieval.
    """

    def __init__(self) -> None:
        self._lock:        threading.Lock           = threading.Lock()
        self._findings:    dict[str, dict]          = {}   # fp → finding
        self._by_severity: dict[str, list[str]]     = {}   # severity → [fp]
        self._by_module:   dict[str, list[str]]     = {}   # module → [fp]

    # ── Ingestion ──────────────────────────────────────────────────────────

    def add(self, raw: dict, module: str = "") -> bool:
        """
        Normalise, deduplicate, and store a finding.
        Returns True if the finding was new, False if duplicate.
        """
        finding            = _normalise(raw)
        finding["module"]  = module or finding.get("module", "")
        fp                 = _fingerprint(finding)
        finding["fp"]      = fp

        with self._lock:
            if fp in self._findings:
                return False

            # CVSS scoring
            score_finding(finding)

            self._findings[fp] = finding

            sev = finding["severity"]
            self._by_severity.setdefault(sev, []).append(fp)

            mod = finding["module"]
            if mod:
                self._by_module.setdefault(mod, []).append(fp)

            return True

    def add_many(self, raws: list[dict], module: str = "") -> int:
        """Bulk ingest. Returns count of new (non-duplicate) findings."""
        return sum(1 for r in raws if self.add(r, module=module))

    # ── Retrieval ──────────────────────────────────────────────────────────

    def all(self) -> list[dict]:
        """Return all findings sorted by descending CVSS score."""
        with self._lock:
            items = list(self._findings.values())
        items.sort(
            key=lambda f: f.get("cvss", {}).get("cvss_score", 0),
            reverse=True,
        )
        return items

    def by_severity(self, severity: str) -> list[dict]:
        """Return findings filtered by severity (case-insensitive)."""
        sev = severity.upper()
        with self._lock:
            fps = self._by_severity.get(sev, [])
            return [self._findings[fp] for fp in fps if fp in self._findings]

    def by_module(self, module: str) -> list[dict]:
        """Return findings from a specific scanner module."""
        with self._lock:
            fps = self._by_module.get(module, [])
            return [self._findings[fp] for fp in fps if fp in self._findings]

    def critical_and_high(self) -> list[dict]:
        """Return only Critical and High severity findings."""
        return self.by_severity("CRITICAL") + self.by_severity("HIGH")

    def severity_counts(self) -> dict[str, int]:
        """Return a count of findings per severity level."""
        with self._lock:
            return {
                sev: len(fps)
                for sev, fps in self._by_severity.items()
            }

    def module_counts(self) -> dict[str, int]:
        """Return a count of findings per module."""
        with self._lock:
            return {
                mod: len(fps)
                for mod, fps in self._by_module.items()
            }

    def summary(self) -> dict:
        """Return a high-level scan result summary."""
        findings = self.all()
        scores   = [
            f["cvss"]["cvss_score"]
            for f in findings
            if "cvss" in f
        ]
        return {
            "total_findings": len(findings),
            "severity_counts": self.severity_counts(),
            "module_counts":   self.module_counts(),
            "max_cvss":        max(scores, default=0.0),
            "avg_cvss":        round(sum(scores) / len(scores), 2) if scores else 0.0,
        }

    def __len__(self) -> int:
        return len(self._findings)

    def __repr__(self) -> str:
        return f"ResultCollector({len(self)} findings)"
