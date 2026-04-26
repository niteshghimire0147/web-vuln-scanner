"""
scanner_base.py — Abstract base class for all OWASP scanner modules.

Every scanner inherits from ScannerBase and implements scan().
"""
from abc import ABC, abstractmethod
from typing import List, Optional
import requests


class ScannerBase(ABC):
    """
    Abstract base class for all web vulnerability scanner modules.

    Each module scans for one OWASP Top 10 category and returns a
    standardized list of finding dictionaries.
    """

    def __init__(
        self,
        session: requests.Session,
        target_url: str,
        verbose: bool = False,
        timeout: int = 10,
        delay: float = 0.0,
    ):
        """
        Args:
            session: Shared requests.Session (with cookies, headers, auth).
            target_url: Base URL of the target.
            verbose: If True, print progress to stdout.
            timeout: HTTP request timeout in seconds.
            delay: Seconds to sleep between requests (rate limiting).
        """
        self.session = session
        self.target = target_url.rstrip("/")
        self.verbose = verbose
        self.timeout = timeout
        self.delay = delay
        self.findings: List[dict] = []

    @abstractmethod
    def scan(self) -> List[dict]:
        """
        Run all checks for this scanner module.

        Returns:
            List of finding dicts with standardized keys.
        """

    def _finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: str,
        recommendation: str,
        owasp_id: str,
        url: Optional[str] = None,
        cwe_id: str = "",
        parameter: str = "",
        payload: str = "",
    ) -> dict:
        """
        Create a standardized finding dictionary.

        Args:
            title: Short finding title.
            severity: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
            description: Detailed technical description.
            evidence: Proof — what was observed (response snippet, timing, etc.).
            recommendation: How to fix the issue.
            owasp_id: OWASP Top 10 identifier (e.g. "A03:2021").
            url: Specific URL where the issue was found (defaults to target).
            cwe_id: CWE identifier (e.g. "CWE-89").
            parameter: The parameter/field that was tested.
            payload: The payload that triggered the issue.

        Returns:
            Standardized finding dict.
        """
        return {
            "title": title,
            "severity": severity.upper(),
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
            "owasp_id": owasp_id,
            "url": url or self.target,
            "cwe_id": cwe_id,
            "parameter": parameter,
            "payload": payload,
        }

    def _log(self, msg: str) -> None:
        """Print a verbose progress message if verbose mode is on."""
        if self.verbose:
            print(f"  [*] {msg}")
