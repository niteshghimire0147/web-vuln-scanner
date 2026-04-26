"""
core/scanner_engine.py — Multi-threaded Scanner Engine

Orchestrates all scanner modules using a ThreadPoolExecutor,
feeding each module the appropriate endpoint subset from
EndpointManager and collecting results into ResultCollector.

Each module adapter translates the new core API into the existing
modules/ interface so legacy code is preserved untouched.
"""
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import requests

from core.target          import Target
from core.endpoint_manager import EndpointManager, Endpoint
from core.result_collector import ResultCollector


# ── Module adapter type ────────────────────────────────────────────────────────
# A module adapter is a callable:
#   adapter(session, target, endpoints, collector, verbose) → None

ModuleAdapter = Callable[
    [requests.Session, Target, list[Endpoint], ResultCollector, bool],
    None,
]


# ── Built-in module adapters ───────────────────────────────────────────────────

def _adapt_header_auditor(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.header_auditor import HeaderAuditor
    scanner = HeaderAuditor(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    findings = scanner.scan()
    for f in findings:
        f["type"] = f.get("type") or f.get("title", "Header Issue")
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["payload"]  = f.get("payload", "")
        f["confidence"] = "High"
    collector.add_many(findings, module="headers")


def _adapt_info_disclosure(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.info_disclosure import InfoDisclosureScanner
    scanner = InfoDisclosureScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    findings = scanner.scan()
    for f in findings:
        f["type"] = f.get("type") or f.get("title", "Info Disclosure")
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["payload"]  = f.get("payload", "")
        f["confidence"] = "Medium"
    collector.add_many(findings, module="info")


def _adapt_sqli(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.sql_injection import SQLiScanner
    scanner = SQLiScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    forms      = _eps_to_forms(endpoints)
    url_params = _eps_to_url_params(endpoints)
    scanner.scan_forms(forms)
    scanner.scan_url_params(url_params)
    for f in scanner.findings:
        f["type"] = "SQL Injection"
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["confidence"] = "High"
    collector.add_many(scanner.findings, module="sqli")


def _adapt_xss(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.xss_scanner import XSSScanner
    scanner = XSSScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    forms      = _eps_to_forms(endpoints)
    url_params = _eps_to_url_params(endpoints)
    scanner.scan_forms(forms)
    scanner.scan_url_params(url_params)
    for f in scanner.findings:
        f["type"] = "XSS"
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["confidence"] = "High"
    collector.add_many(scanner.findings, module="xss")


def _adapt_bac(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.broken_access_control import BrokenAccessControlScanner
    scanner = BrokenAccessControlScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    findings = scanner.scan()
    scanner.scan_url_params(_eps_to_url_params(endpoints))
    all_f = findings + [
        f for f in scanner.findings if f not in findings
    ]
    for f in all_f:
        f["type"] = f.get("type") or f.get("title", "IDOR / BAC")
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["payload"]  = f.get("payload", "")
        f["confidence"] = "Medium"
    collector.add_many(all_f, module="bac")


def _adapt_crypto(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.cryptographic_failures import CryptographicFailuresScanner
    scanner = CryptographicFailuresScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    findings = scanner.scan()
    scanner.scan_url_params(_eps_to_url_params(endpoints))
    all_f = findings + [f for f in scanner.findings if f not in findings]
    for f in all_f:
        f["type"] = f.get("type") or f.get("title", "Cryptographic Failure")
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["payload"]  = f.get("payload", "")
        f["confidence"] = "High"
    collector.add_many(all_f, module="crypto")


def _adapt_auth(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.broken_auth_scanner import BrokenAuthScanner
    scanner = BrokenAuthScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    findings = scanner.scan()
    for f in findings:
        f["type"] = f.get("type") or f.get("title", "Broken Authentication")
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["payload"]  = f.get("payload", "")
        f["confidence"] = "High"
    collector.add_many(findings, module="auth")


def _adapt_ssrf(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.ssrf_scanner import SSRFScanner
    scanner = SSRFScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    findings = scanner.scan()
    scanner.scan_url_params(_eps_to_url_params(endpoints))
    all_f = findings + [f for f in scanner.findings if f not in findings]
    for f in all_f:
        f["type"] = f.get("type") or f.get("title", "SSRF")
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["confidence"] = "Medium"
    collector.add_many(all_f, module="ssrf")


def _adapt_api(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.api_scanner import APIScanner
    scanner = APIScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    findings = scanner.scan()
    for f in findings:
        f["type"] = f.get("type") or f.get("title", "API Vulnerability")
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["payload"]  = f.get("payload", "")
        f["confidence"] = "Medium"
    collector.add_many(findings, module="api")


def _adapt_ai(
    session: requests.Session,
    target: Target,
    endpoints: list[Endpoint],
    collector: ResultCollector,
    verbose: bool,
) -> None:
    from modules.ai_scanner import AIScanner
    scanner = AIScanner(
        session=session, target_url=target.url,
        verbose=verbose, timeout=target.timeout,
    )
    findings = scanner.scan()
    for f in findings:
        f["type"] = f.get("type") or f.get("title", "AI/LLM Vulnerability")
        f["endpoint"] = f.get("endpoint") or f.get("url", target.url)
        f["payload"]  = f.get("payload", "")
        f["confidence"] = "Low"
    collector.add_many(findings, module="ai")


# ── Module registry ────────────────────────────────────────────────────────────

MODULE_ADAPTERS: dict[str, ModuleAdapter] = {
    "headers": _adapt_header_auditor,
    "info":    _adapt_info_disclosure,
    "sqli":    _adapt_sqli,
    "xss":     _adapt_xss,
    "bac":     _adapt_bac,
    "crypto":  _adapt_crypto,
    "auth":    _adapt_auth,
    "ssrf":    _adapt_ssrf,
    "api":     _adapt_api,
    "ai":      _adapt_ai,
}


# ── Engine ─────────────────────────────────────────────────────────────────────

class ScannerEngine:
    """
    Runs all selected scanner modules in parallel using ThreadPoolExecutor.

    Each module runs in its own thread. Results are written into a shared
    ResultCollector which is thread-safe.
    """

    def __init__(
        self,
        target:    Target,
        manager:   EndpointManager,
        collector: ResultCollector,
        modules:   list[str],
        threads:   int  = 10,
        verbose:   bool = False,
    ) -> None:
        self.target    = target
        self.manager   = manager
        self.collector = collector
        self.modules   = modules
        self.threads   = threads
        self.verbose   = verbose
        self._session  = self._build_session()

    def run(self) -> None:
        """Execute all modules in parallel and wait for completion."""
        endpoints = self.manager.all()

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {}
            for module_name in self.modules:
                adapter = MODULE_ADAPTERS.get(module_name)
                if adapter is None:
                    continue
                future = pool.submit(
                    self._run_module,
                    module_name, adapter, endpoints,
                )
                futures[future] = module_name

            for future in as_completed(futures):
                module_name = futures[future]
                try:
                    future.result()
                    if self.verbose:
                        count = len(self.collector.by_module(module_name))
                        print(f"  [engine] {module_name:12s} ✓ "
                              f"({count} finding(s))")
                except Exception:
                    if self.verbose:
                        print(f"  [engine] {module_name:12s} ✗ (error)")
                        traceback.print_exc()

    def _run_module(
        self,
        name:      str,
        adapter:   ModuleAdapter,
        endpoints: list[Endpoint],
    ) -> None:
        """Invoke a single module adapter, catching all exceptions."""
        try:
            adapter(
                self._session, self.target,
                endpoints, self.collector, self.verbose,
            )
        except Exception as exc:
            # Log but do not propagate — other modules must continue
            if self.verbose:
                print(f"  [engine] Module '{name}' raised: {exc}")

    def _build_session(self) -> requests.Session:
        """Create a requests.Session configured from the Target."""
        session = requests.Session()
        cfg     = self.target.session_config()
        session.cookies.update(cfg["cookies"])
        session.headers["User-Agent"] = (
            "WebVulnScanner/2.0 (authorized-security-testing)"
        )
        session.headers.update(cfg["headers"])
        if cfg["proxies"]:
            session.proxies.update(cfg["proxies"])
        session.verify = cfg["verify"]
        return session


# ── Helper converters ──────────────────────────────────────────────────────────

def _eps_to_forms(endpoints: list[Endpoint]) -> list[dict]:
    """Convert Endpoint objects with form_data into the legacy form dict format."""
    forms = []
    for ep in endpoints:
        if ep.form_data:
            forms.append({
                "action":  ep.form_data.get("action", ep.url),
                "method":  ep.form_data.get("method", "POST"),
                "inputs":  ep.form_data.get("inputs", ep.params),
                "enctype": ep.form_data.get("enctype", "application/x-www-form-urlencoded"),
            })
    return forms


def _eps_to_url_params(endpoints: list[Endpoint]) -> list[dict]:
    """Convert Endpoint objects with query params into the legacy url_param format."""
    result = []
    for ep in endpoints:
        if ep.params and ep.method == "GET":
            result.append({"url": ep.url, "params": ep.params})
    return result
