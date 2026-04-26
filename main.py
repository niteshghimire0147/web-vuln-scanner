"""
<<<<<<< HEAD
main.py — Web Vulnerability Scanner v2.0.0 — Master Orchestrator

Entry point for the full platform:
  OWASP Web Application Top 10 (2021)
  OWASP API Security Top 10 (2023)
  OWASP AI / LLM Top 10 (2025)

Integrates:
  core/crawler.py         — Enhanced crawler + EndpointManager population
  core/scanner_engine.py  — Multi-threaded module executor
  core/attack_chain.py    — Vulnerability correlation engine
  core/cvss.py            — Real CVSS v3.1 scoring
  core/report.py          — Professional HTML + JSON reporting
  core/auth.py            — Form-based authentication handler

AUTHORIZED TESTING ONLY — Always obtain written permission before scanning.
"""
import sys
import os
=======
main.py — Web Application Vulnerability Scanner v2.0.0

Scans web applications for:
  OWASP Web Application Top 10 (2021)
  OWASP API Security Top 10 (2023)
  OWASP AI Security Top 10 (2025)

AUTHORIZED TESTING ONLY — Always obtain written permission before scanning.

Usage:
    python main.py --url http://localhost:8080 --format html -v
    python main.py --url http://target.com --depth 2 --modules sqli,xss,headers,bac,crypto
    python main.py --url http://api.target.com --modules api,ai --format all
    python main.py --url http://target.com --cookie "PHPSESSID=abc123" -o report
"""
import sys
import os
import time
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a
import argparse
from datetime import datetime
from urllib.parse import urlparse

<<<<<<< HEAD
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.target           import Target
from core.crawler          import CoreCrawler
from core.endpoint_manager import EndpointManager
from core.scanner_engine   import ScannerEngine, MODULE_ADAPTERS
from core.result_collector import ResultCollector
from core.attack_chain     import AttackChainEngine
from core.report           import ReportGenerator
from core.auth             import AuthHandler
from core.utils            import cprint, Timer, normalise_url, severity_colour, C

VERSION = "2.0.0"

ALL_MODULES = list(MODULE_ADAPTERS.keys())

BANNER = f"""\
{C['cyan']}{C['bold']}
  ╔════════════════════════════════════════════════════════════════════╗
  ║   Web Application Vulnerability Scanner  v{VERSION}                  ║
  ║                                                                    ║
  ║   OWASP Web Top 10 (2021)  ·  API Top 10 (2023)                  ║
  ║   OWASP AI / LLM Top 10 (2025)  ·  CVSS v3.1 Scoring            ║
  ║   Attack Chain Correlation  ·  Multi-threaded Engine              ║
  ║                                                                    ║
  ║   *** AUTHORIZED TESTING ONLY ***                                 ║
  ╚════════════════════════════════════════════════════════════════════╝
{C['reset']}"""
=======
sys.path.insert(0, os.path.dirname(__file__))

import requests
from modules.crawler                import WebCrawler
from modules.header_auditor         import HeaderAuditor
from modules.sql_injection          import SQLiScanner
from modules.xss_scanner            import XSSScanner
from modules.info_disclosure        import InfoDisclosureScanner
from modules.false_positive_filter  import FalsePositiveFilter
from modules.broken_access_control  import BrokenAccessControlScanner
from modules.cryptographic_failures import CryptographicFailuresScanner
from modules.ssrf_scanner           import SSRFScanner
from modules.broken_auth_scanner    import BrokenAuthScanner
from modules.api_scanner            import APIScanner
from modules.ai_scanner             import AIScanner
from utils.logger  import get_logger, configure_root
from utils.config  import load_config
from utils.mitre   import get_dict as mitre_get

log = get_logger(__name__)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C_GREEN   = Fore.GREEN
    C_RED     = Fore.RED
    C_YELLOW  = Fore.YELLOW
    C_CYAN    = Fore.CYAN
    C_BOLD    = Style.BRIGHT
    C_RESET   = Style.RESET_ALL
    C_MAGENTA = Fore.MAGENTA
    C_BLUE    = Fore.BLUE
except ImportError:
    C_GREEN = C_RED = C_YELLOW = C_CYAN = C_BOLD = C_RESET = C_MAGENTA = C_BLUE = ""

VERSION = "2.0.0"
BANNER = f"""\
{C_CYAN}{C_BOLD}
  ╔══════════════════════════════════════════════════════════════════╗
  ║       Web Application Vulnerability Scanner  v{VERSION}            ║
  ║                                                                  ║
  ║  OWASP Web Top 10 (2021) · OWASP API Top 10 (2023)             ║
  ║  OWASP AI / LLM Top 10 (2025)                                  ║
  ║                                                                  ║
  ║  *** AUTHORIZED TESTING ONLY ***                                ║
  ╚══════════════════════════════════════════════════════════════════╝
{C_RESET}"""

SEVERITY_COLORS = {
    "CRITICAL":      C_RED + C_BOLD,
    "HIGH":          C_RED,
    "MEDIUM":        C_YELLOW,
    "LOW":           C_GREEN,
    "INFORMATIONAL": C_CYAN,
}

ALL_MODULES = [
    "headers",
    "info",
    "sqli",
    "xss",
    "bac",
    "crypto",
    "auth",
    "ssrf",
    "api",
    "ai",
]

MODULE_LABELS = {
    "headers": "Security Headers (A05:2021)",
    "info":    "Information Disclosure (A05:2021)",
    "sqli":    "SQL Injection (A03:2021)",
    "xss":     "Cross-Site Scripting (A03:2021)",
    "bac":     "Broken Access Control (A01:2021)",
    "crypto":  "Cryptographic Failures (A02:2021)",
    "auth":    "Broken Authentication (A07:2021)",
    "ssrf":    "SSRF (A10:2021)",
    "api":     "API Security Top 10 (2023)",
    "ai":      "AI / LLM Top 10 (2025)",
}

_MITRE_KEYWORD_MAP = {
    "sql":    "sql_injection",
    "xss":    "xss",
    "header": "info_disclosure",
    "info":   "info_disclosure",
    "path":   "path_traversal",
    "idor":   "info_disclosure",
    "ssrf":   "info_disclosure",
    "jwt":    "info_disclosure",
    "api":    "info_disclosure",
    "llm":    "info_disclosure",
}


def build_session(args: argparse.Namespace) -> requests.Session:
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": (
            f"WebVulnScanner/{VERSION} (authorized-security-testing)"
        ),
    })
    if args.cookie:
        for cookie in args.cookie.split(";"):
            if "=" in cookie:
                name, _, value = cookie.strip().partition("=")
                session.cookies.set(name.strip(), value.strip())
    if args.header:
        for h in args.header:
            if ":" in h:
                name, _, value = h.partition(":")
                session.headers[name.strip()] = value.strip()
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
    return session


def _phase(n: int, total: int, label: str) -> None:
    print(f"{C_CYAN}[{n}/{total}] {label}...{C_RESET}")


def _phase_result(count: int) -> None:
    colour = C_RED if count else C_GREEN
    noun   = "issue" if count == 1 else "issues"
    print(f"      {colour}Found {count} {noun}{C_RESET}")


def _print_summary(findings: list, elapsed: float) -> None:
    counts: dict = {}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1

    print()
    print(f"{C_BOLD}{'=' * 60}{C_RESET}")
    print(f"{C_BOLD}  Scan Summary{C_RESET}")
    print(f"{'─' * 60}")
    print(f"  Total findings : {len(findings)}")
    print(f"  Elapsed time   : {elapsed:.1f}s")
    print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        c = counts.get(sev, 0)
        if c:
            color = SEVERITY_COLORS.get(sev, "")
            print(f"  {color}{sev:<15}{c}{C_RESET}")
    print(f"{C_BOLD}{'=' * 60}{C_RESET}")
    print()


def run_scan(args: argparse.Namespace) -> int:
    print(BANNER)
    log.info("Target : %s", args.url)
    log.info("Modules: %s", ", ".join(args.modules))
    print()

    session       = build_session(args)
    all_findings  = []
    start_time    = time.time()
    total_phases  = len(args.modules) + (1 if any(
        m in args.modules for m in ("sqli", "xss", "bac", "ssrf")
    ) else 0)
    phase = 0

    common_opts = dict(
        session=session,
        target_url=args.url,
        verbose=args.verbose,
        timeout=args.timeout,
        delay=args.delay,
    )

    if "headers" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["headers"])
        scanner = HeaderAuditor(**common_opts)
        findings = scanner.scan()
        all_findings.extend(findings)
        _phase_result(len(findings))

    if "info" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["info"])
        scanner = InfoDisclosureScanner(**common_opts)
        findings = scanner.scan()
        all_findings.extend(findings)
        _phase_result(len(findings))

    if "bac" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["bac"])
        scanner = BrokenAccessControlScanner(**common_opts)
        findings = scanner.scan()
        all_findings.extend(findings)
        _phase_result(len(findings))

    if "crypto" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["crypto"])
        scanner = CryptographicFailuresScanner(**common_opts)
        findings = scanner.scan()
        all_findings.extend(findings)
        _phase_result(len(findings))

    if "auth" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["auth"])
        scanner = BrokenAuthScanner(**common_opts)
        findings = scanner.scan()
        all_findings.extend(findings)
        _phase_result(len(findings))

    if "ssrf" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["ssrf"])
        scanner = SSRFScanner(**common_opts)
        findings = scanner.scan()
        all_findings.extend(findings)
        _phase_result(len(findings))

    if "api" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["api"])
        scanner = APIScanner(**common_opts)
        findings = scanner.scan()
        all_findings.extend(findings)
        _phase_result(len(findings))

    if "ai" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["ai"])
        scanner = AIScanner(**common_opts)
        findings = scanner.scan()
        all_findings.extend(findings)
        _phase_result(len(findings))

    # Crawler (feeds SQLi, XSS, BAC URL params, SSRF params)
    forms      = []
    url_params = []
    needs_crawl = any(m in args.modules for m in ("sqli", "xss", "bac", "ssrf"))
    if needs_crawl:
        phase += 1
        _phase(phase, total_phases, "Crawler")
        crawler = WebCrawler(
            base_url=args.url,
            session=session,
            max_depth=args.depth,
            max_pages=args.max_pages,
            timeout=args.timeout,
            delay=args.delay,
            verbose=args.verbose,
        )
        urls, forms = crawler.crawl()
        url_params  = crawler.extract_url_params(urls)
        print(f"      {C_GREEN}Discovered {len(urls)} URL(s), "
              f"{len(forms)} form(s), "
              f"{len(url_params)} URL parameter(s){C_RESET}")

    if "sqli" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["sqli"])
        scanner = SQLiScanner(**common_opts)
        scanner.scan_forms(forms)
        scanner.scan_url_params(url_params)
        all_findings.extend(scanner.findings)
        _phase_result(len(scanner.findings))

    if "xss" in args.modules:
        phase += 1
        _phase(phase, total_phases, MODULE_LABELS["xss"])
        scanner = XSSScanner(**common_opts)
        scanner.scan_forms(forms)
        scanner.scan_url_params(url_params)
        all_findings.extend(scanner.findings)
        _phase_result(len(scanner.findings))

    if "bac" in args.modules and url_params:
        bac = BrokenAccessControlScanner(**common_opts)
        bac.scan_url_params(url_params)
        all_findings.extend(bac.findings)

    if "ssrf" in args.modules and url_params:
        ssrf = SSRFScanner(**common_opts)
        ssrf.scan_url_params(url_params)
        all_findings.extend(ssrf.findings)

    if "crypto" in args.modules and url_params:
        crypto = CryptographicFailuresScanner(**common_opts)
        crypto.scan_url_params(url_params)
        all_findings.extend(crypto.findings)

    elapsed = time.time() - start_time

    # Attach MITRE ATT&CK context
    for f in all_findings:
        title_lower = f.get("title", "").lower()
        for keyword, mitre_key in _MITRE_KEYWORD_MAP.items():
            if keyword in title_lower:
                mitre_data = mitre_get(mitre_key)
                if mitre_data:
                    f.setdefault("mitre", mitre_data)
                break

    # False-positive filtering
    cfg = load_config()
    if cfg.get("false_positive.enabled", True):
        fp_filter = FalsePositiveFilter(
            min_body_diff=cfg.get("false_positive.min_body_diff_bytes", 50),
            reflection_threshold=cfg.get("false_positive.reflection_threshold", 0.8),
        )
        confirmed, filtered_out = fp_filter.filter_findings(all_findings)
        if filtered_out:
            log.debug("FP filter removed %d finding(s)", len(filtered_out))
        all_findings = confirmed

    _print_summary(all_findings, elapsed)
    _write_output(all_findings, args)

    return 1 if any(
        f["severity"] in ("CRITICAL", "HIGH") for f in all_findings
    ) else 0


def _default_output_base(target_url: str) -> str:
    hostname = urlparse(target_url).hostname or "target"
    hostname = hostname.replace(":", "_").replace("/", "_")
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, f"scan_{hostname}_{ts}")


def _write_output(findings: list, args: argparse.Namespace) -> None:
    from reporter import JsonReporter, HtmlReporter, MarkdownReporter
    fmt  = args.format
    base = args.output if args.output else _default_output_base(args.url)
    data = {
        "target":          args.url,
        "modules":         args.modules,
        "scanner_version": VERSION,
        "timestamp":       datetime.now().isoformat(),
        "total_findings":  len(findings),
        "findings":        findings,
    }
    if fmt in ("json", "all"):
        path = JsonReporter().save(data, f"{base}.json")
        log.info("%s[+] JSON  : %s%s", C_GREEN, path, C_RESET)
    if fmt in ("html", "all"):
        path = HtmlReporter().save(data, f"{base}.html")
        log.info("%s[+] HTML  : %s%s", C_GREEN, path, C_RESET)
    if fmt in ("text", "markdown", "all"):
        path = MarkdownReporter().save(data, f"{base}.md")
        log.info("%s[+] MD    : %s%s", C_GREEN, path, C_RESET)
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-vuln-scanner",
        description=(
<<<<<<< HEAD
            "OWASP Web/API/AI Top 10 Vulnerability Scanner with "
            "CVSS v3.1 scoring and attack chain correlation.\n"
            "AUTHORIZED TESTING ONLY."
=======
            "OWASP Web Top 10 (2021) · API Top 10 (2023) · AI Top 10 (2025)\n"
            "AUTHORIZED TESTING ONLY"
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Modules:
  headers  Security headers             (OWASP A05:2021)
  info     Information disclosure       (OWASP A05:2021)
  sqli     SQL Injection                (OWASP A03:2021)
  xss      Cross-Site Scripting         (OWASP A03:2021)
  bac      Broken Access Control / IDOR (OWASP A01:2021)
  crypto   Cryptographic Failures       (OWASP A02:2021)
  auth     Broken Authentication / JWT  (OWASP A07:2021)
  ssrf     Server-Side Request Forgery  (OWASP A10:2021)
  api      API Security Top 10 (2023)
  ai       AI / LLM Top 10 (2025)

Examples:
  python main.py --url http://localhost:8080 -v --format html
<<<<<<< HEAD
  python main.py --url http://target.com --modules sqli,xss,bac --threads 15
  python main.py --url http://api.target.com --modules api,ai,ssrf --format all
  python main.py --url http://target.com --login-url http://target.com/login \\
                 --username admin --password admin123 --format all
  python main.py --url http://target.com --proxy http://127.0.0.1:8080 -v
        """
    )

    # Target
    parser.add_argument("--url", "-u", required=True,
                        help="Target URL (e.g. http://localhost:8080)")

    # Module selection
    parser.add_argument("--modules", default="all",
                        help=(f"Comma-separated modules. "
                              f"Options: {','.join(ALL_MODULES)} (default: all)"))

    # Crawler settings
=======
  python main.py --url http://dvwa.local --cookie "security=low; PHPSESSID=abc"
  python main.py --url http://api.target.com --modules api,ai,ssrf
  python main.py --url http://target.com --modules all --depth 3 --max-pages 100
  python main.py --url http://target.com --proxy http://127.0.0.1:8080 --format all
        """
    )
    parser.add_argument("--url", "-u", required=True,
                        help="Target URL")
    parser.add_argument("--modules", default="all",
                        help=f"Comma-separated modules. Options: {','.join(ALL_MODULES)}")
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a
    parser.add_argument("--depth", type=int, default=2,
                        help="Crawler depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=50, dest="max_pages",
                        help="Maximum pages to crawl (default: 50)")
<<<<<<< HEAD

    # Performance
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of scanner threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay between requests in seconds (default: 0)")

    # Authentication
    parser.add_argument("--login-url",
                        help="Login page URL for form-based authentication")
    parser.add_argument("--username",
                        help="Username for form-based login")
    parser.add_argument("--password",
                        help="Password for form-based login")
    parser.add_argument("--cookie",
                        help="Session cookie string (e.g. 'PHPSESSID=abc; role=admin')")
    parser.add_argument("--token",
                        help="Bearer or API token to inject as Authorization header")

    # Network
    parser.add_argument("--proxy",
                        help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--header", action="append", metavar="NAME:VALUE",
                        help="Extra HTTP header (repeatable)")
    parser.add_argument("--no-verify-ssl", action="store_true", dest="no_verify_ssl",
                        help="Disable SSL certificate verification (default: disabled)")

    # Output
    parser.add_argument("-o", "--output",
                        help="Output file base path (default: output/scan_<host>_<ts>)")
    parser.add_argument("--format", choices=["html", "json", "all"],
                        default="html", help="Output format (default: html)")

    # Misc
=======
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--cookie",
                        help="Session cookies (e.g. 'PHPSESSID=abc; role=admin')")
    parser.add_argument("--header", action="append", metavar="NAME:VALUE",
                        help="Extra HTTP header (repeatable)")
    parser.add_argument("--proxy",
                        help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output",
                        help="Output base path (default: output/scan_<host>_<ts>)")
    parser.add_argument("--format", choices=["html", "json", "text", "all"],
                        default="html", help="Output format (default: html)")
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION}")
<<<<<<< HEAD

    return parser


def parse_modules(modules_arg: str) -> list[str]:
    if modules_arg.lower() == "all":
        return list(ALL_MODULES)
    mods = [m.strip().lower() for m in modules_arg.split(",")]
    invalid = set(mods) - set(ALL_MODULES)
    if invalid:
        cprint(f"[!] Unknown modules: {invalid}. Valid: {ALL_MODULES}", "red")
        sys.exit(1)
    return mods


def build_extra_headers(header_args: list | None) -> dict:
    headers = {}
    for h in (header_args or []):
        if ":" in h:
            name, _, value = h.partition(":")
            headers[name.strip()] = value.strip()
    return headers


def default_output_base(target_url: str) -> str:
    hostname = urlparse(target_url).hostname or "target"
    hostname = hostname.replace(":", "_").replace("/", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, f"scan_{hostname}_{ts}")


def print_summary(findings: list[dict], chains: list[dict], timer: Timer) -> None:
    counts: dict = {}
    for f in findings:
        s = f.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    print()
    cprint("=" * 64, "cyan")
    cprint("  Scan Complete", "bold")
    cprint("─" * 64, "cyan")
    print(f"  Total findings  : {len(findings)}")
    print(f"  Attack chains   : {len(chains)}")
    print(f"  Elapsed time    : {timer}")
    print()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        c = counts.get(sev, 0)
        if c:
            col = severity_colour(sev)
            print(f"  {col}{sev:<15}{c}{C['reset']}")
    cprint("=" * 64, "cyan")
    print()


def run(args: argparse.Namespace) -> int:
    print(BANNER)
    timer = Timer()

    url = normalise_url(args.url)
    cprint(f"[*] Target  : {url}", "cyan")
    cprint(f"[*] Modules : {', '.join(args.modules)}", "cyan")
    cprint(f"[*] Threads : {args.threads}", "cyan")
    print()

    # ── 1. Build Target ────────────────────────────────────────────────────
    extra_headers = build_extra_headers(args.header)
    target = Target(
        url=url,
        proxy=args.proxy,
        headers=extra_headers,
        timeout=args.timeout,
        verify_ssl=False,
    )

    # ── 2. Authentication ──────────────────────────────────────────────────
    session = requests.Session()
    session.verify = False
    session.headers["User-Agent"] = (
        f"WebVulnScanner/{VERSION} (authorized-security-testing)"
    )
    session.headers.update(extra_headers)
    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}

    auth = AuthHandler(
        session=session,
        login_url=getattr(args, "login_url", None),
        username=getattr(args, "username", None),
        password=getattr(args, "password", None),
        cookie_string=args.cookie,
        token=getattr(args, "token", None),
        timeout=args.timeout,
    )
    if auth.authenticate():
        target.cookies = dict(session.cookies)
        cprint(f"[+] Authenticated via {auth.auth_method}", "green")
    else:
        cprint("[*] Proceeding unauthenticated", "yellow")

    # ── 3. Crawl ───────────────────────────────────────────────────────────
    manager = EndpointManager()
    cprint("[*] Phase 1/4 — Crawling target...", "cyan")
    crawler = CoreCrawler(
        target=target,
        manager=manager,
        max_depth=args.depth,
        max_pages=args.max_pages,
        delay=args.delay,
        timeout=args.timeout,
        verbose=args.verbose,
    )
    crawler.crawl()
    stats = manager.stats()
    cprint(
        f"[+] Discovered {stats['total']} endpoints "
        f"({stats['forms']} forms, {stats['api']} API, "
        f"{stats['with_params']} with params)",
        "green",
    )
    print()

    # ── 4. Multi-threaded Scanning ─────────────────────────────────────────
    collector = ResultCollector()
    cprint(f"[*] Phase 2/4 — Scanning ({args.threads} threads)...", "cyan")
    engine = ScannerEngine(
        target=target,
        manager=manager,
        collector=collector,
        modules=args.modules,
        threads=args.threads,
        verbose=args.verbose,
    )
    engine.run()
    cprint(f"[+] Scanner complete — {len(collector)} raw findings", "green")
    print()

    # ── 5. Attack Chain Correlation ────────────────────────────────────────
    cprint("[*] Phase 3/4 — Correlating attack chains...", "cyan")
    chain_engine = AttackChainEngine()
    chains = chain_engine.correlate(collector.all())
    cprint(f"[+] Identified {len(chains)} attack chain(s)", "green")
    print()

    # ── 6. Reporting ───────────────────────────────────────────────────────
    cprint("[*] Phase 4/4 — Generating reports...", "cyan")
    findings = collector.all()
    base = args.output if args.output else default_output_base(url)

    reporter = ReportGenerator(
        target_url=url,
        findings=findings,
        chains=chains,
        modules=args.modules,
        elapsed=timer.elapsed(),
        scanner_version=VERSION,
    )

    if args.format in ("html", "all"):
        path = reporter.save_html(f"{base}.html")
        cprint(f"[+] HTML report : {path}", "green")

    if args.format in ("json", "all"):
        path = reporter.save_json(f"{base}.json")
        cprint(f"[+] JSON report : {path}", "green")

    # ── 7. Summary ─────────────────────────────────────────────────────────
    print_summary(findings, chains, timer)

    # Exit code: 1 if any Critical or High findings, else 0 (CI/CD friendly)
    return 1 if any(
        f.get("severity") in ("CRITICAL", "HIGH") for f in findings
    ) else 0


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    args.modules = parse_modules(args.modules)
    return run(args)
=======
    return parser


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()
    configure_root(verbose=args.verbose)

    if args.modules.lower() == "all":
        args.modules = list(ALL_MODULES)
    else:
        args.modules = [m.strip().lower() for m in args.modules.split(",")]
        invalid = set(args.modules) - set(ALL_MODULES)
        if invalid:
            log.error("Unknown modules: %s. Valid: %s", invalid, ALL_MODULES)
            return 1

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return run_scan(args)
>>>>>>> 39f622aba47790ca42e684935d893356126fa41a


if __name__ == "__main__":
    sys.exit(main())
