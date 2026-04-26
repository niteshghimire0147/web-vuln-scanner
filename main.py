"""
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
import argparse
from datetime import datetime
from urllib.parse import urlparse

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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="web-vuln-scanner",
        description=(
            "OWASP Web/API/AI Top 10 Vulnerability Scanner with "
            "CVSS v3.1 scoring and attack chain correlation.\n"
            "AUTHORIZED TESTING ONLY."
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
    parser.add_argument("--depth", type=int, default=2,
                        help="Crawler depth (default: 2)")
    parser.add_argument("--max-pages", type=int, default=50, dest="max_pages",
                        help="Maximum pages to crawl (default: 50)")

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
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {VERSION}")

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


if __name__ == "__main__":
    sys.exit(main())
