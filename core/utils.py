"""
core/utils.py — Shared utilities for the scanner platform.

Provides:
  - HTTP session factory
  - URL normalisation helpers
  - Coloured terminal output
  - Timing utilities
"""
import time
from urllib.parse import urlparse, urljoin
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Colours ───────────────────────────────────────────────────────────────────

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    C = {
        "red":     Fore.RED + Style.BRIGHT,
        "yellow":  Fore.YELLOW,
        "green":   Fore.GREEN,
        "cyan":    Fore.CYAN,
        "blue":    Fore.BLUE,
        "magenta": Fore.MAGENTA,
        "bold":    Style.BRIGHT,
        "reset":   Style.RESET_ALL,
    }
except ImportError:
    C = {k: "" for k in ("red", "yellow", "green", "cyan",
                          "blue", "magenta", "bold", "reset")}


def cprint(msg: str, colour: str = "reset") -> None:
    """Print a coloured message to stdout."""
    print(f"{C.get(colour, '')}{msg}{C['reset']}")


def severity_colour(sev: str) -> str:
    """Return the ANSI colour code for a severity level string."""
    return {
        "CRITICAL":      C["red"],
        "HIGH":          C["red"],
        "MEDIUM":        C["yellow"],
        "LOW":           C["green"],
        "INFORMATIONAL": C["cyan"],
    }.get(sev.upper(), C["reset"])


# ── HTTP session factory ──────────────────────────────────────────────────────

def make_session(
    cookies:    Optional[dict] = None,
    headers:    Optional[dict] = None,
    proxy:      Optional[str]  = None,
    verify_ssl: bool           = False,
    timeout:    int            = 10,
) -> requests.Session:
    """
    Create and configure a requests.Session.

    Args:
        cookies:    Dict of cookie name→value to inject.
        headers:    Dict of extra HTTP headers.
        proxy:      Optional HTTP/HTTPS proxy URL.
        verify_ssl: Whether to verify TLS certificates.
        timeout:    Default per-request timeout (stored on session for reference).

    Returns:
        Configured requests.Session instance.
    """
    session = requests.Session()
    session.verify = verify_ssl
    session.headers["User-Agent"] = (
        "WebVulnScanner/2.0 (authorized-security-testing)"
    )
    if cookies:
        session.cookies.update(cookies)
    if headers:
        session.headers.update(headers)
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    # Attach timeout as a custom attribute for convenience
    session._default_timeout = timeout  # type: ignore[attr-defined]
    return session


# ── URL helpers ───────────────────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    """Strip trailing slashes and ensure scheme is present."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def same_origin(url_a: str, url_b: str) -> bool:
    """Return True if both URLs share the same scheme and host."""
    a, b = urlparse(url_a), urlparse(url_b)
    return a.scheme == b.scheme and a.netloc == b.netloc


def absolute_url(base: str, href: str) -> str:
    """Resolve a potentially relative href against a base URL."""
    return urljoin(base, href)


# ── Timing ────────────────────────────────────────────────────────────────────

class Timer:
    """Simple wall-clock timer."""

    def __init__(self) -> None:
        self._start = time.time()

    def elapsed(self) -> float:
        """Return seconds elapsed since this Timer was created."""
        return time.time() - self._start

    def __str__(self) -> str:
        return f"{self.elapsed():.1f}s"
