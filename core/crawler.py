"""
core/crawler.py — Enhanced Crawler Engine (core layer)

Wraps and extends the existing modules/crawler.py with:
  - Integration with EndpointManager
  - Structured Endpoint creation from discovered URLs and forms
  - API endpoint detection heuristics
  - Configurable scope enforcement via Target
"""
import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, urljoin

import requests
from bs4 import BeautifulSoup

from core.target import Target
from core.endpoint_manager import Endpoint, EndpointManager


# ── API detection heuristics ──────────────────────────────────────────────────

API_PATH_PATTERNS = [
    "/api/", "/rest/", "/v1/", "/v2/", "/v3/",
    "/graphql", "/service/", "/services/",
]

JSON_CONTENT_TYPES = [
    "application/json", "application/ld+json",
    "application/vnd.api+json",
]


class CoreCrawler:
    """
    Crawls a target web application and populates an EndpointManager
    with every discovered URL, form, and parameter surface.

    Args:
        target:     Target object describing the scan target.
        manager:    EndpointManager to populate.
        max_depth:  Maximum link-following depth (default 2).
        max_pages:  Maximum number of unique pages to visit (default 50).
        delay:      Seconds between requests (default 0).
        timeout:    Per-request timeout in seconds (default 10).
        verbose:    Print discovery progress if True.
    """

    def __init__(
        self,
        target:    Target,
        manager:   EndpointManager,
        max_depth: int   = 2,
        max_pages: int   = 50,
        delay:     float = 0.0,
        timeout:   int   = 10,
        verbose:   bool  = False,
    ) -> None:
        self.target    = target
        self.manager   = manager
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.delay     = delay
        self.timeout   = timeout
        self.verbose   = verbose

        self._session  = self._build_session()
        self._visited: set[str] = set()

    # ── Public ────────────────────────────────────────────────────────────

    def crawl(self) -> int:
        """
        Start crawling from target.url.
        Returns the total number of new endpoints registered.
        """
        self._log(f"Starting crawl: {self.target.url} "
                  f"(depth={self.max_depth}, max={self.max_pages})")
        total = self._crawl_url(self.target.url, depth=0)
        self._log(
            f"Crawl complete — {len(self._visited)} pages visited, "
            f"{total} endpoints registered"
        )
        return total

    # ── Internal ──────────────────────────────────────────────────────────

    def _crawl_url(self, url: str, depth: int) -> int:
        """Recursively crawl a URL, following links up to max_depth."""
        if depth > self.max_depth:
            return 0
        if len(self._visited) >= self.max_pages:
            return 0
        if url in self._visited:
            return 0
        if not self.target.is_in_scope(url):
            return 0

        self._visited.add(url)
        registered = 0

        try:
            resp = self._session.get(
                url, timeout=self.timeout, allow_redirects=True
            )
            time.sleep(self.delay)
        except requests.RequestException:
            return 0

        # Register this URL as an endpoint
        tags   = self._detect_tags(url, resp)
        params = self._extract_url_params(url)
        ep     = Endpoint(
            url=url, method="GET", params=params,
            source="crawler", tags=tags,
        )
        if self.manager.add(ep):
            registered += 1
            self._log(f"  [{depth}] {url}")

        # Parse HTML for links and forms
        ct = resp.headers.get("Content-Type", "")
        if "html" not in ct:
            return registered

        soup = BeautifulSoup(resp.text, "html.parser")

        # Extract and register forms
        for form in soup.find_all("form"):
            form_ep = self._endpoint_from_form(form, url)
            if form_ep and self.manager.add(form_ep):
                registered += 1
                self._log(f"  [form] {form_ep.method} {form_ep.url}")

        # Follow links
        for a_tag in soup.find_all("a", href=True):
            href     = a_tag["href"].split("#")[0].strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:")):
                continue
            abs_href = urljoin(url, href)
            registered += self._crawl_url(abs_href, depth + 1)

        return registered

    def _endpoint_from_form(
        self, form, page_url: str
    ) -> Optional[Endpoint]:
        """Convert a BeautifulSoup form element into an Endpoint."""
        action = form.get("action", page_url) or page_url
        if not action.startswith("http"):
            action = urljoin(page_url, action)
        if not self.target.is_in_scope(action):
            return None

        method = form.get("method", "GET").upper()
        params = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                params[name] = inp.get("value", "")

        form_data = {
            "action": action,
            "method": method,
            "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
            "inputs": params,
        }
        tags = self._detect_tags(action, None)
        if any(kw in str(params.keys()).lower() for kw in
               ("user", "email", "pass", "login")):
            tags.append("login-form")

        return Endpoint(
            url=action, method=method,
            params=params, form_data=form_data,
            source="form", tags=tags,
        )

    @staticmethod
    def _extract_url_params(url: str) -> dict:
        """Return a {name: value} dict of query-string parameters."""
        parsed = urlparse(url)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    @staticmethod
    def _detect_tags(url: str, resp: Optional[requests.Response]) -> list[str]:
        """Heuristically assign tags based on URL and response content."""
        tags: list[str] = []
        url_lower = url.lower()

        if any(p in url_lower for p in API_PATH_PATTERNS):
            tags.append("api")

        if any(kw in url_lower for kw in ("/login", "/signin", "/auth")):
            tags.append("auth")

        if resp is not None:
            ct = resp.headers.get("Content-Type", "")
            if any(j in ct for j in JSON_CONTENT_TYPES):
                tags.append("json")
                tags.append("api")

        if any(kw in url_lower for kw in ("/admin", "/dashboard", "/manage")):
            tags.append("admin")

        return list(set(tags))

    def _build_session(self) -> requests.Session:
        """Create a requests.Session configured from the Target."""
        session = requests.Session()
        cfg     = self.target.session_config()
        session.cookies.update(cfg["cookies"])
        session.headers.update({
            "User-Agent": "WebVulnScanner/2.0 (authorized-security-testing)",
        })
        session.headers.update(cfg["headers"])
        if cfg["proxies"]:
            session.proxies.update(cfg["proxies"])
        session.verify = cfg["verify"]
        return session

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"  [crawler] {msg}")
