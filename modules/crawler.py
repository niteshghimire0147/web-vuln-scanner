"""
crawler.py — Web crawler that extracts URLs and HTML forms from a target site.

Used by scanner modules to build a list of endpoints and form inputs to test.
"""
import time
from typing import List, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class WebCrawler:
    """
    Crawls a web application and collects URLs and form definitions.

    Respects same-origin policy — only crawls URLs on the same host.
    """

    def __init__(
        self,
        base_url: str,
        session: requests.Session,
        max_depth: int = 2,
        max_pages: int = 50,
        timeout: int = 10,
        delay: float = 0.0,
        verbose: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self._base_host = urlparse(base_url).netloc

    def crawl(self) -> Tuple[Set[str], List[dict]]:
        """
        Crawl the target site.

        Returns:
            Tuple of:
                - Set of discovered URLs (strings)
                - List of form dicts: {action, method, inputs: [{name, type, value}]}
        """
        visited: Set[str] = set()
        forms: List[dict] = []
        queue = [(self.base_url, 0)]

        while queue and len(visited) < self.max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > self.max_depth:
                continue

            try:
                if self.delay > 0:
                    time.sleep(self.delay)
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                visited.add(url)
                if self.verbose:
                    print(f"  [CRAWL] {url} ({resp.status_code})")
            except requests.RequestException:
                continue

            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Extract links
            for tag in soup.find_all("a", href=True):
                href = tag["href"]
                abs_url = urljoin(url, href)
                parsed = urlparse(abs_url)
                # Same-origin only, no fragments
                if parsed.netloc == self._base_host and parsed.scheme in ("http", "https"):
                    clean = abs_url.split("#")[0]
                    if clean not in visited:
                        queue.append((clean, depth + 1))

            # Extract forms
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = (form.get("method", "get") or "get").upper()
                form_url = urljoin(url, action) if action else url
                inputs = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    inputs.append({
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", ""),
                    })
                forms.append({
                    "action": form_url,
                    "method": method,
                    "inputs": inputs,
                    "source_url": url,
                })

        return visited, forms

    def extract_url_params(self, urls: Set[str]) -> List[dict]:
        """
        Extract URLs that have query parameters for parameter-based testing.

        Returns:
            List of {url, param_name, original_value} dicts.
        """
        targets = []
        for url in urls:
            parsed = urlparse(url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        name, _, value = param.partition("=")
                        targets.append({
                            "url": url,
                            "param_name": name,
                            "original_value": value,
                        })
        return targets
