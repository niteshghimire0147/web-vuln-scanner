"""
core/target.py — Target representation and metadata container.

Encapsulates everything known about a scan target: the base URL,
parsed components, scope rules, and scan-time metadata.
"""
from dataclasses import dataclass, field
from urllib.parse import urlparse, ParseResult
from typing import Optional
import time


@dataclass
class Target:
    """
    Immutable representation of a scan target.

    Attributes:
        url:        Canonical base URL (trailing slash stripped).
        scheme:     URL scheme ('http' or 'https').
        host:       Hostname or IP.
        port:       Port number (explicit or scheme default).
        path:       Base path component.
        parsed:     urllib ParseResult for the base URL.
        scope:      Additional in-scope URLs/patterns (default: base URL only).
        started_at: Unix timestamp when the Target was created.
        proxy:      Optional HTTP/HTTPS proxy URL.
        cookies:    Session cookies to attach to all requests.
        headers:    Extra HTTP headers for all requests.
        timeout:    Per-request HTTP timeout (seconds).
        verify_ssl: Whether to verify TLS certificates.
    """
    url:        str
    proxy:      Optional[str]          = None
    cookies:    dict                   = field(default_factory=dict)
    headers:    dict                   = field(default_factory=dict)
    timeout:    int                    = 10
    verify_ssl: bool                   = False
    scope:      list[str]              = field(default_factory=list)

    # Populated post-init
    scheme:     str                    = field(init=False)
    host:       str                    = field(init=False)
    port:       int                    = field(init=False)
    path:       str                    = field(init=False)
    parsed:     ParseResult            = field(init=False)
    started_at: float                  = field(init=False, default_factory=time.time)

    def __post_init__(self) -> None:
        self.url    = self.url.rstrip("/")
        self.parsed = urlparse(self.url)
        self.scheme = self.parsed.scheme.lower()
        self.host   = self.parsed.hostname or ""
        self.path   = self.parsed.path or "/"

        if self.parsed.port:
            self.port = self.parsed.port
        else:
            self.port = 443 if self.scheme == "https" else 80

        # Default scope: anything under the same origin
        if not self.scope:
            self.scope = [self.url]

    def is_in_scope(self, url: str) -> bool:
        """Return True if the given URL falls within the configured scope."""
        parsed = urlparse(url)
        target_origin = f"{parsed.scheme}://{parsed.netloc}"
        base_origin   = f"{self.scheme}://{self.parsed.netloc}"
        return target_origin == base_origin

    def session_config(self) -> dict:
        """Return a dict suitable for configuring a requests.Session."""
        return {
            "cookies": self.cookies,
            "headers": self.headers,
            "proxies": {"http": self.proxy, "https": self.proxy} if self.proxy else {},
            "verify":  self.verify_ssl,
            "timeout": self.timeout,
        }

    def __str__(self) -> str:
        return f"Target({self.url})"
