"""
core/endpoint_manager.py — Central, thread-safe endpoint registry.

All crawler discoveries and module findings are funnelled through
EndpointManager, which deduplicates, categorises, and distributes
endpoints to scanner modules.
"""
import threading
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs


@dataclass
class Endpoint:
    """
    Represents a single scannable surface area element.

    Attributes:
        url:        Full URL of this endpoint.
        method:     HTTP method (GET, POST, PUT, …).
        params:     Query or body parameters keyed by name.
        form_data:  Form action details (action URL, enctype, inputs).
        source:     Where this endpoint was discovered (crawler, header, etc.).
        tags:       Descriptive tags (e.g. 'api', 'login', 'json').
    """
    url:       str
    method:    str                   = "GET"
    params:    dict                  = field(default_factory=dict)
    form_data: Optional[dict]        = None
    source:    str                   = "crawler"
    tags:      list[str]             = field(default_factory=list)

    # Derived
    _key:      str                   = field(init=False)

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        self._key   = self._make_key()

    def _make_key(self) -> str:
        """Stable deduplication key: method + url (param-name-only, sorted)."""
        parsed     = urlparse(self.url)
        param_keys = sorted(parse_qs(parsed.query).keys())
        base       = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return f"{self.method}:{base}?{','.join(param_keys)}"

    @property
    def key(self) -> str:
        return self._key

    def has_params(self) -> bool:
        return bool(self.params) or bool(self.form_data)

    def is_api(self) -> bool:
        return "api" in self.tags or "/api/" in self.url

    def __repr__(self) -> str:
        return f"Endpoint({self.method} {self.url})"


class EndpointManager:
    """
    Thread-safe central store for all discovered endpoints.

    Usage:
        mgr = EndpointManager()
        mgr.add(Endpoint(url="http://target.com/search", params={"q": ""}))
        for ep in mgr.all():
            ...
    """

    def __init__(self) -> None:
        self._lock:      threading.Lock         = threading.Lock()
        self._store:     dict[str, Endpoint]    = {}
        self._tag_index: dict[str, list[str]]   = {}   # tag → [key, …]

    # ── Mutation ──────────────────────────────────────────────────────────

    def add(self, endpoint: Endpoint) -> bool:
        """
        Register an endpoint. Returns True if it was new, False if duplicate.
        """
        with self._lock:
            if endpoint.key in self._store:
                return False
            self._store[endpoint.key] = endpoint
            for tag in endpoint.tags:
                self._tag_index.setdefault(tag, []).append(endpoint.key)
            return True

    def add_many(self, endpoints: list[Endpoint]) -> int:
        """Bulk register. Returns count of newly added endpoints."""
        return sum(1 for ep in endpoints if self.add(ep))

    def tag(self, key: str, *tags: str) -> None:
        """Add tags to an existing endpoint."""
        with self._lock:
            if key in self._store:
                for t in tags:
                    if t not in self._store[key].tags:
                        self._store[key].tags.append(t)
                        self._tag_index.setdefault(t, []).append(key)

    # ── Queries ────────────────────────────────────────────────────────────

    def all(self) -> list[Endpoint]:
        """Return all registered endpoints (snapshot)."""
        with self._lock:
            return list(self._store.values())

    def with_params(self) -> list[Endpoint]:
        """Return endpoints that have at least one parameter."""
        return [ep for ep in self.all() if ep.has_params()]

    def with_tag(self, tag: str) -> list[Endpoint]:
        """Return endpoints matching a specific tag."""
        with self._lock:
            keys = self._tag_index.get(tag, [])
            return [self._store[k] for k in keys if k in self._store]

    def by_method(self, method: str) -> list[Endpoint]:
        """Return all endpoints for a given HTTP method."""
        return [ep for ep in self.all() if ep.method == method.upper()]

    def api_endpoints(self) -> list[Endpoint]:
        """Return endpoints identified as API surfaces."""
        return [ep for ep in self.all() if ep.is_api()]

    def forms(self) -> list[Endpoint]:
        """Return endpoints discovered via form extraction."""
        return [ep for ep in self.all() if ep.form_data is not None]

    # ── Statistics ─────────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return a summary of stored endpoints."""
        eps = self.all()
        return {
            "total":       len(eps),
            "with_params": sum(1 for e in eps if e.has_params()),
            "forms":       sum(1 for e in eps if e.form_data),
            "api":         sum(1 for e in eps if e.is_api()),
            "get":         sum(1 for e in eps if e.method == "GET"),
            "post":        sum(1 for e in eps if e.method == "POST"),
        }

    def __len__(self) -> int:
        return len(self._store)

    def __repr__(self) -> str:
        return f"EndpointManager({len(self)} endpoints)"
