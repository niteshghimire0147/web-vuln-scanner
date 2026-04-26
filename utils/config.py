"""
utils/config.py — YAML configuration loader with CLI override support.

Usage:
    from utils.config import load_config
    cfg = load_config()                  # loads config.yaml next to this project
    cfg = load_config("custom.yaml")     # loads a custom path
    threads = cfg.get("scan.threads", 50)
    cfg.set("scan.threads", args.threads)  # CLI arg overrides config value
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

# PyYAML is optional; fall back to empty dict if not installed
try:
    import yaml as _yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_CONFIG = _PROJECT_ROOT / "config.yaml"


class Config:
    """
    Dot-notation access to a nested YAML configuration dict.

    Keys are addressed with dots: ``cfg.get("scan.threads")``.
    """

    def __init__(self, data: dict) -> None:
        self._data = data

    # ── Read ─────────────────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value by dot-separated key path.

        Example: ``cfg.get("scan.threads", 50)``
        """
        parts = key.split(".")
        node: Any = self._data
        for part in parts:
            if not isinstance(node, dict):
                return default
            node = node.get(part)
            if node is None:
                return default
        return node

    def __getitem__(self, key: str) -> Any:
        return self.get(key)

    # ── Write (CLI overrides) ─────────────────────────────────────────────────

    def set(self, key: str, value: Any) -> None:
        """
        Override a config value at runtime (e.g. from a CLI argument).

        Only applied if *value* is not None / not the argparse default.
        """
        if value is None:
            return
        parts = key.split(".")
        node = self._data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def override_from_args(self, mapping: dict[str, Any]) -> None:
        """
        Bulk-apply a {dot_key: value} dict of CLI overrides.

        Skips None values so unset argparse arguments don't clobber config.

        Example:
            cfg.override_from_args({
                "scan.threads": args.threads,
                "output.verbose": args.verbose,
            })
        """
        for key, value in mapping.items():
            if value is not None:
                self.set(key, value)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def as_dict(self) -> dict:
        """Return the raw underlying dict (for serialisation)."""
        return self._data

    def __repr__(self) -> str:
        return f"Config({list(self._data.keys())})"


def load_config(path: Optional[str | Path] = None) -> Config:
    """
    Load configuration from a YAML file.

    Falls back to empty config if:
    - PyYAML is not installed
    - The file does not exist
    - The file is not valid YAML

    Args:
        path: Path to config YAML.  Defaults to ``config.yaml`` in the
              project root (sibling of this file's ``utils/`` directory).

    Returns:
        Config instance with dot-notation access.
    """
    config_path = Path(path) if path else _DEFAULT_CONFIG

    if not _YAML_AVAILABLE:
        return Config({})

    if not config_path.is_file():
        return Config({})

    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            data = _yaml.safe_load(fh) or {}
    except Exception:
        return Config({})

    return Config(data)
