"""
utils/payload_loader.py — OWASP-mapped payload file resolver.

Priority order:
  1. -w folder  → load every .txt file inside the folder
  2. -w file    → load that single file
  3. -w string  → use the literal string as one payload
  4. no -w      → load data/<module>.txt (OWASP-mapped default)
  5. fallback   → empty list (module uses its own hardcoded defaults)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional

# Absolute path to the data/ directory next to this utils/ package
DATA_DIR: Path = Path(__file__).resolve().parent.parent / "data"

# Maps module key → filename inside DATA_DIR
MODULE_FILE: dict[str, str] = {
    "sqli":  "sqli.txt",
    "xss":   "xss.txt",
    "ssrf":  "ssrf.txt",
    "bac":   "bac.txt",
    "auth":  "auth.txt",
    "info":  "paths.txt",
}


def _read_file(path: Path) -> List[str]:
    """Return non-empty, non-comment lines from a payload file."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def resolve_payloads(
    w_arg: Optional[str],
    module_name: str,
    data_dir: Path = DATA_DIR,
) -> List[str]:
    """
    Return the effective payload list for *module_name*.

    Args:
        w_arg:       Value of the -w/--wordlist CLI flag, or None.
        module_name: Module key (e.g. "sqli", "xss", "ssrf").
        data_dir:    Override for the data directory (used in tests).

    Returns:
        List of payload strings, or [] if no file found (caller uses
        its own hardcoded defaults).
    """
    if w_arg is not None:
        p = Path(w_arg)
        if p.is_dir():
            payloads: List[str] = []
            for txt in sorted(p.glob("*.txt")):
                payloads.extend(_read_file(txt))
            return payloads
        if p.is_file():
            return _read_file(p)
        # Treat as a literal single-payload string
        return [w_arg]

    # No -w: try the OWASP-mapped default file
    filename = MODULE_FILE.get(module_name)
    if filename:
        default_path = data_dir / filename
        if default_path.is_file():
            return _read_file(default_path)

    return []
