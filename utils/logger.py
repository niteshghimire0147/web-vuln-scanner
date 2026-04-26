"""
utils/logger.py — Structured logging with coloured console output.

Usage:
    from utils.logger import get_logger
    log = get_logger(__name__)
    log.info("Scanning %s", target)
    log.debug("Raw response: %s", resp.text)
    log.warning("No banners found on port %d", port)
    log.error("Connection refused: %s", exc)
"""
from __future__ import annotations

import logging
import sys
from typing import Optional

# ── Colour constants (degrade gracefully if colorama is absent) ──────────────
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    _LEVEL_COLOURS = {
        "DEBUG":    Fore.CYAN,
        "INFO":     Fore.GREEN,
        "WARNING":  Fore.YELLOW,
        "ERROR":    Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }
    _RESET = Style.RESET_ALL
    _DIM   = Style.DIM
except ImportError:
    _LEVEL_COLOURS = {}
    _RESET = _DIM = ""


class _ColouredFormatter(logging.Formatter):
    """Formatter that prepends a coloured severity prefix to every record."""

    _PREFIX = {
        "DEBUG":    "[DBG]",
        "INFO":     "[*]  ",
        "WARNING":  "[!]  ",
        "ERROR":    "[-]  ",
        "CRITICAL": "[!!] ",
    }

    def format(self, record: logging.LogRecord) -> str:
        colour  = _LEVEL_COLOURS.get(record.levelname, "")
        prefix  = self._PREFIX.get(record.levelname, "[?]  ")
        message = super().format(record)
        return f"{colour}{prefix} {message}{_RESET}"


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Return a named logger configured with a coloured StreamHandler.

    Call ``configure_root(verbose=True)`` once in main() to switch the
    root logger to DEBUG so all child loggers emit debug output.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_ColouredFormatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


def configure_root(verbose: bool = False, quiet: bool = False) -> None:
    """
    Set the global log level for all project loggers.

    Call once at the top of main() after parsing args:
        configure_root(verbose=args.verbose, quiet=args.quiet)
    """
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    # Push the level to every already-created handler on the root logger
    for handler in root.handlers:
        handler.setLevel(level)
    # Also push to every logger that was already created under this package
    for name, logger in logging.Logger.manager.loggerDict.items():
        if isinstance(logger, logging.Logger):
            logger.setLevel(level)
